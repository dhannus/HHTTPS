/**
 * Privacy Pass Token Issuer — RFC 9578 §6 (Token Type 0x0002, multi-role).
 *
 * The truncated_token_key_id in the TokenRequest tells us which role-specific
 * key the client wants to use. We look it up in the issuer registry, then run
 * the standard VOPRF blind evaluation against that key.
 */

import { Oprf, VOPRFServer, EvaluationRequest } from '@cloudflare/voprf-ts';

import {
  TOKEN_TYPE,
  SUITE,
  SUITE_NAME,
  Ne,
  Ns,
  getIssuer,
  findIssuerByTruncatedKeyId,
  listIssuers,
} from './keys.js';

// Cache of VOPRFServer instances per issuer (avoids reconstruction per request)
const _servers = new Map();
function getServer(issuer) {
  let s = _servers.get(issuer.role);
  if (!s) {
    s = new VOPRFServer(SUITE, issuer.privateKey);
    _servers.set(issuer.role, s);
  }
  return s;
}

function parseTokenRequest(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  const expectedLen = 2 + 1 + Ne;
  if (buf.length !== expectedLen) {
    throw new Error(`TokenRequest length ${buf.length} != expected ${expectedLen}`);
  }
  const tokenType         = buf.readUInt16BE(0);
  const truncatedKeyIdVal = buf.readUInt8(2);
  const blindedMsg        = buf.subarray(3, 3 + Ne);

  if (tokenType !== TOKEN_TYPE) {
    throw new Error(`Unsupported token_type 0x${tokenType.toString(16).padStart(4, '0')}`);
  }
  return { truncatedKeyIdVal, blindedMsg };
}

function blindedToEvalRequest(blindedMsg) {
  const wire = Buffer.concat([Buffer.from([0x00, 0x01]), Buffer.from(blindedMsg)]);
  return EvaluationRequest.deserialize(SUITE, wire);
}

function evaluationToTokenResponse(ev) {
  if (!ev.evaluated || ev.evaluated.length !== 1) {
    throw new Error('Internal: expected one evaluated element');
  }
  if (!ev.proof) {
    throw new Error('Internal: VOPRF evaluation missing DLEQ proof');
  }
  const evalMsg   = Buffer.from(ev.evaluated[0].serialize());
  const evalProof = Buffer.from(ev.proof.serialize());
  return Buffer.concat([evalMsg, evalProof]);
}

/**
 * Core issuance: given a raw blinded_msg and an issuer descriptor, produce
 * the TokenResponse bytes. Reused by the public token-request endpoint and
 * by the authenticated batch-issue endpoint.
 */
export async function issueTokenResponse(blindedMsg, issuer) {
  const evalReq = blindedToEvalRequest(blindedMsg);
  const ev      = await getServer(issuer).blindEvaluate(evalReq);
  return evaluationToTokenResponse(ev);
}

/**
 * POST /privacy-pass/token-request
 *
 * Public endpoint per RFC 9578. The role is implicit in the truncated_token_key_id.
 */
export async function handleTokenRequest(req, res) {
  try {
    let body;
    if (Buffer.isBuffer(req.body)) body = req.body;
    else if (typeof req.body === 'string') body = Buffer.from(req.body, 'base64');
    else if (req.body?.token_request) body = Buffer.from(req.body.token_request, 'base64');
    else throw new Error('Body must be raw bytes or base64-encoded TokenRequest');

    const { truncatedKeyIdVal, blindedMsg } = parseTokenRequest(body);
    const issuer = findIssuerByTruncatedKeyId(truncatedKeyIdVal);
    if (!issuer) {
      throw new Error('truncated_token_key_id matches no known issuer key');
    }

    const tokenResp = await issueTokenResponse(blindedMsg, issuer);
    res.setHeader('Content-Type', 'application/private-token-response');
    res.status(200).send(tokenResp);

  } catch (err) {
    res.status(400)
      .setHeader('Content-Type', 'application/json')
      .json({ error: 'invalid_token_request', detail: err.message });
  }
}

/**
 * GET /privacy-pass/keys
 *
 * Lists all available issuer keys (default + per-role), in a developer-friendly
 * shape. Origins discovering specific roles use the per-role .well-known
 * documents instead.
 */
export function handleKeysList(req, res) {
  const tokenKeys = listIssuers().map(role => {
    const i = getIssuer(role);
    return {
      role,
      'token-type': TOKEN_TYPE,
      'token-key':  i.publicKey.toString('base64url'),
      'not-before': i.notBefore,
    };
  });
  res.json({ suite: SUITE_NAME, count: tokenKeys.length, 'token-keys': tokenKeys });
}

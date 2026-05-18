/**
 * Privacy Pass Token Issuer — RFC 9578 §6 (Token Type 0x0002, VOPRF)
 *
 * Wire format per RFC 9578 §6.1:
 *
 *   struct {
 *     uint16 token_type;             // 0x0002
 *     uint8  truncated_token_key_id; // SHA-256(pkS)[31]
 *     uint8  blinded_msg[Ne];        // Ne = 49 bytes for P-384
 *   } TokenRequest;
 *
 *   struct {
 *     uint8  evaluated_msg[Ne];      // 49 bytes
 *     uint8  evaluated_proof[Ns+Ns]; // 96 bytes (DLEQ proof: c || s)
 *   } TokenResponse;
 *
 * Content-Type for request:  application/private-token-request
 * Content-Type for response: application/private-token-response
 *
 * Implementation strategy: the @cloudflare/voprf-ts library has its own
 * serialization format that wraps elements in length prefixes. We bridge
 * between that format and the Privacy Pass wire format by:
 *   1. Wrapping the raw blinded_msg in a single-element EvaluationRequest
 *      (which we build by re-serializing in the library's format).
 *   2. Calling VOPRFServer.blindEvaluate to get an Evaluation.
 *   3. Pulling the single evaluated element and the DLEQ proof out, then
 *      concatenating them into the Privacy Pass TokenResponse.
 */

import { Oprf, VOPRFServer, EvaluationRequest } from '@cloudflare/voprf-ts';

import {
  TOKEN_TYPE,
  SUITE,
  SUITE_NAME,
  Ne,
  Ns,
  getPrivateKey,
  getPublicKeyB64Url,
  getNotBefore,
  truncatedKeyId,
} from './keys.js';

let _server = null;

function getServer() {
  if (!_server) {
    _server = new VOPRFServer(SUITE, getPrivateKey());
  }
  return _server;
}

/**
 * Parse a TokenRequest from a raw byte buffer.
 * Throws on any structural or value mismatch.
 */
function parseTokenRequest(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);

  const expectedLen = 2 + 1 + Ne;  // 52 bytes
  if (buf.length !== expectedLen) {
    throw new Error(`TokenRequest length ${buf.length} != expected ${expectedLen}`);
  }

  const tokenType         = buf.readUInt16BE(0);
  const truncatedKeyIdVal = buf.readUInt8(2);
  const blindedMsg        = buf.subarray(3, 3 + Ne);

  if (tokenType !== TOKEN_TYPE) {
    throw new Error(`Unsupported token_type 0x${tokenType.toString(16).padStart(4, '0')}`);
  }
  if (truncatedKeyIdVal !== truncatedKeyId()) {
    throw new Error('truncated_token_key_id does not match current issuer key');
  }

  return { blindedMsg };
}

/**
 * Build an EvaluationRequest from a raw blinded element.
 *
 * The library's EvaluationRequest.deserialize expects:
 *   uint16 count, followed by `count` elements of size Ne each.
 * We construct that exact buffer with count=1.
 */
function blindedToEvalRequest(blindedMsg) {
  const wireFormat = Buffer.concat([
    Buffer.from([0x00, 0x01]),   // count = 1, big-endian
    Buffer.from(blindedMsg),
  ]);
  return EvaluationRequest.deserialize(SUITE, wireFormat);
}

/**
 * Encode an Evaluation result into the Privacy Pass TokenResponse wire format.
 * The library gives us a single Elt and a DLEQProof; we serialize each and
 * concatenate them with no length prefixes (PP format).
 */
function evaluationToTokenResponse(evaluation) {
  if (!evaluation.evaluated || evaluation.evaluated.length !== 1) {
    throw new Error('Internal: expected exactly one evaluated element');
  }
  if (!evaluation.proof) {
    throw new Error('Internal: VOPRF evaluation missing DLEQ proof');
  }

  const evaluatedMsg   = evaluation.evaluated[0].serialize();  // Ne bytes
  const evaluatedProof = evaluation.proof.serialize();          // 2*Ns bytes

  if (evaluatedMsg.length !== Ne) {
    throw new Error(`Internal: evaluated element size ${evaluatedMsg.length} != ${Ne}`);
  }
  if (evaluatedProof.length !== 2 * Ns) {
    throw new Error(`Internal: proof size ${evaluatedProof.length} != ${2 * Ns}`);
  }

  return Buffer.concat([Buffer.from(evaluatedMsg), Buffer.from(evaluatedProof)]);
}

/**
 * POST /privacy-pass/token-request
 *
 * Express handler. Expects a raw body of bytes (Content-Type:
 * application/private-token-request). For development convenience, also
 * accepts base64-encoded body as a JSON field { "token_request": "<b64>" }.
 */
export async function handleTokenRequest(req, res) {
  try {
    let body;
    if (Buffer.isBuffer(req.body)) {
      body = req.body;
    } else if (typeof req.body === 'string') {
      body = Buffer.from(req.body, 'base64');
    } else if (req.body && typeof req.body.token_request === 'string') {
      body = Buffer.from(req.body.token_request, 'base64');
    } else {
      throw new Error('Request body must be raw bytes or base64-encoded TokenRequest');
    }

    const { blindedMsg } = parseTokenRequest(body);

    // Real VOPRF blind evaluation
    const evalRequest  = blindedToEvalRequest(blindedMsg);
    const evaluation   = await getServer().blindEvaluate(evalRequest);
    const tokenResp    = evaluationToTokenResponse(evaluation);

    res.setHeader('Content-Type', 'application/private-token-response');
    res.status(200).send(tokenResp);

  } catch (err) {
    return res.status(400)
      .setHeader('Content-Type', 'application/json')
      .json({
        error: 'invalid_token_request',
        detail: err.message,
      });
  }
}

/**
 * GET /privacy-pass/keys
 *
 * Convenience endpoint that returns the same information as the well-known
 * directory but in a developer-friendly JSON shape. Not required by the spec.
 */
export function handleKeysList(req, res) {
  res.json({
    suite: SUITE_NAME,
    'token-keys': [
      {
        'token-type': TOKEN_TYPE,
        'token-key':  getPublicKeyB64Url(),
        'not-before': getNotBefore(),
      },
    ],
  });
}

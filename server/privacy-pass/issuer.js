/**
 * Privacy Pass Token Issuer — RFC 9578 §6 (Token Type 0x0002, VOPRF)
 *
 * Accepts a TokenRequest from a client, blind-evaluates it with the issuer's
 * VOPRF private key, and returns a TokenResponse. The client unblinds the
 * response locally to obtain a valid token.
 *
 * Wire format per RFC 9578 §6.1:
 *
 *   struct {
 *     uint16 token_type;             // 0x0002
 *     uint8  truncated_token_key_id;
 *     uint8  blinded_msg[Ne];        // Ne = 49 bytes for P-384
 *   } TokenRequest;
 *
 *   struct {
 *     uint8  evaluated_msg[Ne];      // 49 bytes
 *     uint8  evaluated_proof[Ns+Ns]; // 96 bytes for P-384 (DLEQ proof)
 *   } TokenResponse;
 *
 * Content-Type for request:  application/private-token-request
 * Content-Type for response: application/private-token-response
 */

import {
  TOKEN_TYPE,
  SUITE_NAME,
  getPrivateKey,
  getPublicKeyB64Url,
  getNotBefore,
  truncatedKeyId,
} from './keys.js';

const Ne_P384 = 49;  // compressed EC point size for P-384
const Ns_P384 = 48;  // scalar size for P-384

/**
 * Parse a TokenRequest from a raw byte buffer.
 * Throws if the structure or field values are invalid.
 */
function parseTokenRequest(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);

  // Minimum size: 2 (token_type) + 1 (truncated_key_id) + Ne (blinded_msg)
  const expected = 2 + 1 + Ne_P384;
  if (buf.length !== expected) {
    throw new Error(`TokenRequest length ${buf.length} != expected ${expected}`);
  }

  const tokenType         = buf.readUInt16BE(0);
  const truncatedKeyIdVal = buf.readUInt8(2);
  const blindedMsg        = buf.subarray(3, 3 + Ne_P384);

  if (tokenType !== TOKEN_TYPE) {
    throw new Error(`Unsupported token_type 0x${tokenType.toString(16).padStart(4, '0')}`);
  }
  if (truncatedKeyIdVal !== truncatedKeyId()) {
    throw new Error('truncated_token_key_id does not match current issuer key');
  }

  return { blindedMsg };
}

/**
 * POST /privacy-pass/token-request
 *
 * Express handler. Expects a raw body of bytes (Content-Type:
 * application/private-token-request). The Express app must register
 * `express.raw({ type: 'application/private-token-request' })` upstream
 * for this route, OR the body should arrive as a Buffer already.
 */
export async function handleTokenRequest(req, res) {
  try {
    // The request body should be raw bytes per RFC 9578. Accept Buffer or
    // base64-encoded string for flexibility during development.
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

    // ── VOPRF blind evaluation ─────────────────────────────────────────────
    //
    // TODO: implement once @cloudflare/voprf-ts is installed.
    //
    // Real implementation:
    //
    //   import { Oprf, OPRFServer } from '@cloudflare/voprf-ts';
    //   const suite  = Oprf.Suite.P384_SHA384;
    //   const server = new OPRFServer(suite, getPrivateKey());
    //   const { evaluatedElement, proof } = await server.blindEvaluate(blindedMsg);
    //   const responseBuf = Buffer.concat([evaluatedElement, proof]);
    //
    // Until then, return 501 to signal that the protocol stub is in place
    // but cryptography is not yet wired.

    void getPrivateKey();  // silence unused-import warning until implemented
    void blindedMsg;

    return res.status(501)
      .setHeader('Content-Type', 'application/json')
      .json({
        error: 'not_implemented',
        detail: 'VOPRF blind evaluation pending. See server/privacy-pass/issuer.js',
      });

    // When implemented, the success branch will be:
    //
    //   res.setHeader('Content-Type', 'application/private-token-response');
    //   res.status(200).send(responseBuf);

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

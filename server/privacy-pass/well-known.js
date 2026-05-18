/**
 * Privacy Pass Issuer Directory — RFC 9578 §4
 *
 * Served at /.well-known/private-token-issuer-directory.
 * Tells clients which token types this issuer supports and the public keys.
 */

import { TOKEN_TYPE, getPublicKeyB64Url, getNotBefore } from './keys.js';

/**
 * Express handler. Mounts at /.well-known/private-token-issuer-directory.
 *
 * Content-Type per RFC 9578 §4: application/private-token-issuer-directory
 */
export function handleIssuerDirectory(req, res) {
  res.setHeader('Content-Type', 'application/private-token-issuer-directory');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json({
    'issuer-request-uri': '/privacy-pass/token-request',
    'token-keys': [
      {
        'token-type': TOKEN_TYPE,
        'token-key':  getPublicKeyB64Url(),
        'not-before': getNotBefore(),
      },
    ],
  });
}

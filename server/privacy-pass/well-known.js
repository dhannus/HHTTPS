/**
 * Privacy Pass Issuer Directories — RFC 9578 §4
 *
 * Two flavors:
 *
 *   /.well-known/private-token-issuer-directory
 *     Aggregated directory listing all issuer keys (default + per-role).
 *     This is non-standard but a useful single source of truth for our wallet.
 *
 *   /privacy-pass/r/<role>/.well-known/private-token-issuer-directory
 *     Per-role spec-compliant directory. An origin that wants to accept tokens
 *     for role X discovers the public key here. This is the path origins use
 *     for federation later on.
 */

import { TOKEN_TYPE, getIssuer, listIssuers, ROLES } from './keys.js';

/**
 * Aggregated directory: lists every issuer key we run.
 * Used by the wallet on hhttps.org/privacy-pass to know which key to bind to
 * each role.
 */
export function handleAggregateDirectory(req, res) {
  res.setHeader('Content-Type', 'application/private-token-issuer-directory');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json({
    'issuer-request-uri': '/privacy-pass/token-request',
    'token-keys': listIssuers().map(role => {
      const i = getIssuer(role);
      return {
        role,
        'token-type': TOKEN_TYPE,
        'token-key':  i.publicKey.toString('base64url'),
        'not-before': i.notBefore,
      };
    }),
  });
}

/**
 * Per-role directory: spec-compliant single-key document for the named role.
 */
export function handleRoleDirectory(req, res) {
  const role = req.params.role;
  if (role !== 'default' && !ROLES.includes(role)) {
    return res.status(404).json({ error: 'unknown_role', detail: role });
  }
  try {
    const i = getIssuer(role);
    res.setHeader('Content-Type', 'application/private-token-issuer-directory');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json({
      'issuer-request-uri': '/privacy-pass/token-request',
      'token-keys': [{
        'token-type': TOKEN_TYPE,
        'token-key':  i.publicKey.toString('base64url'),
        'not-before': i.notBefore,
      }],
    });
  } catch (err) {
    res.status(404).json({ error: 'issuer_not_initialized', detail: err.message });
  }
}

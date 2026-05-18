/**
 * Privacy Pass Module — entry point
 *
 * Exports:
 *   initPrivacyPass()          — async init, must be awaited before mounting
 *   privacyPassRouter          — Express router for /privacy-pass/* routes
 *   privacyPassWellKnownRouter — Express router for /.well-known/* routes
 *
 * Integration with server.js requires three lines (see INSTALL.md):
 *
 *   import { initPrivacyPass, privacyPassRouter, privacyPassWellKnownRouter }
 *     from './privacy-pass/index.js';
 *
 *   await initPrivacyPass();
 *
 *   app.use(privacyPassWellKnownRouter);
 *   app.use('/privacy-pass', privacyPassRouter);
 */

import express from 'express';
import { loadOrCreateKeys }    from './keys.js';
import { handleIssuerDirectory } from './well-known.js';
import { handleTokenRequest, handleKeysList } from './issuer.js';
import { handleVerify }         from './verifier.js';

let _initialized = false;

export async function initPrivacyPass() {
  if (_initialized) return;
  await loadOrCreateKeys();
  _initialized = true;
  console.log('   [PRIVACY-PASS] Module initialised');
}

// ─── Main router: /privacy-pass/* ─────────────────────────────────────────────

export const privacyPassRouter = express.Router();

// Accept both raw bytes (per RFC 9578) and JSON-wrapped base64 for flexibility
privacyPassRouter.use(
  '/token-request',
  express.raw({
    type: ['application/private-token-request', 'application/octet-stream'],
    limit: '1kb',
  })
);

privacyPassRouter.post('/token-request', handleTokenRequest);
privacyPassRouter.get ('/keys',          handleKeysList);
privacyPassRouter.post('/verify',        express.json({ limit: '4kb' }), handleVerify);

// ─── Well-known router: served at the root of .well-known ─────────────────────

export const privacyPassWellKnownRouter = express.Router();
privacyPassWellKnownRouter.get(
  '/.well-known/private-token-issuer-directory',
  handleIssuerDirectory
);

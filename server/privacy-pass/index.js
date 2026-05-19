/**
 * Privacy Pass Module — entry point
 *
 * Exports:
 *   initPrivacyPass()           — async init: keys + DB migration
 *   privacyPassRouter           — Express router for /privacy-pass/* routes
 *   privacyPassWellKnownRouter  — Express router for /.well-known/* routes
 *
 * Integration with server.js (already done):
 *   import { initPrivacyPass, privacyPassRouter, privacyPassWellKnownRouter }
 *     from './privacy-pass/index.js';
 *   await initPrivacyPass();
 *   app.use(privacyPassWellKnownRouter);
 *   app.use('/privacy-pass', privacyPassRouter);
 */

import express from 'express';
import { readFileSync, existsSync }       from 'fs';
import { dirname, join }                  from 'path';
import { fileURLToPath }                  from 'url';

import { loadOrCreateKeys }               from './keys.js';
import { handleAggregateDirectory,
         handleRoleDirectory }            from './well-known.js';
import { handleTokenRequest,
         handleKeysList }                 from './issuer.js';
import { handleVerify }                   from './verifier.js';
import { issuanceRouter }                 from './issuance.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');

let _initialized = false;

async function runMigration() {
  const sqlPath = join(__dirname, '..', 'sql', 'migration-pp.sql');
  if (!existsSync(sqlPath)) {
    console.warn('   [PRIVACY-PASS] migration-pp.sql not found, skipping DB migration');
    return;
  }
  try {
    const sql = readFileSync(sqlPath, 'utf8');
    const db  = await import('../db.js');
    await db.pool().query(sql);
    console.log('   [PRIVACY-PASS] DB migration applied (pp_issuance_log)');
  } catch (err) {
    console.error('   [PRIVACY-PASS] DB migration failed:', err.message);
    // Non-fatal — issuance endpoint will return clearer error if table missing
  }
}

export async function initPrivacyPass() {
  if (_initialized) return;
  await loadOrCreateKeys();
  await runMigration();
  _initialized = true;
  console.log('   [PRIVACY-PASS] Module initialised');
}

// ─── Main router: /privacy-pass/* ─────────────────────────────────────────────

export const privacyPassRouter = express.Router();

// Wallet UI — the main page users see when they visit hhttps.org/privacy-pass
privacyPassRouter.get('/', (req, res) => {
  res.sendFile(join(PUBLIC_DIR, 'wallet.html'));
});

// Static assets for the wallet (bundled voprf library, etc.)
privacyPassRouter.use('/lib',     express.static(join(PUBLIC_DIR, 'lib'),     { maxAge: '1d' }));
privacyPassRouter.use('/assets',  express.static(join(PUBLIC_DIR, 'assets'),  { maxAge: '1d' }));

// Public token request endpoint (raw bytes per RFC 9578)
privacyPassRouter.use(
  '/token-request',
  express.raw({ type: ['application/private-token-request', 'application/octet-stream'], limit: '1kb' })
);
privacyPassRouter.post('/token-request', handleTokenRequest);

// Authenticated batch issuance + quota check (used by wallet)
privacyPassRouter.use('/', issuanceRouter);

// Developer-friendly keys overview
privacyPassRouter.get('/keys', handleKeysList);

// Public verify endpoint
privacyPassRouter.post('/verify', express.json({ limit: '4kb' }), handleVerify);

// Per-role spec-compliant discovery
privacyPassRouter.get('/r/:role/.well-known/private-token-issuer-directory', handleRoleDirectory);

// ─── Well-known router (at root) ─────────────────────────────────────────────

export const privacyPassWellKnownRouter = express.Router();
privacyPassWellKnownRouter.get(
  '/.well-known/private-token-issuer-directory',
  handleAggregateDirectory
);

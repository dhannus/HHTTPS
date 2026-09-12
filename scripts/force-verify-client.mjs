// ---------------------------------------------------------------------------
//  force-verify-client.mjs  —  TEST SERVER ONLY
//
//  Forces one OAuth client to verification_status='verified' by calling the
//  same db.oauthClients.adminApprove() the admin portal uses — but WITHOUT the
//  'pending_review' state guard, so it works even when email/domain/DNS
//  verification could not be completed (e.g. an IP-only test box).
//
//  Run from the flat live dir so ./db.js and .env resolve:
//     cd /var/www/hhttps
//     node force-verify-client.mjs songbird-2423
//
//  Optional 2nd arg = the admin id recorded in verified_by (default below).
//
//  ⚠  DO NOT RUN ON PRODUCTION. This mints a "verified" badge that was not
//     earned (no confirmed email, no domain match, no DNS proof). On prod that
//     directly breaks the credibility model the verified flag exists to protect.
// ---------------------------------------------------------------------------
import 'dotenv/config';          // must be first: loads DB_* env for db.js
import * as db from './db.js';

const clientId = process.argv[2] || 'songbird-2423';
const adminId  = process.argv[3] || 'force-verify-cli';

console.warn('⚠  TEST-ONLY force-verify — bypasses email/domain/DNS checks.');
console.warn('   Never run this on production.\n');

db.init();

const SEL = `SELECT client_id, name, verification_status, verified, is_active, contact_email
             FROM oauth_clients WHERE client_id = $1`;

const before = (await db.q(SEL, [clientId])).rows[0];
if (!before) {
  console.error(`Client '${clientId}' not found in oauth_clients.`);
  process.exit(1);
}
console.log('BEFORE:', before);

// Intended code path — keeps us in sync if approve semantics change later.
await db.oauthClients.adminApprove(clientId, adminId);

// A usable test issuer must also be active (createDraft sets this TRUE; guard anyway).
if (before.is_active === false) {
  await db.q(`UPDATE oauth_clients SET is_active = TRUE WHERE client_id = $1`, [clientId]);
  console.log('   note: also set is_active = TRUE');
}

const after = (await db.q(SEL, [clientId])).rows[0];
console.log('AFTER :', after);
console.log(`\nDone — '${clientId}' is now verification_status=verified, verified=TRUE.`);
process.exit(0);

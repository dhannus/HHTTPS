// ---------------------------------------------------------------------------
//  force-verify-client.mjs  —  TEST SERVER ONLY
//
//  Forces one OAuth client to verification_status='verified' by calling the
//  same db.oauthClients.adminApprove() the admin portal uses — but WITHOUT the
//  'pending_review' state guard, so it works even when email/domain/DNS
//  verification could not be completed (e.g. an IP-only test box).
//
//  AP6-58 (#213): the script lives in server/scripts/ and imports ../db.js, so
//  it runs from the repo checkout — it used to sit in the repo-root scripts/
//  while expecting to be started from the flat live directory, which is why
//  deploy-phase8.sh copied it onto the production box in the first place.
//
//     cd /var/www/hhttps && node scripts/force-verify-client.mjs <client-id> --yes-i-know
//
//  Optional 3rd positional arg = the admin id recorded in verified_by.
//
//  AP6-25 (#213): guards, because this mints a "verified" badge that was not
//  earned (no confirmed email, no domain match, no DNS proof) and on prod that
//  directly breaks the credibility model the verified flag exists to protect:
//    - refuses to run with NODE_ENV=production,
//    - requires --yes-i-know,
//    - has no default client id (it used to approve one hard-coded test
//      client when called with no arguments at all).
// ---------------------------------------------------------------------------
import 'dotenv/config';          // must be first: loads DB_* env for db.js
import * as db from '../db.js';

const args     = process.argv.slice(2);
const confirmed = args.includes('--yes-i-know');
const positional = args.filter(a => !a.startsWith('--'));
const clientId = positional[0];
const adminId  = positional[1] || 'force-verify-cli';

function die(msg) {
  console.error(msg);
  process.exit(1);
}

if (process.env.NODE_ENV === 'production') {
  die('Refusing to run with NODE_ENV=production — this bypasses email/domain/DNS verification.');
}
if (!clientId) {
  die('Usage: node scripts/force-verify-client.mjs <client-id> [admin-id] --yes-i-know');
}
if (!confirmed) {
  die('Refusing to run without --yes-i-know: this mints an unearned "verified" badge.');
}

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

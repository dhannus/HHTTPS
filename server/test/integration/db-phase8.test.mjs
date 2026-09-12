// T3 / AK-1, AK-16, AK-17: phase-8 migration and identity DB layer.
// Talks to db.js directly (no server process) against the local test Postgres.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { sql, closeDb, TEST_DB } from '../helpers/db.mjs';

const skip = !TEST_DB.host && 'TEST_PG_HOST not set';

// db.js reads DB_* at import time — set them (from the shared TEST_DB config,
// W-27) before the dynamic import.
if (TEST_DB.host) {
  process.env.DB_HOST = TEST_DB.host;
  process.env.DB_USER = TEST_DB.user;
  process.env.DB_NAME = TEST_DB.database;
  process.env.DB_PASSWORD = TEST_DB.password;
}
const db = skip ? null : await import('../../db.js');

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MIGRATION = path.join(SERVER_DIR, 'sql', 'migration-phase-8-email-anchored-identity.sql');

const rnd = () => crypto.randomBytes(6).toString('hex');
const hash = () => crypto.createHash('sha256').update('t3-' + rnd()).digest('hex');

test.before(async () => {
  if (skip) return;
  await db.ensurePhase8Schema();
});

test.after(async () => {
  if (skip) return;
  await db.close();
  await closeDb();
});

test('resolveOrCreate: same hash keeps the FIRST userId and pseudonym (AK-1)', { skip }, async (t) => {
  const emailHash = hash();
  const u1 = 'u-' + rnd(); const u2 = 'u-' + rnd();
  t.after(() => sql('DELETE FROM identity_anchors WHERE email_hash = $1', [emailHash]));

  const first = await db.identityAnchors.resolveOrCreate({ emailHash, userId: u1, pseudonym: 'anna' });
  assert.deepEqual(first, { userId: u1, pseudonym: 'anna', created: true });

  const second = await db.identityAnchors.resolveOrCreate({ emailHash, userId: u2, pseudonym: 'other' });
  assert.deepEqual(second, { userId: u1, pseudonym: 'anna', created: false });

  const byUser = await db.identityAnchors.getByUserId(u1);
  assert.equal(byUser.emailHash, emailHash);
  assert.equal(byUser.pseudonym, 'anna');
  assert.equal(await db.identityAnchors.getByUserId(u2), null);
});

test('identityClaimsCache: upsert/get roundtrip, expiry, cleanupExpired (AK-16)', { skip }, async (t) => {
  const userId = 'u-' + rnd();
  t.after(() => sql('DELETE FROM identity_claims_cache WHERE user_id = $1', [userId]));

  await db.identityClaimsCache.upsert({ userId, email: 'Anna@Example.org', pseudonym: 'anna', verifiedMethods: ['email'] });
  assert.deepEqual(await db.identityClaimsCache.get(userId),
    { userId, email: 'Anna@Example.org', pseudonym: 'anna', verifiedMethods: ['email'] });

  // Upsert overwrites (same PK) …
  await db.identityClaimsCache.upsert({ userId, email: 'anna@example.org', pseudonym: 'anna', verifiedMethods: ['email', 'passkey'] });
  assert.deepEqual((await db.identityClaimsCache.get(userId)).verifiedMethods, ['email', 'passkey']);

  // … and an expired row is invisible to get() and removed by cleanupExpired().
  await db.identityClaimsCache.upsert({ userId, email: 'anna@example.org', pseudonym: 'anna', verifiedMethods: ['email'], ttlMs: -1000 });
  assert.equal(await db.identityClaimsCache.get(userId), null);
  await db.cleanupExpired();
  const rows = await sql('SELECT 1 FROM identity_claims_cache WHERE user_id = $1', [userId]);
  assert.equal(rows.length, 0);
});

test('sessions.update accepts userId and pseudonym; get returns them (AK-1)', { skip }, async (t) => {
  const sessionId = 's-' + rnd();
  t.after(() => sql('DELETE FROM sessions WHERE session_id = $1', [sessionId]));

  await db.sessions.create(sessionId, { userId: 'u-old-' + rnd(), verified: false, trustScore: 0 });
  await db.sessions.update(sessionId, { userId: 'u-stable', pseudonym: 'iamhmn_abc123def4' });
  const s = await db.sessions.get(sessionId);
  assert.equal(s.userId, 'u-stable');
  assert.equal(s.pseudonym, 'iamhmn_abc123def4');
});

test('authCodes: create with email/pseudonym/verifiedMethods, claim returns them and nulls email (AK-17)', { skip }, async (t) => {
  const clientId = 'test-t3-' + rnd();
  const code = 'c-' + rnd();
  t.after(async () => {
    await sql('DELETE FROM authorization_codes WHERE code = $1', [code]);
    await sql('DELETE FROM oauth_clients WHERE client_id = $1', [clientId]);
  });
  await sql(
    `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes)
     VALUES ($1, 'T3 test client', '["https://example.org/cb"]', '["openid","email"]')`, [clientId]);

  await db.authCodes.create({
    code, clientId, userId: 'u-' + rnd(), redirectUri: 'https://example.org/cb',
    scopes: ['openid', 'email'], role: 'citizen', trustScore: 60,
    email: 'anna@example.org', pseudonym: 'anna', verifiedMethods: ['email', 'passkey'],
  });

  const claimed = await db.authCodes.claim(code);
  assert.ok(claimed, 'claim returned a row');
  assert.equal(claimed.email, 'anna@example.org');
  assert.equal(claimed.pseudonym, 'anna');
  assert.deepEqual(claimed.verified_methods, ['email', 'passkey']);
  assert.deepEqual(claimed.scopes, ['openid', 'email']);
  assert.equal(claimed.used, true);

  const [row] = await sql('SELECT email, used FROM authorization_codes WHERE code = $1', [code]);
  assert.equal(row.email, null);
  assert.equal(row.used, true);

  // Second claim: single-use.
  assert.equal(await db.authCodes.claim(code), null);
});

test('authCodes.claim without the new fields yields defaults', { skip }, async (t) => {
  const clientId = 'test-t3-' + rnd();
  const code = 'c-' + rnd();
  t.after(async () => {
    await sql('DELETE FROM authorization_codes WHERE code = $1', [code]);
    await sql('DELETE FROM oauth_clients WHERE client_id = $1', [clientId]);
  });
  await sql(`INSERT INTO oauth_clients (client_id, name, redirect_uris) VALUES ($1, 'T3', '[]')`, [clientId]);
  await db.authCodes.create({ code, clientId, userId: 'u', redirectUri: 'x', scopes: ['openid'], role: 'citizen', trustScore: 60 });
  const claimed = await db.authCodes.claim(code);
  assert.equal(claimed.email, null);
  assert.equal(claimed.pseudonym, null);
  assert.deepEqual(claimed.verified_methods, []);
});

// F-7 (K-6 / P-2 / W-11): the boot path runs ONLY the DDL section of the
// migration file (guarded by an applied-check); the data update
// (allowed_scopes += email) and the grants stay an explicit operator step.
test('F-7: boot DDL section contains no data update / grants and is idempotent', { skip }, async () => {
  const ddl = db.phase8BootDdl();
  const statements = ddl.replace(/--[^\n]*/g, ''); // statements only, no comments
  assert.ok(/CREATE TABLE IF NOT EXISTS identity_anchors/.test(ddl), 'DDL: identity_anchors');
  assert.ok(/CREATE TABLE IF NOT EXISTS identity_claims_cache/.test(ddl), 'DDL: identity_claims_cache');
  assert.ok(/ALTER TABLE authorization_codes/.test(ddl), 'DDL: authorization_codes columns');
  assert.ok(!/UPDATE\s+oauth_clients/i.test(statements), 'boot DDL must not update oauth_clients');
  assert.ok(!/GRANT|OWNER TO/i.test(statements), 'boot DDL must not contain grants');

  await sql(ddl);
  await sql(ddl); // safe to re-run
  assert.equal(await db.phase8SchemaApplied(), true);

  // Columns/tables exist after the DDL.
  const cols = await sql(
    `SELECT table_name, column_name FROM information_schema.columns
     WHERE (table_name = 'sessions' AND column_name = 'pseudonym')
        OR (table_name = 'authorization_codes' AND column_name IN ('email','pseudonym','verified_methods'))
        OR (table_name IN ('identity_anchors','identity_claims_cache') AND column_name = 'user_id')`);
  assert.equal(cols.length, 6, JSON.stringify(cols));
});

test('F-7: the operator data-update block appends "email" to allowed_scopes (checked on a test client only)', { skip }, async (t) => {
  const clientId = 'test-t3-' + rnd();
  t.after(() => sql('DELETE FROM oauth_clients WHERE client_id = $1', [clientId]));
  await sql(
    `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes)
     VALUES ($1, 'T3 legacy client', '[]', '["openid","role"]')`, [clientId]);

  // The boot DDL leaves the client untouched …
  await db.ensurePhase8Schema();
  let [row] = await sql('SELECT allowed_scopes FROM oauth_clients WHERE client_id = $1', [clientId]);
  assert.deepEqual(JSON.parse(row.allowed_scopes), ['openid', 'role']);

  // … the operator section's UPDATE (from the file, scoped to this client) does the job.
  const file = fs.readFileSync(MIGRATION, 'utf8');
  const operator = file.split('-- >>> BOOT-DDL END')[1];
  assert.ok(operator, 'marker "-- >>> BOOT-DDL END" splits the file');
  const m = operator.match(/UPDATE\s+oauth_clients[\s\S]*?;/i);
  assert.ok(m, 'operator section contains the UPDATE oauth_clients statement');
  const scoped = m[0].replace(/WHERE\s+NOT/i, 'WHERE client_id = $1 AND NOT');
  await sql(scoped, [clientId]);
  await sql(scoped, [clientId]); // idempotent
  [row] = await sql('SELECT allowed_scopes FROM oauth_clients WHERE client_id = $1', [clientId]);
  assert.deepEqual(JSON.parse(row.allowed_scopes), ['openid', 'role', 'email']);
});

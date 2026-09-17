// Review 2026-09, Welle 2 — AP6 (Persistenz / Betrieb), DB layer.
// Talks to db.js directly (no server process) against the local test Postgres.
//
//   AP6-03 (#58)   cleanup_expired() also removes consumed rows; the hot-path
//                  index sits on session_id, not on the (hashed) email
//   AP6-06 (#73)   email_verifications.code is part of the schema and of the
//                  boot DDL — no fire-and-forget ALTER on module import
//   AP6-15 (#107)  oauth_clients.email_token is stored as sha256
//   AP6-29 (#143)  the COUNT(*) statistics are memoised
//   AP6-33 (#153)  the pool carries statement_timeout / query_timeout
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { sql, closeDb, TEST_DB } from '../helpers/db.mjs';
import { MIGRATION_ORDER } from '../../scripts/migrate.js';

const skip = !TEST_DB.host && 'TEST_PG_HOST not set';

// db.js reads DB_* at import time — set them (shared TEST_DB config, W-27)
// before the dynamic import.
if (TEST_DB.host) {
  process.env.DB_HOST = TEST_DB.host;
  process.env.DB_USER = TEST_DB.user;
  process.env.DB_NAME = TEST_DB.database;
  process.env.DB_PASSWORD = TEST_DB.password;
}
const db = skip ? null : await import('../../db.js');

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const PHASE10 = 'migration-phase-10-review-welle-2.sql';
const rnd = () => crypto.randomBytes(8).toString('hex');
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

test.before(async () => {
  if (skip) return;
  await db.ensureBootSchema();
});

test.after(async () => {
  if (skip) return;
  await db.close();
  await closeDb();
});

// ─── AP6-06: the `code` column is schema, not a side effect of an import ────

test('AP6-06: the phase-10 migration is wired into schema, boot DDL and the runner', () => {
  const schema = fs.readFileSync(path.join(SERVER_DIR, 'sql', 'schema.sql'), 'utf8');
  const migration = fs.readFileSync(path.join(SERVER_DIR, 'sql', PHASE10), 'utf8');
  const dbSrc = fs.readFileSync(path.join(SERVER_DIR, 'db.js'), 'utf8');

  // schema.sql creates the column for a fresh database …
  assert.match(schema, /CREATE TABLE IF NOT EXISTS email_verifications[\s\S]*?\n\s*code\s+TEXT/);
  // … the migration adds it to an existing one, above the boot-DDL marker.
  const bootDdl = migration.slice(0, migration.indexOf('-- >>> BOOT-DDL END'));
  assert.ok(bootDdl.includes('ADD COLUMN IF NOT EXISTS code TEXT'));
  // … and nothing creates it behind the application's back any more.
  assert.ok(!dbSrc.includes('ensureCodeColumn'), 'fire-and-forget ALTER still present in db.js');

  assert.ok(MIGRATION_ORDER.includes(PHASE10), 'phase 10 missing from MIGRATION_ORDER');
  assert.ok(db.BOOT_DDL_FILES.some((e) => e.file === PHASE10), 'phase 10 missing from BOOT_DDL_FILES');
});

test('AP6-06: the boot check reports the phase-10 schema as applied', { skip }, async () => {
  assert.equal(await db.phase10SchemaApplied(), true);
  const cols = await sql(
    `SELECT 1 FROM information_schema.columns
      WHERE table_name = 'email_verifications' AND column_name = 'code'`);
  assert.equal(cols.length, 1);
});

// ─── AP6-03: cleanup and indexes ────────────────────────────────────────────

test('AP6-03: the hot-path index is on session_id, the email index is gone', { skip }, async () => {
  const idx = await sql(
    `SELECT indexname FROM pg_indexes WHERE tablename = 'email_verifications'`);
  const names = idx.map((r) => r.indexname);
  assert.ok(names.includes('email_verifications_session_id_idx'), names.join(', '));
  assert.ok(!names.includes('email_verifications_email_idx'), names.join(', '));
});

test('AP6-03: cleanup_expired removes consumed rows, keeps a fresh one', { skip }, async (t) => {
  const tag = rnd();
  const mk = async (suffix, { used, ageHours, ttlMinutes }) => {
    const token = `t-${tag}-${suffix}`;
    await sql(
      `INSERT INTO email_verifications (token, code, email, domain, used, created_at, expires_at)
       VALUES ($1, $2, $3, 'example.org', $4,
               NOW() - ($5 || ' hours')::interval,
               NOW() + ($6 || ' minutes')::interval)`,
      [token, sha256(`c-${suffix}`), sha256(`${tag}@example.org`), used, String(ageHours), String(ttlMinutes)]
    );
    return token;
  };
  // (a) expired + consumed — the row the old function kept forever
  const expiredUsed  = await mk('a', { used: true,  ageHours: 2,  ttlMinutes: -1 });
  // (b) consumed 25 h ago, TTL still nominally open — past the 24 h grace
  const oldUsed      = await mk('b', { used: true,  ageHours: 25, ttlMinutes: 60 });
  // (c) consumed a minute ago — kept for the operator
  const freshUsed    = await mk('c', { used: true,  ageHours: 0,  ttlMinutes: 10 });
  // (d) expired, never consumed — always went
  const expiredOpen  = await mk('d', { used: false, ageHours: 1,  ttlMinutes: -1 });
  // (e) open and valid — must survive
  const openValid    = await mk('e', { used: false, ageHours: 0,  ttlMinutes: 10 });

  t.after(() => sql(`DELETE FROM email_verifications WHERE token LIKE $1`, [`t-${tag}-%`]));

  const out = await db.cleanupExpired();
  assert.ok(Number(out.deleted_emails) >= 3, `deleted_emails=${out.deleted_emails}`);

  const left = (await sql(`SELECT token FROM email_verifications WHERE token LIKE $1`, [`t-${tag}-%`]))
    .map((r) => r.token);
  assert.deepEqual(left.sort(), [freshUsed, openValid].sort());
  for (const gone of [expiredUsed, oldUsed, expiredOpen]) assert.ok(!left.includes(gone), gone);
});

test('AP6-03 / AP2-23: cleanupExpired reports every counter', { skip }, async () => {
  const out = await db.cleanupExpired();
  for (const key of ['deleted_tokens', 'deleted_refresh', 'deleted_sessions', 'deleted_challenges',
                     'deleted_emails', 'deleted_claims_cache', 'deleted_auth_codes',
                     // AP1 / AP5-29 (Welle 2), folded into the same function.
                     'deleted_revoked', 'deleted_webhook_deliveries', 'deleted_stale_clients']) {
    assert.ok(key in out, `missing ${key}`);
  }
});

test('AP1 / AP5-29: retention for revoked tokens, deliveries and stale drafts', { skip }, async (t) => {
  const tag = rnd();
  const jtiOld = `j-old-${tag}`, jtiNew = `j-new-${tag}`;
  const staleId = `c-stale-${tag}`, liveId = `c-live-${tag}`;
  t.after(async () => {
    await sql(`DELETE FROM revoked_tokens WHERE jti = ANY($1)`, [[jtiOld, jtiNew]]);
    await sql(`DELETE FROM oauth_clients WHERE client_id = ANY($1)`, [[staleId, liveId]]);
  });

  await sql(`INSERT INTO revoked_tokens (jti, revoked_at) VALUES ($1, NOW() - INTERVAL '100 days'), ($2, NOW())`,
    [jtiOld, jtiNew]);
  const mkClient = (clientId, days) => sql(
    `INSERT INTO oauth_clients (client_id, client_secret_hash, name, homepage_url, redirect_uris,
                                verification_status, email_token, email_token_expires_at)
     VALUES ($1, 's', 'AP5-29', 'https://example.org', $2, 'email_pending', $3,
             NOW() - ($4 || ' days')::interval)`,
    [clientId, JSON.stringify(['https://example.org/cb']), sha256(clientId), String(days)]);
  await mkClient(staleId, 8);   // never confirmed, token expired 8 days ago
  await mkClient(liveId, -1);   // token still valid for another day

  await db.cleanupExpired();

  assert.equal((await sql(`SELECT 1 FROM revoked_tokens WHERE jti = $1`, [jtiOld])).length, 0);
  assert.equal((await sql(`SELECT 1 FROM revoked_tokens WHERE jti = $1`, [jtiNew])).length, 1);
  assert.equal((await sql(`SELECT 1 FROM oauth_clients WHERE client_id = $1`, [staleId])).length, 0);
  assert.equal((await sql(`SELECT 1 FROM oauth_clients WHERE client_id = $1`, [liveId])).length, 1);
});

test('AP5: the OPERATOR section drops the dead workload_identities table', () => {
  const migration = fs.readFileSync(path.join(SERVER_DIR, 'sql', PHASE10), 'utf8');
  const marker = migration.indexOf('-- >>> BOOT-DDL END');
  assert.ok(!migration.slice(0, marker).includes('DROP TABLE IF EXISTS workload_identities'),
    'the drop must never run automatically at boot');
  assert.ok(migration.slice(marker).includes('DROP TABLE IF EXISTS workload_identities'));
  // Phase 6 stays in the chain so the ledger keeps the real history.
  assert.ok(MIGRATION_ORDER.includes('migration-phase-6-workload-identity.sql'));
  assert.ok(MIGRATION_ORDER.indexOf('migration-phase-6-workload-identity.sql') < MIGRATION_ORDER.indexOf(PHASE10));
});

// ─── AP6-15: client e-mail tokens are hashed ────────────────────────────────

test('AP6-15: email_token is stored hashed and looked up by hash', { skip }, async (t) => {
  const clientId = `c-${rnd()}`;
  const token = rnd() + rnd();
  t.after(() => sql(`DELETE FROM oauth_clients WHERE client_id = $1`, [clientId]));

  await db.oauthClients.createDraft({
    clientId, clientSecret: 'secret', name: 'AP6 test', homepageUrl: 'https://example.org',
    redirectUris: ['https://example.org/cb'], contactEmail: 'dev@example.org',
    ownerUserId: `u-${rnd()}`, domainEmailMatch: false,
    emailToken: token, emailTokenExpiresAt: new Date(Date.now() + 3600_000),
  });

  const [row] = await sql(`SELECT email_token FROM oauth_clients WHERE client_id = $1`, [clientId]);
  assert.equal(row.email_token, sha256(token), 'plaintext token still in the database');
  assert.notEqual(row.email_token, token);

  // The plaintext from the confirmation link resolves …
  const found = await db.oauthClients.getByEmailToken(token);
  assert.equal(found?.client_id, clientId);
  // … the stored hash itself does not, and neither does an empty value.
  assert.equal(await db.oauthClients.getByEmailToken(sha256(token)), null);
  assert.equal(await db.oauthClients.getByEmailToken(''), null);
  assert.equal(await db.oauthClients.getByEmailToken(null), null);

  // Resend and e-mail change take the same path.
  const next = rnd() + rnd();
  await db.oauthClients.refreshEmailToken(clientId, next, new Date(Date.now() + 3600_000));
  assert.equal(await db.oauthClients.getByEmailToken(token), null);
  assert.equal((await db.oauthClients.getByEmailToken(next))?.client_id, clientId);

  const third = rnd() + rnd();
  await db.oauthClients.updateContactEmail(clientId, 'new@example.org', false, third, new Date(Date.now() + 3600_000));
  const [after] = await sql(`SELECT email_token FROM oauth_clients WHERE client_id = $1`, [clientId]);
  assert.equal(after.email_token, sha256(third));
  assert.equal((await db.oauthClients.getByEmailToken(third))?.client_id, clientId);
});

test('AP6-15: the OPERATOR section nulls outstanding plaintext tokens', { skip }, async (t) => {
  const migration = fs.readFileSync(path.join(SERVER_DIR, 'sql', PHASE10), 'utf8');
  const operator = migration.slice(migration.indexOf('-- >>> BOOT-DDL END'));
  assert.match(operator, /UPDATE oauth_clients[\s\S]*email_token !~ '\^\[0-9a-f\]\{64\}\$'/);

  const plainId = `c-${rnd()}`, hashedId = `c-${rnd()}`;
  t.after(() => sql(`DELETE FROM oauth_clients WHERE client_id = ANY($1)`, [[plainId, hashedId]]));
  const mk = (clientId, emailToken) => db.oauthClients.createDraft({
    clientId, clientSecret: 's', name: 'AP6 op', homepageUrl: 'https://example.org',
    redirectUris: ['https://example.org/cb'], contactEmail: 'dev@example.org',
    ownerUserId: `u-${rnd()}`, domainEmailMatch: false, emailToken,
    emailTokenExpiresAt: new Date(Date.now() + 3600_000),
  });
  await mk(hashedId, 'still-valid-token');
  await mk(plainId, 'x');
  // Simulate a row written before the fix: plaintext, not 64 hex chars.
  await sql(`UPDATE oauth_clients SET email_token = 'legacy-plaintext-token' WHERE client_id = $1`, [plainId]);

  await sql(`UPDATE oauth_clients
                SET email_token = NULL, email_token_expires_at = NULL
              WHERE email_token IS NOT NULL AND email_token !~ '^[0-9a-f]{64}$'`);

  const [plain]  = await sql(`SELECT email_token FROM oauth_clients WHERE client_id = $1`, [plainId]);
  const [hashed] = await sql(`SELECT email_token FROM oauth_clients WHERE client_id = $1`, [hashedId]);
  assert.equal(plain.email_token, null);
  assert.equal(hashed.email_token, sha256('still-valid-token'));
});

// ─── AP6-29: the COUNT(*) statistics are memoised ───────────────────────────

test('AP6-29: cachedCount shares one promise per key and expires', { skip }, async () => {
  db.resetCountCache();
  let calls = 0;
  const fn = async () => { calls++; return 42; };

  const [a, b] = await Promise.all([db.cachedCount('ap6', fn), db.cachedCount('ap6', fn)]);
  assert.equal(a, 42);
  assert.equal(b, 42);
  assert.equal(calls, 1, 'concurrent callers must share one query');

  assert.equal(await db.cachedCount('ap6', fn), 42);
  assert.equal(calls, 1, 'a warm entry must not re-query');

  // A zero TTL entry is stale immediately.
  await db.cachedCount('ap6-ttl', fn, 0);
  await db.cachedCount('ap6-ttl', fn, 0);
  assert.equal(calls, 3);

  db.resetCountCache();
  assert.equal(await db.cachedCount('ap6', fn), 42);
  assert.equal(calls, 4, 'resetCountCache must drop the memo');
});

test('AP6-29: a failed count is not cached', { skip }, async () => {
  db.resetCountCache();
  let calls = 0;
  const boom = async () => { calls++; throw new Error('nope'); };
  await assert.rejects(() => db.cachedCount('ap6-fail', boom));
  await assert.rejects(() => db.cachedCount('ap6-fail', boom));
  assert.equal(calls, 2);
});

test('AP6-29: the six /hhttps/info counters go through the memo', { skip }, async () => {
  db.resetCountCache();
  const first = await Promise.all([
    db.credentials.count(), db.tokens.count(), db.refreshTokens.count(),
    db.sessions.count(), db.revokedTokens.count(), db.machineOperators.count(),
  ]);
  for (const n of first) assert.equal(typeof n, 'number');
  // Second round: served from the memo — same values, no query.
  const second = await Promise.all([
    db.credentials.count(), db.tokens.count(), db.refreshTokens.count(),
    db.sessions.count(), db.revokedTokens.count(), db.machineOperators.count(),
  ]);
  assert.deepEqual(second, first);
  db.resetCountCache();
});

// ─── AP6-33: the pool bounds every statement ────────────────────────────────

test('AP6-33: pool and session carry statement_timeout / query_timeout', { skip }, async () => {
  const opts = db.pool().options;
  assert.equal(opts.statement_timeout, db.STATEMENT_TIMEOUT_MS);
  assert.equal(opts.query_timeout, db.QUERY_TIMEOUT_MS);

  // The value actually reaches the server session, not just the pg config.
  const { rows } = await db.pool().query('SHOW statement_timeout');
  assert.equal(rows[0].statement_timeout, `${db.STATEMENT_TIMEOUT_MS / 1000}s`);
});

test('AP6-33: a statement over the limit is aborted, the pool stays usable', { skip }, async () => {
  const client = await db.pool().connect();
  try {
    await client.query('SET statement_timeout = 200');
    await assert.rejects(
      () => client.query('SELECT pg_sleep(2)'),
      (err) => err.code === '57014' // query_canceled
    );
  } finally {
    // Destroy instead of returning it: the SET above is session state and
    // would otherwise follow the connection back into the pool.
    client.release(true);
  }
  // The pool still answers afterwards, with the configured default back.
  const { rows } = await db.pool().query('SHOW statement_timeout');
  assert.equal(rows[0].statement_timeout, `${db.STATEMENT_TIMEOUT_MS / 1000}s`);
});

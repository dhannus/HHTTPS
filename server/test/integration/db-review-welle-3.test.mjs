// Review 2026-09, Welle 3 — AP6 (Persistenz / Migrationen / Betrieb).
// Talks to db.js directly (no server process) against the local test Postgres,
// plus a few source-level assertions about the ops scripts.
//
//   AP6-40 (#160)  ONE schema registry (db.js: MIGRATIONS) and ONE ledger
//                  (schema_migrations) — the boot DDL is a marked subset
//   AP6-43 (#172)  webhooks.list / findForEvent share one _normalize; list
//                  still never carries the secret
//   AP6-45 (#180)  scripts/deploy-privacy-pass.sh is gone
//   AP6-46 (#213)  server/scripts/migrate.sh is gone
//   AP6-47 (#186)  deploy-all.sh provisions Postgres via install-pg.sh only
//   AP6-48 (#192)  exactly ONE .env parser (scripts/lib/common.sh: env_get)
//   AP6-49 (#200)  uniform "HOW TO RUN" header, no OWNER/GRANT blocks
//   AP6-05 (#213)  an explicit trustScore: 0 is not silently replaced by 60
//   AP6-11 (#213)  the counter COLUMNS on `stats` are gone; metrics are rows
//   AP6-36 (#213)  webhook statistics in one statement
//   AP6-42 (#213)  one hydrateClient() instead of copied JSON.parse try/catch
//   AP6-58 (#213)  force-verify-client.mjs lives in server/scripts/ and guards
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { sql, closeDb, TEST_DB } from '../helpers/db.mjs';
import { MIGRATION_ORDER } from '../../scripts/migrate.js';

const skip = !TEST_DB.host && 'TEST_PG_HOST not set';

if (TEST_DB.host) {
  process.env.DB_HOST = TEST_DB.host;
  process.env.DB_USER = TEST_DB.user;
  process.env.DB_NAME = TEST_DB.database;
  process.env.DB_PASSWORD = TEST_DB.password;
}
const db = skip ? null : await import('../../db.js');

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPO_DIR   = path.resolve(SERVER_DIR, '..');
const SQL_DIR    = path.join(SERVER_DIR, 'sql');
const read = (...p) => fs.readFileSync(path.join(...p), 'utf8');
const rnd = () => crypto.randomBytes(8).toString('hex');

test.before(async () => {
  if (skip) return;
  await db.ensureBootSchema();
});

test.after(async () => {
  if (skip) return;
  await db.close();
  await closeDb();
});

// ─── AP6-40: one registry, one ledger ───────────────────────────────────────

test('AP6-40: the migration runner takes its order from db.js MIGRATIONS', { skip }, () => {
  assert.deepEqual(MIGRATION_ORDER, db.MIGRATIONS.map(m => m.file),
    'MIGRATION_ORDER must be derived from the registry, not a second list');
  // No duplicates, every file present on disk.
  assert.equal(new Set(MIGRATION_ORDER).size, MIGRATION_ORDER.length, 'duplicate entry');
  for (const f of MIGRATION_ORDER) {
    assert.ok(fs.existsSync(path.join(SQL_DIR, f)), `missing sql/${f}`);
  }
  // Every .sql that is not a helper must be registered — a file nobody applies
  // is exactly the drift AP6-40 is about.
  const onDisk = fs.readdirSync(SQL_DIR).filter(f => f.endsWith('.sql') && f !== 'ownership-hhttps.sql');
  assert.deepEqual([...onDisk].sort(), [...MIGRATION_ORDER].sort());
});

test('AP6-40: the boot DDL is a marked SUBSET of the registry, in registry order', { skip }, () => {
  const bootFiles = db.BOOT_DDL_FILES.map(e => e.file);
  for (const f of bootFiles) assert.ok(MIGRATION_ORDER.includes(f), `${f} not in the registry`);
  const expected = db.MIGRATIONS.filter(m => m.boot).map(m => m.file);
  assert.deepEqual(bootFiles, expected, 'boot list out of registry order');
  // Each boot entry has an applied-check; without one the server would re-run
  // the DDL on every start (AP6-37).
  for (const e of db.BOOT_DDL_FILES) {
    assert.ok(e.applied || (e.columns && e.columns.length), `${e.file}: no applied-check`);
  }
});

test('AP6-40: what the boot applies is recorded in the shared ledger', { skip }, async () => {
  const rows = await sql(`SELECT to_regclass('schema_migrations') IS NOT NULL AS t`);
  assert.equal(rows[0].t, true, 'schema_migrations table missing');
  // The boot records under a distinct name so a later full migrate.js run
  // still applies the OPERATOR section of the same file.
  const name = db.bootLedgerName('migration-phase-10-review-welle-2.sql');
  assert.equal(name, 'migration-phase-10-review-welle-2.sql#boot-ddl');
  assert.ok(!MIGRATION_ORDER.includes(name), 'boot ledger name must not collide with a file name');
});

test('AP6-40 / AP6-54: db.js documents the one way and drops the phase-8 alias', { skip }, () => {
  const src = read(SERVER_DIR, 'db.js');
  assert.match(src, /SCHEMA: ONE WAY, ONE LEDGER/, 'module header does not describe the mechanism');
  assert.match(src, /scripts\/migrate\.js/, 'header does not name the runner');
  assert.ok(!/ensurePhase8Schema/.test(src), 'the ensurePhase8Schema alias is still there');
  assert.ok(!/ensureSchema below/.test(src), 'stale "ensureSchema below" comment');
});

// ─── AP6-49: migration file convention ──────────────────────────────────────

test('AP6-49: every sql/ file carries the same HOW TO RUN header', { skip }, () => {
  for (const f of MIGRATION_ORDER) {
    const src = read(SQL_DIR, f);
    assert.match(src, /HOW TO RUN \(uniform for every file in sql\//, `sql/${f}: no uniform header`);
    assert.match(src, /node scripts\/migrate\.js/, `sql/${f}: header does not name the runner`);
  }
});

test('AP6-49: no migration carries OWNER/GRANT blocks', { skip }, () => {
  for (const f of MIGRATION_ORDER) {
    const src = read(SQL_DIR, f);
    assert.ok(!/OWNER TO/i.test(src), `sql/${f} still has an OWNER TO block`);
    assert.ok(!/^\s*GRANT /mi.test(src), `sql/${f} still has a GRANT block`);
  }
  // The repair script is the one place that assigns ownership.
  assert.match(read(SQL_DIR, 'ownership-hhttps.sql'), /OWNER TO/);
});

// ─── AP6-11: stats counters are rows, not columns ───────────────────────────

test('AP6-11: the vestigial counter columns on `stats` are gone and seeded as rows', { skip }, async () => {
  const cols = await sql(
    `SELECT column_name FROM information_schema.columns WHERE table_name = 'stats'`);
  const names = cols.map(c => c.column_name);
  for (const c of ['signatures_created', 'signatures_verified', 'signatures_revoked',
                   'oauth_authorizations', 'oauth_tokens_issued', 'oauth_logins']) {
    assert.ok(!names.includes(c), `stats.${c} still exists`);
    const rows = await sql(`SELECT 1 FROM stats WHERE metric = $1`, [c]);
    assert.equal(rows.length, 1, `stats row for ${c} missing`);
  }
});

// ─── AP6-05: an explicit trustScore of 0 survives ───────────────────────────

test('AP6-05: sessions.create keeps an explicit trustScore of 0', { skip }, async () => {
  const id = 'w3-' + rnd();
  try {
    await db.sessions.create(id, { userId: 'u-' + rnd(), verified: false, trustScore: 0 });
    const s = await db.sessions.get(id);
    assert.equal(s.trustScore, 0, 'an explicit 0 was replaced by the default');
    // …and a missing value still gets the documented default.
    const id2 = 'w3-' + rnd();
    await db.sessions.create(id2, { userId: 'u-' + rnd() });
    assert.equal((await db.sessions.get(id2)).trustScore, db.DEFAULT_TRUST_SCORE);
    await db.sessions.delete(id2);
  } finally {
    await db.sessions.delete(id);
  }
});

// ─── AP6-43 / AP6-36: webhooks ──────────────────────────────────────────────

test('AP6-43: list and findForEvent share one shape; only findForEvent has the secret', { skip }, async () => {
  const id = 'wh-' + rnd();
  const owner = 'u-' + rnd();
  const event = 'w3.' + rnd();
  try {
    await db.webhooks.create({ id, url: 'https://example.org/hook', events: [event],
      secret: 'top-secret', ownerUserId: owner });

    const [listed] = await db.webhooks.list(owner);
    assert.equal(listed.id, id);
    assert.ok(!('secret' in listed), 'webhooks.list leaks the HMAC secret (AP6-16)');
    assert.deepEqual(Object.keys(listed).sort(),
      ['createdAt', 'deliveries', 'events', 'failures', 'id', 'lastDelivery', 'url']);

    const [found] = await db.webhooks.findForEvent(event);
    assert.equal(found.secret, 'top-secret');
    // The common fields come from the same mapper and must agree.
    for (const k of ['id', 'url', 'failures', 'deliveries']) assert.deepEqual(found[k], listed[k]);
  } finally {
    await sql('DELETE FROM webhook_deliveries WHERE webhook_id = $1', [id]);
    await sql('DELETE FROM webhooks WHERE webhook_id = $1', [id]);
  }
});

test('AP6-36: recordDelivery and deactivateIfFailing keep their semantics', { skip }, async () => {
  const id = 'wh-' + rnd();
  const owner = 'u-' + rnd();
  const event = 'w3.' + rnd();
  try {
    await db.webhooks.create({ id, url: 'https://example.org/hook', events: [event],
      secret: 's', ownerUserId: owner });

    await db.webhooks.recordDelivery(id, event, 'failed', 500);
    await db.webhooks.recordDelivery(id, event, 'failed', 500);
    let [row] = await sql('SELECT failures, deliveries, active FROM webhooks WHERE webhook_id = $1', [id]);
    assert.equal(row.failures, 2);
    assert.equal(row.deliveries, 0);
    assert.equal(await db.webhooks.deactivateIfFailing(id, 10), false, 'deactivated below threshold');
    assert.equal(await db.webhooks.deactivateIfFailing(id, 2), true);
    [row] = await sql('SELECT active FROM webhooks WHERE webhook_id = $1', [id]);
    assert.equal(row.active, false);

    // A success resets the failure counter, bumps deliveries and last_delivery_at.
    await db.webhooks.recordDelivery(id, event, 'success', 200);
    [row] = await sql(
      'SELECT failures, deliveries, last_delivery_at FROM webhooks WHERE webhook_id = $1', [id]);
    assert.equal(row.failures, 0);
    assert.equal(row.deliveries, 1);
    assert.ok(row.last_delivery_at, 'last_delivery_at not set on success');

    const log = await sql('SELECT status FROM webhook_deliveries WHERE webhook_id = $1', [id]);
    assert.equal(log.length, 3, 'every attempt is still logged');
  } finally {
    await sql('DELETE FROM webhook_deliveries WHERE webhook_id = $1', [id]);
    await sql('DELETE FROM webhooks WHERE webhook_id = $1', [id]);
  }
});

// ─── AP6-42 / AP6-60: no copied JSON.parse, no unused catch bindings ────────

test('AP6-42 / AP6-60: db.js hydrates client rows in one place', { skip }, () => {
  const src = read(SERVER_DIR, 'db.js');
  assert.match(src, /function hydrateClient\(r\)/);
  assert.ok(!/JSON\.parse\(r\.redirect_uris\)/.test(src), 'copied JSON.parse for redirect_uris');
  assert.ok(!/catch \(e\) \{ r\./.test(src), 'copied catch (e) { r.… = [] } pairs');
  assert.ok(!/async listByOwner\(/.test(src), 'dead oauthClients.listByOwner is back');
});

test('AP6-42: oauthClients.get still returns parsed arrays', { skip }, async () => {
  const clientId = 'w3-' + rnd();
  try {
    await db.oauthClients.create({ clientId, name: 'W3 Test',
      redirectUris: ['https://example.org/cb'], allowedScopes: ['openid', 'email'] });
    const c = await db.oauthClients.get(clientId);
    assert.deepEqual(c.redirect_uris, ['https://example.org/cb']);
    assert.deepEqual(c.allowed_scopes, ['openid', 'email']);
    const [owned] = await db.oauthClients.listAllByOwner(c.owner_user_id ?? null)
      .then(rows => rows.filter(r => r.client_id === clientId));
    if (owned) assert.deepEqual(owned.redirect_uris, ['https://example.org/cb']);
  } finally {
    await sql('DELETE FROM oauth_clients WHERE client_id = $1', [clientId]);
  }
});

// ─── AP6-45 / AP6-46 / AP6-26 / AP6-58: the ops scripts ─────────────────────

test('AP6-45 / AP6-46 / AP6-26: the obsolete scripts are deleted, not commented out', () => {
  for (const f of ['scripts/deploy-privacy-pass.sh',      // AP6-45, Privacy-Pass is gone
                   'scripts/patch-coop-popups.sh',        // AP6-26, live patcher
                   'scripts/patch-pseudonym-stage1.sh',   // AP6-26, live patcher
                   'server/scripts/migrate.sh']) {        // AP6-46, ZIP-based v4.0→v4.1
    assert.ok(!fs.existsSync(path.join(REPO_DIR, f)), `${f} still exists`);
  }
});

test('AP6-25 / AP6-58: force-verify-client.mjs moved and guards production', () => {
  assert.ok(!fs.existsSync(path.join(REPO_DIR, 'scripts', 'force-verify-client.mjs')),
    'the old copy under scripts/ is still there');
  const src = read(SERVER_DIR, 'scripts', 'force-verify-client.mjs');
  assert.match(src, /from '\.\.\/db\.js'/, 'still imports ./db.js from the wrong directory');
  assert.match(src, /NODE_ENV === 'production'/, 'no production guard');
  assert.match(src, /--yes-i-know/, 'no explicit confirmation flag');
  assert.ok(!/'songbird-2423'/.test(src), 'default client id is back');
  // deploy-phase8.sh must not carry it onto the live box any more.
  assert.ok(!/force-verify-client\.mjs; do|f in \.env keys eudi-keys developers force-verify/
    .test(read(SERVER_DIR, 'scripts', 'deploy-phase8.sh')));
});

// ─── AP6-47 / AP6-48 / AP6-57: one provisioning, one parser, one preamble ───

test('AP6-47: deploy-all.sh provisions Postgres through install-pg.sh only', () => {
  const src = read(REPO_DIR, 'scripts', 'deploy-all.sh');
  assert.match(src, /bash "\$\{SERVER_DIR\}\/scripts\/install-pg\.sh"/);
  assert.ok(!/CREATE USER \$\{DB_USER\}/.test(src), 'own CREATE USER copy still present');
  assert.ok(!/CREATE DATABASE \$\{DB_NAME\}/.test(src), 'own CREATE DATABASE copy still present');
  assert.ok(!/GRANT ALL PRIVILEGES ON DATABASE/.test(src), 'own GRANT copy still present');
  assert.ok(!/node scripts\/migrate\.js/.test(src), 'own migration run still present');
});

test('AP6-48: there is exactly one .env parser, and every script sources it', () => {
  const lib = read(SERVER_DIR, 'scripts', 'lib', 'common.sh');
  assert.match(lib, /^env_get\(\) \{/m);
  const users = [
    path.join(SERVER_DIR, 'scripts', 'install-pg.sh'),
    path.join(SERVER_DIR, 'scripts', 'make-admin.sh'),
    path.join(SERVER_DIR, 'scripts', 'deploy-phase8.sh'),
    path.join(REPO_DIR, 'scripts', 'deploy-all.sh'),
  ];
  for (const f of users) {
    const src = fs.readFileSync(f, 'utf8');
    assert.match(src, /lib\/common\.sh/, `${path.basename(f)} does not source the library`);
    assert.ok(!/^env_get\(\) \{/m.test(src), `${path.basename(f)} has its own env_get`);
    assert.ok(!/^envval\(\)/m.test(src), `${path.basename(f)} still has envval`);
    assert.ok(!/grep .*DB_PASSWORD.* \| *cut -d=/.test(src),
      `${path.basename(f)} still parses DB_PASSWORD with grep|cut`);
  }
});

test('AP6-57: no script keeps its own colour/log preamble; options are uniform', () => {
  for (const f of [path.join(SERVER_DIR, 'scripts', 'install-pg.sh'),
                   path.join(SERVER_DIR, 'scripts', 'deploy-phase8.sh'),
                   path.join(REPO_DIR, 'scripts', 'deploy-all.sh')]) {
    const src = fs.readFileSync(f, 'utf8');
    assert.match(src, /set -euo pipefail/, `${path.basename(f)}: shell options not uniform`);
    assert.ok(!/^ok\(\) *\{ *printf/m.test(src), `${path.basename(f)}: own log helpers`);
    assert.ok(!/npm (ci|install) .*--production/.test(src),
      `${path.basename(f)}: deprecated npm --production`);
  }
});

// ─── AP6-21 / AP6-22 / AP6-23 / AP6-24: secrets and downloads ───────────────

test('AP6-21 / AP6-22: the DB password is never exported or put on a command line', () => {
  const deploy = read(SERVER_DIR, 'scripts', 'deploy-phase8.sh');
  assert.ok(!/^export PGPASSWORD=/m.test(deploy), 'PGPASSWORD is still exported script-wide');
  assert.match(deploy, /env "PGPASSWORD=\$DB_PASSWORD" psql/);

  const pg = read(SERVER_DIR, 'scripts', 'install-pg.sh');
  assert.ok(!/WITH PASSWORD '\$\{DB_PASSWORD\}'/.test(pg), 'password still interpolated into psql -c');
  assert.match(pg, /-v pw="\$\{DB_PASSWORD\}"/);
});

test('AP6-23 / AP6-24: no piped remote script, no TLS verification turned off', () => {
  const code = read(REPO_DIR, 'scripts', 'deploy-all.sh')
    .split('\n').filter(l => !/^\s*#/.test(l)).join('\n');
  const src = read(REPO_DIR, 'scripts', 'deploy-all.sh');
  assert.ok(!/curl[^\n|]*\|\s*bash/.test(code), 'curl … | bash is back');
  assert.match(src, /signed-by=\/usr\/share\/keyrings\/nodesource\.gpg/);
  assert.ok(!/curl +-[a-zA-Z]*k/.test(code), 'curl -k is back');
  assert.ok(src.includes('AP6-24'), 'the reason for dropping -k is not recorded');
});

// ─── AP6-12 / AP6-50: make-admin.sh ─────────────────────────────────────────

test('AP6-12 / AP6-50: argument parsing and the identity note', () => {
  const src = read(SERVER_DIR, 'scripts', 'make-admin.sh');
  assert.ok(!/USER_ID="\$\{2:-\}"; shift 2 /.test(src), 'bare `shift 2` can still abort silently');
  assert.match(src, /shift \$\(\( \$# >= 2 \? 2 : 1 \)\)/);
  assert.match(src, /e-mail-anchored identity/, 'the identity note is still the pre-phase-8 one');
  assert.ok(!/mints a fresh uuid per/.test(src), 'stale claim about e-mail sign-ins');
});

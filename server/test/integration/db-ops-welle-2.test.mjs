// Review 2026-09, Welle 2 — AP6 (Betrieb / CI): the operator scripts and the
// CI workflow.
//
//   AP6-08 (#85)   no silent `sudo -u postgres` fallback; ownership repair
//   AP6-09 (#89)   deploy-phase8.sh has a real --rollback mode
//   AP6-14 (#103)  make-admin.sh validates and binds USER_ID (executed)
//   AP6-17 (#118)  no script sources the .env into a pm2 environment
//   AP6-18 (#126)  nginx security headers survive a location's own add_header
//   AP6-19 (#134)  the CI workflow is a gate: tests, lint, audit, permissions
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sql, closeDb, TEST_DB } from '../helpers/db.mjs';

const skip = !TEST_DB.host && 'TEST_PG_HOST not set';
const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPO_DIR = path.resolve(SERVER_DIR, '..');
const read = (...p) => fs.readFileSync(path.join(...p), 'utf8');

test.after(async () => { if (!skip) await closeDb(); });

// ─── AP6-14: make-admin.sh, actually executed ───────────────────────────────

/** A throwaway install tree: scripts/make-admin.sh next to an .env. */
function makeAdminTree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ap6-admin-'));
  fs.mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
  fs.copyFileSync(path.join(SERVER_DIR, 'scripts', 'make-admin.sh'),
                  path.join(dir, 'scripts', 'make-admin.sh'));
  // AP6-48 (#192) / AP6-57 (#213): the script sources the shared library.
  fs.copyFileSync(path.join(SERVER_DIR, 'scripts', 'lib', 'common.sh'),
                  path.join(dir, 'scripts', 'lib', 'common.sh'));
  fs.writeFileSync(path.join(dir, '.env'),
    `DB_HOST=${TEST_DB.host}\nDB_PORT=5432\nDB_NAME=${TEST_DB.database}\n` +
    `DB_USER=${TEST_DB.user}\nDB_PASSWORD=${TEST_DB.password}\n`);
  return dir;
}

function runAdmin(dir, args) {
  try {
    const stdout = execFileSync('bash', [path.join(dir, 'scripts', 'make-admin.sh'), ...args],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    return { code: err.status ?? 1, stdout: String(err.stdout || ''), stderr: String(err.stderr || '') };
  }
}

test('AP6-14: make-admin.sh rejects a USER_ID outside the id alphabet', { skip }, (t) => {
  const dir = makeAdminTree();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  // The injection the old string interpolation allowed.
  const evil = "x'); DROP TABLE admins; --";
  for (const action of ['--whoami', '--grant', '--revoke']) {
    const r = runAdmin(dir, [action, evil]);
    assert.equal(r.code, 1, `${action} accepted the payload: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /invalid USER_ID/);
  }
  // `admins` is still there — nothing was executed.
  assert.doesNotThrow(() => execFileSync('bash', ['-c', 'true']));
});

test('AP6-14: a legitimate USER_ID is bound, not interpolated', { skip }, async (t) => {
  const dir = makeAdminTree();
  const userId = 'u-' + crypto.randomBytes(8).toString('hex');
  t.after(async () => {
    fs.rmSync(dir, { recursive: true, force: true });
    await sql('DELETE FROM admins WHERE user_id = $1', [userId]);
  });

  // whoami exits 2 for "not an admin" — but it must reach the query at all.
  let r = runAdmin(dir, ['--whoami', userId]);
  assert.equal(r.code, 2, r.stderr);
  assert.match(r.stdout, /NOT an admin/);

  r = runAdmin(dir, ['--grant', userId, '--note', "O'Brien's platform"]);
  assert.equal(r.code, 0, r.stderr);
  const rows = await sql('SELECT user_id, note FROM admins WHERE user_id = $1', [userId]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].note, "O'Brien's platform", 'a quote in --note must survive verbatim');

  r = runAdmin(dir, ['--whoami', userId]);
  assert.match(r.stdout, /is an admin/);

  r = runAdmin(dir, ['--revoke', userId]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal((await sql('SELECT 1 FROM admins WHERE user_id = $1', [userId])).length, 0);
});

test('AP6-14: no USER_ID is interpolated into SQL any more', () => {
  const src = read(SERVER_DIR, 'scripts', 'make-admin.sh');
  assert.ok(!/'\$\{USER_ID[^}]*\}'/.test(src), 'raw USER_ID interpolation left in make-admin.sh');
  assert.match(src, /check_user_id/);
  assert.match(src, /:'uid'/);
});

// ─── AP6-08: schema/migrations as the app user, ownership repaired ──────────

test('AP6-08: no silent superuser fallback, ownership file present and wired', () => {
  const install = read(SERVER_DIR, 'scripts', 'install-pg.sh');
  const deploy = read(REPO_DIR, 'scripts', 'deploy-all.sh');
  const ownership = read(SERVER_DIR, 'sql', 'ownership-hhttps.sql');

  assert.ok(!/sudo -u postgres psql[^\n]*-f[^\n]*schema\.sql/.test(install),
    'install-pg.sh still applies schema.sql as postgres');
  assert.match(install, /ownership-hhttps\.sql/, 'install-pg.sh does not run the ownership repair');
  assert.match(install, /owner_role=/, 'install-pg.sh does not pass the app role to the repair');
  // AP6-47 (#186): deploy-all.sh no longer has its own copy of any of this —
  // it delegates the whole provisioning to install-pg.sh.
  assert.ok(!/sudo -u postgres psql[^\n]*-f[^\n]*schema\.sql/.test(deploy),
    'deploy-all.sh still applies schema.sql as postgres');
  assert.match(deploy, /bash "\$\{SERVER_DIR\}\/scripts\/install-pg\.sh"/,
    'deploy-all.sh does not delegate to install-pg.sh');
  assert.ok(!/ownership-hhttps\.sql/.test(deploy),
    'deploy-all.sh still has its own ownership-repair copy');
  assert.match(ownership, /ALTER TABLE public\.%I OWNER TO %I/);
  assert.match(ownership, /ALTER DEFAULT PRIVILEGES FOR ROLE postgres/);
});

// ─── AP6-09: rollback mode ──────────────────────────────────────────────────

test('AP6-09: deploy-phase8.sh documents and implements --rollback <sha>', () => {
  const src = read(SERVER_DIR, 'scripts', 'deploy-phase8.sh');
  assert.match(src, /--rollback\)/, 'no --rollback branch in the option parser');
  assert.match(src, /git checkout -q -B "\$BRANCH" "\$ROLLBACK_SHA"/);
  // The preflight must not reject a detached HEAD in rollback mode …
  assert.match(src, /if \[\[ -n "\$ROLLBACK_SHA" \]\]; then[\s\S]*?Rollback-Ziel/);
  // … and the closing hint must no longer advise the broken sequence.
  assert.ok(!src.includes('checkout $(cat'), 'old rollback advice still printed');
  assert.match(src, /Rollback: bash \$0 --rollback/);
});

// ─── AP6-17: the .env is never sourced into a pm2 environment ───────────────

test('AP6-17: no deploy script sources the .env', () => {
  // AP6-46 (#213): scripts/migrate.sh (the ZIP-based v4.0 -> v4.1 migration)
  // was deleted in Welle 3; the remaining deploy scripts are checked here.
  for (const f of [path.join(REPO_DIR, 'scripts', 'deploy-all.sh'),
                   path.join(SERVER_DIR, 'scripts', 'install-pg.sh'),
                   path.join(SERVER_DIR, 'scripts', 'deploy-phase8.sh'),
                   path.join(SERVER_DIR, 'scripts', 'make-admin.sh')]) {
    const src = fs.readFileSync(f, 'utf8');
    assert.ok(!/^\s*(set -a;\s*)?(source|\.)\s+\.env/m.test(src), `${path.basename(f)} sources the .env`);
  }
  // AP6-48 (#192): they all read single keys as data, through the ONE env_get
  // in scripts/lib/common.sh.
  assert.match(read(SERVER_DIR, 'scripts', 'lib', 'common.sh'), /env_get\(\)/);
});

// ─── AP6-18: nginx header inheritance ───────────────────────────────────────

test('AP6-18: every location with its own headers includes the snippet', () => {
  const src = read(REPO_DIR, 'scripts', 'deploy-all.sh');
  assert.match(src, /snippets\/hhttps-security-headers\.conf/);
  assert.match(src, /snippets\/iamhmn-security-headers\.conf/);

  // Inside the generated nginx configs (the heredocs), Cache-Control must not
  // be an add_header any more — that is what cut off the inheritance.
  assert.ok(!/add_header Cache-Control/.test(src), 'Cache-Control still set via add_header');
  assert.ok(!/add_header Content-Type/.test(src), 'Content-Type still set via add_header');

  // The /spec location and the iamhmn root location carry the include.
  const spec = src.slice(src.indexOf('location = /spec {'), src.indexOf('location = /spec.html'));
  assert.match(spec, /include snippets\/hhttps-security-headers\.conf;/);
  assert.match(spec, /expires 5m;/);
});

// ─── AP6-19: CI is a gate ───────────────────────────────────────────────────

test('AP6-19: the CI workflow runs tests, lint and audit against Postgres 16', () => {
  const ci = read(REPO_DIR, '.github', 'workflows', 'ci.yml');

  assert.match(ci, /^permissions:\n\s+contents: read$/m, 'no top-level read-only permissions block');
  assert.match(ci, /image: postgres:16/);
  assert.match(ci, /TEST_PG_HOST: localhost/);
  assert.match(ci, /EMAIL_DEV_MODE: '1'/);
  assert.match(ci, /npm ci --no-audit --no-fund/);
  assert.ok(!/npm ci[^\n]*\|\|[^\n]*npm install/.test(ci), 'npm ci still falls back to npm install');
  assert.match(ci, /run: npx eslint \./);
  assert.match(ci, /run: npm test/);
  assert.match(ci, /npm audit --audit-level=high/);
  assert.match(ci, /node scripts\/migrate\.js/);

  // No unpinned major-tag actions, no apt-get nodejs.
  const uses = [...ci.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
  assert.ok(uses.length > 0);
  for (const u of uses) {
    assert.match(u, /@(v\d+\.\d+\.\d+|[0-9a-f]{40})$/, `action not pinned to a fixed version: ${u}`);
  }
  assert.ok(!/apt-get install -y nodejs/.test(ci), 'still installs node via apt-get');

  // docs-lint must be able to fail.
  const docs = ci.slice(ci.indexOf('docs-lint:'));
  assert.ok(!/Don't fail yet/.test(docs));
  assert.match(docs, /exit 1/);
});

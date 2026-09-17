// AP8-47 (#246): the browser extension had NO tests and NO lint gate — CI only
// checked that manifest.json parses and that each file survives `node --check`.
//
// Two things happen here:
//   1. the testable logic (lib/identity.js) is imported and exercised for real;
//   2. ESLint is run over extension/ through its API, so `npm test` fails on a
//      lint error there just like it does for the server package.
//
// The chrome.* surface is not stubbed: everything under extension/lib/ is
// deliberately free of it, which is the point of the split.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ESLint } from 'eslint';
import js from '@eslint/js';
import globals from 'globals';

import {
  ISSUER_BASE, STORAGE_IDENTITIES, STORAGE_ACTIVE_ID, STORAGE_SIGN_MODE,
  REFRESH_AHEAD_MS, issuerBase, decodeJwtPayload, computeIdentityId,
  refreshFireAt, alarmNameFor, idFromAlarmName, normaliseSignMode,
  bindingTypeFor, applyRefresh, SIGN_MODES
} from '../../../extension/lib/identity.js';

const here = dirname(fileURLToPath(import.meta.url));
const ext = (f) => join(here, '../../../extension/', f);
const read = (f) => readFileSync(ext(f), 'utf8');
const manifest = JSON.parse(read('manifest.json'));

const jwt = (payload) =>
  ['h', Buffer.from(JSON.stringify(payload)).toString('base64url'), 'sig'].join('.');

// ── lint gate ──────────────────────────────────────────────────────────────
// The extension lives outside the server package, so `npx eslint .` cannot
// reach it and a flat config inside extension/ could not resolve eslint itself
// (node_modules lives in server/). The config is therefore declared here.
const EXTENSION_LINT_CONFIG = [
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      // background.js and lib/ are ES modules ("type": "module" in the
      // manifest's background entry); the content scripts and the popup are
      // classic scripts wrapped in an IIFE, which parses fine either way.
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.webextensions },
    },
    rules: {
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-unused-vars': 'warn',
      'no-useless-escape': 'warn',
    },
  },
];

test('AP8-47: extension/ passes ESLint with zero errors', async () => {
  const eslint = new ESLint({
    cwd: ext('.'), overrideConfigFile: true, overrideConfig: EXTENSION_LINT_CONFIG
  });
  const results = await eslint.lintFiles(['**/*.js']);
  assert.ok(results.length >= 5, `the extension's scripts were found (${results.length})`);
  const errors = results.flatMap((r) =>
    r.messages.filter((m) => m.severity === 2)
      .map((m) => `${r.filePath.split('/extension/')[1]}:${m.line} ${m.message}`));
  assert.deepEqual(errors, [], 'no ESLint errors in the extension');
});

// ── AP8-36 (#223): the issuer mapping lives in one place ───────────────────
test('AP8-36: issuerBase() maps the hhttps:// scheme form to a real URL', () => {
  assert.equal(issuerBase({ issuer: 'hhttps://hhttps.org' }), 'https://hhttps.org');
  assert.equal(issuerBase({ issuer: 'hhttps://hhttps.org/' }), 'https://hhttps.org');
  assert.equal(issuerBase({ issuer: 'https://staging.hhttps.org' }), 'https://staging.hhttps.org');
  assert.equal(issuerBase({}), ISSUER_BASE);
  assert.equal(issuerBase(null), ISSUER_BASE);
  assert.equal(ISSUER_BASE, 'https://hhttps.org');
});

test('AP8-53: no script re-derives the issuer with its own replace()', () => {
  for (const f of ['background.js', 'popup.js', 'content-issuer.js', 'content-universal.js']) {
    const src = read(f);
    const inline = src.match(/replace\(\/\^hhttps:\\\/\\\//g) || [];
    assert.equal(inline.length, 0, `${f} uses issuerBase() instead of an inline replace()`);
  }
});

// ── AP8-04 / AP8-05: identity ids ──────────────────────────────────────────
test('AP8-05: the identity id is actor + stable subject, not issuer#role', () => {
  const human = { issuer: 'hhttps://hhttps.org', role: null,
    token: jwt({ sub: 'human-verified', actorType: 'human', userId: 'u-123', jti: 'a' }) };
  const bot = { issuer: 'hhttps://hhttps.org', role: null,
    token: jwt({ sub: 'machine', actorType: 'bot', operatorId: 'op-9', jti: 'b' }) };

  const humanId = computeIdentityId(human);
  assert.equal(humanId, 'hhttps://hhttps.org#human#u-123');
  assert.equal(computeIdentityId(bot), 'hhttps://hhttps.org#bot#op-9');
  assert.notEqual(computeIdentityId(bot), humanId, 'a human and a bot never share an entry');

  const other = { ...human, token: jwt({ actorType: 'human', userId: 'u-999' }) };
  assert.notEqual(computeIdentityId(other), humanId, 'two users get two ids');

  const reissued = { ...human, token: jwt({ actorType: 'human', userId: 'u-123', jti: 'new' }) };
  assert.equal(computeIdentityId(reissued), humanId, 're-issuance keeps the same id');
});

test('computeIdentityId falls back gracefully on an unreadable token', () => {
  assert.equal(computeIdentityId({ token: 'garbage' }), 'hhttps://hhttps.org#unknown#unknown');
  assert.equal(computeIdentityId({ token: 'garbage', actorType: 'bot', role: 'r' }),
    'hhttps://hhttps.org#bot#r');
  assert.equal(computeIdentityId({ token: jwt({ human: false, sub: 's' }) }),
    'hhttps://hhttps.org#bot#s', 'the legacy human:false flag still maps to a bot');
});

test('decodeJwtPayload survives padding, url-safe alphabet and garbage', () => {
  assert.deepEqual(decodeJwtPayload(jwt({ a: 1 })), { a: 1 });
  assert.equal(decodeJwtPayload('nope'), null);
  assert.equal(decodeJwtPayload(null), null);
  assert.equal(decodeJwtPayload(''), null);
});

// ── AP8-04 (#72): the refresh alarm needs a real schedule ──────────────────
test('refreshFireAt schedules 5 minutes before expiry, or immediately', () => {
  const now = 1_700_000_000_000;
  const exp = (ms) => jwt({ exp: Math.floor(ms / 1000) });

  assert.equal(refreshFireAt({ refreshToken: 'rt', token: exp(now + 3600_000) }, now),
    Math.floor((now + 3600_000) / 1000) * 1000 - REFRESH_AHEAD_MS);
  assert.equal(refreshFireAt({ refreshToken: 'rt', token: exp(now + 60_000) }, now), now,
    'a token that expires within the lead time refreshes right away');
  assert.equal(refreshFireAt({ token: exp(now + 3600_000) }, now), null,
    'no refresh token, no alarm');
  assert.equal(refreshFireAt({ refreshToken: 'rt', token: 'garbage' }, now), null);
  assert.equal(refreshFireAt(null, now), null);
});

test('alarm names round-trip and ignore foreign alarms', () => {
  assert.equal(idFromAlarmName(alarmNameFor('hhttps://hhttps.org#human#u-1')),
    'hhttps://hhttps.org#human#u-1');
  assert.equal(idFromAlarmName('something-else'), null);
});

// ── AP3-18 (#116): the refresh token rotates ───────────────────────────────
test('applyRefresh adopts the rotated refresh token and keeps the old one otherwise', () => {
  const ident = { id: 'x', token: 'old', refreshToken: 'r-old', trustScore: 50,
    refreshExpiresAt: '2030-01-01T00:00:00Z' };
  const rotated = applyRefresh(ident, { token: 'new', refreshToken: 'r-new',
    expiresAt: '2030-01-02T00:00:00Z', refreshExpiresAt: '2030-03-01T00:00:00Z' }, 42);
  assert.equal(rotated.token, 'new');
  assert.equal(rotated.refreshToken, 'r-new');
  assert.equal(rotated.refreshExpiresAt, '2030-03-01T00:00:00Z');
  assert.equal(rotated.lastRefreshAt, 42);
  assert.equal(rotated.id, 'x', 'the identity id is preserved');

  const notRotated = applyRefresh(ident, { token: 'new' }, 42);
  assert.equal(notRotated.refreshToken, 'r-old', 'no rotation, keep what we have');
  assert.equal(notRotated.refreshExpiresAt, '2030-01-01T00:00:00Z');
  assert.equal(notRotated.expiresAt, null);
});

// ── AP8-44 (#237): the sign-mode switch is finally read ────────────────────
test('AP8-44: one context-menu entry, and it signs in the stored mode', () => {
  const bg = read('background.js');
  assert.doesNotMatch(bg, /hhttps-sign-alpha|hhttps-sign-beta/,
    'the two hard-wired mode entries are gone');
  assert.match(bg, /id: 'hhttps-sign'/, 'a single context-menu entry is created');
  const onClicked = bg.slice(bg.indexOf('chrome.contextMenus?.onClicked'));
  assert.match(onClicked, /const mode = await getSignMode\(\)/,
    'the click handler reads the stored sign mode');
  assert.doesNotMatch(onClicked, /info\.menuItemId === 'hhttps-sign-beta'/,
    'the mode no longer comes from which menu item was clicked');
  // The popup writes the preference the handler now reads.
  assert.match(read('popup.js'), /type: 'SET_SIGN_MODE'/);
  for (const lang of ['de', 'en']) {
    const msgs = JSON.parse(read(`_locales/${lang}/messages.json`));
    assert.ok(msgs.ctxSign?.message, `ctxSign is translated (${lang})`);
    assert.equal(msgs.ctxSignAlpha, undefined, `the alpha entry's string is gone (${lang})`);
    assert.equal(msgs.ctxSignBeta, undefined, `the beta entry's string is gone (${lang})`);
  }
});

test('AP8-44: the sign mode maps to the binding type the server expects', () => {
  assert.deepEqual(SIGN_MODES, ['alpha', 'beta']);
  assert.equal(normaliseSignMode('beta'), 'beta');
  assert.equal(normaliseSignMode('alpha'), 'alpha');
  assert.equal(normaliseSignMode('nonsense'), 'alpha', 'an unknown mode falls back to alpha');
  assert.equal(normaliseSignMode(undefined), 'alpha');
  assert.equal(bindingTypeFor('beta'), 'document', 'beta binds to the exact text');
  assert.equal(bindingTypeFor('alpha'), 'web', 'alpha binds to the domain only');
  assert.equal(bindingTypeFor('nonsense'), 'web');
});

// ── AP8-45 (#240): the dead sniffer and its plumbing are gone ──────────────
test('AP8-45: the fetch/XHR sniffer and its background plumbing are removed', () => {
  const content = read('content-universal.js');
  assert.doesNotMatch(content, /window\.fetch\s*=/, 'window.fetch is not monkey-patched');
  assert.doesNotMatch(content, /XMLHttpRequest\.prototype/, 'XHR.send is not monkey-patched');
  assert.doesNotMatch(content, /'PAGE_STATE'/, 'no PAGE_STATE message is sent any more');
  assert.doesNotMatch(content, /collectContextForSlug/, 'the caller-less helper is gone');
  assert.match(content, /GET_PAGE_STATE/, 'the popup still asks the tab directly');

  const bg = read('background.js');
  for (const dead of ['tabState', 'GET_TAB_STATE', "'PAGE_STATE'", 'REMOVE_IDENTITY']) {
    assert.ok(!bg.includes(dead), `background.js no longer carries ${dead}`);
  }
  assert.match(read('popup.js'), /REVOKE_IDENTITY/, 'the popup logs out via REVOKE_IDENTITY');
});

test('AP8-19: the meta-derived page state is still flagged as a claim', () => {
  const content = read('content-universal.js');
  assert.match(content, /claimed:\s*true/, 'meta tags stay a claim, not a verification');
  assert.match(read('popup.js'), /if \(state\.claimed\)/, 'the popup branches on the claim flag');
});

test('AP8-53: the service worker has exactly one onMessage listener', () => {
  const bg = read('background.js');
  assert.equal((bg.match(/chrome\.runtime\.onMessage\.addListener/g) || []).length, 1,
    'one router instead of three listeners');
});

// ── AP8-21 (#249): no permissions the extension does not use ───────────────
test('AP8-21: manifest asks only for permissions the code actually uses', () => {
  assert.deepEqual(manifest.permissions, ['storage', 'alarms', 'contextMenus']);
  const all = ['background.js', 'popup.js', 'content-issuer.js', 'content-universal.js',
    'lib/identity.js'].map(read).join('\n');
  assert.doesNotMatch(all, /chrome\.scripting/, 'nothing uses the scripting API');
  for (const p of manifest.permissions) {
    const api = { storage: 'chrome.storage', alarms: 'chrome.alarms', contextMenus: 'chrome.contextMenus' }[p];
    assert.ok(all.includes(api), `${p} is requested because ${api} is used`);
  }
});

// ── AP8-22 (#249): no debug logging on every page ──────────────────────────
test('AP8-22: the content script only logs behind a debug flag', () => {
  const content = read('content-universal.js');
  assert.equal((content.match(/console\.log/g) || []).length, 1,
    'the single console.log left is the debug() helper itself');
  assert.match(content, /const debug = \(\.\.\.a\) => \{ if \(DEBUG\)/, 'logging goes through debug()');
  assert.match(content, /localStorage\.getItem\('hhttpsDebug'\)/, 'the flag is opt-in per page');
});

// ── AP8-52 (#249): the capture toast keys on the pickup source ─────────────
test('AP8-52: the capture toast fires on a fresh issuance, not on a storage pickup', () => {
  const src = read('content-issuer.js');
  assert.doesNotMatch(src, /document\.readyState/,
    'the pickup source is no longer guessed from the load state');
  assert.match(src, /forwardToBackground\(event\.data\.payload, 'postMessage'\)/,
    'the live path names itself');
  assert.match(src, /forwardToBackground\(identity, 'storage'\)/,
    'the localStorage path names itself');
  assert.match(src, /response\?\.ok && source === 'postMessage'/,
    'only a fresh issuance shows the toast');
  assert.equal((src.match(/console\.log/g) || []).length, 1,
    'logging on hhttps.org goes through the same debug() flag');
});

// ── AP8-30 (#249): one storage read per badge update, not one per tab ──────
test('AP8-30: the badge is set globally instead of per tab', () => {
  const bg = read('background.js');
  assert.doesNotMatch(bg, /updateAllBadges/, 'the per-tab fan-out is gone');
  assert.doesNotMatch(bg, /chrome\.tabs\.query/, 'no tab enumeration on every identity change');
  assert.match(bg, /chrome\.action\.setBadgeText\(\{ text \}\)/, 'the badge is set without a tabId');
});

// ── AP8-48 (#249): the version lives in the manifest only ──────────────────
test('AP8-48: the version string is not duplicated anywhere', () => {
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  for (const f of ['background.js', 'popup.js', 'popup.html', 'content-universal.js',
    'content-issuer.js', 'INSTALL.md']) {
    const src = read(f);
    assert.doesNotMatch(src, /v\d+\.\d+\.\d+/, `${f} carries no hard-coded version`);
  }
  assert.match(read('popup.js'), /chrome\.runtime\.getManifest\(\)\.version/,
    'the popup reads the version from the manifest');
  assert.match(read('popup.html'), /id="version"/, 'the popup has a slot to render it into');
});

// ── AP8-49 (#249): the date format follows the UI language ─────────────────
test('AP8-49: the seal date is formatted in the UI language', () => {
  const content = read('content-universal.js');
  assert.doesNotMatch(content, /'de-DE'/, 'no hard-coded German locale');
  assert.match(content, /chrome\.i18n\.getUILanguage\(\)/, 'the UI language decides');
});

// ── AP8-46 (#243): INSTALL.md matches what the code does ───────────────────
test('AP8-46: INSTALL.md documents exactly the manifest permissions', () => {
  const doc = read('INSTALL.md');
  const table = doc.slice(doc.indexOf('## Berechtigungen'), doc.indexOf('## Was die Extension'));
  assert.ok(table.length > 100, 'the permission table was located');
  for (const p of manifest.permissions) {
    assert.ok(table.includes('`' + p + '`'), `INSTALL.md explains the '${p}' permission`);
  }
  for (const gone of ['`activeTab`', '`scripting`']) {
    assert.ok(!table.includes(gone), `INSTALL.md no longer lists ${gone}`);
  }
  assert.ok(doc.includes('/hhttps/signatures'),
    'the signature endpoint is named under the data-flow section');
  assert.ok(doc.includes('/hhttps/signatures/batch'),
    'the batch verification endpoint is named under the data-flow section');
});

test('the lib has no chrome.* dependency, which is what makes it testable', () => {
  assert.ok(existsSync(ext('lib/identity.js')));
  assert.doesNotMatch(read('lib/identity.js'), /chrome\./);
});

test('the storage keys the lib exports are the ones the code writes', () => {
  const bg = read('background.js');
  for (const [name, key] of [['STORAGE_IDENTITIES', STORAGE_IDENTITIES],
    ['STORAGE_ACTIVE_ID', STORAGE_ACTIVE_ID], ['STORAGE_SIGN_MODE', STORAGE_SIGN_MODE]]) {
    assert.match(bg, new RegExp(`\\b${name}\\b`), `background.js uses ${name}`);
    assert.match(key, /^hhttps_/, `${name} is namespaced`);
  }
  assert.doesNotMatch(bg, /'hhttps_identities'|'hhttps_active_id'|'hhttps_sign_mode'/,
    'the keys are not re-spelled as literals');
});

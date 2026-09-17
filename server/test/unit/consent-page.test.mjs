// T9 / AK-30 / AP2-07 / AP2-31: the consent page.
//
// AP2-31 (#165): the page's browser script is no longer a ~150-line string
// inside server.js — it lives in server/consent-client.js and is imported
// here as a real module (i18n tables directly, the browser half as source
// text, since it needs a DOM). The HTML shell that is still rendered by
// renderConsentPage in server.js is inspected as source text as before.
// The behaviour over HTTP (params carried, relogin body) is covered by
// test/integration/login-hint.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { CONSENT_I18N, SCOPE_ICONS, scopeLabel } from '../../consent-client.js';

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, '../../server.js'), 'utf8');
const clientSrc = readFileSync(join(here, '../../consent-client.js'), 'utf8');

/** Source of renderConsentPage(...) — the HTML shell, up to its `</html>`. */
function renderer() {
  const start = src.indexOf('function renderConsentPage(');
  assert.ok(start > 0, 'renderConsentPage is defined');
  const end = src.indexOf('</html>', start);
  assert.ok(end > start, 'renderConsentPage ends with </html>');
  return src.slice(start, end);
}

test('AK-30: relogin() appends login_hint and pseudonym (URL-encoded) to the sign-in URL, keeping returnTo', () => {
  const fn = clientSrc.match(/function relogin\(\) \{([\s\S]*?)\n {2}\}/);
  assert.ok(fn, 'relogin() exists in consent-client.js');
  const body = fn[1];
  assert.match(body, /\?returnTo=' \+ encodeURIComponent\(window\.location\.href\)/, 'returnTo is still the consent URL');
  assert.match(body, /params\.get\('login_hint'\)/, 'login_hint read from params');
  assert.match(body, /params\.get\('pseudonym'\)/, 'pseudonym read from params');
  assert.match(body, /&login_hint=' \+ encodeURIComponent\(/, 'login_hint appended URL-encoded');
  assert.match(body, /&pseudonym=' \+ encodeURIComponent\(/, 'pseudonym appended URL-encoded');
});

test('AK-30: #pseudoInput is pre-filled from params via the DOM, not via HTML interpolation', () => {
  assert.match(clientSrc, /getElementById\('pseudoInput'\)[\s\S]{0,160}params\.get\('pseudonym'\)/, 'DOM pre-fill');
  const tag = renderer().match(/<input id="pseudoInput"[^>]*>/);
  assert.ok(tag, '#pseudoInput input exists');
  assert.doesNotMatch(tag[0], /value=/, 'no value attribute in the template');
  assert.doesNotMatch(tag[0], /\$\{/, 'no template interpolation in the input tag');
});

test('AK-29: authorize reads login_hint/pseudonym and only adds valid values to the consent params', () => {
  const start = src.indexOf("app.get('/hhttps/oauth/authorize'");
  const end = src.indexOf("app.post('/hhttps/oauth/approve'", start);
  assert.ok(start > 0 && end > start, 'authorize route located');
  const route = src.slice(start, end);
  assert.match(route, /login_hint/, 'reads login_hint');
  assert.match(route, /sanitizePseudonym\(/, 'pseudonym goes through sanitizePseudonym');
  assert.match(route, /normalizeEmail\(/, 'login_hint goes through normalizeEmail');
  assert.match(route, /254/, 'login_hint length bounded to 254');
  assert.match(route, /params\.set\('login_hint'/, 'login_hint set conditionally on the params object');
  assert.match(route, /params\.set\('pseudonym'/, 'pseudonym set conditionally on the params object');
});

// ─── AP2-07 (#87): no hard-coded https://hhttps.org — BASE_URL everywhere ────

test('AP2-07: consent page and OAuth error page reference BASE_URL, never a hard-coded https://hhttps.org', () => {
  const r = renderer();
  assert.doesNotMatch(r, /https:\/\/hhttps\.org/, 'no hard-coded origin in renderConsentPage');
  assert.match(r, /JSON\.stringify\(\{ base: BASE_URL, params \}\)/, 'script config carries BASE_URL');
  assert.match(r, /href="\$\{escapeHtml\(BASE_URL\)\}"/, 'links use escapeHtml(BASE_URL)');

  assert.doesNotMatch(clientSrc, /https:\/\/hhttps\.org/, 'no hard-coded origin in consent-client.js');
  const fn = clientSrc.match(/function relogin\(\) \{([\s\S]*?)\n {2}\}/);
  assert.ok(fn, 'relogin() exists');
  assert.match(fn[1], /HHTTPS_BASE \+ '\/\?returnTo=' \+ encodeURIComponent\(window\.location\.href\)/, 'relogin goes to BASE_URL');
  assert.match(clientSrc, /fetch\(HHTTPS_BASE \+ '\/hhttps\/token\/refresh'/, 'token refresh goes to BASE_URL');

  const errStart = src.indexOf('function renderOAuthError(');
  const errEnd = src.indexOf('function renderConsentPage(', errStart);
  assert.ok(errStart > 0 && errEnd > errStart, 'renderOAuthError located');
  const err = src.slice(errStart, errEnd);
  assert.doesNotMatch(err, /https:\/\/hhttps\.org/, 'no hard-coded origin in renderOAuthError');
  assert.match(err, /href="\$\{escapeHtml\(BASE_URL\)\}"/, 'back link uses BASE_URL');
});

// ─── AP2-31 (#165): script/CSS extracted, labels defined once ────────────────

test('AP2-31: renderConsentPage carries no inline browser script and no inline CSS block', () => {
  const r = renderer();
  assert.doesNotMatch(r, /<style>/, 'CSS lives in public/consent.css');
  assert.match(r, /<link rel="stylesheet" href="\/consent\.css">/, 'the stylesheet is linked');
  assert.match(r, /<script type="module" src="\/hhttps\/oauth\/consent\.js"><\/script>/, 'the script is loaded as a module');
  // The only <script> elements are the JSON config block and the module tag.
  const scripts = r.match(/<script[^>]*>/g) || [];
  assert.equal(scripts.length, 2, `exactly two script tags, got ${scripts.join(' ')}`);
  assert.ok(scripts.some(s => s.includes('application/json')), 'params travel as a JSON block');
  assert.ok(r.length < 6000, `the HTML shell stays small (${r.length} chars)`);
});

test('AP2-31: the consent script is served from /hhttps/oauth/consent.js', () => {
  assert.match(src, /app\.get\('\/hhttps\/oauth\/consent\.js'/, 'route exists');
  assert.match(src, /readFileSync\(join\(__dirname, 'consent-client\.js'\)/, 'served straight from the module file');
});

test('AP2-31: the JSON config block cannot break out of the <script> element', () => {
  const r = renderer();
  assert.match(r, /\.replace\(\/<\/g, '\\\\u003c'\)/, '`<` is escaped in the embedded JSON');
});

test('AP2-31: scope labels are defined once — the server renders them from CONSENT_I18N', () => {
  const r = renderer();
  assert.match(r, /scopeLabel\(s, 'de'\)/, 'scope rows use the shared label table');
  // No second, server-local copy of the German scope texts.
  assert.doesNotMatch(r, /Eine pseudonyme Kennung/, 'no duplicated scope description in server.js');
  assert.doesNotMatch(r, /Deine verifizierte Berufsrolle/, 'no duplicated scope description in server.js');

  for (const scope of ['openid', 'role', 'verification_method', 'age_group', 'email']) {
    for (const lang of ['de', 'en']) {
      const l = scopeLabel(scope, lang);
      assert.equal(l.icon, SCOPE_ICONS[scope], `${scope}/${lang}: icon`);
      assert.equal(l.title, CONSENT_I18N[lang][`scope.${scope}.title`], `${scope}/${lang}: title`);
      assert.equal(l.desc, CONSENT_I18N[lang][`scope.${scope}.desc`], `${scope}/${lang}: desc`);
    }
  }
  const unknown = scopeLabel('does-not-exist', 'de');
  assert.equal(unknown.icon, '?');
  assert.equal(unknown.title, 'does-not-exist');
  assert.equal(unknown.desc, CONSENT_I18N.de['scope.unknown.desc']);
});

test('AP2-31: DE and EN carry exactly the same i18n keys, and every data-i18n key in the page exists', () => {
  const de = Object.keys(CONSENT_I18N.de).sort();
  const en = Object.keys(CONSENT_I18N.en).sort();
  assert.deepEqual(de, en, 'DE and EN keys match');

  const used = new Set();
  for (const m of renderer().matchAll(/data-i18n="([^"$]+)"/g)) used.add(m[1]);
  for (const m of clientSrc.matchAll(/\bt\('([^']+)'\)/g)) used.add(m[1]);
  for (const key of used) {
    assert.ok(CONSENT_I18N.de[key], `i18n key used by the page exists: ${key}`);
  }
});

test('AP2-41: the dead i18n key consent.noIdentity is gone', () => {
  assert.equal(CONSENT_I18N.de['consent.noIdentity'], undefined);
  assert.equal(CONSENT_I18N.en['consent.noIdentity'], undefined);
  assert.doesNotMatch(src, /consent\.noIdentity/, 'not referenced in server.js either');
});

test('AP2-31: the /approve request body is built once (postApprove), not spelled out twice', () => {
  assert.match(clientSrc, /function approveBody\(token\)/, 'one body builder');
  assert.match(clientSrc, /function postApprove\(token\)/, 'one request helper');
  const bodies = clientSrc.match(/code_challenge_method:\s*params\.get\('code_challenge_method'\)/g) || [];
  assert.equal(bodies.length, 1, 'the approve body appears exactly once');
});

test('AP2-33: the consent script treats invalid_token as an expiry and retries once', () => {
  assert.match(clientSrc, /function isTokenExpiry\(d\)/, 'expiry detection is its own function');
  assert.match(clientSrc, /d\.error === 'invalid_token'/, 'the RFC code is the primary signal');
});

test('AP2-31: importing consent-client.js under Node runs no DOM code', () => {
  // The import at the top of this file already proves it; assert the guard is
  // present so it cannot be dropped by accident.
  assert.match(clientSrc, /if \(typeof document !== 'undefined'\) initConsentPage\(\);/);
  assert.equal(typeof CONSENT_I18N.de, 'object');
});

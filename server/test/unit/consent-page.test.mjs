// T9 / AK-30: static checks of the consent page renderer (renderConsentPage
// in server.js is not exported — we inspect its source text). The behaviour
// over HTTP (params carried, relogin body) is covered by
// test/integration/login-hint.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, '../../server.js'), 'utf8');

/** Source of renderConsentPage(...) up to the next top-level function. */
function renderer() {
  const start = src.indexOf('function renderConsentPage(');
  assert.ok(start > 0, 'renderConsentPage is defined');
  // The renderer returns one template literal; it ends at the closing
  // </html> (the next top-level `function ` would be a false end, since the
  // inline consent script declares functions of its own).
  const end = src.indexOf('</html>', start);
  assert.ok(end > start, 'renderConsentPage ends with </html>');
  return src.slice(start, end);
}

test('AK-30: relogin() appends login_hint and pseudonym (URL-encoded) to the sign-in URL, keeping returnTo', () => {
  const fn = renderer().match(/function relogin\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'relogin() exists in the consent page script');
  const body = fn[1];
  assert.match(body, /\?returnTo=' \+ encodeURIComponent\(window\.location\.href\)/, 'returnTo is still the consent URL');
  assert.match(body, /params\.get\('login_hint'\)/, 'login_hint read from params');
  assert.match(body, /params\.get\('pseudonym'\)/, 'pseudonym read from params');
  assert.match(body, /&login_hint=' \+ encodeURIComponent\(/, 'login_hint appended URL-encoded');
  assert.match(body, /&pseudonym=' \+ encodeURIComponent\(/, 'pseudonym appended URL-encoded');
});

test('AK-30: #pseudoInput is pre-filled from params via the DOM, not via HTML interpolation', () => {
  const r = renderer();
  assert.match(r, /getElementById\('pseudoInput'\)[\s\S]{0,120}params\.get\('pseudonym'\)/, 'DOM pre-fill');
  const tag = r.match(/<input id="pseudoInput"[^>]*>/);
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

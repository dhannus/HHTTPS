// Review 2026-09, Welle 3 — AP1 unit tests for the pieces this wave extracted:
//
//   AP1-42 (#145)  sendJson's HTML half now lives in views/json-viewer.js
//   AP1-27 (#220)  the viewer escapes title / subtitle / path
//   AP1-15 (#220)  the raw-JSON link keeps the request's query string
//   AP1-44 (#161)  the slug validator is one constant, and it accepts what
//                  generateSlug produces
//   AP1-46 (#176)  the ESCO URL + `_embedded.results` unwrapping live in
//                  roles.taxonomy.js; resolveEsco is a thin wrapper over it
//   AP1-50 (#191)  resolveVerification / VERIFICATION_CHECKS are gone from the
//                  server's import surface; VERIFICATION_LEVELS is a label map
//   AP1-53 (#204)  roles.taxonomy.i18n.js is gone
//   AP1-54 (#207)  roles.eaa.js no longer exports the unreachable setRoleHeaders
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  escapeHtml, highlightJson, rawJsonUrl, renderJsonPage
} from '../../views/json-viewer.js';
import { searchEsco, resolveEsco, ESCO_API } from '../../roles.taxonomy.js';
import * as rolesEaa from '../../roles.eaa.js';
import * as roles from '../../roles.js';

const here = dirname(fileURLToPath(import.meta.url));
const read = (f) => readFileSync(join(here, '../..', f), 'utf8');

/** Source with comments blanked out — assertions here are about CODE, not prose.
 *  Line comments are stripped FIRST: a line comment that mentions a wildcard
 *  path (for example the /eudi status routes) contains a slash-star sequence,
 *  and stripping block comments first would swallow everything up to the next
 *  star-slash — several hundred lines of real code. */
const stripComments = (src) => src
  .split('\n').map(l => l.replace(/(^|\s)\/\/.*$/, '$1')).join('\n')
  .replace(/\/\*[\s\S]*?\*\//g, '');

const serverSrc  = read('server.js');
const serverCode = stripComments(serverSrc);

// ─── AP1-42 / AP1-27 / AP1-15: the JSON viewer ───────────────────────────────

test('AP1-42: server.js no longer carries the viewer markup; the module does', () => {
  // The whole point of the split: no CSS palette, no <!DOCTYPE, no copy script
  // in the request handler file.
  assert.equal(serverSrc.includes('<!DOCTYPE html>\n<html lang="en">\n<head>'), false,
    'server.js still embeds the viewer document');
  assert.equal(serverSrc.includes('--terra-dp'), false, 'server.js still embeds the viewer palette');
  assert.match(serverSrc, /import \{ renderJsonPage \} from '\.\/views\/json-viewer\.js'/);

  const html = renderJsonPage({ data: { ok: true }, path: '/hhttps/info' });
  assert.match(html, /^<!DOCTYPE html>/);
  assert.match(html, /--terra-dp/);
  assert.match(html, /<pre id="json">/);
});

test('AP1-27: title, subtitle and path are HTML-escaped', () => {
  const html = renderJsonPage({
    data: { ok: 1 },
    title: '<img src=x onerror="alert(1)">',
    subtitle: "</p><script>alert('sub')</script>",
    path: '/x"><script>alert(2)</script>'
  });
  assert.equal(html.includes('<img src=x'), false);
  assert.equal(html.includes('<script>alert('), false);
  assert.match(html, /&lt;img src=x/);
  assert.match(html, /&lt;script&gt;/);
});

test('AP1-27: payload values cannot break out of the highlighted block', () => {
  const html = renderJsonPage({ data: { evil: '</pre><script>alert(1)</script>' } });
  assert.equal(html.includes('</pre><script>'), false);
  assert.match(html, /&lt;\/pre&gt;/);
});

test('AP1-27: escapeHtml covers the five significant characters', () => {
  assert.equal(escapeHtml(`<&>"'`), '&lt;&amp;&gt;&quot;&#39;');
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
  assert.equal(escapeHtml(42), '42');
});

test('AP1-42: highlightJson escapes first and then marks up keys/values', () => {
  const out = highlightJson(JSON.stringify({ a: 'b<c', n: 7, t: true, z: null }, null, 2));
  assert.equal(out.includes('b<c'), false);
  assert.match(out, /<span class="k">"a"<\/span>/);
  assert.match(out, /<span class="n">7<\/span>/);
  assert.match(out, /<span class="b">true<\/span>/);
  assert.match(out, /<span class="b">null<\/span>/);
});

test('AP1-15: the raw-JSON link keeps the query string and forces format=json', () => {
  assert.equal(rawJsonUrl('/hhttps/s/hp-ABC?domain=example.com'),
               '/hhttps/s/hp-ABC?domain=example.com&format=json');
  assert.equal(rawJsonUrl('/hhttps/info'), '/hhttps/info?format=json');
  // an existing format= is overridden, not duplicated
  assert.equal(rawJsonUrl('/x?format=html&a=1'), '/x?format=json&a=1');

  const html = renderJsonPage({
    data: {}, path: '/hhttps/s/hp-ABC', originalUrl: '/hhttps/s/hp-ABC?domain=example.com'
  });
  assert.match(html, /href="\/hhttps\/s\/hp-ABC\?domain=example\.com&amp;format=json"/);
});

test('AP1-27: the copy script reads location instead of an interpolated path', () => {
  const html = renderJsonPage({ data: {}, path: "/x');alert(1);//" });
  const script = html.slice(html.lastIndexOf('<script>'), html.lastIndexOf('</script>'));
  assert.equal(script.includes('/x'), false, 'the request path reached the script body');
  assert.equal(script.includes('alert(1)'), false);
  assert.match(script, /new URL\(location\.href\)/);
  // the path is still shown, but only as escaped text
  assert.match(html, /&#39;\);alert\(1\);/);
});

// ─── AP1-44: one slug validator ──────────────────────────────────────────────

test('AP1-44: SLUG_RE is defined once and used at every validation site', () => {
  assert.equal((serverCode.match(/const SLUG_RE = /g) || []).length, 1);
  // the literal appears exactly once in code: in that definition
  assert.equal((serverCode.match(/\/\^hp-\[A-Z0-9/g) || []).length, 1,
    'an inline slug regex survives next to SLUG_RE');
  assert.ok((serverCode.match(/SLUG_RE\.test\(/g) || []).length >= 4);
});

test('AP1-44: the validator accepts what the generator produces', () => {
  // mirror of generateSlug(): hp- + 10 Crockford chars with dashes after 3 and 7
  const SLUG_RE = /^hp-[A-Z0-9-]+$/i;
  const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  for (let n = 0; n < 200; n++) {
    let out = 'hp-';
    for (let i = 0; i < 10; i++) {
      out += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
      if (i === 2 || i === 6) out += '-';
    }
    assert.ok(SLUG_RE.test(out), out);
  }
  for (const bad of ['', 'hp-', 'not-a-slug', 'HP', 'hp_ABC', 'hp-ABC.DEF', 'xhp-ABC']) {
    assert.equal(SLUG_RE.test(bad), false, bad);
  }
});

// ─── AP1-46: one ESCO client ─────────────────────────────────────────────────

function escoStub(results, { ok = true } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return { ok, json: async () => ({ _embedded: { results } }) };
  };
  return { fetchImpl, calls };
}

test('AP1-46: searchEsco builds the ESCO URL and unwraps _embedded.results', async () => {
  const { fetchImpl, calls } = escoStub([
    { title: 'Tischlerin', code: '7522', uri: 'http://data.europa.eu/esco/occupation/1' },
    { preferredLabel: 'Schreiner', code: null, uri: null }
  ]);
  const hits = await searchEsco('Tischler', { language: 'de', limit: 8, fetchImpl });
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.startsWith(ESCO_API), calls[0].url);
  assert.match(calls[0].url, /type=occupation/);
  assert.match(calls[0].url, /language=de/);
  assert.match(calls[0].url, /limit=8/);
  assert.deepEqual(hits, [
    { escoUri: 'http://data.europa.eu/esco/occupation/1', isco08: '7522', prefLabel: 'Tischlerin' },
    { escoUri: null, isco08: null, prefLabel: 'Schreiner' }
  ]);
});

test('AP1-46: searchEsco is failure-tolerant — never throws, returns []', async () => {
  assert.deepEqual(await searchEsco('x', { fetchImpl: escoStub([], { ok: false }).fetchImpl }), []);
  assert.deepEqual(await searchEsco('x', { fetchImpl: async () => { throw new Error('boom'); } }), []);
  assert.deepEqual(await searchEsco('', { fetchImpl: escoStub([]).fetchImpl }), []);
  assert.deepEqual(await searchEsco('x', { fetchImpl: null }), []);
});

test('AP1-46: resolveEsco is a thin wrapper over searchEsco', async () => {
  const { fetchImpl, calls } = escoStub([
    { title: 'Ärztin', code: '2212', uri: 'http://data.europa.eu/esco/occupation/9' }
  ]);
  const hit = await resolveEsco('Ärztin', { language: 'de', fetchImpl });
  assert.deepEqual(hit, {
    escoUri: 'http://data.europa.eu/esco/occupation/9', isco08: '2212', prefLabel: 'Ärztin'
  });
  assert.match(calls[0].url, /limit=1/);
  // a hit without a URI is not a resolution
  assert.equal(await resolveEsco('x', { fetchImpl: escoStub([{ title: 'x' }]).fetchImpl }), null);
});

test('AP1-46: the ESCO proxy in server.js no longer builds the URL itself', () => {
  assert.equal(serverCode.includes('ec.europa.eu/esco/api/search'), false);
  assert.equal(serverCode.includes('_embedded'), false);
  assert.match(serverCode, /await searchEsco\(/);
});

// ─── AP1-50 / AP1-53 / AP1-54: dead code is gone ─────────────────────────────

test('AP1-50: resolveVerification is removed and no longer imported', () => {
  assert.equal('resolveVerification' in roles, false);
  assert.equal(serverCode.includes('resolveVerification'), false);
  assert.equal(serverCode.includes('VERIFICATION_CHECKS'), false);
  assert.equal(serverCode.includes('TRUST_BANDS'), false);
  assert.equal(serverCode.includes('HUMAN_CONFIRMED_THRESHOLD'), false);
});

test('AP1-50: VERIFICATION_LEVELS survives as a label map and is documented as one', () => {
  for (const def of Object.values(roles.VERIFICATION_LEVELS)) assert.equal(typeof def.label, 'string');
  assert.match(read('roles.js'), /LEGACY — LABEL MAP ONLY \(AP1-50/);
});

test('AP1-53: roles.taxonomy.i18n.js is deleted and nothing references it', () => {
  assert.equal(existsSync(join(here, '../../roles.taxonomy.i18n.js')), false);
  for (const f of ['roles.taxonomy.js', 'roles.i18n.js', 'roles.js', 'server.js']) {
    assert.equal(stripComments(read(f)).includes('roles.taxonomy.i18n'), false, f);
  }
});

test('AP1-54: setRoleHeaders is gone; the reachable role-EAA API stays', () => {
  assert.equal('setRoleHeaders' in rolesEaa, false);
  assert.equal(typeof rolesEaa.buildRoleEaaClaims, 'function');
  assert.equal(typeof rolesEaa.guardRoleEaa, 'function');
  assert.equal(serverSrc.includes('setRoleHeaders'), false);
  assert.equal(stripComments(read('roles.eaa.js')).includes('guardReservedRole'), false,
    'the unused guardReservedRole import is gone');
});

test('AP1-10: the taxonomy sanity checks run under npm test now', () => {
  assert.equal(existsSync(join(here, '../../roles.taxonomy.test.mjs')), false);
  assert.equal(existsSync(join(here, 'roles-taxonomy.test.mjs')), true);
});

// ─── AP1-49 / AP1-47: one protocol-version constant, honest header ───────────

test('AP1-49: PROTOCOL_VERSION replaces the literal in the AP1 surface', () => {
  assert.match(serverSrc, /const PROTOCOL_VERSION = '0\.5\.0';/);
  assert.ok((serverSrc.match(/PROTOCOL_VERSION/g) || []).length >= 14);
  // no '0.5.0' literal left before the OAuth section (the AP1 range)
  const head = serverSrc.slice(0, serverSrc.indexOf('OAuth 2.0 / OpenID Connect Provider'));
  const literals = [...head.matchAll(/'0\.5\.0'/g)].filter(m => {
    const line = head.slice(head.lastIndexOf('\n', m.index) + 1, head.indexOf('\n', m.index));
    return !line.trimStart().startsWith('//') && !line.trimStart().startsWith('*');
  });
  assert.deepEqual(literals.map(m => m[0]), ["'0.5.0'"], 'only the constant itself may hold the literal');
});

test('AP1-47: the file header no longer advertises v4.1 and "14 roles"', () => {
  const head = serverSrc.slice(0, serverSrc.indexOf("import express"));
  assert.equal(head.includes('✓ 14 roles'), false);
  assert.equal(head.includes('HHTTPS v4.1 — Role Identity API'), false);
  assert.equal(head.includes('medical_professional'), false, 'the old role enumeration survives');
  assert.match(head, /ESCO-dynamic/);
  assert.match(head, /PROTOCOL_VERSION/);
});

// Review 2026-09, Welle 3 — AP5 unit tests.
//
// AP5-38 (#205): server.js and wp-plugin-registration.js each carried their own
//                apex resolution, redirect validation, client-id generation and
//                two-part-TLD list, with semantics that differed. There is now
//                ONE module; these tests pin the chosen (stricter) semantics.
// AP5-14        homepage_url is checked the way its error message always claimed.
// AP5-44        the shared constants exist and are used by both doors.
// AP5-45        jwkThumbprint lives once, in pop-verify.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  TWO_PART_TLDS, normalizeApexDomain, apexDomainFromUrl, apexDomainFromEmail,
  emailMatchesPlatform, expectedDnsHost, isValidRedirectUri, isValidHomepageUrl,
  generateClientId, randomToken, WP_PLUGIN_OWNER_ID, PLATFORM_EMAIL_TOKEN_TTL_MS,
  MAX_REDIRECT_URI_LENGTH
} from '../../client-registration.js';
import { dnsCheckTooSoon, DNS_MIN_INTERVAL_MS } from '../../dns-verify.js';
import { POP_CHALLENGE_TTL_S, POP_IAT_SKEW_S } from '../../pop-verify.js';

const here = (p) => new URL(p, import.meta.url);

test('AP5-38: the apex list is the long one — `stadt.gov.uk` no longer collapses to `gov.uk`', () => {
  // The plugin's own 10-entry list did not know gov.uk, so it asked the site
  // owner for a TXT record at a host they do not control (and that any other
  // *.gov.uk site could have satisfied).
  assert.equal(apexDomainFromUrl('https://stadt.gov.uk'), 'stadt.gov.uk');
  assert.equal(expectedDnsHost(apexDomainFromUrl('https://stadt.gov.uk')),
    '_hhttps-verify.stadt.gov.uk');
  for (const suffix of ['gov.uk', 'gov.au', 'co.za', 'com.tr', 'or.jp', 'ne.jp']) {
    assert.ok(TWO_PART_TLDS.has(suffix), `${suffix} must be known`);
    assert.equal(apexDomainFromUrl(`https://www.example.${suffix}`), `example.${suffix}`);
  }
  assert.equal(apexDomainFromUrl('https://old.reddit.com'), 'reddit.com');
  assert.equal(apexDomainFromUrl('example.com:8443/path'), 'example.com');
});

test('AP5-38: a registration apex needs a real zone — single-label hosts are rejected', () => {
  assert.equal(apexDomainFromUrl('https://localhost'), null);
  assert.equal(apexDomainFromUrl('https://localhost:3000'), null);
  assert.equal(apexDomainFromUrl(''), null);
  assert.equal(apexDomainFromUrl(null), null);
  assert.equal(apexDomainFromUrl('not a url://'), null);
  // normalizeApexDomain keeps its own, broader contract — it is also used for
  // the Phase-2.5 domain-bound slugs, where a bare label is a valid answer.
  assert.equal(normalizeApexDomain('localhost'), 'localhost');
});

test('AP5-38: e-mail apex must equal platform apex; subdomain mail is fine', () => {
  assert.equal(apexDomainFromEmail('admin@team.example.com'), 'example.com');
  assert.equal(apexDomainFromEmail('no-at-sign'), null);
  assert.equal(emailMatchesPlatform('admin@team.example.com', 'https://www.example.com'), true);
  assert.equal(emailMatchesPlatform('admin@example.org', 'https://example.com'), false);
  assert.equal(emailMatchesPlatform('a@stadt.gov.uk', 'https://www.stadt.gov.uk'), true);
  // the short list used to make these two the same apex ('gov.uk')
  assert.equal(emailMatchesPlatform('a@andere.gov.uk', 'https://stadt.gov.uk'), false);
});

test('AP5-38: isValidRedirectUri is the INTERSECTION of the two old copies', () => {
  assert.equal(isValidRedirectUri('https://example.com/cb'), true);
  assert.equal(isValidRedirectUri('http://localhost:3000/cb'), true);   // portal rule
  assert.equal(isValidRedirectUri('http://127.0.0.1/cb'), true);
  assert.equal(isValidRedirectUri('http://example.com/cb'), false);     // portal rule
  assert.equal(isValidRedirectUri('ftp://localhost/cb'), false);        // the plugin allowed this
  assert.equal(isValidRedirectUri('https://example.com/cb#frag'), false); // RFC 6749 §3.1.2
  assert.equal(isValidRedirectUri('https://user:pw@example.com/cb'), false);
  assert.equal(isValidRedirectUri('https://example.com/' + 'a'.repeat(MAX_REDIRECT_URI_LENGTH)), false);
  assert.equal(isValidRedirectUri('/relative'), false);
  assert.equal(isValidRedirectUri(''), false);
  assert.equal(isValidRedirectUri(null), false);
});

test('AP5-14: homepage_url is HTTPS with a resolvable apex, as the message always said', () => {
  assert.equal(isValidHomepageUrl('https://example.com'), true);
  assert.equal(isValidHomepageUrl('http://example.com'), false);
  assert.equal(isValidHomepageUrl('ftp://example.com'), false);
  assert.equal(isValidHomepageUrl('https://localhost'), false);
  assert.equal(isValidHomepageUrl('https://user:pw@example.com'), false);
  assert.equal(isValidHomepageUrl('example.com'), false);
  assert.equal(isValidHomepageUrl(undefined), false);
});

test('AP5-38: generateClientId is one implementation with an optional prefix', () => {
  const portal = generateClientId('My Platform!');
  const plugin = generateClientId('My Platform!', { prefix: 'wp-', fallback: 'site' });
  assert.match(portal, /^my-platform-[A-Za-z0-9_-]{8}$/);
  assert.match(plugin, /^wp-my-platform-[A-Za-z0-9_-]{8}$/);
  assert.match(generateClientId('!!!'), /^platform-/);
  assert.match(generateClientId('!!!', { prefix: 'wp-', fallback: 'site' }), /^wp-site-/);
  assert.ok(generateClientId('x', { prefix: 'wp-' }).length <= 64, 'fits client_id VARCHAR(64)');
  assert.ok(generateClientId('a'.repeat(200)).length <= 64);
  // 48 bit of tail, not the portal's old 16 bit
  const seen = new Set(Array.from({ length: 500 }, () => generateClientId('same name')));
  assert.equal(seen.size, 500, 'no collision over 500 draws');
});

test('AP5-38: randomToken has one meaning — bytes of entropy, base64url-encoded', () => {
  assert.match(randomToken(24), /^[A-Za-z0-9_-]{32}$/);
  assert.match(randomToken(6), /^[A-Za-z0-9_-]{8}$/);
  assert.notEqual(randomToken(), randomToken());
});

test('AP5-31/AP5-39: the per-client DNS interval is one rule for both doors', () => {
  assert.equal(dnsCheckTooSoon({}), false);
  assert.equal(dnsCheckTooSoon({ dns_last_checked_at: null }), false);
  assert.equal(dnsCheckTooSoon({ dns_last_checked_at: new Date() }), true);
  assert.equal(dnsCheckTooSoon(
    { dns_last_checked_at: new Date(Date.now() - DNS_MIN_INTERVAL_MS - 1000) }), false);
});

test('AP5-44: the shared constants replaced the literals that were spelled out', () => {
  assert.equal(WP_PLUGIN_OWNER_ID, 'wp-plugin');
  assert.equal(PLATFORM_EMAIL_TOKEN_TTL_MS, 48 * 3600 * 1000);
  assert.equal(POP_CHALLENGE_TTL_S, 120);
  assert.equal(POP_IAT_SKEW_S, 300);
});

test('AP5-38/AP5-39/AP5-45: no module keeps a private copy of a shared helper', async () => {
  const [server, plugin] = await Promise.all([
    readFile(here('../../server.js'), 'utf8'),
    readFile(here('../../wp-plugin-registration.js'), 'utf8')
  ]);
  for (const [name, src] of [['server.js', server], ['wp-plugin-registration.js', plugin]]) {
    for (const helper of ['apexDomainFromUrl', 'isValidRedirectUri', 'generateClientId',
                          'emailMatchesPlatform', 'jwkThumbprint', 'normalizeApexDomain']) {
      assert.equal(src.includes(`function ${helper}(`), false,
        `${name} must import ${helper}, not define it`);
    }
    // AP5-39: neither file runs its own TXT lookup any more.
    assert.equal(src.includes('resolveTxt('), false, `${name} must use dns-verify.js`);
    assert.equal(/new Resolver\(/.test(src), false, `${name} must not build a resolver`);
  }
  // AP5-38: the second TLD list is gone for good.
  assert.equal(server.includes('TWO_PART_TLDS = new Set'), false);
  assert.equal(plugin.includes('TWO_PART_TLDS'), false);
  // AP5-46: the trailing patch markers are gone and nothing is mounted from
  // inside main() any more.
  assert.equal(/(POP-VERIFY|WP-PLUGIN-REG)\s*$/m.test(server), false, 'no patch markers');
  const mainBody = server.slice(server.indexOf('async function main()'));
  assert.equal(/mount(PopVerify|WpPluginRegistration)\(/.test(mainBody), false,
    'the mounts belong next to the other app.use() calls');
});

// Review 2026-09, Welle 2 — AP3 unit tests (pure functions in email.js):
//   AP3-15  URLs in HTML mails are escaped; only http(s) URLs are used at all
//   AP3-25  the shared SMTP transport carries bounded timeouts
//   AP3-05  the mail states the validity it actually has
//   AP3-10  classifyDomain has direct coverage (label boundaries, casing)
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  renderVerificationEmail, httpUrlOrNull, emailTransportConfig,
  classifyDomain, EMAIL_VERIFICATION_TTL_MS,
} from '../../email.js';

const base = { code: '123456', role: 'citizen',
  classification: { domain: 'example.org', level: 'email-verified', trustBonus: 0, category: 'generic' } };

// ─── AP3-15 (#99) ────────────────────────────────────────────────────────────
test('AP3-15: a URL with quotes/angle brackets cannot break out of the href attribute', () => {
  const evil = 'https://evil.example/x?a=1"><img src=x onerror=alert(1)>';
  const { html } = renderVerificationEmail({ ...base, verifyUrl: evil });
  assert.ok(!html.includes('<img src=x'), 'no injected tag in the mail body');
  assert.ok(!html.includes('"><img'), 'attribute is not closed early');
  assert.ok(html.includes('&quot;') || html.includes('%22'), 'the quote is neutralised');
});

test('AP3-15: httpUrlOrNull passes http(s) only and serialises the URL', () => {
  assert.equal(httpUrlOrNull('javascript:alert(1)'), null);
  assert.equal(httpUrlOrNull('data:text/html,<script>'), null);
  assert.equal(httpUrlOrNull('/wp-admin/options.php'), null);   // not absolute
  assert.equal(httpUrlOrNull(''), null);
  assert.equal(httpUrlOrNull(null), null);
  assert.equal(httpUrlOrNull('https://example.org/wp-admin/x'), 'https://example.org/wp-admin/x');
  // WHATWG serialisation percent-encodes the characters an injection needs.
  const serialised = httpUrlOrNull('https://evil.example/"><img src=x>');
  assert.ok(serialised.startsWith('https://evil.example/'), serialised);
  assert.ok(!serialised.includes('"') && !serialised.includes('<') && !serialised.includes('>'), serialised);
});

// ─── AP3-25 (#135) ───────────────────────────────────────────────────────────
test('AP3-25: the shared transport is pooled and every SMTP phase is bounded', () => {
  const cfg = emailTransportConfig();
  assert.equal(cfg.pool, true);
  assert.equal(cfg.connectionTimeout, 10_000);
  assert.equal(cfg.greetingTimeout, 10_000);
  assert.equal(cfg.socketTimeout, 30_000);
  // The sendmail binary is probed once at module load, not per mail.
  assert.ok(cfg.sendmailBin === null || typeof cfg.sendmailBin === 'string');
});

// ─── AP3-05 (#61) ────────────────────────────────────────────────────────────
test('AP3-05: a shortened TTL is what the mail promises', () => {
  const full = renderVerificationEmail({ ...base, verifyUrl: 'https://hhttps.org/v' });
  assert.match(full.html, /Valid for 15 minutes/);
  assert.match(full.text, /15 min/);

  const short = renderVerificationEmail({ ...base, verifyUrl: 'https://hhttps.org/v', ttlMs: 4 * 60_000 });
  assert.match(short.html, /Valid for 4 minutes · 4 Minuten gültig/);
  assert.match(short.text, /Your verification code \(4 min\)/);
  assert.match(short.text, /Dein Bestätigungs-Code \(4 Min\)/);
  assert.ok(!short.html.includes('after 15 minutes'), 'footer follows the real TTL');
  assert.equal(EMAIL_VERIFICATION_TTL_MS, 15 * 60_000);
});

// ─── AP3-10 (#83): classifyDomain had no direct test ─────────────────────────
test('AP3-10: classifyDomain — categories, sub-domains and label boundaries', () => {
  assert.deepEqual(classifyDomain('a@gmail.com'),
    { level: 'email-verified', trustBonus: 0, category: 'generic', domain: 'gmail.com' });
  assert.equal(classifyDomain('a@bundestag.de').category, 'official');
  assert.equal(classifyDomain('a@MAIL.BUNDESTAG.DE').category, 'official');   // sub-domain + casing
  assert.equal(classifyDomain('a@notbundestag.de').category, 'generic');      // AP3-02 boundary
  assert.equal(classifyDomain('a@uni-koeln.de').category, 'university');
  assert.equal(classifyDomain('a@hochschule-x.evil.com').category, 'generic');
  assert.equal(classifyDomain('a@spiegel.de').category, 'press');
  assert.equal(classifyDomain('a@gema.de').category, 'creative');
  assert.equal(classifyDomain('not-an-address').domain, '');
});

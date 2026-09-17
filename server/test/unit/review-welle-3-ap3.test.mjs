// Review 2026-09, Welle 3 — AP3 unit tests.
//
//   AP3-35 (#163)  the e-mail-verification hash contract has ONE definition
//   AP3-36 (#169)  BASE_URL is resolved once, for server.js and email.js alike
//   AP3-46 (#199)  ONE html escaper
//   AP3-41 (#183)  the platform / admin mails had no tests at all: renderers,
//                  escaping, negative cases and the classifyDomain gaps
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { emailVerificationHash, normalizeEmail } from '../../identity.js';
import { resolveRpId, resolveOrigin, resolveBaseUrl } from '../../config.js';
import { escapeHtml } from '../../html.js';
import {
  classifyDomain,
  renderPlatformRegistrationEmail,
  renderPlatformVerifiedEmail,
  renderPlatformRejectedEmail,
  renderAdminPlatformNotification,
  sendAdminPlatformNotification,
} from '../../email.js';

// ─── AP3-35 (#163) ───────────────────────────────────────────────────────────
test('AP3-35: emailVerificationHash is sha256 of the NORMALIZED address', () => {
  const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
  assert.equal(emailVerificationHash('Anna@Example.ORG'), sha('anna@example.org'));
  // The old writer used email.toLowerCase(), the old reader normalizeEmail():
  // they agreed only because /email/send happened to normalize first. Untrimmed
  // input is exactly where the two used to part company.
  assert.equal(emailVerificationHash('  anna@example.org  '), sha('anna@example.org'));
  assert.equal(emailVerificationHash('  Anna@Example.ORG '), emailVerificationHash('anna@example.org'));
  assert.equal(emailVerificationHash(null), sha(normalizeEmail(null)));
});

// ─── AP3-36 (#169) ───────────────────────────────────────────────────────────
test('AP3-36: BASE_URL follows RP_ID/ORIGIN — no hard-coded hhttps.org fallback', () => {
  assert.equal(resolveRpId({}), 'hhttps.org');
  assert.equal(resolveOrigin({}), 'https://hhttps.org');
  assert.equal(resolveBaseUrl({}), 'https://hhttps.org');

  // An issuer under another RP_ID: email.js used to fall back to hhttps.org
  // here and shipped verified/rejected/admin mails pointing at the wrong host.
  assert.equal(resolveBaseUrl({ RP_ID: 'id.example.org' }), 'https://id.example.org');
  assert.equal(resolveBaseUrl({ RP_ID: 'x', ORIGIN: 'http://localhost:3000' }), 'http://localhost:3000');
  // An explicit BASE_URL still wins over both.
  assert.equal(resolveBaseUrl({ RP_ID: 'x', ORIGIN: 'http://o', BASE_URL: 'https://b' }), 'https://b');
});

// ─── AP3-46 (#199) ───────────────────────────────────────────────────────────
test('AP3-46: the shared escaper covers both quote forms', () => {
  assert.equal(escapeHtml(`<a href="x" title='y'>&</a>`),
    '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
  assert.equal(escapeHtml(0), '0');
  // & is rewritten first — no double-escaping of the entities we just produced.
  assert.equal(escapeHtml('&lt;'), '&amp;lt;');
});

// ─── AP3-41 (#183): platform registration mail ───────────────────────────────
const reg = {
  platformName: 'Acme Forum',
  homepageUrl:  'https://acme.example',
  confirmUrl:   'https://hhttps.org/confirm?email_token=abc',
};

test('AP3-41: registration mail carries name, homepage, confirm link and both languages', () => {
  const { subject, html, text } = renderPlatformRegistrationEmail(reg);
  assert.match(subject, /Confirm your platform registration: Acme Forum/);
  assert.ok(html.includes('Acme Forum'));
  assert.ok(html.includes('https://acme.example'));
  assert.ok(html.includes(reg.confirmUrl), 'the CTA link is in the html');
  assert.ok(html.includes('lang="de"'), 'bilingual: the German block is present');
  assert.match(text, /Confirmation link \(valid 48 hours\)/);
  assert.match(text, /Bestätigungslink \(48 Stunden gültig\)/);
  assert.ok(text.includes(reg.confirmUrl));
});

test('AP3-41: an email_change registration mail says so in both languages', () => {
  const { subject, html } = renderPlatformRegistrationEmail({ ...reg, kind: 'email_change' });
  assert.match(subject, /Confirm new email for platform "Acme Forum"/);
  assert.ok(html.includes('Confirm new contact email') || html.includes('new contact email'));
  assert.ok(html.includes('Neue Kontakt-Email') || html.includes('neue Kontakt-Email'));
});

test('AP3-41/AP3-15: a hostile platform name cannot inject markup into the mail', () => {
  const { html } = renderPlatformRegistrationEmail({
    ...reg,
    platformName: '<img src=x onerror=alert(1)>"evil',
    homepageUrl:  'https://evil.example/"><script>alert(1)</script>',
  });
  assert.ok(!html.includes('<img src=x'), 'no injected tag');
  assert.ok(!html.includes('<script>alert(1)</script>'), 'no injected script');
  assert.ok(html.includes('&lt;img src=x'), 'the name is escaped, not dropped');
});

test('AP3-41: the WordPress setup link is used only when it is a real http(s) URL', () => {
  const plugin = renderPlatformRegistrationEmail({ ...reg, setupUrl: 'https://shop.example/wp-admin/options.php' });
  assert.ok(plugin.html.includes('https://shop.example/wp-admin/options.php'));
  assert.ok(plugin.html.includes('iamhmn Setup'), 'plugin wording, not the portal wording');

  // AP3-15: a javascript: URL is not a setup URL — the mail falls back to the
  // developer-portal wording and the scheme never reaches the href.
  const evil = renderPlatformRegistrationEmail({ ...reg, setupUrl: 'javascript:alert(1)' });
  assert.ok(!evil.html.includes('javascript:alert(1)'));
  assert.ok(!evil.html.includes('iamhmn Setup'));
  assert.ok(evil.html.includes('unverified'), 'portal wording instead');

  // A relative path is not absolute → same fallback.
  const rel = renderPlatformRegistrationEmail({ ...reg, setupUrl: '/wp-admin/options.php' });
  assert.ok(!rel.html.includes('iamhmn Setup'));
});

// ─── AP3-41 (#183): verified / rejected mails ────────────────────────────────
test('AP3-41: the "verified" mail names the platform and links the dashboard', () => {
  const { subject, html, text } = renderPlatformVerifiedEmail({ platformName: 'Acme Forum' });
  assert.match(subject, /Acme Forum is now verified/);
  assert.ok(html.includes('Acme Forum'));
  assert.ok(html.includes('/developers'), 'dashboard CTA');
  assert.match(text, /Acme Forum was verified by the HHTTPS admin\./);
  assert.match(text, /wurde vom HHTTPS-Admin verifiziert\./);
});

test('AP3-41: the "rejected" mail shows the reason and escapes it', () => {
  const { subject, html, text } = renderPlatformRejectedEmail({
    platformName: 'Acme Forum', reason: 'Impressum <missing> & "unclear"',
  });
  assert.match(subject, /Request for "Acme Forum" rejected/);
  assert.ok(html.includes('&lt;missing&gt;'), 'the reason is escaped');
  assert.ok(!html.includes('<missing>'));
  assert.ok(text.includes('Impressum <missing> & "unclear"'), 'plain text is not escaped');
});

test('AP3-41: a rejection without a reason falls back in both languages', () => {
  const { html, text } = renderPlatformRejectedEmail({ platformName: 'Acme Forum' });
  assert.ok(html.includes('(no reason given)'));
  assert.match(text, /Reason: \(no reason given\)/);
  assert.match(text, /Grund: \(kein Grund angegeben\)/);
});

// ─── AP3-41 (#183): admin notification ───────────────────────────────────────
const adminBase = {
  platformName: 'Acme Forum', clientId: 'hp-ABC-DEF-GHJ',
  homepageUrl: 'https://acme.example', contactEmail: 'ops@acme.example',
};

test('AP3-41: the review notification asks for a decision and lists the Impressum', () => {
  const { subject, html, text } = renderAdminPlatformNotification({
    ...adminBase, kind: 'review', impressumUrl: 'https://acme.example/impressum',
  });
  assert.match(subject, /Prüfung erforderlich: "Acme Forum"/);
  assert.ok(html.includes('wartet auf deine Prüfung'));
  assert.ok(html.includes('https://acme.example/impressum'));
  assert.ok(html.includes('hp-ABC-DEF-GHJ'));
  assert.match(text, /Impressum:\s+https:\/\/acme\.example\/impressum/);
  assert.match(text, /Admin-Queue: .*\/developers\/admin\.html/);
});

test('AP3-41: the "registered" notification is FYI only and omits the Impressum row', () => {
  const { subject, html, text } = renderAdminPlatformNotification({ ...adminBase, kind: 'registered' });
  assert.match(subject, /Neue Plattform: "Acme Forum"/);
  assert.ok(html.includes('Neue Plattform registriert'));
  // The prose mentions the Impressum as a TODO for the operator, but the
  // data table must not carry an Impressum row before the review step.
  assert.ok(!html.includes('<div class="ib-key">Impressum</div>'), 'no Impressum row yet');
  assert.ok(!text.includes('Impressum:'));
});

test('AP3-41: a mismatching contact domain is flagged, and missing fields render as —', () => {
  const flagged = renderAdminPlatformNotification({ ...adminBase, domainEmailMatch: false });
  assert.ok(flagged.html.includes('Domain stimmt nicht überein'));
  assert.ok(flagged.text.includes('(Domain stimmt nicht überein)'));

  const bare = renderAdminPlatformNotification({ kind: 'registered' });
  assert.ok(bare.html.includes('(ohne Namen)'));
  assert.ok(bare.html.includes('—'), 'empty fields render as an em dash, not "undefined"');
  assert.ok(!bare.html.includes('undefined'));
  assert.ok(!bare.text.includes('undefined'));
});

test('AP3-41: admin fields are escaped — a hostile contact address cannot inject markup', () => {
  const { html } = renderAdminPlatformNotification({
    ...adminBase, contactEmail: '"><script>alert(1)</script>@x.example',
  });
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('AP3-41: without ADMIN_NOTIFY_EMAIL the notification is skipped, never sent', async () => {
  const prev = process.env.ADMIN_NOTIFY_EMAIL;
  delete process.env.ADMIN_NOTIFY_EMAIL;
  try {
    const r = await sendAdminPlatformNotification({ ...adminBase, kind: 'review' });
    assert.deepEqual(r, { sent: false, skipped: 'ADMIN_NOTIFY_EMAIL not configured' });
  } finally {
    if (prev === undefined) delete process.env.ADMIN_NOTIFY_EMAIL;
    else process.env.ADMIN_NOTIFY_EMAIL = prev;
  }
});

// ─── AP3-41 (#183): classifyDomain gaps left by the Welle-0/2 test ───────────
test('AP3-41: classifyDomain — levels and bonuses per category, not just the label', () => {
  assert.deepEqual(classifyDomain('a@bundestag.de'),
    { level: 'official-email', trustBonus: 40, category: 'official', domain: 'bundestag.de' });
  assert.deepEqual(classifyDomain('a@tum.de'),
    { level: 'school-email', trustBonus: 15, category: 'university', domain: 'tum.de' });
  assert.deepEqual(classifyDomain('a@zeit.de'),
    { level: 'email-verified', trustBonus: 15, category: 'press', domain: 'zeit.de' });
  assert.deepEqual(classifyDomain('a@vgwort.de'),
    { level: 'email-verified', trustBonus: 15, category: 'creative', domain: 'vgwort.de' });
});

test('AP3-41: classifyDomain — the German school prefixes and their boundaries', () => {
  for (const d of ['uni-koeln.de', 'tu-dresden.de', 'hs-mainz.de', 'fh-kiel.de', 'hochschule-bremen.de'])
    assert.equal(classifyDomain(`a@${d}`).category, 'university', d);
  // The prefix must start the registrable label, and only under .de/.edu.
  assert.equal(classifyDomain('a@mail.uni-koeln.de').category, 'university', 'sub-domain of a university');
  assert.equal(classifyDomain('a@uni-koeln.com').category, 'generic', '.com is not covered');
  assert.equal(classifyDomain('a@notuni-koeln.de').category, 'generic', 'label boundary');
  assert.equal(classifyDomain('a@uni-koeln.de.evil.com').category, 'generic', 'suffix must be the end');
});

test('AP3-41: classifyDomain never throws on junk input', () => {
  for (const v of [null, undefined, '', '@', 'a@', 42, {}]) {
    const c = classifyDomain(v);
    assert.equal(c.category, 'generic', String(v));
    assert.equal(c.trustBonus, 0);
    assert.equal(typeof c.domain, 'string');
  }
  // Only the part after the LAST-parsed @ matters, lower-cased.
  assert.equal(classifyDomain('A@BUNDESTAG.DE').domain, 'bundestag.de');
});

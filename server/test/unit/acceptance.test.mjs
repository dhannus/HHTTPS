// Tester (Feature email-anchored-identity): additional acceptance evidence for
// the pure helpers and the mail renderer — boundary values that the T1/T2 unit
// tests do not pin down explicitly. Spec: docs/specs/email-anchored-identity/requirements.md
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizePseudonym, generatePseudonym, resolvePseudonym,
  normalizeCode, isValidCode, buildIdentityClaims, resolvePasskeySession,
} from '../../identity.js';
import { renderVerificationEmail } from '../../email.js';

const mail = () => renderVerificationEmail({
  code: '012345', verifyUrl: 'https://x/y', role: 'citizen',
  classification: { domain: 'example.org', level: 'email-verified', trustBonus: 0, category: 'generic' },
});

// ─── AK-6 / AK-7: pseudonym boundaries ──────────────────────────────────────
describe('AK-6 boundaries: sanitizePseudonym length and charset', () => {
  test('33 chars → cut to exactly 32; 32 chars → unchanged', () => {
    assert.equal(sanitizePseudonym('a'.repeat(33)).length, 32);
    assert.equal(sanitizePseudonym('b'.repeat(32)), 'b'.repeat(32));
  });
  test('German umlauts, dot, dash, underscore and space survive; other symbols are dropped', () => {
    assert.equal(sanitizePseudonym('Änne Müller-Ö.ß_1'), 'Änne Müller-Ö.ß_1');
    assert.equal(sanitizePseudonym('Anna😀!@#$%^&*()+=[]{};:\'"<>,/?|\\`~'), 'Anna');
  });
  test('cut happens BEFORE trim: 32 chars + trailing space → 31 chars is NOT produced (space is the 33rd char)', () => {
    const v = sanitizePseudonym('c'.repeat(32) + ' ');
    assert.equal(v, 'c'.repeat(32));
  });
  test('32 chars whose 32nd char is a space → 31 chars after trim (documented edge)', () => {
    const v = sanitizePseudonym('d'.repeat(31) + ' x');
    assert.equal(v, 'd'.repeat(31));
  });
});

describe('AK-7 boundaries: generated pseudonym', () => {
  test('is exactly 17 chars: "iamhmn_" + 10', () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePseudonym();
      assert.equal(p.length, 17);
      assert.equal(p.slice(0, 7), 'iamhmn_');
      assert.match(p.slice(7), /^[a-z0-9]{10}$/);
    }
  });
  test('resolvePseudonym: whitespace-only, symbols-only and >32-char symbol strings all generate', () => {
    for (const input of ['   ', '!!!', '!'.repeat(40), '\t\n']) {
      assert.match(resolvePseudonym(input), /^iamhmn_[a-z0-9]{10}$/, JSON.stringify(input));
    }
  });
});

// ─── AK-23 / AK-24: code normalisation boundaries ───────────────────────────
describe('AK-23/AK-24 boundaries: normalizeCode + isValidCode', () => {
  test('tabs, NBSP-free mixed separators and hyphens → 6 digits', () => {
    assert.equal(normalizeCode('482\t913'), '482913');
    assert.equal(normalizeCode('4 8 2 9 1 3'), '482913');
    assert.equal(normalizeCode('--482913--'), '482913');
    assert.equal(isValidCode(normalizeCode('\t 482-913 \n')), true);
  });
  test('after normalisation: letters, 5 or 7 digits, unicode digits, empty → invalid', () => {
    for (const bad of ['48291a', '48291', '4829133', '٤٨٢٩١٣', '', '48 29 1', 'abcdef']) {
      assert.equal(isValidCode(normalizeCode(bad)), false, JSON.stringify(bad));
    }
  });
  test('a code with a leading zero stays 6 digits ("012345")', () => {
    assert.equal(isValidCode(normalizeCode('012 345')), true);
  });
});

// ─── AK-18 / AK-21: passkey flag derivation ────────────────────────────────
describe('AK-21 (derivation): verified_methods with passkey → passkey_verified true in the claim bundle', () => {
  test('["email","passkey"] → passkey_verified true, preferred_username kept, email with scope', () => {
    const c = buildIdentityClaims({ methods: ['email', 'passkey'], pseudonym: 'iamhmn_k3j9x0q2wz', email: 'anna@example.org', scopes: ['openid', 'email'] });
    assert.equal(c.passkey_verified, true);
    assert.equal(c.email_verified, true);
    assert.deepEqual(c.verified_methods, ['email', 'passkey']);
    assert.equal(c.preferred_username, 'iamhmn_k3j9x0q2wz');
    assert.equal(c.email, 'anna@example.org');
  });
});

// ─── AK-5 (unit evidence): passkey auth binds to the credential's userId ────
describe('AK-5 (unit): resolvePasskeySession never yields a fresh/random id', () => {
  test('without a parked userId and without a prior session the result is exactly cred.userId', () => {
    const r = resolvePasskeySession({ storedUserId: null, cred: { userId: 'U-stable' }, prior: null });
    assert.equal(r.userId, 'U-stable');
    assert.deepEqual(r.priorMerge, {});
  });
  test('parked userId equal to cred.userId → same result, no error', () => {
    const r = resolvePasskeySession({ storedUserId: 'U-stable', cred: { userId: 'U-stable' }, prior: null });
    assert.equal(r.userId, 'U-stable');
    assert.equal(r.error, undefined);
  });
});

// ─── AK-22 / AK-25 / AK-26: verification mail ───────────────────────────────
describe('AK-22: code rendering', () => {
  test('a leading-zero code is rendered verbatim in html AND text (no number coercion, no grouping)', () => {
    const { html, text } = mail();
    assert.ok(html.includes('>012345<'), 'html code box contains 012345 as its own text node');
    assert.ok(!/012\s345/.test(html) && !/012\s345/.test(text), 'no grouped variant');
    assert.match(text, /\n\s*012345\s*\n/, 'text part shows the code on its own line');
  });
});

describe('AK-25: light hhttps.org design', () => {
  test('body background #F9F9F8, ink #0A0A0A, Inter/Syne stack with system fallback', () => {
    const { html } = mail();
    assert.match(html, /body\s*\{[^}]*background:#F9F9F8[^}]*color:#0A0A0A/);
    assert.match(html, /font-family:'Inter',system-ui,sans-serif/);
    assert.match(html, /font-family:'Syne',system-ui,sans-serif/);
  });
  test('code in JetBrains Mono with monospace fallback', () => {
    const { html } = mail();
    assert.match(html, /font-family:'JetBrains Mono',ui-monospace,monospace;[^>]*">012345</);
  });
  test('pill CTA: .btn is black with white text and border-radius:999px', () => {
    const { html } = mail();
    const btn = html.match(/\.btn\s*\{([^}]*)\}/);
    assert.ok(btn, '.btn rule exists');
    assert.match(btn[1], /background:#0A0A0A/);
    assert.match(btn[1], /color:#FFFFFF/i);
    assert.match(btn[1], /border-radius:999px/);
    assert.match(html, /<a href="https:\/\/x\/y" class="btn">/);
  });
  test('no cyan neon in any casing and no dark legacy shell colours', () => {
    const { html } = mail();
    assert.ok(!/#00e5ff/i.test(html), 'no #00e5ff');
    assert.ok(!html.includes('#04080f') && !html.includes('#070d18'), 'no dark shell background');
  });
});

describe('AK-26: truthful privacy note', () => {
  test('html AND text say the address is cached until passed on to the platform (EN + DE)', () => {
    const { html, text } = mail();
    for (const part of [html, text]) {
      assert.match(part, /until it has been passed on to the platform/);
      assert.match(part, /bis zur Übertragung an die Plattform/);
      assert.match(part, /up to 7 days|bis zu 7 Tage/);
      assert.ok(!/not stored|nicht gespeichert/i.test(part), 'no "not stored" claim');
    }
  });
});

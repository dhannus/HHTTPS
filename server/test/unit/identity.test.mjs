// Unit tests for identity.js (T1) — pure helpers, no DB/HTTP.
// Covers AK-2 (E-Mail-Normalisierung), AK-6/AK-7 (Pseudonym), AK-23/AK-24 (Code-Normalisierung), AK-18 (Methoden-Flags).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  normalizeEmail,
  emailAnchorHash,
  sanitizePseudonym,
  generatePseudonym,
  resolvePseudonym,
  normalizeCode,
  isValidCode,
  methodFlags,
  resolvePasskeySession,
} from '../../identity.js';

describe('normalizeEmail (AK-2)', () => {
  test('trims and lowercases', () => {
    assert.equal(normalizeEmail('  Anna.Muster@Example.COM \n'), 'anna.muster@example.com');
  });
  test('null/undefined → empty string', () => {
    assert.equal(normalizeEmail(null), '');
    assert.equal(normalizeEmail(undefined), '');
  });
  test('non-string input is coerced', () => {
    assert.equal(normalizeEmail(42), '42');
  });
});

describe('emailAnchorHash (D1, AK-2)', () => {
  test('is hex HMAC-SHA256(pepper, normalized email)', () => {
    const expected = crypto.createHmac('sha256', 'p1').update('anna@example.com').digest('hex');
    assert.equal(emailAnchorHash('Anna@Example.com', 'p1'), expected);
    assert.match(emailAnchorHash('x@y.z', 'p1'), /^[0-9a-f]{64}$/);
  });
  test('same email with different casing/whitespace → same hash', () => {
    assert.equal(emailAnchorHash(' ANNA@example.COM ', 'p1'), emailAnchorHash('anna@example.com', 'p1'));
  });
  test('different pepper → different hash', () => {
    assert.notEqual(emailAnchorHash('anna@example.com', 'p1'), emailAnchorHash('anna@example.com', 'p2'));
  });
  test('different emails → different hash', () => {
    assert.notEqual(emailAnchorHash('a@example.com', 'p1'), emailAnchorHash('b@example.com', 'p1'));
  });
  test('without pepper: warns once and falls back to dev-pepper', () => {
    const orig = console.warn;
    const calls = [];
    console.warn = (...a) => calls.push(a.join(' '));
    try {
      const expected = crypto.createHmac('sha256', 'dev-pepper').update('a@b.c').digest('hex');
      assert.equal(emailAnchorHash('a@b.c', undefined), expected);
      assert.equal(emailAnchorHash('a@b.c', ''), expected);
      assert.equal(emailAnchorHash('a@b.c', undefined), expected);
    } finally {
      console.warn = orig;
    }
    assert.equal(calls.length, 1, 'console.warn must be called exactly once');
    assert.match(calls[0], /HHTTPS_VERIFICATION_PEPPER/);
  });
});

describe('sanitizePseudonym (AK-6)', () => {
  test('keeps allowed charset, strips the rest', () => {
    assert.equal(sanitizePseudonym('Anna Müller-Ö.ß_1'), 'Anna Müller-Ö.ß_1');
    assert.equal(sanitizePseudonym('<script>Anna</script>'), 'scriptAnnascript');
    assert.equal(sanitizePseudonym('a@b!c#d'), 'abcd');
  });
  test('truncates to 32 chars and trims', () => {
    const long = 'x'.repeat(40);
    assert.equal(sanitizePseudonym(long), 'x'.repeat(32));
    assert.equal(sanitizePseudonym('  Anna  '), 'Anna');
  });
  test('empty after cleaning → null', () => {
    assert.equal(sanitizePseudonym('!!!'), null);
    assert.equal(sanitizePseudonym('   '), null);
    assert.equal(sanitizePseudonym(''), null);
  });
  test('null/undefined → null', () => {
    assert.equal(sanitizePseudonym(null), null);
    assert.equal(sanitizePseudonym(undefined), null);
  });
});

describe('generatePseudonym (AK-7)', () => {
  test('matches iamhmn_ + 10 × [a-z0-9]', () => {
    for (let i = 0; i < 100; i++) assert.match(generatePseudonym(), /^iamhmn_[a-z0-9]{10}$/);
  });
  test('100 calls yield distinct values', () => {
    const set = new Set(Array.from({ length: 100 }, () => generatePseudonym()));
    assert.equal(set.size, 100);
  });
});

describe('resolvePseudonym (AK-6/AK-7)', () => {
  test('uses sanitized input when non-empty', () => {
    assert.equal(resolvePseudonym('  Anna! '), 'Anna');
  });
  test('generates when input empty/null/only invalid chars', () => {
    assert.match(resolvePseudonym(null), /^iamhmn_[a-z0-9]{10}$/);
    assert.match(resolvePseudonym(''), /^iamhmn_[a-z0-9]{10}$/);
    assert.match(resolvePseudonym('###'), /^iamhmn_[a-z0-9]{10}$/);
  });
});

describe('normalizeCode / isValidCode (AK-23, AK-24)', () => {
  test('removes whitespace, tabs and hyphens', () => {
    assert.equal(normalizeCode('482 913'), '482913');
    assert.equal(normalizeCode(' 482913 '), '482913');
    assert.equal(normalizeCode('482-913'), '482913');
    assert.equal(normalizeCode('4\t8 2\n9-1 3'), '482913');
  });
  test('always returns a string', () => {
    assert.equal(normalizeCode(null), '');
    assert.equal(normalizeCode(undefined), '');
    assert.equal(normalizeCode(482913), '482913');
  });
  test('valid codes', () => {
    assert.equal(isValidCode('482 913'), true);
    assert.equal(isValidCode(' 482913 '), true);
    assert.equal(isValidCode('482-913'), true);
    assert.equal(isValidCode('482913'), true);
  });
  test('invalid codes', () => {
    assert.equal(isValidCode('48291'), false);
    assert.equal(isValidCode('4829133'), false);
    assert.equal(isValidCode('48291a'), false);
    assert.equal(isValidCode(''), false);
    assert.equal(isValidCode(null), false);
    assert.equal(isValidCode(undefined), false);
  });
});

describe('methodFlags (AK-18)', () => {
  test('maps method ids to booleans', () => {
    assert.deepEqual(methodFlags(['email', 'passkey']), {
      email_verified: true,
      passkey_verified: true,
      github_verified: false,
      eudi_verified: false,
    });
    assert.deepEqual(methodFlags(['github', 'eudi']), {
      email_verified: false,
      passkey_verified: false,
      github_verified: true,
      eudi_verified: true,
    });
  });
  test('ignores unknown ids (domain, age)', () => {
    assert.deepEqual(methodFlags(['domain', 'age', 'email']), {
      email_verified: true,
      passkey_verified: false,
      github_verified: false,
      eudi_verified: false,
    });
  });
  test('non-array → all false', () => {
    const allFalse = { email_verified: false, passkey_verified: false, github_verified: false, eudi_verified: false };
    assert.deepEqual(methodFlags(null), allFalse);
    assert.deepEqual(methodFlags(undefined), allFalse);
    assert.deepEqual(methodFlags('email'), allFalse);
    assert.deepEqual(methodFlags([]), allFalse);
  });
});

// F-2 (K-3/S-2): the passkey session is bound to the credential's userId, never
// to the caller-supplied userId from /webauthn/auth/start.
describe('resolvePasskeySession (F-2 / K-3)', () => {
  const cred = { userId: 'u-cred' };
  test('userId is always cred.userId', () => {
    const r = resolvePasskeySession({ storedUserId: null, cred, prior: null });
    assert.deepEqual(r, { userId: 'u-cred', priorMerge: {} });
    const r2 = resolvePasskeySession({ storedUserId: 'u-cred', cred, prior: null });
    assert.equal(r2.userId, 'u-cred');
  });
  test('stored (attacker) userId ≠ cred.userId → error credential_user_mismatch', () => {
    const r = resolvePasskeySession({ storedUserId: 'u-victim', cred, prior: null });
    assert.equal(r.error, 'credential_user_mismatch');
    assert.equal(r.userId, undefined);
  });
  test('prior session merges only when prior.userId === cred.userId', () => {
    const prior = { userId: 'u-cred', emailVerified: true, emailDomain: 'example.org', emailLevel: 'email-verified',
                    emailTrustBonus: 0, githubVerified: true, pseudonym: 'anna' };
    const r = resolvePasskeySession({ storedUserId: null, cred, prior });
    assert.deepEqual(r.priorMerge, {
      emailVerified: true, emailDomain: 'example.org', emailLevel: 'email-verified', emailTrustBonus: 0,
      githubVerified: true, pseudonym: 'anna',
    });
  });
  test('prior session of ANOTHER user is ignored (no merge, no error)', () => {
    const prior = { userId: 'u-other', emailVerified: true, emailDomain: 'x', pseudonym: 'mallory' };
    const r = resolvePasskeySession({ storedUserId: null, cred, prior });
    assert.deepEqual(r, { userId: 'u-cred', priorMerge: {} });
  });
  test('credential without userId → error', () => {
    assert.equal(resolvePasskeySession({ storedUserId: null, cred: {}, prior: null }).error, 'credential_user_mismatch');
  });
});

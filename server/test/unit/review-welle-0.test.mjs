// Review 2026-09, Welle 0 — unit tests for the S1 e-mail findings:
//   AP3-13: strict e-mail syntax (no comments / quotes / non-ASCII that the
//           mail transport and classifyDomain read differently)
//   AP3-02: classifyDomain matches on label boundaries only
import test from 'node:test';
import assert from 'node:assert/strict';
import { isValidEmail, normalizeEmail } from '../../identity.js';
import { classifyDomain } from '../../email.js';

test('AP3-13: isValidEmail accepts ordinary addresses', () => {
  for (const e of ['anna@example.org', 'a.b+tag@sub.example.co.uk', 'x_y-z@bundestag.de', "o'neil@example.org"]) {
    assert.equal(isValidEmail(normalizeEmail(e)), true, e);
  }
});

test('AP3-13: isValidEmail rejects comment / quote / bracket / non-ASCII forms', () => {
  for (const e of [
    'x@evil.com(bundestag.de', 'x@evil.com(.uni-', 'x@evil.com＠bundestag.de',
    '"x"@example.org', 'x@[127.0.0.1]', 'x@example', 'x@.example.org', 'x@example..org',
    'x@-example.org', '', ' ', 'x@exämple.de', 'a@b@c.de', 'x@example.org\n', null, undefined, 42,
    'a'.repeat(65) + '@example.org', 'x@' + 'a'.repeat(250) + '.de',
  ]) {
    assert.equal(isValidEmail(e), false, String(e));
  }
});

test('AP3-02: official / press / creative suffixes only match on label boundaries', () => {
  assert.equal(classifyDomain('a@bundestag.de').category, 'official');
  assert.equal(classifyDomain('a@mail.bundestag.de').category, 'official');
  assert.equal(classifyDomain('a@notbundestag.de').category, 'generic');
  assert.equal(classifyDomain('a@bundestag.de.evil.com').category, 'generic');
  assert.equal(classifyDomain('a@umwelt.de').category, 'generic');   // was press via 'welt.de'
  assert.equal(classifyDomain('a@welt.de').category, 'press');
  assert.equal(classifyDomain('a@xgema.de').category, 'generic');
});

test('AP3-02: university prefixes must start the registrable label under .de/.edu', () => {
  for (const d of ['uni-heidelberg.de', 'mail.uni-heidelberg.de', 'tu-berlin.de', 'student.tu-berlin.de', 'hs-x.de', 'fh-y.de', 'hochschule-z.de', 'kit.edu', 'lmu.de', 'x.tum.de']) {
    assert.equal(classifyDomain('a@' + d).category, 'university', d);
  }
  for (const d of ['a.uni-b.evil.com', 'hochschule-x.evil.com', 'uni-x.de.evil.com', 'evil-uni-x.de', 'x.tu-evil.com', 'kit.education']) {
    assert.equal(classifyDomain('a@' + d).category, 'generic', d);
  }
});

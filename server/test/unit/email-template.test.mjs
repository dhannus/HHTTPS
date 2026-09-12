// T2 / AK-22, AK-25, AK-26: the verification email renderer is a pure function.
// Importing email.js pulls in db.js; pg.Pool is created lazily so no DB is needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderVerificationEmail } from '../../email.js';

const input = {
  code: '482913',
  verifyUrl: 'https://x/y',
  role: 'citizen',
  classification: { domain: 'example.org', level: 'email-verified', trustBonus: 0, category: 'generic' },
};

test('renderVerificationEmail shows the raw 6-digit code without spaces (AK-22)', () => {
  const { html, text } = renderVerificationEmail(input);
  assert.ok(html.includes('482913'), 'html contains code');
  assert.ok(!html.includes('482 913'), 'html must not contain spaced code');
  assert.ok(text.includes('482913'), 'text contains code');
  assert.ok(!text.includes('482 913'), 'text must not contain spaced code');
});

test('renderVerificationEmail uses the light hhttps.org design (AK-25)', () => {
  const { html } = renderVerificationEmail(input);
  assert.ok(html.includes('#F9F9F8'), 'light background');
  assert.ok(html.includes('#0A0A0A'), 'ink color');
  assert.ok(html.includes('border-radius:999px'), 'pill button');
  assert.ok(html.includes('JetBrains Mono'), 'mono code font');
  assert.ok(!html.includes('#00e5ff'), 'no cyan neon');
  assert.ok(html.includes('https://x/y'), 'verify url present');
});

test('renderVerificationEmail privacy note no longer claims "not stored" (AK-26)', () => {
  const { html, subject } = renderVerificationEmail(input);
  assert.ok(!html.includes('not stored'));
  assert.ok(!html.includes('your email address is not stored'));
  assert.ok(subject.length > 0);
});

// F-5 (S-7): nothing caller-controlled reaches the mail unescaped.
test('renderVerificationEmail escapes an injected role label, domain and level (F-5 / S-7)', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const { html, subject } = renderVerificationEmail({
    code: '482913', verifyUrl: 'https://x/y', role: payload,
    classification: { domain: `${payload}.org`, level: `lvl${payload}`, trustBonus: 0, category: `cat${payload}` },
  });
  assert.ok(!html.includes(payload), 'html must not contain the raw payload');
  assert.ok(!subject.includes(payload), 'subject must not contain the raw payload');
  assert.ok(html.includes('&lt;img'), 'html contains the escaped label');
});

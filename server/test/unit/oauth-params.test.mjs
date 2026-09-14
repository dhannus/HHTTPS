// Unit tests for oauth-params.js (#31) — pure input validation for
// /hhttps/oauth/authorize and /hhttps/oauth/approve. No DB/HTTP.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  validateAuthorizeParams,
  STATE_MAX_LENGTH,
  CODE_CHALLENGE_MIN_LENGTH,
  CODE_CHALLENGE_MAX_LENGTH,
} from '../../oauth-params.js';

const ok = (p) => assert.deepEqual(validateAuthorizeParams(p), { ok: true });
const bad = (p, re) => {
  const r = validateAuthorizeParams(p);
  assert.equal(r.ok, false, `expected rejection for ${JSON.stringify(p).slice(0, 80)}`);
  assert.equal(r.error, 'invalid_request');
  assert.match(r.description, re);
};

describe('validateAuthorizeParams: state / nonce (#31)', () => {
  test('constants match the documented limits', () => {
    assert.equal(STATE_MAX_LENGTH, 2048);
    assert.equal(CODE_CHALLENGE_MIN_LENGTH, 43);
    assert.equal(CODE_CHALLENGE_MAX_LENGTH, 128);
  });
  test('empty / missing params are fine', () => {
    ok({});
    ok({ state: '', nonce: '', code_challenge: '', code_challenge_method: '' });
    ok({ state: undefined, nonce: null });
  });
  test('state of 1000 and 2048 chars is accepted (previously varchar(128) overflow)', () => {
    ok({ state: 'x'.repeat(1000) });
    ok({ state: 'x'.repeat(2048) });
  });
  test('state of 2049 chars is rejected', () => {
    bad({ state: 'x'.repeat(2049) }, /state.*2048/);
  });
  test('nonce: 2048 ok, 2049 rejected', () => {
    ok({ nonce: 'n'.repeat(2048) });
    bad({ nonce: 'n'.repeat(2049) }, /nonce.*2048/);
  });
  test('non-string state/nonce (array from repeated query params) is rejected', () => {
    bad({ state: ['a', 'b'] }, /state/);
    bad({ nonce: { x: 1 } }, /nonce/);
  });
});

describe('validateAuthorizeParams: PKCE (RFC 7636 §4.2)', () => {
  const c = (n) => 'a'.repeat(n);
  test('code_challenge length 43 and 128 accepted', () => {
    ok({ code_challenge: c(43) });
    ok({ code_challenge: c(128), code_challenge_method: 'S256' });
  });
  test('code_challenge length 42 and 129 rejected', () => {
    bad({ code_challenge: c(42) }, /code_challenge.*43.*128/);
    bad({ code_challenge: c(129) }, /code_challenge.*43.*128/);
  });
  test('code_challenge "abc" rejected', () => {
    bad({ code_challenge: 'abc' }, /code_challenge/);
  });
  test('code_challenge with characters outside [A-Za-z0-9._~-] rejected', () => {
    bad({ code_challenge: c(42) + '+' }, /code_challenge/);
    bad({ code_challenge: c(42) + '=' }, /code_challenge/);
    bad({ code_challenge: c(42) + ' ' }, /code_challenge/);
    bad({ code_challenge: c(42) + '/' }, /code_challenge/);
  });
  test('all allowed unreserved characters accepted', () => {
    ok({ code_challenge: 'ABCxyz019._~-' + c(30) });
  });
  test('code_challenge_method: S256 and plain accepted, default plain, others rejected', () => {
    ok({ code_challenge: c(43), code_challenge_method: 'S256' });
    ok({ code_challenge: c(43), code_challenge_method: 'plain' });
    ok({ code_challenge: c(43), code_challenge_method: undefined });
    bad({ code_challenge: c(43), code_challenge_method: 's256' }, /code_challenge_method/);
    bad({ code_challenge: c(43), code_challenge_method: 'SHA256' }, /code_challenge_method/);
    bad({ code_challenge: c(43), code_challenge_method: 'S512' }, /code_challenge_method/);
  });
  test('code_challenge_method without code_challenge is still validated', () => {
    bad({ code_challenge_method: 'foo' }, /code_challenge_method/);
    ok({ code_challenge_method: 'S256' });
  });
});

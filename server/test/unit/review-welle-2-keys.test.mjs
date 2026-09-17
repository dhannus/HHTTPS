// Review 2026-09, Welle 2 — keys.js in isolation (own key directory via
// HHTTPS_KEYS_DIR, so the server's ./keys is never touched):
//   AP1-09  verifyToken resolves the key by `kid`: a token signed before a
//           rotation still verifies, the JWKS publishes both keys, and a
//           forgotten retired key no longer verifies
//   AP1-03  verifyToken(token, { ignoreExpiration: true }) returns the payload
//           of an expired-but-authentic token; the algorithm stays pinned
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'hhttps-keys-'));
process.env.HHTTPS_KEYS_DIR = dir;
const keys = await import('../../keys.js');
const { loadOrCreateKeys, rotateKeys, forgetRetiredKey, signToken, verifyToken, getJWKS, getKid, getRetiredKids } = keys;

test.after(() => rmSync(dir, { recursive: true, force: true }));

test('AP1-09: a token signed before a rotation verifies via its retired kid; JWKS lists both', () => {
  loadOrCreateKeys();
  const oldKid = getKid();
  const before = signToken({ sub: 'human-verified', jti: 'j1' }, { expiresIn: 60 });
  const { oldKid: rotatedFrom, newKid } = rotateKeys();
  assert.equal(rotatedFrom, oldKid);
  assert.equal(getKid(), newKid);
  assert.deepEqual(getRetiredKids(), [oldKid]);

  assert.equal(verifyToken(before).jti, 'j1', 'pre-rotation token still verifies');
  const after = signToken({ sub: 'human-verified', jti: 'j2' }, { expiresIn: 60 });
  assert.equal(verifyToken(after).jti, 'j2');

  const jwks = getJWKS();
  assert.deepEqual(jwks.keys.map(k => k.kid), [newKid, oldKid]);
  for (const k of jwks.keys) { assert.equal(k.alg, 'ES256'); assert.equal(k.use, 'sig'); assert.equal(k.kty, 'EC'); assert.ok(!('d' in k), 'no private part'); }

  assert.equal(forgetRetiredKey(oldKid), true);
  assert.deepEqual(getRetiredKids(), []);
  assert.throws(() => verifyToken(before), /invalid signature/, 'unknown kid falls back to the active key and fails');
});

test('AP1-03: ignoreExpiration returns the authentic payload of an expired token; alg stays pinned', () => {
  loadOrCreateKeys();
  const now = Math.floor(Date.now() / 1000);
  const expired = signToken({ sub: 'text-signature', textHash: 'h', exp: now - 10 });
  assert.throws(() => verifyToken(expired), { name: 'TokenExpiredError' });
  const d = verifyToken(expired, { ignoreExpiration: true });
  assert.equal(d.sub, 'text-signature');
  assert.equal(d.exp, now - 10);
  // the options cannot widen the algorithm list
  assert.throws(() => verifyToken(expired + 'x', { ignoreExpiration: true, algorithms: ['none', 'HS256'] }));
  const tampered = expired.replace(/\.[^.]+$/, '.AAAA');
  assert.throws(() => verifyToken(tampered, { ignoreExpiration: true }));
});

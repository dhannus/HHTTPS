// Review 2026-09, Welle 2 — AP5 unit tests for server/pop-verify.js:
//   AP5-10  verifyPoP / jwkThumbprint / rawToDer have no tests
//   AP5-04  the nonce is consumed atomically (compare-and-delete, single statement)
//   AP5-05  the token is checked with checkTokenValid (revocation), not verifyToken
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyPoP, jwkThumbprint, rawToDer, consumeNonce } from '../../pop-verify.js';

const b64u = (b) => Buffer.from(b).toString('base64url');
const HTU = 'http://localhost/hhttps/pop/demo';

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  return { privateKey, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}

/** Compact ES256 JWS (raw R||S signature) as the PoP header carries it. */
function popJws({ privateKey, jwk }, claims, header = {}) {
  const h = b64u(JSON.stringify({ typ: 'wimse-pop+jwt', alg: 'ES256', jwk, ...header }));
  const c = b64u(JSON.stringify(claims));
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${c}`), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${h}.${c}.${b64u(sig)}`;
}

/** In-memory stand-in for db.q on the challenges table (one row). */
function fakeDb(row) {
  const state = { row, deletes: 0 };
  return {
    state,
    async q(sqlText, params) {
      assert.match(sqlText, /DELETE FROM challenges/);
      state.deletes++;
      const [id, nonce] = params;
      if (state.row && state.row.id === id && state.row.nonce === nonce && state.row.expires > Date.now()) {
        state.row = null;
        return { rowCount: 1 };
      }
      return { rowCount: 0 };
    }
  };
}

const now = () => Math.floor(Date.now() / 1000);

test('AP5-10: jwkThumbprint accepts only EC P-256 public keys (RSA → null) and is RFC 7638-canonical', () => {
  const { jwk } = keyPair();
  const t = jwkThumbprint(jwk);
  assert.match(t, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(jwkThumbprint({ ...jwk, extra: 'ignored', kid: 'x' }), t, 'only crv/kty/x/y count');
  const expected = crypto.createHash('sha256')
    .update(JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y })).digest('base64url');
  assert.equal(t, expected);
  assert.equal(jwkThumbprint({ kty: 'RSA', n: 'abc', e: 'AQAB' }), null);
  assert.equal(jwkThumbprint({ kty: 'EC', crv: 'P-384', x: 'a', y: 'b' }), null);
  assert.equal(jwkThumbprint(null), null);
  assert.equal(jwkThumbprint('string'), null);
});

test('AP5-10: rawToDer produces a DER ECDSA signature Node accepts', () => {
  const { privateKey, jwk } = keyPair();
  const data = Buffer.from('signing input');
  const raw = crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(raw.length, 64);
  const der = rawToDer(raw.subarray(0, 32), raw.subarray(32));
  assert.equal(der[0], 0x30);
  const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  assert.equal(crypto.verify('sha256', data, { key: pub, dsaEncoding: 'der' }, der), true);
  // a high-bit leading byte gets the 0x00 prefix (positive INTEGER)
  const r = Buffer.alloc(32, 0xff); const s = Buffer.alloc(32, 0x01);
  const d2 = rawToDer(r, s);
  assert.deepEqual([...d2.subarray(2, 5)], [0x02, 33, 0x00]);
});

test('AP5-10: verifyPoP happy path — bound key, valid signature, fresh nonce, matching htu/htm', async () => {
  const kp = keyPair();
  const jkt = jwkThumbprint(kp.jwk);
  const token = 'tok';
  const claims = { jti: 'j1', cnf: { jkt }, operatorId: 'op-1' };
  const db = fakeDb({ id: `pop:j1:${jkt}`, nonce: 'n1', expires: Date.now() + 60_000 });
  const pop = popJws(kp, { htu: HTU, htm: 'POST', nonce: 'n1', iat: now(), jti: 'p1' });
  const r = await verifyPoP({ popHeader: pop, token, checkTokenValid: async () => claims, db,
    expect: { htm: 'POST', htu: HTU } });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.jkt, jkt);
  assert.equal(r.claims.operatorId, 'op-1');
  assert.equal(db.state.row, null, 'nonce consumed');
});

test('AP5-04: the nonce is consumed by ONE compare-and-delete — a replay of the same proof fails', async () => {
  const kp = keyPair();
  const jkt = jwkThumbprint(kp.jwk);
  const claims = { jti: 'j2', cnf: { jkt } };
  const db = fakeDb({ id: `pop:j2:${jkt}`, nonce: 'n2', expires: Date.now() + 60_000 });
  const pop = popJws(kp, { htu: HTU, htm: 'POST', nonce: 'n2', iat: now(), jti: 'p2' });
  const args = { popHeader: pop, token: 't', checkTokenValid: async () => claims, db, expect: { htm: 'POST', htu: HTU } };
  const [a, b] = await Promise.all([verifyPoP(args), verifyPoP(args)]);
  assert.deepEqual([a.ok, b.ok].sort(), [false, true], 'exactly one of two concurrent proofs passes');
  assert.equal([a, b].find(x => !x.ok).error, 'nonce_mismatch');
  assert.equal(db.state.deletes, 2, 'no SELECT-then-DELETE: each attempt is one DELETE');
  // wrong nonce and an expired row are the same single statement
  assert.equal(await consumeNonce(fakeDb({ id: 'x', nonce: 'a', expires: Date.now() + 1000 }), 'x', 'b'), false);
  assert.equal(await consumeNonce(fakeDb({ id: 'x', nonce: 'a', expires: Date.now() - 1000 }), 'x', 'a'), false);
  assert.equal(await consumeNonce(fakeDb(null), 'x', undefined), false, 'missing nonce never queries as NULL');
});

test('AP5-05: verifyPoP uses checkTokenValid — a revoked (or inactive) token fails with token_invalid', async () => {
  const kp = keyPair();
  const jkt = jwkThumbprint(kp.jwk);
  const db = fakeDb({ id: `pop:j3:${jkt}`, nonce: 'n3', expires: Date.now() + 60_000 });
  const pop = popJws(kp, { htu: HTU, htm: 'POST', nonce: 'n3', iat: now(), jti: 'p3' });
  let verifyTokenCalls = 0;
  const r = await verifyPoP({ popHeader: pop, token: 't', db,
    verifyToken: () => { verifyTokenCalls++; return { jti: 'j3', cnf: { jkt } }; },
    checkTokenValid: async () => { throw new Error('Token revoked'); } });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'token_invalid');
  assert.equal(verifyTokenCalls, 0, 'the signature-only check is not consulted when checkTokenValid is given');
  assert.ok(db.state.row, 'the nonce is untouched');
});

test('AP5-10: verifyPoP rejects a foreign key, a bad signature, a wrong target and a stale proof', async () => {
  const kp = keyPair(); const other = keyPair();
  const jkt = jwkThumbprint(kp.jwk);
  const claims = { jti: 'j4', cnf: { jkt } };
  const mk = () => fakeDb({ id: `pop:j4:${jkt}`, nonce: 'n4', expires: Date.now() + 60_000 });
  const base = { token: 't', checkTokenValid: async () => claims, expect: { htm: 'POST', htu: HTU } };
  const good = { htu: HTU, htm: 'POST', nonce: 'n4', iat: now(), jti: 'p4' };

  assert.equal((await verifyPoP({ ...base, db: mk(), popHeader: undefined })).error, 'pop_missing');
  assert.equal((await verifyPoP({ ...base, db: mk(), popHeader: 'a.b' })).error, 'pop_malformed');
  assert.equal((await verifyPoP({ ...base, db: mk(), popHeader: popJws(other, good) })).error, 'jkt_mismatch');
  // header claims kp's key but is signed with the other private key
  const forged = popJws({ privateKey: other.privateKey, jwk: kp.jwk }, good);
  assert.equal((await verifyPoP({ ...base, db: mk(), popHeader: forged })).error, 'signature_invalid');
  assert.equal((await verifyPoP({ ...base, db: mk(), popHeader: popJws(kp, { ...good, htm: 'GET' }) })).error, 'htm_mismatch');
  assert.equal((await verifyPoP({ ...base, db: mk(), popHeader: popJws(kp, { ...good, iat: now() - 3600 }) })).error, 'stale');
  assert.equal((await verifyPoP({ ...base, db: mk(), checkTokenValid: async () => ({ jti: 'j4' }), popHeader: popJws(kp, good) })).error, 'token_not_bound');
});

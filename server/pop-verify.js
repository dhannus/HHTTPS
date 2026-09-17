// server/pop-verify.js
//
// Phase 5 — Proof-of-Possession (PoP) für HHTTPS-Maschinen-Token, serverseitig
// ERZWUNGEN. Der cnf.jkt-Claim (Phase 4) bindet einen Schlüssel ans Token;
// hier muss der Aufrufer beweisen, dass er den zugehörigen PRIVATE key hält —
// per frischer Signatur über eine servergestellte Challenge. Damit wird aus
// einem Bearer-Token (jeder mit dem Token) ein Holder-of-Key-Token (nur der
// Schlüsselinhaber). Mechanik = WIMSE / Web Bot Auth / DPoP-artig.
//
// Endpoints (mountPopVerify(app, deps)):
//   POST /hhttps/pop/challenge   { token }
//        → { challenge, expires_in }   (bindet die Nonce an jti+jkt des Tokens)
//   POST /hhttps/pop/demo        (geschützt: verlangt Bearer-Token + PoP-Header)
//        → { ok, operatorId, jkt }     Beispiel für einen PoP-gated Request.
//
// Der PoP-Beweis ist ein kompaktes JWS im Header  `HHTTPS-PoP: <jws>` mit
//   header : { typ:'wimse-pop+jwt', alg:'ES256', jwk:<presented public JWK> }
//   claims : { htu, htm, nonce, iat, jti }
// Verifikation (verifyPoP) macht GENAU vier Prüfungen:
//   (1) presented JWK  → thumbprint == token.cnf.jkt      (Bindung)
//   (2) JWS-Signatur mit genau diesem JWK gültig           (Besitz)
//   (3) nonce == die für (jti,jkt) ausgegebene Challenge   (Frische/Anti-Replay)
//   (4) htu/htm passen zum tatsächlichen Request           (Ziel-Bindung)
//
// Zero-PII, kein neues Schema: nutzt die vorhandene `challenges`-Tabelle.

import crypto from 'crypto';

// ── base64url helpers ────────────────────────────────────────────────────────
// AP5-45: Node's 'base64url' encoding does the character swap and the padding
// by itself — the hand-rolled replace() chains predate it.
function b64uDecode(s) {
  return Buffer.from(String(s), 'base64url');
}
function b64uEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

// AP5-44: the PoP timings, named instead of inlined.
export const POP_CHALLENGE_TTL_S = 120;    // how long an issued nonce is usable
export const POP_IAT_SKEW_S      = 300;    // accepted clock skew on the proof's iat

// RFC 7638 JWK thumbprint for an EC P-256 public JWK (base64url SHA-256).
function jwkThumbprint(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) return null;
  const canon = JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canon).digest('base64url');
}

// Build a Node public KeyObject from an EC P-256 JWK (for signature verify).
function ecPublicKeyFromJwk(jwk) {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

// Verify an ES256 JWS whose signature is raw R||S (JWS standard), against a JWK.
function verifyEs256Jws(signingInput, rawSigB64u, jwk) {
  const raw = b64uDecode(rawSigB64u);
  if (raw.length !== 64) return false;
  // Node's verify expects DER for ECDSA → wrap R||S into DER.
  const r = raw.subarray(0, 32), s = raw.subarray(32);
  const der = rawToDer(r, s);
  try {
    return crypto.verify('sha256', Buffer.from(signingInput),
      { key: ecPublicKeyFromJwk(jwk), dsaEncoding: 'der' }, der);
  } catch { return false; }
}

// Minimal ASN.1 DER encoder for an ECDSA signature (two INTEGERs).
function rawToDer(r, s) {
  const trim = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i);
    return (b[0] & 0x80) ? Buffer.concat([Buffer.from([0]), b]) : b; };
  const ri = trim(r), si = trim(s);
  const seqLen = 2 + ri.length + 2 + si.length;
  return Buffer.concat([
    Buffer.from([0x30, seqLen]),
    Buffer.from([0x02, ri.length]), ri,
    Buffer.from([0x02, si.length]), si
  ]);
}

// AP5-04: compare-and-delete in ONE statement. `get` + `delete` was a
// check-then-act — two requests with the same proof both saw the nonce and
// both passed. Only the request whose DELETE removed the row wins.
// (A db.challenges.consume() helper would be the cleaner home — db.js is
// outside this change; db.q is the module's parameterised query.)
async function consumeNonce(db, chId, nonce) {
  if (typeof nonce !== 'string' || !nonce) return false;
  const { rowCount } = await db.q(
    `DELETE FROM challenges
      WHERE challenge_id = $1 AND challenge = $2 AND expires_at > NOW()`,
    [chId, nonce]
  );
  return rowCount === 1;
}

/**
 * Verify a PoP proof for a given access token.
 * @returns {ok:true, jkt, claims} | {ok:false, error}
 */
async function verifyPoP({ popHeader, token, verifyToken, checkTokenValid, db, expect }) {
  if (!popHeader) return { ok: false, error: 'pop_missing' };
  // AP5-05: the full check (signature + exp + revocation + active row), so a
  // revoked machine token cannot pass the possession proof. `verifyToken`
  // (signature only) is kept as a fallback for callers without a DB check.
  const check = checkTokenValid || verifyToken;
  let decoded;
  try { decoded = await check(token); }
  catch { return { ok: false, error: 'token_invalid' }; }
  const boundJkt = decoded && decoded.cnf && decoded.cnf.jkt;
  if (!boundJkt) return { ok: false, error: 'token_not_bound' }; // no cnf → nothing to prove

  const parts = String(popHeader).split('.');
  if (parts.length !== 3) return { ok: false, error: 'pop_malformed' };
  let ph, pc;
  try {
    ph = JSON.parse(b64uDecode(parts[0]).toString('utf8'));
    pc = JSON.parse(b64uDecode(parts[1]).toString('utf8'));
  } catch { return { ok: false, error: 'pop_malformed' }; }

  if (ph.typ !== 'wimse-pop+jwt' || ph.alg !== 'ES256' || !ph.jwk) {
    return { ok: false, error: 'pop_bad_header' };
  }

  // (1) presented key binds to the token's cnf.jkt
  const presentedJkt = jwkThumbprint(ph.jwk);
  if (!presentedJkt || presentedJkt !== boundJkt) {
    return { ok: false, error: 'jkt_mismatch' };
  }
  // (2) signature valid with exactly that key
  if (!verifyEs256Jws(parts[0] + '.' + parts[1], parts[2], ph.jwk)) {
    return { ok: false, error: 'signature_invalid' };
  }
  // (3) nonce is the one we issued for this (jti,jkt), and still valid
  const chId = 'pop:' + decoded.jti + ':' + boundJkt;
  if (!(await consumeNonce(db, chId, pc.nonce))) {
    return { ok: false, error: 'nonce_mismatch' };
  }
  // (4) target binding
  if (expect) {
    if (expect.htm && pc.htm !== expect.htm) return { ok: false, error: 'htm_mismatch' };
    if (expect.htu && pc.htu !== expect.htu) return { ok: false, error: 'htu_mismatch' };
  }
  // freshness window on iat (±POP_IAT_SKEW_S)
  if (!pc.iat || Math.abs(Date.now() / 1000 - pc.iat) > POP_IAT_SKEW_S) {
    return { ok: false, error: 'stale' };
  }
  return { ok: true, jkt: boundJkt, claims: decoded };
}

// AP5-09: forward async rejections to the app's central error handler.
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export function mountPopVerify(app, deps) {
  const { db, verifyToken, checkTokenValid, BASE_URL } = deps;
  const check = checkTokenValid || verifyToken;

  // ── POST /hhttps/pop/challenge ─────────────────────────────────────────────
  app.post('/hhttps/pop/challenge', wrap(async (req, res) => {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });
    let decoded;
    try { decoded = await check(token); }                      // AP5-05
    catch { return res.status(401).json({ error: 'token_invalid' }); }
    const jkt = decoded && decoded.cnf && decoded.cnf.jkt;
    if (!jkt) return res.status(400).json({ error: 'token_not_bound',
      detail: 'This token carries no cnf.jkt — nothing to prove possession of.' });

    const nonce = b64uEncode(crypto.randomBytes(18));
    const chId  = 'pop:' + decoded.jti + ':' + jkt;
    await db.challenges.create(chId, nonce, decoded.operatorId || null, 'pop',
      POP_CHALLENGE_TTL_S * 1000);
    return res.json({ challenge: nonce, expires_in: POP_CHALLENGE_TTL_S,
      htu: `${BASE_URL}/hhttps/pop/demo`, htm: 'POST' });
  }));

  // ── POST /hhttps/pop/demo (PoP-gated example) ──────────────────────────────
  app.post('/hhttps/pop/demo', wrap(async (req, res) => {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body && req.body.token);
    if (!token) return res.status(401).json({ error: 'bearer_token_required' });

    const r = await verifyPoP({
      popHeader: req.headers['hhttps-pop'],
      token, verifyToken, checkTokenValid, db,
      expect: { htm: 'POST', htu: `${BASE_URL}/hhttps/pop/demo` }
    });
    if (!r.ok) return res.status(401).json({ error: 'pop_failed', reason: r.error });

    return res.json({
      ok: true,
      message: 'Proof-of-possession verified — holder controls the bound key.',
      operatorId: r.claims.operatorId || null,
      actorType:  r.claims.actorType || null,
      jkt: r.jkt
    });
  }));
}

export { verifyPoP, jwkThumbprint, rawToDer, consumeNonce };

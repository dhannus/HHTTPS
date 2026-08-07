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
function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function b64uEncode(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

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

/**
 * Verify a PoP proof for a given access token.
 * @returns {ok:true, jkt, claims} | {ok:false, error}
 */
async function verifyPoP({ popHeader, token, verifyToken, db, expect }) {
  if (!popHeader) return { ok: false, error: 'pop_missing' };
  let decoded;
  try { decoded = verifyToken(token); }
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
  const stored = await db.challenges.get(chId);
  if (!stored || stored.challenge !== pc.nonce) {
    return { ok: false, error: 'nonce_mismatch' };
  }
  await db.challenges.delete(chId); // single-use
  // (4) target binding
  if (expect) {
    if (expect.htm && pc.htm !== expect.htm) return { ok: false, error: 'htm_mismatch' };
    if (expect.htu && pc.htu !== expect.htu) return { ok: false, error: 'htu_mismatch' };
  }
  // freshness window on iat (±300s)
  if (!pc.iat || Math.abs(Date.now() / 1000 - pc.iat) > 300) {
    return { ok: false, error: 'stale' };
  }
  return { ok: true, jkt: boundJkt, claims: decoded };
}

export function mountPopVerify(app, deps) {
  const { db, verifyToken, RP_ID, BASE_URL } = deps;

  // ── POST /hhttps/pop/challenge ─────────────────────────────────────────────
  app.post('/hhttps/pop/challenge', async (req, res) => {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });
    let decoded;
    try { decoded = verifyToken(token); }
    catch { return res.status(401).json({ error: 'token_invalid' }); }
    const jkt = decoded && decoded.cnf && decoded.cnf.jkt;
    if (!jkt) return res.status(400).json({ error: 'token_not_bound',
      detail: 'This token carries no cnf.jkt — nothing to prove possession of.' });

    const nonce = b64uEncode(crypto.randomBytes(18));
    const chId  = 'pop:' + decoded.jti + ':' + jkt;
    await db.challenges.create(chId, nonce, decoded.operatorId || null, 'pop', 120_000);
    return res.json({ challenge: nonce, expires_in: 120,
      htu: `${BASE_URL}/hhttps/pop/demo`, htm: 'POST' });
  });

  // ── POST /hhttps/pop/demo (PoP-gated example) ──────────────────────────────
  app.post('/hhttps/pop/demo', async (req, res) => {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body && req.body.token);
    if (!token) return res.status(401).json({ error: 'bearer_token_required' });

    const r = await verifyPoP({
      popHeader: req.headers['hhttps-pop'],
      token, verifyToken, db,
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
  });
}

export { verifyPoP, jwkThumbprint };

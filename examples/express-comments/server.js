/**
 * Example: Comment system protected by HHTTPS
 *
 * Demonstrates:
 *   - Reading HHTTPS tokens from headers
 *   - Validating via JWKS (no API call!)
 *   - Trust-score thresholds
 *   - Role-based permissions
 *   - Optional verification (anonymous + verified comments)
 *
 * Run:
 *   npm install express jsonwebtoken jwks-rsa
 *   node server.js
 *
 * Test:
 *   curl -X POST http://localhost:4000/comment \
 *     -H 'Content-Type: application/json' \
 *     -H 'HHTTPS-Token: <your-token>' \
 *     -d '{"text":"hello world"}'
 */

import express     from 'express';
import jwt         from 'jsonwebtoken';
import jwksClient  from 'jwks-rsa';

const app = express();
app.use(express.json());

// ─── HHTTPS verification setup ──────────────────────────────────────────────
const ISSUER_BASE = 'https://hhttps.org';
const jwks = jwksClient({
  jwksUri:      `${ISSUER_BASE}/.well-known/jwks.json`,
  cache:        true,
  cacheMaxAge:  60 * 60_000,  // 1 hour
  rateLimit:    true
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

/**
 * Verify HHTTPS token. Returns decoded payload or null.
 * Set `required: true` to reject unauthenticated requests.
 */
function hhttps({ required = false, minTrust = 0, allowedRoles = null } = {}) {
  return (req, res, next) => {
    const token = req.headers['hhttps-token'] ||
                  req.headers.authorization?.replace(/^Bearer\s+/, '');

    if (!token) {
      if (required) return res.status(401).json({ error: 'HHTTPS token required' });
      req.hhttps = { verified: false };
      return next();
    }

    jwt.verify(token, getKey, { algorithms: ['ES256'] }, (err, decoded) => {
      if (err) {
        if (required) return res.status(401).json({ error: 'invalid token: ' + err.message });
        req.hhttps = { verified: false };
        return next();
      }
      if (decoded.trustScore < minTrust) {
        return res.status(403).json({ error: `trust score too low (need ${minTrust})` });
      }
      if (allowedRoles && !allowedRoles.includes(decoded.role)) {
        return res.status(403).json({ error: `role '${decoded.role}' not allowed` });
      }
      req.hhttps = { verified: true, ...decoded };
      next();
    });
  };
}

// ─── Demo data store ────────────────────────────────────────────────────────
const comments = [];

// ─── Routes ─────────────────────────────────────────────────────────────────

// Public: anyone can read comments
app.get('/comments', (req, res) => {
  res.json({ comments });
});

// Optional verification: comments work for anyone, but verified humans get a badge
app.post('/comment', hhttps({ required: false, minTrust: 60 }), (req, res) => {
  const { text } = req.body;
  if (!text || text.length < 1 || text.length > 2000) {
    return res.status(400).json({ error: 'text required (1–2000 chars)' });
  }

  const comment = {
    id: comments.length + 1,
    text,
    createdAt: new Date().toISOString(),
    author: req.hhttps.verified
      ? {
          verified:   true,
          role:       req.hhttps.role,
          trustScore: req.hhttps.trustScore,
          method:     req.hhttps.method
        }
      : { verified: false, role: 'anonymous' }
  };

  comments.push(comment);
  res.status(201).json(comment);
});

// Verified-only: comments here require human verification (trust ≥ 60)
app.post('/comment/verified-only',
  hhttps({ required: true, minTrust: 60 }),
  (req, res) => {
    comments.push({
      id: comments.length + 1,
      text: req.body.text,
      createdAt: new Date().toISOString(),
      author: { verified: true, role: req.hhttps.role, trustScore: req.hhttps.trustScore }
    });
    res.status(201).json({ ok: true });
  }
);

// Role-restricted: only journalists may post here
app.post('/article',
  hhttps({ required: true, minTrust: 80, allowedRoles: ['journalist'] }),
  (req, res) => {
    res.status(201).json({
      ok: true,
      message: 'Article submitted by verified journalist',
      author: req.hhttps.role
    });
  }
);

// High-trust example: medical advice requires approbierter Arzt (trust ≥ 90)
app.post('/medical-advice',
  hhttps({ required: true, minTrust: 90, allowedRoles: ['medical_professional'] }),
  (req, res) => {
    res.status(201).json({
      ok: true,
      message: 'Medical advice submitted — verified doctor, trust ≥ 90',
      verifiedAs: req.hhttps.roleLevel
    });
  }
);

// ─── Start ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`HHTTPS comment example running on http://localhost:${PORT}`);
  console.log(`Trust ≥ 60 needed for verified comments`);
  console.log(`Trust ≥ 90 + role 'medical_professional' for /medical-advice`);
});

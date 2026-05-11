# HHTTPS Integration Guide

How to integrate HHTTPS into your application — from a simple "verified humans get a badge" comment section to full role-based access control for medical, legal, or government applications.

## TL;DR

To verify HHTTPS tokens in your app, you need:

1. **The public JWKS** at `https://hhttps.org/.well-known/jwks.json` (cached for 1 hour)
2. **A JWT library** for ES256 signature verification (any standard JWT library)
3. **Three lines of code** in your request handler

You do **not** need an API key, an account with us, or a contract. Token verification is fully decentralized via JWKS.

## Levels of Integration

### Level 0: Display the badge

The simplest integration: just look at the `HHTTPS-Status` header on every response and show a verification icon if the user is human-verified.

```js
// Client-side, after any fetch:
const status = response.headers.get('HHTTPS-Status');
const human  = response.headers.get('HHTTPS-Human');
if (status === 'verified' && human === 'true') {
  showVerifiedBadge();
}
```

This requires **zero server-side changes** — the HHTTPS extension or any HHTTPS-aware client adds the headers automatically.

### Level 1: Read tokens passed by clients

When a user is authenticated with HHTTPS, your server receives the `HHTTPS-Token` header. Just decode the JWT and read its claims.

```js
const token   = req.headers['hhttps-token'];
const decoded = jwt.decode(token);  // No verification yet, just inspection
console.log(decoded.role, decoded.trustScore);
```

This is enough for displaying things like "Verified by [HHTTPS](https://hhttps.org)" on user comments. **But for any access control, you must verify the signature** (Level 2).

### Level 2: Cryptographically verify tokens

Use any JWT library with the public JWKS to verify ES256 signatures.

#### Node.js / Express

```js
import jwt        from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const jwks = jwksClient({
  jwksUri:     'https://hhttps.org/.well-known/jwks.json',
  cache:       true,
  cacheMaxAge: 3600 * 1000
});

function getKey(header, cb) {
  jwks.getSigningKey(header.kid, (e, k) => cb(e, k?.getPublicKey()));
}

app.use((req, res, next) => {
  const token = req.headers['hhttps-token'];
  if (!token) { req.hhttps = null; return next(); }

  jwt.verify(token, getKey, { algorithms: ['ES256'] }, (err, decoded) => {
    req.hhttps = err ? null : decoded;
    next();
  });
});
```

See `examples/express-comments/server.js` for a complete working example.

#### Python / Flask / Django

```python
import jwt
import requests

ISSUER  = 'https://hhttps.org'
JWKS    = requests.get(f'{ISSUER}/.well-known/jwks.json').json()

def verify(token):
    header = jwt.get_unverified_header(token)
    for k in JWKS['keys']:
        if k['kid'] == header['kid']:
            key = jwt.algorithms.ECAlgorithm.from_jwk(k)
            return jwt.decode(token, key=key, algorithms=['ES256'])
    raise ValueError('unknown kid')
```

Production code should cache the JWKS for an hour. See `examples/flask-petition/app.py` and `examples/django-medical/views.py`.

#### PHP / Laravel

```php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

$jwks    = json_decode(file_get_contents('https://hhttps.org/.well-known/jwks.json'), true);
$keys    = JWK::parseKeySet($jwks);
$decoded = JWT::decode($token, $keys);
```

See `examples/laravel-school/HHTPPSMiddleware.php` for a complete middleware.

#### Other languages

HHTTPS uses standard ES256 JWTs. Any JWT library that supports `ES256` and JWKS lookup will work. Notable ones:

- **Go**: `github.com/lestrrat-go/jwx`
- **Rust**: `jsonwebtoken` crate
- **Ruby**: `ruby-jwt` gem with JWKS extension
- **Java**: `auth0/java-jwt` with JWKS provider
- **C#**: `Microsoft.IdentityModel.Tokens`

### Level 3: Trust-score gating

Once you can verify tokens, use the `trustScore` claim to gate sensitive actions:

| Trust threshold | Use case |
|---|---|
| **0–30**   | Comments, surveys, low-stakes content |
| **60+**    | "Verified human" badge — most public sites |
| **70+**    | Account creation requiring email validation |
| **80+**    | Press articles, scientific publications |
| **85+**    | Professional-only forums (lawyers, doctors) |
| **90+**    | Medical advice, legal advice, government communication |
| **95+**    | Notarization-equivalent, high-value transactions |
| **98**     | Bundestag-verified politicians (highest tier) |

```js
function requireMinTrust(threshold) {
  return (req, res, next) => {
    if (!req.hhttps?.trustScore) return res.status(401).send();
    if (req.hhttps.trustScore < threshold) return res.status(403).send();
    next();
  };
}

app.post('/medical-question', requireMinTrust(90), handler);
```

### Level 4: Role-based access

The 15 HHTTPS roles let you restrict actions by societal role:

```js
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.hhttps?.role) return res.status(401).send();
    if (!allowedRoles.includes(req.hhttps.role)) return res.status(403).send();
    next();
  };
}

app.post('/answer-medical', requireRole('medical_professional'),     handler);
app.post('/answer-legal',   requireRole('lawyer'),                   handler);
app.post('/post-article',   requireRole('journalist', 'researcher'), handler);
```

Combine with `trustScore` for layered authorization:

```js
app.post('/medical-advice',
  requireRole('medical_professional'),
  requireMinTrust(90),
  handler
);
```

## Issuer Discovery

If your application supports multiple HHTTPS issuers (federation), use the `iss` claim and the `.well-known/hhttps-configuration` endpoint:

```js
async function getJWKSFor(issuerUrl) {
  const config = await fetch(`${issuerUrl}/.well-known/hhttps-configuration`).then(r => r.json());
  const jwks   = await fetch(config.jwks_uri).then(r => r.json());
  return jwks;
}

// In your verify handler:
const decoded = jwt.decode(token);
const jwks    = await getJWKSFor(decoded.iss.replace('hhttps://', 'https://'));
// ... verify against jwks
```

For now, only `hhttps.org` is a known production issuer. Federation (multiple cooperating issuers) is planned for v0.6.

## Common Patterns

### "Verified comments" pattern

Allow anonymous comments, but show a verification badge for HHTTPS users:

```js
app.post('/comment', hhttps({ required: false }), (req, res) => {
  comments.push({
    text:   req.body.text,
    author: req.hhttps?.verified
      ? { verified: true, role: req.hhttps.role }
      : { verified: false }
  });
  res.send();
});
```

### "Real names not required" pattern

Most use cases don't need real names. The role + trust score is enough:

> "Asked by a verified Lawyer (trust 92) — *Sarah K., 14 minutes ago*"

The display name "Sarah K." is **app-level state**, chosen by the user when they signed up to your platform. HHTTPS proves only that the human behind the action has the role they claim. The two are orthogonal.

### "Higher trust unlocks features" pattern

Tier features by trust threshold:

```js
function getFeatures(hhttps) {
  if (!hhttps) return ['read'];
  if (hhttps.trustScore >= 60) return ['read', 'comment'];
  if (hhttps.trustScore >= 80) return ['read', 'comment', 'post', 'edit'];
  if (hhttps.trustScore >= 90) return ['read', 'comment', 'post', 'edit', 'moderate'];
  return ['read'];
}
```

## Frontend Integration

When your backend issues HHTTPS-aware responses, set headers in the response:

```js
res.setHeader('HHTTPS-Status',     'verified');
res.setHeader('HHTTPS-Human',      'true');
res.setHeader('HHTTPS-Role',       req.hhttps.role);
res.setHeader('HHTTPS-Trust-Score', String(req.hhttps.trustScore));
res.setHeader('HHTTPS-Issuer',      req.hhttps.iss);
```

The HHTTPS browser extension reads these and displays the verification status. Without setting these, your app still works perfectly — just no extension UI.

## Testing

Get a test token:

```bash
# 1. Register a passkey at https://hhttps.org
# 2. Declare a role
# 3. Copy the token from your browser's HHTTPS extension popup

curl http://localhost:4000/comment \
  -H 'Content-Type: application/json' \
  -H "HHTTPS-Token: $TOKEN" \
  -d '{"text": "Hello from a verified human"}'
```

Or use the demo machine token operator at `/hhttps/machine/register` (for non-human-but-trusted automation).

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| "JWKS unreachable" | Network or firewall | Cache JWKS; serve stale during outages |
| `kid not found` | Issuer rotated keys | Refresh JWKS cache; HHTTPS publishes both old + new for grace period |
| Tokens expire too fast | `exp` is 1h by default | Use refresh tokens; `/hhttps/token/refresh` returns new access tokens |
| Token works locally but not in prod | Clock skew | Allow 30 sec leeway in `jwt.verify({ clockTolerance: 30 })` |
| `403 trust too low` | User has only baseline (60) | Lower your threshold or guide users to upgrade verification |

## Performance

JWKS verification is **fast** and **local**:

- Once JWKS is cached, verification is just an EC signature check (~0.1ms)
- No network call per request
- Scales linearly: 100k token verifications/sec on commodity hardware
- No central rate limit — only the issuer is rate-limited (and only for token issuance, not verification)

## Next Steps

- Read the [full specification](https://hhttps.org/spec)
- Browse working examples in [`examples/`](../examples/)
- Run a local issuer for testing: `cd server && npm start`
- Read about security considerations in [`security.md`](security.md)

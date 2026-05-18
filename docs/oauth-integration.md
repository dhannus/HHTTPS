# Integrating HHTTPS in your platform

This guide walks you through adding "Login with HHTTPS" to your existing application. Estimated time: 10-30 minutes depending on stack.

---

## What you'll get

After integration, your platform will be able to:

- Log users in with one click — no usernames, no passwords, no email verification
- Know each user's verified role (e.g. `developer`, `medical_professional`, `journalist`) and trust score
- Receive a stable pseudonymous identifier per user that's different from every other platform's identifier for the same person
- Optionally request the verification method used (e.g. `passkey`, `orcid`, `github-org`, `official-id`)

What your platform will **not** get:

- Real name, email, phone number, or any PII
- IP address or geolocation
- Cross-platform identity correlation
- Anything that could be used to deanonymize users

---

## Registration: get a `client_id`

Before your platform can use HHTTPS, it needs to be registered as an OAuth client.

### Phase 3a (current, May 2026): manual registration

Currently, client registration is manual. Send an email to [info@iamhmn.org](mailto:info@iamhmn.org) with:

- Your platform's name
- Homepage URL
- Redirect URI(s) where the OAuth callback will land
- A short description
- Whether you want `verified` status (requires Impressum + admin review)

You'll receive a `client_id` (e.g. `your-platform`).

### Phase 3b (Q3 2026): self-service registration

Self-service registration will be available at `hhttps.org/developers`. Process:

1. Sign up with your HHTTPS identity
2. Fill in platform details
3. Receive a verification email (double opt-in)
4. Platform is immediately usable as `unverified`
5. Optionally request `verified` status — admin reviews within 7 days

Unverified platforms can still use HHTTPS — they just appear with an amber warning on the consent page. This is deliberate: low barrier to entry, transparent risk signal for users.

---

## The OAuth flow

HHTTPS implements standard OAuth 2.0 authorization code flow with PKCE. If you've ever integrated "Sign in with Google" or "Sign in with GitHub", this is the same pattern.

```
┌──────────────┐                                            ┌──────────────┐
│   Browser    │                                            │ Your Server  │
└──────┬───────┘                                            └──────┬───────┘
       │                                                            │
       │ 1. Click "Login with HHTTPS"                               │
       │ ─────────────────────────────────────────────────────────> │
       │                                                            │
       │ 2. Redirect to hhttps.org/oauth/authorize?...              │
       │ <───────────────────────────────────────────────────────── │
       │                                                            │
       │ 3. User authorizes on hhttps.org                           │
       │  (consent screen, click "Allow")                           │
       │                                                            │
       │ 4. Redirect back to your_site/auth/callback?code=...        │
       │ ─────────────────────────────────────────────────────────> │
       │                                                            │
       │                                  5. POST /oauth/token      │
       │                                  (server-to-server)        │
       │                                  ──> hhttps.org            │
       │                                                            │
       │                                  6. Receive id_token       │
       │                                  + access_token             │
       │                                  <──                       │
       │                                                            │
       │ 7. User is logged in. Done.                                │
       │ <───────────────────────────────────────────────────────── │
```

---

## Discovery endpoint

To configure your OAuth library, point it at:

```
https://hhttps.org/.well-known/openid-configuration
```

Most OAuth client libraries (Passport.js, Authlib, etc.) can ingest this and auto-configure all endpoints.

The discovery document tells you the exact URLs of authorize, token, userinfo, JWKS endpoints, supported scopes, etc.

---

## Scopes available

| Scope | Required | What you get |
|---|---|---|
| `openid` | yes | pseudonymous `sub` (stable per platform), `iss`, `aud`, standard JWT timestamps |
| `role` | no | `role`, `role_label`, `role_icon`, `trust_score` |
| `verification_method` | no | `verification_method`, `verification_method_label` |

Request only what you actually need. Users see the requested scopes on the consent screen — asking for too much reduces approval rate.

---

## Example: Node.js / Express

Minimal working example using the standard OAuth flow. Adapt to your framework.

### Server setup

```javascript
import express from 'express';
import session from 'express-session';
import crypto from 'crypto';

const app = express();
const HHTTPS_BASE = 'https://hhttps.org';
const CLIENT_ID = 'your-platform';
const CLIENT_SECRET = '';  // empty = public client + PKCE
const BASE_URL = 'https://yoursite.com';

app.use(session({ secret: 'change-me', resave: false, saveUninitialized: false }));

// 1. The "Login with HHTTPS" button hits this endpoint
app.get('/login', (req, res) => {
  // Generate PKCE
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = crypto.randomBytes(16).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');

  req.session.pkceVerifier = verifier;
  req.session.oauthState = state;
  req.session.oauthNonce = nonce;

  const params = new URLSearchParams({
    response_type:         'code',
    client_id:             CLIENT_ID,
    redirect_uri:          `${BASE_URL}/auth/callback`,
    scope:                 'openid role',
    state,
    nonce,
    code_challenge:        challenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`${HHTTPS_BASE}/hhttps/oauth/authorize?${params}`);
});

// 2. HHTTPS redirects back here after user consent
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.status(400).send(`OAuth error: ${error}`);
  if (state !== req.session.oauthState) {
    return res.status(400).send('State mismatch (possible CSRF)');
  }

  // Exchange code for tokens (server-to-server)
  const tokenRes = await fetch(`${HHTTPS_BASE}/hhttps/oauth/token`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type:    'authorization_code',
      code,
      redirect_uri:  `${BASE_URL}/auth/callback`,
      client_id:     CLIENT_ID,
      code_verifier: req.session.pkceVerifier
    })
  });
  const tokens = await tokenRes.json();

  // Decode the id_token (a JWT)
  const idTokenPayload = JSON.parse(
    Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString()
  );

  // Verify nonce
  if (idTokenPayload.nonce !== req.session.oauthNonce) {
    return res.status(401).send('Nonce mismatch');
  }

  // The pseudonymous user ID is `sub`. Store in session.
  req.session.userId = idTokenPayload.sub;
  req.session.userRole = idTokenPayload.role;
  req.session.userTrust = idTokenPayload.trust_score;

  res.redirect('/');
});

// 3. Now your routes can check req.session.userId
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.send(`Hello ${req.session.userRole} (trust: ${req.session.userTrust})!`);
  } else {
    res.send('<a href="/login">Login with HHTTPS</a>');
  }
});

app.listen(3000);
```

### HTML login button

```html
<a href="/login" class="hhttps-login-button">
  <svg width="20" height="20"><!-- HHTTPS logo SVG --></svg>
  Login with HHTTPS
</a>
```

Standard CSS for the button (matching HHTTPS branding):

```css
.hhttps-login-button {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 18px;
  background: #2D2823;
  color: #FCFAF5;
  border-radius: 100px;
  font-family: system-ui, sans-serif;
  font-size: 14px;
  font-weight: 500;
  text-decoration: none;
  transition: background 0.2s;
}
.hhttps-login-button:hover {
  background: #A86246;
}
```

---

## Example: Python / Flask

```python
from flask import Flask, redirect, request, session, url_for
import requests, secrets, hashlib, base64, json

app = Flask(__name__)
app.secret_key = 'change-me'

HHTTPS_BASE = 'https://hhttps.org'
CLIENT_ID = 'your-platform'
BASE_URL = 'https://yoursite.com'


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


@app.route('/login')
def login():
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = b64url(secrets.token_bytes(16))
    nonce = b64url(secrets.token_bytes(16))

    session['pkce_verifier'] = verifier
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce

    params = {
        'response_type':         'code',
        'client_id':             CLIENT_ID,
        'redirect_uri':          f'{BASE_URL}/auth/callback',
        'scope':                 'openid role',
        'state':                 state,
        'nonce':                 nonce,
        'code_challenge':        challenge,
        'code_challenge_method': 'S256'
    }
    return redirect(f'{HHTTPS_BASE}/hhttps/oauth/authorize?{requests.compat.urlencode(params)}')


@app.route('/auth/callback')
def callback():
    if request.args.get('state') != session.get('oauth_state'):
        return 'State mismatch', 400

    code = request.args.get('code')
    if not code:
        return 'No code', 400

    r = requests.post(f'{HHTTPS_BASE}/hhttps/oauth/token', json={
        'grant_type':    'authorization_code',
        'code':          code,
        'redirect_uri':  f'{BASE_URL}/auth/callback',
        'client_id':     CLIENT_ID,
        'code_verifier': session['pkce_verifier']
    })
    tokens = r.json()

    # Decode id_token payload
    payload_b64 = tokens['id_token'].split('.')[1]
    payload_b64 += '=' * (4 - len(payload_b64) % 4)  # pad
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

    if payload['nonce'] != session['oauth_nonce']:
        return 'Nonce mismatch', 401

    session['user_id'] = payload['sub']
    session['user_role'] = payload.get('role', 'citizen')
    session['user_trust'] = payload.get('trust_score', 30)

    return redirect('/')


@app.route('/')
def index():
    if 'user_id' in session:
        return f"Hello {session['user_role']} (trust: {session['user_trust']})"
    return '<a href="/login">Login with HHTTPS</a>'
```

---

## Example: Plain PHP

```php
<?php
session_start();

const HHTTPS_BASE = 'https://hhttps.org';
const CLIENT_ID   = 'your-platform';
const BASE_URL    = 'https://yoursite.com';

function b64url($bytes) {
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

if ($_SERVER['REQUEST_URI'] === '/login') {
    $verifier  = b64url(random_bytes(32));
    $challenge = b64url(hash('sha256', $verifier, true));
    $state     = b64url(random_bytes(16));
    $nonce     = b64url(random_bytes(16));

    $_SESSION['pkce_verifier'] = $verifier;
    $_SESSION['oauth_state']   = $state;
    $_SESSION['oauth_nonce']   = $nonce;

    $params = http_build_query([
        'response_type'         => 'code',
        'client_id'             => CLIENT_ID,
        'redirect_uri'          => BASE_URL . '/auth/callback',
        'scope'                 => 'openid role',
        'state'                 => $state,
        'nonce'                 => $nonce,
        'code_challenge'        => $challenge,
        'code_challenge_method' => 'S256'
    ]);
    header('Location: ' . HHTTPS_BASE . '/hhttps/oauth/authorize?' . $params);
    exit;
}

if (str_starts_with($_SERVER['REQUEST_URI'], '/auth/callback')) {
    parse_str($_SERVER['QUERY_STRING'], $q);

    if ($q['state'] !== $_SESSION['oauth_state']) {
        http_response_code(400);
        exit('State mismatch');
    }

    $ch = curl_init(HHTTPS_BASE . '/hhttps/oauth/token');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS     => json_encode([
            'grant_type'    => 'authorization_code',
            'code'          => $q['code'],
            'redirect_uri'  => BASE_URL . '/auth/callback',
            'client_id'     => CLIENT_ID,
            'code_verifier' => $_SESSION['pkce_verifier']
        ])
    ]);
    $resp = json_decode(curl_exec($ch), true);

    $idPayload = json_decode(base64_decode(strtr(
        explode('.', $resp['id_token'])[1], '-_', '+/'
    )), true);

    if ($idPayload['nonce'] !== $_SESSION['oauth_nonce']) {
        http_response_code(401);
        exit('Nonce mismatch');
    }

    $_SESSION['user_id']    = $idPayload['sub'];
    $_SESSION['user_role']  = $idPayload['role'] ?? 'citizen';
    $_SESSION['user_trust'] = $idPayload['trust_score'] ?? 30;

    header('Location: /');
    exit;
}

if (isset($_SESSION['user_id'])) {
    echo "Hello {$_SESSION['user_role']} (trust: {$_SESSION['user_trust']})";
} else {
    echo '<a href="/login">Login with HHTTPS</a>';
}
```

---

## Best practices

### Verify the JWT signature

The examples above decode the `id_token` payload without verifying its signature. **For production, you must verify the signature.**

Fetch the issuer's JWKS:

```
GET https://hhttps.org/.well-known/jwks.json
```

Then use any JWT library that supports ES256 to verify the token. In Node.js with the `jose` library:

```javascript
import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://hhttps.org/.well-known/jwks.json'));

const { payload } = await jwtVerify(idToken, JWKS, {
  issuer: 'https://hhttps.org',
  audience: CLIENT_ID
});
```

### Store the pairwise subject ID as your user identifier

Don't try to use email or real name as the primary key — you won't get any. Use the `sub` claim from the id_token. It's stable for your platform but different on every other platform.

### Cache `userinfo` responses

If you call `GET /hhttps/oauth/userinfo` to refresh role/trust data, cache the result for at least 5 minutes. The data doesn't change frequently.

### Handle role changes

A user's role and trust score can change between logins (e.g. their ORCID verification expires, they add a new verification method). On every successful login, update the cached values for that user in your database.

### Don't request scopes you don't need

If your platform only needs to know "this is a real human", request just `openid`. If you need the role, add `role`. Asking for `verification_method` when you don't use it lowers trust and approval rates.

---

## Troubleshooting

**"invalid_redirect_uri"**
Your redirect URI doesn't match the one registered for your `client_id`. The match is exact — `https://yoursite.com/auth/callback` is different from `https://yoursite.com/auth/callback/`.

**"invalid_grant"**
The authorization code has been used already, has expired (60-second TTL), or your PKCE verifier doesn't match the challenge. Don't try to reuse codes.

**"State mismatch"**
The user's session was lost between starting the login and the callback. Common causes: session cookie not persisted, opening the callback in a different browser, attempting cross-domain session sharing.

**Empty user info**
You requested only `openid`. To get role info, add `role` to your scope parameter.

**User keeps seeing "Unverified platform" warning**
Your client is not yet verified. Email [info@iamhmn.org](mailto:info@iamhmn.org) with your domain proof and Impressum to request verification.

---

## Need help?

- **Specifications**: [`protocol/`](../docs/protocol/)
- **Reference implementation**: [`examples/express-login/`](../examples/express-login/)
- **GitHub Discussions**: [github.com/dhannus/HumanProof/discussions](https://github.com/dhannus/HumanProof/discussions)
- **Email**: [info@iamhmn.org](mailto:info@iamhmn.org)

# HHTTPS Security Considerations

This document describes the threat model, security guarantees, and known limitations of the HHTTPS protocol (v0.4.1).

## Threat Model

### What HHTTPS protects against

| Threat | Protection |
|---|---|
| **AI bots impersonating humans** | WebAuthn requires a hardware key + user gesture (Touch ID, PIN). Bots cannot fake a hardware-backed signature. |
| **Deepfakes claiming someone's identity** | Tokens are cryptographically bound to a passkey. A deepfake video proves nothing without the corresponding private key, which never leaves the user's device. |
| **PII exposure in case of issuer breach** | The issuer stores no name, email, or address. Worst case: an attacker learns *that* a user exists, but not who they are. |
| **Replay attacks** | Each WebAuthn ceremony uses a fresh server-generated challenge with a 2-minute TTL. |
| **Token theft via XSS** | Tokens are signed but not encrypted; if stolen, an attacker can use them. Mitigation: short token lifetime (1h), revocation endpoint, refresh tokens. |
| **Sybil attacks (one person, many identities)** | A single passkey produces a single user identity at the issuer. While a determined attacker can register many devices, each requires its own physical authentication ceremony — significantly raising the cost compared to bot accounts. |
| **Phishing via lookalike domains** | The WebAuthn `RP_ID` binds passkeys to a specific origin. A passkey for `hhttps.org` cannot be used at `hhttps-org.evil.com` even if the user is tricked. |
| **MITM token injection** | All HHTTPS endpoints require HTTPS. Tokens are HMAC-protected by their signature; an in-flight modification breaks signature validation. |
| **Centralized takedown** | Anyone can run an HHTTPS issuer compatible with the spec. `hhttps.org` is the reference, not the only one. |

### What HHTTPS does NOT protect against

| Threat | Why not |
|---|---|
| **Coerced verification** | If someone has a gun to your head and tells you to authenticate, HHTTPS will sign the request. This is a fundamental limitation of any presence-based protocol. |
| **Stolen unlocked device** | If your phone is unlocked and unattended, anyone can use it for HHTTPS. Mitigation: short token lifetimes; remote revocation. |
| **Insider threat at the issuer** | An issuer operator could theoretically issue tokens for non-existent users. Mitigation: transparency log (planned for v0.5) and reproducible builds. |
| **Compromised passkey hardware** | If the secure enclave / TPM is compromised, an attacker can extract private keys. This is below HHTTPS's threat model — assumed secure by WebAuthn. |
| **Real-world identity verification** | HHTTPS proves *a* human is on the other end, with a *role* they claim. It does **not** prove the human is who they say they are by name. Use it for "is this a real doctor?" not "is this Dr. Schmidt specifically?". |
| **Liveness for video/photo** | HHTTPS does not check whether the person in front of the camera is the one with the passkey. Pair with FIDO2-with-biometrics if needed. |

## Cryptographic Choices

| Component | Algorithm | Why |
|---|---|---|
| Token signature | **ES256** (ECDSA P-256 + SHA-256) | Industry standard, native browser support, fast, tiny keys (32 bytes), post-quantum migration plan exists |
| Refresh token signature | **ES256** (same key) | Simplifies key management; refresh has its own `sub: 'refresh'` namespace |
| Webhook signature | **HMAC-SHA-256** | Symmetric, simple, fast for high-volume delivery |
| Email verification token | **SHA-256** of plain token | Stored hashed; raw token only known to user via email |
| Password storage | **None** | HHTTPS uses no passwords. WebAuthn handles all secrets. |
| Database column encryption | **None** | The DB stores no plaintext PII. Hashed identifiers and public keys only. |

Rotation:
- **Issuer signing keys** rotate every 90 days. JWKS publishes the previous key for a 7-day grace period.
- **Webhook secrets** are user-chosen; users may rotate via DELETE + re-register.
- **Refresh tokens** rotate on use (each use issues a new access token + retires the old refresh token, optionally).

## Storage

The `hhttps.org` issuer stores:

| Table | Contains | Encrypted at rest? |
|---|---|---|
| `credentials` | WebAuthn public key, counter, transports, deviceType | No (public-key info) |
| `sessions` | Short-lived session state (10 min TTL) | No (no PII) |
| `tokens` | Active access token JTIs | No |
| `refresh_tokens` | Active refresh token JTIs | No |
| `revoked_tokens` | Revoked JTIs (permanent) | No |
| `roles_declared` | userId → role mapping | No (userId is opaque random UUID) |
| `email_verifications` | Hashed token + hashed email + domain (15 min TTL) | No |
| `webhooks` | URL, events, HMAC secret | Secret stored as plaintext; rotate as needed |

**The issuer never stores:**
- Real names or display names
- Email addresses (only domain + hashed full address, briefly, for verification)
- Phone numbers
- Postal addresses
- IP addresses (beyond ephemeral request logs, retained ≤ 7 days)
- Browsing or behavioral data

## Network

- All endpoints require HTTPS (TLS 1.2+).
- The reference `hhttps.org` server uses Let's Encrypt certificates with OCSP stapling.
- HSTS header is set with `max-age=63072000; includeSubDomains; preload`.
- The server runs behind Nginx with rate-limiting and connection-limit modules.
- WebSockets are not used.

## Rate Limiting

Per IP (lifetime, sliding window):

| Endpoint group | Limit |
|---|---|
| Global (`*`) | 300 / minute |
| `/hhttps/check` | 120 / minute |
| `/hhttps/webauthn/{register,auth}/start` | 20 / 15 minutes |
| `/hhttps/email/send` | 5 / hour |
| `/hhttps/revoke` | 30 / minute |
| `/hhttps/webhooks` | 20 / hour |
| `/hhttps/machine/{register,token}` | 60 / minute |

The `trust proxy` setting is enabled because the server runs behind Nginx; rate-limiting uses the `X-Forwarded-For` header (single trusted hop).

## Revocation

Tokens can be revoked at any time via `POST /hhttps/revoke`:

1. The token's `jti` is added to the `revoked_tokens` table.
2. Subsequent calls to `/hhttps/check`, `/hhttps/validate`, or token-protected endpoints reject the token.
3. Third-party verifiers should periodically check `/hhttps/revoke/status?jti=<jti>` if they cache decisions.

For high-trust use cases (medical, legal, government), verifiers should:
- Cache decisions for at most 5 minutes
- Re-check revocation status before each high-stakes action

## Privacy Properties

### Unlinkability across sites

A user's HHTTPS token is bound to a `userId`, which is a random UUID generated at registration and never tied to any external identity. Even if two third-party sites both verify the same token, they only learn:
- The user is a verified human
- The user's role + trust score
- The token's JTI (unique per session)

They do **not** learn:
- The user's identity at the issuer (`userId` is opaque)
- The user's other roles or activities
- The user's other tokens (each token has a unique JTI)

For maximum unlinkability, use **role-only tokens** (planned for v0.6) which omit the JTI and are valid for a short, randomized window.

### Pseudonymity by default

The HHTTPS protocol is pseudonymous: every interaction is tied to a stable `userId`, but that userId reveals nothing about the human. Apps can choose:
- **Anonymous mode**: ignore the `userId`, treat each token as a fresh interaction
- **Pseudonymous mode**: use the `userId` as a stable handle for that user on your site
- **Linked mode**: associate the `userId` with an account in your DB (still no PII from HHTTPS)

### Minimal disclosure

Selective disclosure (zero-knowledge proofs of role attributes) is planned for v0.7. Until then, the entire JWT payload is visible to verifiers, including the role, trust score, method, and JTI.

## Bug Bounty

There is no formal bug bounty program. Report security issues to:

**daniel.hannuschka@tweakz.de** (PGP key fingerprint TBD)

We will respond within 7 days and aim to patch within 30 days for critical issues. Public disclosure happens 90 days after patch deployment, or earlier if a patch is publicly available.

## Audits

No formal third-party audit has been conducted yet. Plans:
- v0.5 — Independent code review by a German university research group
- v0.6 — Penetration test by a CISPA-affiliated firm
- v1.0 — Full audit before IETF RFC submission

Until then, the codebase is small (~970 lines for `server.js`, similar for other modules) and reviewable. Pull requests welcome.

## See also

- [`spec.md`](spec.md) — full protocol specification
- [`integration-guide.md`](integration-guide.md) — how to verify tokens in your app
- [`governance.md`](governance.md) — how protocol changes are decided
- [hhttps.org/spec](https://hhttps.org/spec) — public specification page

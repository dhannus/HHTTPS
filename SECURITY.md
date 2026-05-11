# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.4.1   | ✅ Current production |
| 0.4.0   | ⚠ Security fixes only, until 2026-08-01 |
| < 0.4.0 | ❌ No longer supported |

## Reporting a vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

Email: **daniel.hannuschka@tweakz.de**
Subject: **`[SECURITY] <short description>`**

Include:
- Affected version (`/hhttps/info` shows it)
- Steps to reproduce
- Impact assessment (your view of severity)
- Suggested mitigation (optional)

### Response timeline

| | Target |
|---|---|
| Initial acknowledgement | 48 hours |
| Severity assessment | 7 days |
| Patch available | 30 days for critical/high; 90 days for medium/low |
| Public disclosure | 90 days after patch deployed, OR 30 days if actively exploited |

### Bug bounty

There is no formal paid bug bounty program (this is an unfunded civic-tech project). However:
- Reporters get explicit credit in `CHANGELOG.md` and the release notes.
- For significant findings, I will gladly write a public LinkedIn/Mastodon recommendation.
- If institutional funding materializes, retroactive bounties for past reports are on the table.

## Threat model

See [`docs/security.md`](docs/security.md) for the full threat model.

### What HHTTPS protects against

- AI bots impersonating humans (WebAuthn hardware requirement)
- Deepfake-based identity claims (cryptographic binding to passkey)
- PII exposure in case of issuer breach (no PII stored)
- Replay attacks (fresh challenges, 2-min TTL)
- Phishing via lookalike domains (RP_ID binding)
- MITM token injection (HTTPS + signature)
- Centralized takedown (anyone can run an issuer)

### What HHTTPS does **not** protect against

- Coerced verification (someone forcing you to authenticate)
- Stolen unlocked device (short token TTL helps)
- Insider threat at the issuer (transparency log planned for v0.5)
- Compromised hardware enclave (below threat model — assumed secure)
- Real-name verification (HHTTPS proves role, not specific identity)

## Cryptographic choices

| Component | Algorithm | Justification |
|---|---|---|
| Token signature | ES256 (ECDSA P-256 + SHA-256) | RFC 7518, native WebAuthn support |
| Refresh signature | ES256 (same key) | Simpler key management |
| Webhook signature | HMAC-SHA-256 | Symmetric, fast for high volume |
| Email tokens | SHA-256 of plain token | Hashed at rest |

Issuer signing keys rotate every 90 days. JWKS publishes both old and new keys during the 7-day grace period.

## Storage

The reference issuer (`hhttps.org`) stores:

| Table | Contains | Encrypted at rest? |
|---|---|---|
| `credentials` | WebAuthn public key + counter | No (public info) |
| `sessions` | Short-lived state (10-min TTL) | No (no PII) |
| `tokens` | Active JTIs | No |
| `revoked_tokens` | Revoked JTIs (permanent) | No |
| `roles_declared` | userId → role mapping | No (userId is opaque) |
| `email_verifications` | Hashed token + hashed email (15-min TTL) | No |
| `webhooks` | URL + HMAC secret | Plain (rotate as needed) |

**Never stored**: real names, plain emails, phone numbers, postal addresses, behavioral data.

## Audits

| Phase | Status | Target |
|---|---|---|
| Independent code review | Planned | v0.5 — German university |
| Penetration test | Planned | v0.6 — CISPA-affiliated firm |
| Formal audit | Planned | v1.0 — before IETF RFC submission |

Until then, the codebase is small (~1,200 lines for `server.js`) and reviewable. PRs welcome.

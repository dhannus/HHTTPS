# HHTTPS Protocol Specification

**Version: 0.4.1** · **Status: Production** · **License: EUPL-1.2**

## Abstract

HHTTPS (Human-verified HTTPS) is an open protocol that adds a cryptographic proof-of-personhood layer on top of HTTPS. It allows web servers to verify that an HTTP request was initiated by a real human — without storing personally identifiable information.

The protocol combines three established standards:
- **WebAuthn** (W3C) for human-presence verification via hardware-backed passkeys
- **ES256-signed JWTs** (RFC 7519) for portable claims about the verified human
- **JWKS** (RFC 7517) for distributed signature verification by third parties

Adoption requires no central authority — any operator can run an HHTTPS issuer compatible with this spec.

## Table of Contents

1. [Design Principles](#design-principles)
2. [Terminology](#terminology)
3. [Protocol Flow](#protocol-flow)
4. [API Endpoints](#api-endpoints)
5. [Token Format](#token-format)
6. [HTTP Headers](#http-headers)
7. [Roles](#roles)
8. [Trust Scoring](#trust-scoring)
9. [Discovery](#discovery)
10. [Refresh Tokens](#refresh-tokens)
11. [Machine Tokens](#machine-tokens)
12. [Revocation](#revocation)
13. [Webhooks](#webhooks)
14. [Security](#security)
15. [Governance](#governance)

## Design Principles

1. **Zero PII storage.** The issuer stores no name, address, or contact data. Only public keys, hashed identifiers, and ephemeral session state.
2. **No central authority.** Anyone can run an HHTTPS issuer. Tokens are verified against the issuer's public JWKS — no API key exchange, no rate-limited validation calls.
3. **Standards over invention.** WebAuthn, JWT, JWKS — all W3C/IETF standards. No proprietary cryptography. No new threat model.
4. **European by default.** GDPR-compliant by design. eIDAS-aware. Servers in the EU.
5. **Roles, not identities.** A token claims a role (e.g. `medical_professional`) and trust score (0–100), not a person.
6. **Revocable.** Tokens can be revoked via the issuer; revocation status is published in real-time.

## Terminology

- **Issuer** — A server implementing this spec that issues HHTTPS tokens. Reference: `hhttps.org`.
- **Subject** — The human (or machine) being verified.
- **Verifier** — Any third-party server that consumes HHTTPS tokens to authorize actions.
- **Token** — An ES256-signed JWT issued by the issuer.
- **Trust score** — Integer 0–100 reflecting how robustly the subject's role has been verified.
- **JWKS** — JSON Web Key Set, the issuer's public keys at `/.well-known/jwks.json`.
- **Role** — A societal/professional category like `citizen`, `medical_professional`, or `politician`.

## Protocol Flow

```
Subject (browser)        Issuer (hhttps.org)            Verifier (3rd party)
       │                         │                              │
       │   1. WebAuthn register  │                              │
       │ ───────────────────────►│                              │
       │                         │                              │
       │   2. Declare role       │                              │
       │ ───────────────────────►│                              │
       │                         │                              │
       │   3. Receive token      │                              │
       │ ◄───────────────────────│                              │
       │                         │                              │
       │   4. HTTP request with HHTTPS-Token header             │
       │ ──────────────────────────────────────────────────────►│
       │                         │                              │
       │                         │   5. Fetch JWKS (cached 1h)  │
       │                         │ ◄────────────────────────────│
       │                         │                              │
       │                         │   6. Send public keys        │
       │                         │ ────────────────────────────►│
       │                         │                              │
       │                         │            7. Verify         │
       │                         │            signature locally │
       │                         │                              │
       │                         │            8. Authorize      │
       │                         │            based on role +   │
       │                         │            trust score       │
```

The verifier never contacts the issuer per request. JWKS is cached for one hour by default.

## API Endpoints

### Discovery

```
GET /.well-known/hhttps-configuration
GET /.well-known/jwks.json
```

### Registration & Authentication

```
POST /hhttps/webauthn/register/start
POST /hhttps/webauthn/register/finish
POST /hhttps/webauthn/auth/start
POST /hhttps/webauthn/auth/finish
POST /hhttps/role/declare
POST /hhttps/token/refresh
```

### Token Operations

```
POST /hhttps/check
POST /hhttps/validate
POST /hhttps/revoke
GET  /hhttps/revoke/status?jti=...
```

### Email Verification

```
POST /hhttps/email/send
GET  /hhttps/email/verify?token=...&session=...
POST /hhttps/email/status
```

### Machine Tokens

```
POST /hhttps/machine/register
POST /hhttps/machine/token
```

### Webhooks

```
GET    /hhttps/webhooks
POST   /hhttps/webhooks
DELETE /hhttps/webhooks/:id
POST   /hhttps/webhooks/verify
```

### Public

```
GET /hhttps/info
GET /hhttps/stats
GET /hhttps/roles
```

## Token Format

An HHTTPS access token is a JWT signed with ES256.

### Example payload (decoded)

```json
{
  "jti":        "550e8400-e29b-41d4-a716-446655440000",
  "iss":        "hhttps://hhttps.org",
  "sub":        "human-verified",
  "human":      true,
  "actorType":  "human",
  "role":       "medical_professional",
  "roleLevel":  "approbation-id",
  "trustScore": 93,
  "method":     "webauthn-passkey",
  "deviceType": "singleDevice",
  "ia":         1715242800,
  "exp":        1715246400
}
```

### Required claims

| Claim | Type | Description |
|---|---|---|
| `jti` | string | Unique token identifier (UUIDv4 recommended) |
| `iss` | string | Issuer URL prefixed with `hhttps://` |
| `sub` | string | One of: `"human-verified"`, `"machine"`, `"refresh"` |
| `human` | boolean | True for human, false for machine tokens |
| `actorType` | string | `"human"` or `"bot"` |
| `role` | string | One of the defined roles (see § Roles) |
| `roleLevel` | string | The verification method that established the role |
| `trustScore` | integer | 0–100, see § Trust Scoring |
| `method` | string | Primary auth method (e.g. `"webauthn-passkey"`) |
| `ia` | integer | Issued-at, Unix epoch seconds |
| `exp` | integer | Expiry, Unix epoch seconds (recommended TTL: 3600) |

### Optional claims

| Claim | Type | Description |
|---|---|---|
| `deviceType` | string | `"singleDevice"` or `"multiDevice"` (from WebAuthn) |
| `userId` | string | Stable opaque UUID for the subject (for app-level linking) |
| `kid` | string | Key ID, redundant with header — included for convenience |

## HTTP Headers

HHTTPS-aware servers SHOULD set these response headers:

```
HHTTPS-Protocol-Version: 0.4.1
HHTTPS-Status:           verified | unverified | invalid | revoked | none
HHTTPS-Human:            true | false
HHTTPS-Actor-Type:       human | bot | unknown
HHTTPS-Role:             <role-id>
HHTTPS-Role-Label:       <human-readable role name>
HHTTPS-Role-Level:       <verification method>
HHTTPS-Trust-Score:      <0..100>
HHTTPS-Method:           <auth method>
HHTTPS-Issuer:           hhttps://<issuer-host>
HHTTPS-Token:            <JWT, optional>
```

For requests, clients send:

```
HHTTPS-Token: <JWT>
```

Or use `Authorization: Bearer <JWT>`.

## Roles

The protocol defines 15 roles. Verifiers MAY accept any subset.

| Role ID | Label (en) | Highest verification | Max trust |
|---|---|---|:---:|
| `citizen` | Citizen | WebAuthn baseline | 60 |
| `journalist` | Journalist | Press card | 85 |
| `student` | Student | Education email + matriculation | 85 |
| `teacher` | Teacher | Teacher ID | 86 |
| `researcher` | Researcher | ORCID | 88 |
| `creative` | Creative professional | Association membership | 85 |
| `developer` | Developer | GitHub verification | 72 |
| `medical_professional` | Medical professional | Approbation number | 93 |
| `caregiver` | Care professional | Pflegekammer ID | 90 |
| `lawyer` | Attorney | Bar association | 92 |
| `notary` | Notary | Notarkammer | 95 |
| `civil_servant` | Civil servant | Official email | 90 |
| `politician` | Politician | Bundestag verification | 98 |
| `business` | Business | Handelsregister | 92 |
| `craftsman` | Skilled tradesperson | Master certificate | 90 |

A role's `roleLevel` describes the verification method that produced it (e.g. `approbation-id`, `bar-association-id`, `school-email`).

## Trust Scoring

Trust scores are assigned by the issuer based on the verification path. They are advisory — verifiers MAY choose any threshold appropriate to their use case.

| Method | Score |
|---|:---:|
| `self-declared` | 30 |
| `webauthn` | 60 |
| `email-verified` (consumer domain) | 70 |
| `github-verified` | 72 |
| `school-email` (.schule.de etc.) | 75 |
| `medical-email` | 78 |
| `lawyer-email` | 78 |
| `domain-verified` | 82 |
| `press-card` | 85 |
| `student-id` | 85 |
| `association-member` | 85 |
| `teacher-id` | 86 |
| `craft-chamber-id` | 86 |
| `orcid` | 88 |
| `master-certificate` | 90 |
| `care-chamber-id` | 90 |
| `service-id` | 90 |
| `official-email` | 90 |
| `bar-association-id` | 92 |
| `handelsregister` | 92 |
| `approbation-id` | 93 |
| `notary-chamber-id` | 95 |
| `bundestag-verified` | 98 |

Higher methods strictly imply lower ones. A token with `trustScore: 93` also satisfies any threshold ≤ 93.

## Discovery

Issuers publish their configuration at `/.well-known/hhttps-configuration`:

```json
{
  "issuer":                   "hhttps://hhttps.org",
  "protocol_version":         "0.4.1",
  "jwks_uri":                 "https://hhttps.org/.well-known/jwks.json",
  "check_endpoint":           "https://hhttps.org/hhttps/check",
  "registration_endpoint":    "https://hhttps.org/hhttps/webauthn/register/start",
  "authentication_endpoint":  "https://hhttps.org/hhttps/webauthn/auth/start",
  "revocation_endpoint":      "https://hhttps.org/hhttps/revoke",
  "supported_algorithms":     ["ES256"],
  "supported_roles":          ["citizen", "journalist", "..."],
  "token_ttl":                3600,
  "refresh_ttl":              604800
}
```

JWKS at `/.well-known/jwks.json`:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x":   "<base64url>",
      "y":   "<base64url>",
      "kid": "hhttps-2026-q2",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```

## Refresh Tokens

Access tokens are short-lived (1 hour). Refresh tokens (7 days) allow extension without repeated WebAuthn challenges.

```
POST /hhttps/token/refresh
Content-Type: application/json

{ "refreshToken": "<JWT>" }
```

Response:

```json
{
  "hhttps":    { "version": "0.4.1", "status": "refreshed", "human": true },
  "token":     "<new access JWT>",
  "expiresAt": "2026-05-10T13:30:00Z",
  "role":      { "id": "medical_professional", "trustScore": 93 }
}
```

Refresh tokens have `sub: "refresh"` and are tracked in a separate persistent store. They can be revoked independently of access tokens.

## Machine Tokens

For non-human automation (CI bots, monitoring, etc.) operating with the user's consent:

```
POST /hhttps/machine/register
{ "operatorName": "...", "purpose": "...", "contactEmail": "..." }

→ { "operatorId": "op-xxx", "apiKey": "mk-yyy" }

POST /hhttps/machine/token
{ "operatorId": "op-xxx", "apiKey": "mk-yyy" }

→ { "token": "<JWT with sub: machine, human: false>" }
```

Machine tokens have `actorType: "bot"` and `human: false`. Verifiers SHOULD distinguish humans from machines based on these fields.

## Revocation

Any token holder may revoke their own token:

```
POST /hhttps/revoke
{ "token": "<JWT>" }
```

The JTI is added to a permanent revocation list. Verifiers SHOULD check revocation for high-trust use cases:

```
GET /hhttps/revoke/status?jti=<jti>
→ { "jti": "...", "revoked": false, "active": true }
```

## Webhooks

Issuers MAY notify subscribers of events:

```
POST /hhttps/webhooks
{ "url": "https://yoursite/hhttps", "events": ["token.issued", "token.revoked", "role.declared"] }
```

Each delivery includes an `HHTTPS-Webhook-Sig` header with HMAC-SHA-256 signature using the registered secret.

## Security

See [`security.md`](security.md) for the full threat model and security considerations.

Highlights:
- Private keys never leave the user's device (WebAuthn enforces this in hardware).
- Replay protection via fresh server-generated challenges (2-min TTL).
- Rate-limiting at all sensitive endpoints.
- Token revocation persists permanently.
- Issuer signing keys rotate every 90 days; JWKS publishes both old + new during grace period.

## Governance

The HHTTPS specification is maintained by the **HumanProof Initiative**, an unfunded civic-tech project. Decisions are made via:

- **Minor changes** (clarifications, examples, typos): pull request, single maintainer review
- **Specification changes** (new claims, endpoint changes): public discussion period ≥ 30 days, then maintainer consensus
- **Breaking changes** (token format, signing algorithm): major version bump, ≥ 90-day discussion + 6-month migration window

The IETF Internet-Draft is published independently and welcomes formal comments.

Anyone may fork the protocol; running a different issuer is explicitly encouraged. The reference implementation (`hhttps.org`) does not have privileged status in the protocol — only practical first-mover advantage in adoption.

---

**Maintainer**: Daniel Hannuschka (daniel.hannuschka@tweakz.de)
**Repository**: https://github.com/dhannus/HumanProof
**License**: EUPL-1.2
**Last updated**: 2026-05-10

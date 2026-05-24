# HHTTPS Identity Token Specification

**Status**: Draft v0.4.1 — Implemented in production
**Last updated**: May 2026

This document specifies the format of HHTTPS identity tokens.

---

## Overview

An HHTTPS identity token is a JSON Web Token (JWT) issued by a HHTTPS-compliant identity issuer (e.g. hhttps.org). It asserts that:

1. A real human registered an identity at the issuer
2. The human has a verified role
3. The trust score reflects how strongly the role was verified

Tokens are short-lived (typically 1 hour), refreshable, and signed with ECDSA (ES256).

---

## Token format

A HHTTPS identity token is a JWT with three parts:

```
<header>.<payload>.<signature>
```

### Header

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "<key-id>"
}
```

| Field | Required | Description |
|---|---|---|
| `alg` | yes | Must be `ES256`. Other algorithms are not currently supported. |
| `typ` | yes | Must be `JWT`. |
| `kid` | yes | Key ID. Used by clients to fetch the right public key from the JWKS endpoint. |

### Payload (claims)

```json
{
  "iss": "https://hhttps.org",
  "hhttps_iss": "hhttps://hhttps.org",
  "sub": "human-verified",
  "human": true,
  "actorType": "human",
  "role": "developer",
  "trustScore": 72,
  "roleLevel": "github-verified",
  "method": "webauthn-passkey",
  "iat": 1715000000,
  "exp": 1715003600,
  "jti": "5f8d2e91-..."
}
```

| Claim | Type | Required | Description |
|---|---|---|---|
| `iss` | string | yes | Issuer origin as `https://<host>` (RFC 7519 / OIDC compatible). Must match a registered HHTTPS issuer. |
| `sub` | string | yes | Subject. Human tokens: `"human-verified"`. Machine tokens: `"machine"`. Refresh tokens: `"refresh"`. OAuth tokens: a pairwise pseudonymous id. |
| `hhttps_iss` | string | no | Branding-only label in `hhttps://<host>` form. Informational; verifiers MUST validate against `iss`, never this field. |
| `human` | boolean | yes | `true` for human-issued tokens. |
| `actorType` | string | yes | `"human"` or `"bot"`. |
| `role` | string | yes | One of the 15 defined roles. See [`roles.md`](roles.md). |
| `trustScore` | number | yes | Integer 0–100. Computed from verification methods used. |
| `roleLevel` | string | yes | The verification method that established the role (e.g. `webauthn`, `orcid`, `github-verified`, `bundestag-verified`). |
| `iat` | number | yes | Issued at (Unix timestamp). Set automatically by the signer (RFC 7519). |
| `exp` | number | yes | Expires at (Unix timestamp). Typically 1 hour after `iat`. |
| `jti` | string | yes | Unique token ID. Used for revocation. |
| `method` | string | no | Primary authentication method (e.g. `webauthn-passkey`). |
| `userId` | string | no | Opaque, stable per-user id within this issuer for app-level linking. Not personally identifiable. Omitted in OAuth flows, which use a pairwise `sub` instead. |

### Signature

Computed over `base64url(header) + '.' + base64url(payload)` using the issuer's ECDSA P-256 private key.

---

## Verification

To verify a HHTTPS identity token:

1. **Parse** the token (split on `.`, base64url-decode header and payload).
2. **Fetch the issuer's JWKS** from `{iss}/.well-known/jwks.json`.
3. **Select the public key** matching the token's `kid`. The JWKS may contain
   more than one key during a rotation grace period; pick the entry whose `kid`
   equals the token header `kid`.
4. **Verify the signature** using ES256.
5. **Check `exp`** — token must not be expired.
6. **Check `iss`** — must match an issuer your platform trusts.
7. **(Optional) Check revocation** by calling `{iss}/hhttps/check` with the token.

---

## Refresh tokens

To get a new access token without re-authentication, exchange a refresh token at:

```
POST {iss}/hhttps/token/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh-token-string>"
}
```

Refresh tokens are ES256-signed JWTs with `sub: "refresh"`, valid for 7 days by
default, and tracked in a persistent store so they can be revoked independently
of access tokens. They are bound to:

- The user's credential ID (passkey)
- The user's role at issue time

On successful refresh, a new short-lived access token is returned. The refresh
token itself remains valid until it expires or is explicitly revoked at
`{iss}/hhttps/revoke`.

---

## Revocation

Tokens can be revoked at the issuer:

```
POST {iss}/hhttps/revoke
Content-Type: application/json

{
  "token": "<access-or-refresh-token>"
}
```

Revoked tokens are added to a revocation list. Clients SHOULD check the revocation status of high-value tokens by calling:

```
POST {iss}/hhttps/check
Content-Type: application/json
HHTTPS-Token: <token>
```

---

## HTTP headers

For convenience, HHTTPS defines a set of response headers that platforms can include to advertise their HHTTPS status:

| Header | Value |
|---|---|
| `HHTTPS-Status` | `verified` / `unverified` / `invalid` / `revoked` / `required` / `info` / `issuer` / `none` |
| `HHTTPS-Human` | `true` / `false` |
| `HHTTPS-Actor-Type` | `human` / `bot` / `unknown` |
| `HHTTPS-Role` | The role from the token |
| `HHTTPS-Role-Label` | Human-readable role name |
| `HHTTPS-Role-Label` | Human-readable role name |
| `HHTTPS-Role-Level` | The verification method that established the role |
| `HHTTPS-Trust-Score` | 0–100 |
| `HHTTPS-Method` | The verification method used |
| `HHTTPS-Issuer` | The issuer in `hhttps://<host>` protocol form (the JWT `iss` claim is the `https://` origin) |
| `HHTTPS-Protocol-Version` | Current: `0.4.1` |

These headers are consumed by the browser extension to render visual indicators.

---

## Security considerations

- **Trust the issuer**: An identity token is only as trustworthy as its issuer. Platforms should maintain a list of trusted issuers and reject tokens from unknown sources.
- **Short TTLs**: Default 1-hour TTL limits the impact of token compromise.
- **PKCE for OAuth**: Public clients (mobile apps, SPAs) MUST use PKCE to prevent code interception attacks.
- **Pairwise subject IDs**: When tokens are issued via OAuth, the `sub` field is computed as `HMAC(uid + client_id, issuer-secret)` so platforms cannot correlate users across the federation.

---

## Changelog

- **v0.4.1** (May 2026): Pairwise subject IDs for OAuth flow; `iat`/`iss` aligned
  to RFC 7519 (standard `iat`; `iss` is `https://`, with `hhttps_iss` as a
  branding label); JWKS supports graceful key rotation with dated `kid`s.
- **v0.4.0** (April 2026): Machine tokens, expanded role taxonomy (15 roles)
- **v0.3** (March 2026): Refresh tokens, ES256 signatures, JWKS endpoint
- **v0.2** (February 2026): Trust score system, multiple verification methods
- **v0.1** (January 2026): Initial draft, HS256 signatures, single role

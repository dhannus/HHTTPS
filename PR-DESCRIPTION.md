# PR: Interoperability & standards-conformance fixes for the HHTTPS token layer

**Branch suggestion:** `fix/jwt-iat-iss-jwks-rotation-sdk-localverify`
**Scope:** `server/server.js`, `server/keys.js`, `server/sdk/client.js`, `server/sdk/client.py`, `docs/spec.md`, `docs/protocol/identity-token.md`
**Breaking?** One behavioural change (RP_ID default) — see Migration. Token wire-format changes are additive/standardising.

---

## Why

An interop audit of the protocol-defining side (the issuer) and the consuming
side (SDKs + examples) surfaced four conformance gaps between the spec, the
code, and what a third-party verifier built on standard JWT libraries would
actually accept. This PR fixes all four and re-aligns the docs to the code so we
never document a feature we do not ship.

---

## Changes

### 1. RFC 7519: `ia` → `iat`  *(server.js)*
Native HHTTPS tokens used a non-standard `ia` issued-at claim. Standard JWT
libraries (`jsonwebtoken`, PyJWT, jose, php-jwt) ignore `ia`, so issued-at was
invisible to every standards-based verifier.

- Removed the manual `ia` claim at all four signing sites (access, refresh,
  text-signature, machine). `jsonwebtoken` now emits the standard `iat`
  automatically.
- Updated the four read sites (`d.ia` → `d.iat`) in `/hhttps/check`,
  text-signature verify, machine check, and validate.
- **Verified:** signing without a manual claim yields a standard `iat`
  (integration test below).

### 2. OIDC/RFC 7519: `iss` is now an `https://` origin  *(server.js)*
Native tokens used `iss: "hhttps://<host>"`, which a standard OIDC verifier
rejects (issuer must be an `https://` URL matching discovery). The OAuth path
already used `https://`, so the two halves of the codebase disagreed.

- All tokens now carry `iss: "https://<host>"`.
- The `hhttps://` branding value is preserved in a dedicated, **informational**
  `hhttps_iss` claim. Verifiers MUST validate against `iss`, never `hhttps_iss`.
- `/.well-known/hhttps-configuration` now reports `issuer: https://…` (matching
  the token `iss`) plus a separate `hhttps_issuer: hhttps://…` branding field.
- The `HHTTPS-Issuer` **response header** keeps the `hhttps://` form — it is a
  protocol display value, not a JWT claim — and the docs now say so explicitly.

### 3. Graceful key rotation + dated `kid`  *(keys.js)*
The spec promised "JWKS publishes both old + new during grace period", but
`keys.js` held a single key and the JWKS exposed exactly one entry, so any
rotation would instantly invalidate every outstanding token. `kid` was also a
random string, not the dated value the spec showed.

- `keys.js` now keeps retired public keys in `keys/retired/<kid>.pem` and
  publishes them alongside the active key in the JWKS until they are explicitly
  dropped.
- New `rotateKeys()` mints a new active key and retires the previous public key.
- `verifyToken()` selects the verifying key by the token header `kid`, so tokens
  signed before a rotation keep verifying.
- `kid` is now dated: `hhttps-YYYY-qN-<suffix>`.
- **Verified:** a token signed with the pre-rotation key still verifies after
  `rotateKeys()` because both keys are in the JWKS (integration test below).

### 4. SDK local JWKS verification  *(client.js, client.py)*
The spec's core promise is offline, federated verification ("the verifier never
contacts the issuer per request"). The examples did this, but the official SDKs
only offered the remote `/hhttps/check` round-trip. Verifiers using the SDK had
to hand-roll JWKS verification themselves.

- **JS SDK** — added `verifyLocal(token)` and `getJwks()`. `verifyLocal` fetches
  the JWKS (cached 1 h), selects the key by `kid`, verifies the ES256 signature
  via Web Crypto (Node 16+/browser, no new dependency), and checks `exp`/`nbf`.
  The Express `middleware()` now defaults to local verification; pass
  `{ mode: 'remote' }` for the old behaviour.
- **Python SDK** — added `verify_local(token)` and `get_jwks()`. Uses PyJWT with
  the cryptography backend (`pip install "PyJWT[crypto]"`); the remote `check()`
  path keeps working with stdlib-only.
- Both `verifyLocal`/`verify_local` return the same normalized result shape as
  the remote path.
- **Verified:** valid tokens verify, tampered tokens are rejected, expired tokens
  are reported as `expired`, in both SDKs (tests below).

### 5. Branding & legacy cleanup  *(all files)*
- `HumanProof` → `iamhmn` (initiative name) across `server.js` headers, footer,
  `/hhttps/info` payload, WebAuthn display name, and both SDK headers.
- Repo URL `dhannus/HumanProof` → `dhannus/HHTTPS`.
- Legacy SDK base URL `hhttps.funnysearch.eu` → `hhttps.org`.
- `RP_ID` default `funnysearch.eu` → `hhttps.org` (see Migration).
- The `hp-` signature slug prefix is **unchanged** — it is wire-format matched by
  five server regexes, the extension, and `signature-format.md`; the misleading
  "for HumanProof" code comment was corrected to "(HHTTPS signature)".

---

## Migration notes

1. **`RP_ID` default changed to `hhttps.org`.** WebAuthn credentials are bound to
   the RP ID. Production already sets `RP_ID` via environment variable, so this
   is a no-op there. Anyone relying on the old `funnysearch.eu` default MUST set
   `RP_ID=funnysearch.eu` explicitly, or existing passkeys will not match. The
   default now reflects the canonical domain.

2. **Existing tokens keep verifying.** Token-format changes are additive
   (`iat` instead of `ia`; `iss` switches scheme but the OAuth path already used
   `https://`). Tokens already in the wild with `ia`/`hhttps://` will simply
   expire on their normal TTL (≤1 h for access, ≤7 d for refresh). No forced
   invalidation.

3. **Key rotation is opt-in.** Nothing rotates automatically. Call `rotateKeys()`
   when you choose; retired keys remain in the JWKS until you stop publishing
   them via `forgetRetiredKey(kid)` (only after one full token TTL has elapsed).

4. **Python `verify_local` needs a dependency.** `pip install "PyJWT[crypto]"`.
   The remote `check()` path remains stdlib-only.

---

## Test evidence

All tests run against the patched files in this PR.

```
JS SDK verifyLocal:    valid → verified (role+trust correct) · tampered → invalid · expired → expired   PASS
Py SDK verify_local:   valid → verified (role+trust correct) · tampered → invalid · expired → expired   PASS
keys.js auto-iat:      signing without manual claim emits standard iat                                  PASS
Integration (real keys.js + real SDK):
  - token verifies locally via JWKS                                                                     PASS
  - after rotateKeys(): JWKS has 2 keys; pre-rotation token STILL verifies; new token verifies          PASS
```

---

## Files in this PR

```
server/server.js                 — iat, iss/hhttps_iss, discovery, branding (53 lines)
server/keys.js                   — multi-key rotation, dated kid, kid-aware verify (rewritten)
server/sdk/client.js             — verifyLocal + getJwks + local-mode middleware (rewritten)
server/sdk/client.py             — verify_local + get_jwks + _parse_claims (extended)
docs/spec.md                     — token example, claims tables, discovery, JWKS, rotation, governance
docs/protocol/identity-token.md  — claims, refresh-token reality, header table, status values
```

Unified diffs for each file are in `_pr/*.diff`.

---

**License:** EUPL-1.2 (unchanged).
**Maintainer:** Daniel Hannuschka · daniel.hannuschka@tweakz.de

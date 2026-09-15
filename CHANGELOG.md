# Changelog

All notable changes to the HHTTPS protocol and reference implementation are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Phase 8: email-anchored identity

### Added
- **E-mail identity anchor** (`identity_anchors`): the same verified e-mail address (trimmed, lower-cased) always resolves to the same stable `userId` — and therefore to the same pairwise `sub` per platform — on every device and browser. The anchor stores `HMAC-SHA256(HHTTPS_VERIFICATION_PEPPER, email)` only, never the address (`server/identity.js`, `server/db.js`).
- **Account pseudonym**: chosen by the user at first e-mail verification (max. 32 chars) or generated as `iamhmn_<10 chars>`; stable per account, carried in `sessions.pseudonym`, in the HHTTPS access/refresh token (`pseudonym`) and delivered to platforms as `preferred_username`. Optional `pseudonym` field on `POST /hhttps/email/send`.
- **Passkeys bound to the stable identity**: the WebAuthn user handle is the session's `userId`; a returning user gets the same identity on every device.
- **OAuth scope `email`**: delivers the verified address as `email` + `email_verified: true` in ID token, access token and `/hhttps/oauth/userinfo`. Requires user consent and `email` in the client's `allowed_scopes`; new clients get it by default.
- **New OIDC claims on every `openid` login**: `verified_methods[]`, `email_verified`, `passkey_verified`, `github_verified`, `eudi_verified`, `preferred_username` — in ID token, access token, `/oauth/userinfo`, and surviving OAuth refresh grants. Discovery lists `email` in `scopes_supported` and the new claims in `claims_supported`.
- **`POST /hhttps/email/confirm-code`** documented as the primary same-tab verification path.
- **`identity_claims_cache`**: server-side plaintext cache (e-mail, pseudonym, methods) per `userId`, 7-day expiry after the last confirmation, so the address can be transferred to platforms the user authorises.
- **Migration phase 8** (`server/sql/migration-phase-8-email-anchored-identity.sql`), idempotent, in two sections: *BOOT-DDL* (applied by the server at boot after an applied-check; boot aborts if it fails) and *OPERATOR* (`allowed_scopes += "email"` for existing clients + grants — run once manually via `psql`).
- **Test and lint infrastructure**: `npm test` (`node --test`; unit tests for `identity.js` and the mail template, integration tests booting `server.js` against a local Postgres via `TEST_PG_HOST`) and `npm run lint` (ESLint 9 flat config). npm is the package manager (pnpm runs the same scripts).
- `.env.example` documents `HHTTPS_VERIFICATION_PEPPER`, `EMAIL_DEV_MODE`, `GITHUB_CLIENT_ID/SECRET`, `EUDI_VERIFIER_SECRET`, `NODE_ENV`.
- **`login_hint` / `pseudonym` on `GET /hhttps/oauth/authorize`** (AK-29..AK-32, Songbird integration): a platform that already knows the user's e-mail can pass `login_hint=<email>` (syntactic e-mail, ≤ 254 chars, normalised) and `pseudonym=<name>` (`sanitizePseudonym`); invalid values are silently dropped. Both are carried into the consent page (`#pseudoInput` pre-filled via DOM), and when the consent page has to send an unauthenticated user to the sign-in page, `relogin()` forwards them as `/?returnTo=…&login_hint=…&pseudonym=…`. The sign-in page (`handleLoginHint()`) opens the e-mail panel, pre-fills both fields, strips the two params from the URL (`returnTo` stays) and calls `/hhttps/email/send` exactly once, so the user lands directly on the code field; an invalid hint or a failed send shows the pre-filled panel with a hint and never loops. i18n `email.hintAuto`. Docs: `docs/oauth-integration.md` "login_hint / pseudonym". Tests: `server/test/integration/login-hint.test.mjs`, `server/test/unit/consent-page.test.mjs`, `signin-page.test.mjs`, browser test in `signin.e2e.test.mjs`.

### Fixed
- `POST /hhttps/webauthn/register/start` passed the WebAuthn user handle as a Buffer to `@simplewebauthn/server` 9 (which expects a string); browsers therefore registered passkeys with the user handle `"[object Object]"` instead of the stable `userId` (AK-4). Found by the new Playwright test with Chromium's virtual authenticator; now a string, verified end-to-end.
- **`POST /hhttps/machine/register` no longer crashes the server** ([#7](https://github.com/dhannus/HHTTPS/issues/7)): `machineOperators.create` has written `machine_operators.key_jkt` since the workload-identity phase, but no migration ever created the column — on such a database the insert failed with `42703` and, because the route had no error handling, the unhandled rejection terminated the Node process. New idempotent migration `server/sql/migration-phase-4b-machine-key-jkt.sql`, applied automatically at boot via the new generic boot-DDL list in `server/db.js` (`BOOT_DDL_FILES` / `ensureBootSchema()`, phase 8 unchanged); `/hhttps/machine/register` and `/hhttps/machine/token` answer `500 machine_register_failed` / `machine_token_failed` on an internal error instead of dying; `process.on('unhandledRejection')` logs `[UNHANDLED]` instead of exiting. Regression test in `acceptance.test.mjs` (201 + `/hhttps/info` still 200 afterwards).

- **`POST /hhttps/email/confirm-code` checks the session before consuming the code** ([#22](https://github.com/dhannus/HHTTPS/issues/22)): the verification row was marked `used` before the session lookup, so a confirm with an unknown or expired `sessionId` burnt a code the user could still legitimately enter on the real session. The session is now loaded first (`404 Session not found or expired.` as before); the code is only consumed for an existing session. An unknown session with any code therefore answers `404` instead of `400`. Regression test in `server/test/integration/followups.test.mjs`.

- **EUDI verifier passes the backend e-mail gate through instead of a 502** ([#26](https://github.com/dhannus/HHTTPS/issues/26)): `GET /eudi/age/status/:id`, `/eudi/av/status/:id` and `/eudi/eid/status/:id` turned every non-OK answer of `/hhttps/age/upgrade`, `/hhttps/age/direct` (always `403` since AK-28) and `/hhttps/eid/upgrade` into `502 { status:'error', detail:'age/direct failed (403): …' }`, so the sign-in page kept polling. Business errors of the backend (4xx) are now passed through with their status and code — `403 { status:'error', error:'email_verification_required', detail }` — while backend 5xx, an unreachable EU verifier and missing config stay `502` (`server/eudi-verifier/errors.js`: `BackendError`, `mapBackendError`). `server/public/index.html`: `pollEudi()`/`pollAge()` stop polling on `email_verification_required` and show the "confirm your e-mail first" hint. Tests in `server/test/unit/eudi-verifier-errors.test.mjs` and `signin-page.test.mjs`.

- **Wallet and landing page use the email-first passkey flow** ([#27](https://github.com/dhannus/HHTTPS/issues/27)): `server/privacy-pass/public/wallet.html` (`doLogin` new-account branch, `registerNewCredential` after recovery, `addCredential`) and `sites/hhttps.html` (`doRegister`, `doAuth`, `doSendEmail`) still called `POST /hhttps/webauthn/register/start` with `{ userId }`, which the e-mail gate answers with `400`/`403 email_verification_required`. The wallet now creates a session (`/hhttps/session/start`), checks `/hhttps/email/status` and — when the e-mail is not confirmed — shows an inline e-mail/code dialog in the auth card (`ensureHhttpsSession()`, `ensureEmailVerified()`, i18n `js.emailFirst`, `js.emailSend`, `js.emailCode`, `js.emailConfirm`, `js.emailOk`), then calls `register/start { sessionId }` (403 gate retried once), `register/finish { userId, response, sessionId }` and `auth/finish { …, priorSessionId }`; a returning user with a passkey (`excludeCredentials` non-empty or `InvalidStateError`) is logged in directly; a `409 identity_conflict` from `confirm-code` on an already logged-in session is shown as sent by the server. The landing page's step 1 is now "confirm your e-mail" (`doSendEmail` → `doConfirmEmail` with the 6-digit code), step 2 registers the passkey on the session, step 3 merges the e-mail session on login; `localStorage.hhttps_uid` is only a cache of the session's stable `userId`. Static tests in `server/test/unit/legacy-pages.test.mjs`, browser test in `server/test/e2e/wallet.e2e.test.mjs` (Playwright, virtual authenticator).

- **OAuth login no longer fails for clients that send a long `state`/`nonce`** ([#31](https://github.com/dhannus/HHTTPS/issues/31)): `authorization_codes.state`, `nonce` and `pkce_challenge` were `VARCHAR(128)` (phase 3a), so a `state` longer than 128 characters (encrypted state blobs are common) made the code insert in `POST /hhttps/oauth/approve` fail with `[DB] Query failed: value too long for type character varying(128)` and the login broke with `401`/`500`. New idempotent migration `server/sql/migration-phase-3a1-authcodes-text.sql` turns the three columns into `TEXT`; the server applies it itself at boot (`BOOT_DDL_FILES`, applied-check via `information_schema.columns.data_type`). Input is validated up front in the new pure module `server/oauth-params.js` (`validateAuthorizeParams`): `state`/`nonce` ≤ 2048 characters, `code_challenge` 43–128 characters of `[A-Za-z0-9._~-]` (RFC 7636 §4.2), `code_challenge_method` ∈ {`S256`, `plain`}. `GET /hhttps/oauth/authorize` answers `302 error=invalid_request` (an over-long `state` is capped in the error redirect), `POST /hhttps/oauth/approve` answers `400 { error:'invalid_request', error_description }`. `approve` now returns `500 { error:'server_error' }` (logged) for internal errors instead of `401` with the raw DB message; token errors stay `401`. Tests in `server/test/unit/oauth-params.test.mjs` and `server/test/integration/oauth-params.test.mjs`; `deploy-phase8.sh` step 7 checks the column type.

### Changed
- **Verification mail**: the 6-digit code is rendered without spaces (`123456`, previously `123 456`) in HTML and text so it can be copied; new light template matching hhttps.org (background `#F9F9F8`, ink `#0A0A0A`, Inter/Syne, pill button); privacy note states truthfully that the address is cached until transferred / for up to 7 days. Platform-registration mails keep the previous dark shell.
- **Code entry is tolerant**: `/hhttps/email/confirm-code` strips whitespace, tabs and hyphens before validating (`"482 913"` → `482913`); anything that is not exactly 6 digits after normalisation → `400`.
- `/hhttps/email/send` keeps only the **last** verification of a session valid.
- Docs: README (tests, migration, scopes/claims), `docs/oauth-integration.md`, `docs/security.md` and `docs/spec.md` no longer claim "zero PII storage"; the storage table lists `identity_anchors`, `identity_claims_cache`, the e-mail context in `challenges` and the e-mail copy on `authorization_codes`.

### Breaking
- **E-mail verification is mandatory and first.** `POST /hhttps/role/declare`, `POST /hhttps/eid/upgrade` and `GET /hhttps/verify/github/start` answer `403 {"error":"email_verification_required"}` for a session without a confirmed e-mail. Passkey, GitHub or EUDI alone no longer yield a token.
- **`POST /hhttps/webauthn/register/start` requires `sessionId`** of an e-mail-verified session; the legacy body `userId` / anonymous registration path is gone (a body `userId` is ignored, the session's stable `userId` is used).
- **`POST /hhttps/webauthn/register/finish` is bound to the email-verified session** ([#23](https://github.com/dhannus/HHTTPS/issues/23), defence in depth): the body now requires `sessionId` (missing → `400 sessionId required`); the session must exist (`404`), be email-verified (`403 email_verification_required`) and its `userId` must equal the body `userId` (otherwise `401 session_user_mismatch`). All checks run before the challenge lookup, so a rejected call never consumes the challenge. Clients that call `register/finish` with `{userId, response}` only must add the `sessionId` they used for `register/start`; `server/public/index.html` (`passkeyRun()`) does. Tests in `gate.test.mjs` and `signin-page.test.mjs`.
- **`POST /hhttps/webauthn/auth/finish`** answers `401 credential_user_mismatch` when the `userId` parked at `auth/start` does not match the credential's owner; a prior session is merged only when it belongs to the same `userId`.
- **`GET /hhttps/email/verify`** (magic link) binds only the session the link was issued for (`session_mismatch` otherwise); code and link must match the address the session requested (`409 email_context_mismatch`).
- **Second address in an anchored session** → `409 email_already_bound`; an anchor that would move a session with a passkey/GitHub/EUDI proof to another identity → `409 identity_conflict` (previously `500`).
- **Dev mail mode is opt-in**: the code is returned in the `/hhttps/email/send` response only with `EMAIL_DEV_MODE=1` and `NODE_ENV !== 'production'`; without a mail transport the endpoint now answers `503 email_transport_unavailable`.
- **`HHTTPS_VERIFICATION_PEPPER` is mandatory in production** — the server refuses to boot without it. It must never be rotated without re-hashing all anchors.
- **Operators must run the OPERATOR section of the phase-8 migration** once; until then existing clients cannot request scope `email` (`invalid_scope`).

### Security
Fixes from the phase-8 review (details in `docs/specs/email-anchored-identity/verifikation.md`):
- **F-1** Anchor binding coupled to the proven address: the consumed verification row must match the parked e-mail context; magic link bound to its originating session (account pre-hijacking via a second `/email/send` or a foreign link).
- **F-2** Passkey session identity taken from the credential row only; body `userId` mismatch → `401`; no merge of foreign prior sessions.
- **F-3** No fail-open dev mode: verification codes leave the API only with `EMAIL_DEV_MODE=1` outside production.
- **F-4** Boot refuses to start in production without `HHTTPS_VERIFICATION_PEPPER` (dictionary-attackable anchors, silent identity loss on rotation).
- **F-5** HTML/subject injection in the verification mail closed: `role` whitelisted against `ROLES`, labels/domain HTML-escaped.
- **F-6** Anchor conflicts answered as `409` instead of `500`; no cross-anchor rebinding of sessions that carry another proof.
- **F-7** Phase-8 migration awaited before `listen`, DDL-only with applied-check; the data update (`allowed_scopes += email`) is no longer run on every boot.
- **F-8** `/hhttps/oauth/approve` enforces the client's `allowed_scopes` like `/authorize` (scope `email` could be obtained by a direct approve call).

## [0.4.1] — 2026-05-11

### Added
- **PostgreSQL persistence**: 12-table schema replaces in-memory storage. Survives restarts, ready for production load.
- **15 societal roles** (up from 8 in v0.4): added `teacher`, `medical_professional`, `caregiver`, `lawyer`, `notary`, `civil_servant`, `craftsman`.
- **22 verification methods** with trust scores from `self-declared` (30) up to `bundestag-verified` (98).
- **Public token verification UI** on `hhttps.org` — anyone can paste a token and see whether it's valid, without registration.
- **HTML viewer** for `/hhttps/info`, `/hhttps/roles`, `/hhttps/stats`, `/.well-known/*` endpoints — browsers see formatted JSON with syntax highlighting; API clients still get raw JSON.
- **Multi-issuer support** in browser extension — JWKS discovery via `/.well-known/hhttps-configuration`.
- **Refresh tokens** (7-day TTL) with automatic refresh 5 minutes before expiry, scheduled via `chrome.alarms` in the extension.
- **Token revocation** with permanent JTI tracking; revocation status published at `/hhttps/revoke/status?jti=...`.
- **Marketing landing page** at `iamhmn.org` with bilingual DE/EN content, three featured use-cases (doctor/lawyer/teacher), and the "Vision" section showing every digital communication marked human/machine/anonymous.
- **Specification page** at `hhttps.org/spec` with full protocol details.
- **Integration examples** for Express, Flask, Django, and Laravel.
- **JavaScript and Python SDKs**.
- **Master deployment script** (`scripts/deploy-all.sh`) that sets up Node, PostgreSQL, Nginx with rate limits, Certbot SSL, and PM2 auto-restart from scratch.
- **Two-layer rate limiting**: Nginx (DoS protection before reaching Node) + Express (fine-grained per-endpoint).

### Changed
- Pretty-printed all JSON responses (`json spaces: 2`).
- Marketing site uses lively colors: vibrant green for verified humans, vibrant blue for verified machines, lavender for intentionally anonymous.
- HHTTPS hub logo in the network visualization is now larger and properly padded.
- Frontend on `hhttps.org` rebuilt with pastel accent colors, animated gradient HHTTPS logotype, larger role icons in verification result.

### Fixed
- Frontend showed only 8 roles instead of all 15 (hardcoded role list was outdated).
- Nginx config script previously failed to inject `ssl_certificate` paths into all server blocks.
- HTTP/2 directive syntax compatible with Nginx ≥ 1.18 (was using newer `http2 on;`).
- Domain config drift detection in deployment script.
- CSS specificity bug on iamhmn.org caused the header CTA button to render dark text on dark background.
- "GEPLANT" badge positioning broken by `transform: scale()` on featured pricing card.

### Removed
- Personal phone number from server's footer.
- Legacy v0.3-roles tag.

## [0.4.0] — 2026-05-06

### Added
- Initial v4 production deployment.
- ES256 asymmetric signing with JWKS endpoint.
- WebAuthn passkey registration and authentication.
- 8 initial roles with email verification.
- Refresh tokens, machine tokens, webhooks.
- Browser extension v1.0.0.

## [0.3.x] — Earlier development

Iterative prototyping; in-memory storage only. Not deployed for production use.

[0.4.1]: https://github.com/dhannus/HumanProof/releases/tag/v0.4.1
[0.4.0]: https://github.com/dhannus/HumanProof/releases/tag/v0.4.0

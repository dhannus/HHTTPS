# Changelog

All notable changes to the HHTTPS protocol and reference implementation are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

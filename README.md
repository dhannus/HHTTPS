# HHTTPS 🔐

> **The protocol for verifying humans on the internet — without surveillance, without ads, without lock-in.**

[![License: EUPL-1.2](https://img.shields.io/badge/License-EUPL_1.2-blue.svg)](https://opensource.org/licenses/EUPL-1.2)
[![Status: Live in Production](https://img.shields.io/badge/Status-Live%20in%20Production-brightgreen)](https://hhttps.org)
[![Built in Public](https://img.shields.io/badge/Built-In%20Public-lightgrey)](https://github.com/dhannus/HHTTPS)

Live: **[hhttps.org](https://hhttps.org)** · Demo platform: **[ask.iamhmn.org](https://ask.iamhmn.org)** · Brand site: **[iamhmn.org](https://iamhmn.org)**

<!-- IMAGE PLACEHOLDER: hero-screenshot.png
     Wide hero shot (1600×800 recommended): hhttps.org main page on the left
     showing a verified identity, ask.iamhmn.org on the right showing a logged-in
     user with their role badge. Diagonal split or side-by-side.
     Caption: "Identity once. Verified everywhere." -->

![HHTTPS in action](docs/images/hero-illustration.svg)

---

## What is HHTTPS?

HHTTPS (Human-verified HTTPS) is an open protocol that lets any platform on the internet verify that the person they're talking to is actually a human — without storing or revealing personal data.

It's built around three ideas:

1. **Identity once, log in everywhere.** A user verifies their identity once (via passkey, ORCID, official ID, etc.) on a HHTTPS issuer. From then on, they can log in to any participating platform with a single click — like "Sign in with Google", but with no Google.

2. **Roles, not names.** Platforms don't get your name, email, or browsing history. They get a *role* (e.g. `developer`, `medical_professional`, `journalist`) and a *trust score* (how strongly that role was verified). That's enough for most platforms to make decisions about content, rate limits, and trust — without invading privacy.

3. **Cryptographic signatures for content.** Beyond login, users can sign text messages they post anywhere (forums, comments, emails) with their HHTTPS identity. Other users with the extension see a small inline seal showing "verified human, role X". Bots cannot fake these seals.

The protocol is the successor to HTTPS for the AI age: HTTPS proves "the server is who it claims to be"; HHTTPS proves "the *person* is who they claim to be — but privacy-preservingly."

---

## How it works (in one minute)

<!-- IMAGE PLACEHOLDER: how-it-works.png
     Three-panel illustration showing the user journey:
     Panel 1: User on hhttps.org doing one-time setup (passkey scan)
     Panel 2: User on a third-party platform clicking "Login with HHTTPS"
     Panel 3: User posting a comment with inline verified seal
     Style: pastel illustrations matching iamhmn.org branding -->

![How HHTTPS works](docs/images/how-it-works.svg)

**Step 1 — Identity setup (once)**
A user visits a HHTTPS issuer (e.g. hhttps.org), verifies their e-mail address (this is the stable identity anchor: same e-mail ⇒ same identity on every device), picks a pseudonym, then adds a passkey and optionally proves a role (developer via GitHub, journalist via press pass, etc.). The issuer stores the role and a trust score. The user's browser stores the identity locally.

**Step 2 — Logging in (one click, anywhere)**
On any platform that supports HHTTPS, the user clicks "Login with HHTTPS". They're briefly redirected to the issuer, click "Allow", and are back on the platform — now logged in with their role and trust score visible to the platform, but nothing personal.

**Step 3 — Signing content (optional)**
With the browser extension installed, users can right-click in any text field to sign their post. A short marker like `#hhttps:s:hp-7K2-XQ9N` appended to their text becomes a green inline seal for other extension users — showing the author's role and trust without revealing their identity.

---

## What works right now

This is not vaporware. As of May 2026:

| Component | Status | Where to see it |
|---|---|---|
| **HHTTPS Issuer** — production server | ✅ Live | [hhttps.org](https://hhttps.org) |
| **Browser Extension** — Chrome/Firefox | ✅ v1.4.3 | `extension/` in this repo |
| **OAuth 2.0 / OpenID Connect Provider** | ✅ Live | [hhttps.org/.well-known/openid-configuration](https://hhttps.org/.well-known/openid-configuration) |
| **Inline content signatures** with domain binding | ✅ Live | Try the extension on any forum |
| **15-role identity system** with trust scoring | ✅ Live | [hhttps.org/hhttps/roles](https://hhttps.org/hhttps/roles) |
| **Federation registry** for self-hosted issuers | ✅ Spec'd | `docs/federation.md` |
| **ask.iamhmn.org** — Q&A demo platform | ✅ Live | [ask.iamhmn.org](https://ask.iamhmn.org) |

You can:
- Visit [hhttps.org](https://hhttps.org), create an identity in 30 seconds with a passkey
- Visit [ask.iamhmn.org](https://ask.iamhmn.org), click "Login with HHTTPS", post a question
- Install the browser extension from `extension/` and sign any comment on any site
- Run your own HHTTPS issuer using the code in `server/`

---

## A note on privacy: pseudonymous, not anonymous

Honesty matters more than marketing. HHTTPS is **privacy-preserving**, but **not zero-knowledge anonymous** in its current form.

What this means concretely:

| Observer | What they can see |
|---|---|
| **A platform** (e.g. ask.iamhmn.org) | A pairwise pseudonymous ID (e.g. `7K2XQ9NMR3F...`), a role, a trust score, the user's pseudonym and which verification methods were used. The verified e-mail address **only** if the platform requested scope `email`, is allowed to, and the user consented. **No** name, **no** IP address. |
| **A different platform** | A *different* pseudonymous ID for the same user. Cross-platform tracking is cryptographically impossible. |
| **Two colluding platforms** | They cannot link their IDs together. The pairwise function is one-way per (user, client) pair. |
| **The HHTTPS issuer** (e.g. hhttps.org) | Knows which user has which pseudonyms on which platforms. Knows *that* you logged in, not *what* you did there. Stores a peppered hash of your e-mail as the stable identity anchor, and the plaintext address for up to 7 days after each verification so it can be passed to platforms you authorise (see [`docs/security.md`](docs/security.md#storage)). |
| **A network observer / bot / hacker** | Sees nothing — there's no public data leakage. |

**The issuer is a trust anchor.** A user who registers on hhttps.org trusts hhttps.org not to misuse the link between their real identity and their pseudonyms. This is the same trust model as eIDAS 2.0 wallets, certificate authorities, or any other federated identity system today.

We chose JWT-based pseudonyms (rather than zero-knowledge proofs) because ZKP tooling is not yet production-ready for civic-tech use. The architecture is designed so that **a future migration to ZKP requires no protocol-level breaking changes** — only the token issuance and verification layer would change. ZKP migration is on the long-term roadmap.

If you need maximum anonymity (e.g. as a whistleblower), HHTTPS in its current form is not the right tool. For most everyday "is this a real human" use cases, the privacy guarantees are stronger than any existing identity system.

---

## Why now

Every month we wait, the gap between human and machine identity grows wider:

- **The EU AI Act is in force** — content must be labeled, but there's no standard tool.
- **eIDAS 2.0 wallets are rolling out** across Europe — but they're heavy-weight ID systems, overkill for "is this a real person".
- **The DSA requires platforms to act on systemic risks** — but provides no infrastructure for them to verify users.
- **Generative AI floods every discourse channel** — democratic conversation, education, mental health support, journalism.

**The window to define this standard is open.** If we don't build it open-source and privacy-first, someone else will build it closed and surveillance-first.

---

## For platform operators: integrate HHTTPS in 10 minutes

If you run a forum, a Q&A site, a comment system, or any platform where you want to verify users are human — adding HHTTPS as a login option takes about 10 minutes.

<!-- IMAGE PLACEHOLDER: integration-flow.png
     Diagram showing: User clicks "Login with HHTTPS" → redirected to issuer →
     consent screen → redirected back with role + trust → platform welcomes user.
     Use the standard OAuth flow visualization with HHTTPS branding. -->

![Integration flow](docs/images/integration-flow.svg)

### Minimum integration

```html
<a href="https://hhttps.org/hhttps/oauth/authorize?
        response_type=code&
        client_id=YOUR_CLIENT_ID&
        redirect_uri=https://yoursite.com/auth/callback&
        scope=openid+role&
        state=RANDOM_STRING&
        code_challenge=PKCE_CHALLENGE&
        code_challenge_method=S256">
  Login with HHTTPS
</a>
```

Then handle the callback: exchange the `code` for a token at `/hhttps/oauth/token`, decode the `id_token` to get the user's role and trust score, store the pairwise subject ID as your user identifier.

Full integration guide with code examples for Node.js, Python, PHP, and plain JavaScript: [`docs/oauth-integration.md`](docs/oauth-integration.md).

Working reference implementation: see [`examples/`](examples/) directory in this repo, or look at how [ask.iamhmn.org](https://ask.iamhmn.org) does it (its source is in a separate repo at [github.com/dhannus/ask-iamhmn](https://github.com/dhannus/ask-iamhmn) once published).

### Register your platform

To use HHTTPS as a login provider, your platform needs a `client_id`. For Phase 1 of the rollout, registration is **double opt-in**:

1. Submit a registration request via [hhttps.org/developers](https://hhttps.org/developers) *(coming with Phase 3b)*
2. You receive a verification email
3. The HHTTPS maintainer reviews your platform manually (domain, Impressum, contact)
4. Your platform appears as `verified` to users — green checkmark in the consent screen

Unverified platforms can still use HHTTPS — they just appear with an amber "Unverified platform" warning to users. This is intentional: low friction for getting started, transparent risk signal for end users.

---

## Core principles

| Principle | Description |
|---|---|
| 🔒 **Privacy by design** | No PII shared with platforms. Pairwise pseudonyms prevent cross-platform tracking. |
| ⚖️ **Open standard** | Protocol is public, auditable, EUPL-1.2 licensed. No single company controls it. |
| 🌐 **Federated** | Anyone can run a HHTTPS issuer. Platforms decide which issuers to trust. |
| 🤝 **Inclusive verification** | Multiple verification methods supported — passkey, ORCID, official ID, organizational vouching. No one is locked out. |
| 🛡️ **Transparent trust** | Issuer is honestly documented as a trust anchor. No hand-waving about "zero-knowledge magic". |
| 🌍 **EU-aligned** | Built for GDPR, DSA, EU AI Act, and eIDAS 2.0 interoperability. |
| 🚫 **No ads, no tracking** | The issuer doesn't profile users. No revenue from user data. |

---

## Repository structure

```
hhttps/
├── server/                    # HHTTPS issuer reference implementation
│   ├── server.js              # Express app: identity issuance, OAuth, signatures
│   ├── db.js                  # PostgreSQL data layer
│   ├── public/                # Web UI (login, verify, identity dashboard)
│   ├── sql/                   # Schema + migrations
│   └── scripts/               # Setup helpers
│
├── extension/                 # Browser extension (Chrome/Firefox/Edge)
│   ├── manifest.json          # MV3 manifest
│   ├── background.js          # Service worker
│   ├── content-universal.js   # Inline seal renderer on all sites
│   ├── content-issuer.js      # Identity sync on hhttps.org
│   ├── popup.html / popup.js  # Extension UI
│   └── icons/
│
├── protocol/                  # Protocol specifications
│   ├── identity-token.md      # JWT identity token format
│   ├── signature-format.md    # Inline signature markers (#hhttps:s:slug)
│   ├── oauth-extension.md     # HHTTPS-specific OAuth/OIDC claims
│   ├── federation.md          # How multi-issuer federation works
│   └── roles.md               # The 15-role taxonomy + verification methods
│
├── docs/                      # Human-facing documentation
│   ├── architecture.md        # System architecture
│   ├── threat-model.md        # Security & privacy analysis
│   ├── roadmap.md             # Project roadmap
│   ├── governance.md          # Decision-making process
│   ├── oauth-integration.md   # Step-by-step guide for platform developers
│   ├── user-stories.md        # Original 10 user stories that drove the design
│   └── images/                # Diagrams, screenshots
│
├── examples/                  # Reference integrations
│   ├── express-login/         # Node.js / Express + OAuth login
│   ├── python-flask/          # Python / Flask + OAuth login
│   ├── php-vanilla/           # Plain PHP integration
│   └── browser-only/          # Pure JS, no backend
│
├── sites/                     # Static marketing pages
│   ├── iamhmn.html            # Bürger-facing landing page (DE/EN)
│   └── hhttps-org.html        # Developer/Protocol landing page
│
├── CONTRIBUTING.md
├── SECURITY.md
├── README.md
└── LICENSE                    # EUPL-1.2
```

---

## Quick start

### Try it as a user

1. Open [hhttps.org](https://hhttps.org)
2. Enter your e-mail address (and optionally a pseudonym), confirm the 6-digit code — this is your stable identity
3. Set up a passkey (uses your device biometrics)
4. Optionally verify a role (developer → GitHub OAuth, journalist → press card, etc.)
5. Try logging in to [ask.iamhmn.org](https://ask.iamhmn.org) — see your role appear next to your posts
6. Install the [browser extension](extension/) → sign text on any forum or comment site

### Try it as a developer (run your own issuer locally)

```bash
git clone https://github.com/dhannus/HHTTPS.git hhttps
cd hhttps/server
bash scripts/install-pg.sh     # sets up local PostgreSQL
npm install
cp .env.example .env           # adjust DB_PASSWORD, set HHTTPS_VERIFICATION_PEPPER
npm run dev                    # starts on port 3000
```

Open `http://localhost:3000` — you have your own HHTTPS issuer. Point the browser extension at it by editing `extension/background.js` to use `http://localhost:3000` instead of `https://hhttps.org`.

Without SMTP you can set `EMAIL_DEV_MODE=1` in `.env` (never in production): the 6-digit verification code is then returned in the `/hhttps/email/send` response instead of being mailed.

**Package manager:** the project uses **npm**. The scripts are plain `package.json` scripts, so `pnpm install` / `pnpm test` / `pnpm lint` work identically if you prefer pnpm. (`server/package-lock.json` is currently git-ignored; don't commit a `pnpm-lock.yaml` either.)

### Migration: phase 8 (email-anchored identity)

Phase 8 adds `identity_anchors`, `identity_claims_cache`, `sessions.pseudonym` and three columns on `authorization_codes`. The migration file `server/sql/migration-phase-8-email-anchored-identity.sql` has two sections:

- **BOOT-DDL** — tables, columns, indexes. The server applies this section itself at boot (once, after an applied-check) and refuses to listen if it fails. Nothing to do.
- **OPERATOR** — the data update (`allowed_scopes += "email"` for every existing OAuth client) and the grants. This part is **never** run automatically. Run it once, deliberately, as the app user:

```bash
PGPASSWORD=$DB_PASSWORD psql -U hhttps -d hhttps -h localhost \
  -f server/sql/migration-phase-8-email-anchored-identity.sql
```

Remove the `UPDATE oauth_clients` block first if you do not want every existing client to be able to request scope `email`. The file is idempotent; running it twice is safe.

### Deploy (srv1421412)

Runbook: `docs/deploy/RUNBOOK-srv1421412-phase8.md`. Skript: `bash server/scripts/deploy-phase8.sh` (`--dry-run` prüft nur; `--link` stellt `/var/www/hhttps` einmalig auf einen Symlink zum Repo um). Das Skript sichert `.env`/`keys/`/DB, zieht `main`, installiert, startet pm2 neu, spielt den OPERATOR-Abschnitt der Phase-8-Migration ein und verifiziert Discovery, Schema und Gates.

## Migration: phase 4b (`machine_operators.key_jkt`, #7)

`server/sql/migration-phase-4b-machine-key-jkt.sql` adds the `key_jkt` column (JWK thumbprint of an operator's optional `publicKeyJwk`) that `/hhttps/machine/register` has been writing without a migration. It is DDL only and the server applies it itself at boot (`db.js`: `BOOT_DDL_FILES`, after an applied-check) — nothing to do; running the file manually via `psql` is safe and idempotent.

## Migration: phase 3a.1 (`authorization_codes` state/nonce/pkce_challenge → TEXT, #31)

`server/sql/migration-phase-3a1-authcodes-text.sql` changes `authorization_codes.state`, `nonce` and `pkce_challenge` from `VARCHAR(128)` to `TEXT` — clients sending longer `state`/`nonce` values previously broke the login with `value too long for type character varying(128)`. DDL only; the server applies it itself at boot (`db.js`: `BOOT_DDL_FILES`, applied when `information_schema` reports the three columns as `text`). Running the file manually via `psql` is safe and idempotent. The server validates the input (`server/oauth-params.js`): `state`/`nonce` up to 2048 characters, `code_challenge` 43–128 characters of `[A-Za-z0-9._~-]`.

### Tests lokal ausführen

The test suite (`node --test`, no extra framework) has unit tests (pure helpers in `identity.js`, mail template, sign-in page) and integration tests that boot `server.js` as a child process against a **local PostgreSQL**. Integration tests are skipped when `TEST_PG_HOST` is not set.

Prerequisites: PostgreSQL ≥ 14 reachable via TCP host or Unix socket directory, database `hhttps`, role `hhttps`. The harness connects with the fixed password `x`, so the role must either accept that password (`ALTER USER hhttps PASSWORD 'x'`) or be trusted in `pg_hba.conf` for the socket/localhost (the reference setup is a throwaway cluster with `trust` under `/var/lib/pgtest`). `bash scripts/install-pg.sh` creates the role with a random password and loads `server/sql/schema.sql`; the earlier migrations (`server/sql/migration-phase-*.sql`) must be applied too. The phase-8, phase-4b and phase-3a.1 DDL is applied by the server itself at boot. Use a throwaway database — integration tests write real rows.

```bash
cd server
npm install
TEST_PG_HOST=/var/lib/pgtest npm test      # socket dir — or TEST_PG_HOST=localhost
TEST_PG_HOST=/var/lib/pgtest npm run test:e2e  # browser tests of the sign-in page (Playwright + Chromium)
npm run lint                               # ESLint 9 flat config, 0 errors required
```

The harness sets `HHTTPS_VERIFICATION_PEPPER=test-pepper`, `EUDI_VERIFIER_SECRET=test-secret` and `EMAIL_DEV_MODE=1` for the child server, so no `.env` is needed for tests. Both gates (`npm test`, `npm run lint`) must pass before a PR.

**Browser E2E (`npm run test:e2e`, #25):** `server/test/e2e/*.e2e.test.mjs` drive the sign-in page (`server/public/index.html`) in headless Chromium via [Playwright](https://playwright.dev) (devDependency) — email-first gating (AK-14), pseudonym + code entry (AK-15, K-7), magic-link return (K-9) and the passkey flow with Chromium's virtual authenticator (K-4). The suite is separate from `npm test` (its glob covers `test/unit` and `test/integration` only), needs the same `TEST_PG_HOST` and is skipped without it. Playwright needs a Chromium build: `npx playwright install chromium` once, or point `PLAYWRIGHT_BROWSERS_PATH` at an existing install (the tests fall back to `/opt/pw-browsers/chromium`). No network is needed — the unpkg scripts the page loads are answered locally (`@simplewebauthn/browser` from the pinned devDependency).

### Integrate HHTTPS into your platform

See [`docs/oauth-integration.md`](docs/oauth-integration.md) and the working examples in [`examples/`](examples/).

---

## Technical specs (current versions)

### Identity Token (JWT, signed by issuer with ES256)

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
  "jti": "<uuid>"
}
```

Full spec: [`protocol/identity-token.md`](protocol/identity-token.md).

### Content Signature Marker (inline in text)

```
#hhttps:s:hp-7K2-XQ9NMR-3F
```

A short slug that references a server-stored signature record. The record contains the signer's role, trust score, content hash, and domain binding. The marker is short enough for Twitter (28 chars), unlinkable across signatures, and resilient to platform-side text mangling.

Full spec: [`protocol/signature-format.md`](protocol/signature-format.md).

### OAuth/OIDC Extension

HHTTPS extends standard OIDC with custom scopes:

| Scope | Claims |
|---|---|
| `openid` (required) | pseudonymous `sub` (stable per platform, derived from the e-mail-anchored `userId`), `iss`, `aud`, standard timestamps — plus, always: `verified_methods`, `email_verified`, `passkey_verified`, `github_verified`, `eudi_verified`, `preferred_username` |
| `role` | `role`, `role_label`, `role_icon`, `trust_score` |
| `verification_method` | `verification_method`, `verification_method_label` |
| `age_group` | `age_group`, `age_verified`, `age_verification_method` |
| `email` | `email` (the verified address, plaintext) + `email_verified: true`. Requires the user's consent on the consent page and is only available to clients whose `allowed_scopes` include `email` (otherwise `invalid_scope`). |

Since phase 8 (*email-anchored identity*) the same verified e-mail always resolves to the same `userId`, so `sub` is stable across devices and logins. The user's pseudonym (`iamhmn_<random>` if none was chosen) is delivered as `preferred_username`.

Example ID-token / `userinfo` payload for `scope=openid role email` (user verified e-mail + passkey):

```json
{
  "iss": "https://hhttps.org",
  "sub": "7K2XQ9NMR3F...",
  "aud": "your-platform",
  "preferred_username": "iamhmn_k3j9x0q2wz",
  "verified_methods": ["email", "passkey"],
  "email_verified": true,
  "passkey_verified": true,
  "github_verified": false,
  "eudi_verified": false,
  "email": "anna@example.org",
  "role": "citizen",
  "role_label": "Citizen",
  "trust_score": 60
}
```

Without scope `email` the `email` claim is absent (the `*_verified` flags and `preferred_username` are always present). `email_verified` is derived from `verified_methods` and therefore `true` for every phase-8 login — e-mail verification is the mandatory first step.

Discovery: `https://hhttps.org/.well-known/openid-configuration`

Full spec: [`protocol/oauth-extension.md`](protocol/oauth-extension.md).

---

## Roadmap

| Phase | Timeline | Status | Goal |
|---|---|---|---|
| **1 — Foundation** | 2025 H2 | ✅ Complete | Issuer server, browser extension, identity token spec |
| **2 — Content signatures** | 2026 Q1 | ✅ Complete | Inline seal protocol, domain binding, anti-theft |
| **2.5 — Slug-based signatures** | 2026 Q1 | ✅ Complete | Anti-theft hardening, token-stealing prevention |
| **3a — OAuth Provider** | 2026 Q2 | ✅ Complete (now) | OpenID Connect, ask.iamhmn.org as first client |
| **3b — Developer self-service** | 2026 Q3 | 🟡 Next | Platform registration UI, admin verification flow |
| **3c — Extension OAuth integration** | 2026 Q3 | 🟡 Planned | Auto-consent for trusted platforms, "my logins" UI |
| **3d — SDKs** | 2026 Q3 | 🟡 Planned | JS / Node / Python / PHP libraries |
| **4 — Federation** | 2026 Q4 | 🟡 Planned | Multi-issuer trust registry, community-verified issuers |
| **5 — Public pilot** | 2027 Q1 | 🔵 Future | Partnership with a public-sector platform (city, ministry, election service) |
| **6 — Standard track** | 2027–2028 | 🔵 Future | Submit to IETF / W3C / national standards body |
| **7 — ZKP migration** | 2028+ | 🔵 Vision | Replace JWT identity layer with zero-knowledge proofs when ZKP tooling matures |

Full roadmap with rationale: [`docs/roadmap.md`](docs/roadmap.md).

---

## Frequently asked questions

**Is this surveillance?**
No. Platforms get pseudonymous IDs, roles, trust scores and a self-chosen pseudonym — the e-mail address only with explicit scope `email` and user consent. Each platform sees a different pairwise `sub` for the same user. The issuer knows which user has which pseudonyms but doesn't see what users do on platforms.

**What's the trust anchor?**
The HHTTPS issuer. By design. We document this honestly rather than hiding behind cryptographic mystique. ZKP migration in the future will remove this trust requirement.

**Can I run my own HHTTPS issuer?**
Yes — the entire server is open source under EUPL-1.2. See [`docs/architecture.md`](docs/architecture.md) for the operator's guide. Your issuer's users will appear with `unverified issuer` warnings on platforms until either the platform whitelists you or the federation registry includes you.

**What about people without digital ID documents?**
HHTTPS uses an **additive trust score**: verified email is the baseline at 30, an added passkey raises it by +30 (so email + passkey = 60), a recognised institutional email domain adds +15 (university, press, association) or +40 (official authorities like @bundestag.de). On top of that, a verified role-specific method takes over as the floor: GitHub or ORCID push the score to 70–88, an EUDI-Wallet role attestation to 95, and bundestag-verified to 98. Every level proves "this is one person" — already enough to defeat bot armies — and higher levels add stronger role assurance. Even the lowest level provides "this is one person" guarantee, which is enough to defeat bot armies.

**Can AI systems still operate on the internet?**
Yes — they get a parallel **Machine Token** that explicitly identifies them as automated agents. Legitimate bots (crawlers, accessibility tools, moderation systems) are made transparent, not banned. See [`protocol/machine-token.md`](protocol/machine-token.md).

**Is this only for the EU?**
The protocol works anywhere. We start EU-aligned because that's where the legal framework (GDPR, DSA, eIDAS 2.0) is most mature.

**Who is behind this?**
Currently one developer based in Germany, building in the open. Looking for collaborators in: cryptography, policy/law, frontend design, journalism. Email at the bottom of this README.

**Why "HHTTPS" — isn't that confusing with HTTPS?**
That's the point. The protocol is positioned as the next-logical-step after HTTPS:
- HTTP — no security
- HTTPS — proves the server is who it claims to be
- **HHTTPS — proves the *human* on the other end is real, privacy-preservingly**

---

## License

[EUPL-1.2](LICENSE) — the European Union Public Licence. Chosen deliberately: designed for public-sector software, compatible with GPL and AGPL, available in all EU languages.

---

## Contact & community

- **Issues:** [GitHub Issues](https://github.com/dhannus/HHTTPS/issues) — bug reports, feature requests, protocol discussions
- **Discussions:** [GitHub Discussions](https://github.com/dhannus/HHTTPS/discussions) — open-ended questions, ideas, proposals
- **Email:** [info@iamhmn.org](mailto:info@iamhmn.org)
- **Mastodon:** *coming soon*
- **Matrix:** *coming soon*

---

> *"The internet needs a way to say: a human was here."*
> Built in public. For everyone. Started in Germany. Intended for the world.

---

HHTTPS is an independent open-source project. Not affiliated with any government agency or commercial entity.

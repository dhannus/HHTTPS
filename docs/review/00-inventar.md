# Review HHTTPS — 00 Bestandsaufnahme

Stand: `main` @ `bf0a82b` (2026-09-15, Merge PR #34), Review-Branch `claude/kind-pasteur-kweqf1`.
Vorgehen nach „Songbird-Review-Agentenpaket v2“: Review-Lead → pro Arbeitspaket vier Reviewer
(Korrektheit, Sicherheit, Performance, Wartbarkeit) → Verifikator → Report → (nach Freigabe) Issues.

## 1. Projektüberblick

| Bereich | Technologie | Umfang |
|---|---|---|
| Server | Node 22 (Prod: Node 20), Express 4, pg 8, @simplewebauthn/server 9, jsonwebtoken 9 (ES256), nodemailer 6, helmet 7, express-rate-limit 7, @cloudflare/voprf-ts | 13.567 LOC JS in `server/` (ohne node_modules) |
| Datenbank | PostgreSQL 16, Schema + 12 Migrationen | 1.034 LOC SQL |
| Frontend | statische HTML/JS-Seiten (`server/public`, `sites`, `developers`, `privacy-pass/public`) | ~10.700 LOC |
| Browser-Extension | MV3, `extension/` | ~1.750 LOC |
| SDKs / Beispiele | `server/sdk/client.{js,py}`, `examples/{express,flask,django,laravel}` | ~800 LOC |
| Tests | node:test (unit + integration, 203 Tests) + Playwright e2e (7 Tests) | 25 Dateien |
| CI | `.github/workflows/ci.yml`: Syntax-Checks (server, extension, examples) — keine Unit-/Integrationstests in CI | |
| Deploy | pm2 `hhttps-v4`, nginx → :3000, `server/scripts/deploy-phase8.sh`, Runbook `docs/deploy/` | |

Monolith-Schwerpunkt: `server/server.js` (4.829 LOC, 68 Routen), `server/db.js` (1.365 LOC), `server/email.js` (885 LOC).

## 2. Einstiegspunkte

- `server/server.js` `main()` (L4776): Keys laden, `db.ensureBootSchema()`, Privacy-Pass-Init, `app.listen(3000)`.
- Router-Mounts: `/privacy-pass` (L523), `/eudi` (L529), `mountPopVerify`, `mountWpPluginRegistration`.
- Öffentliche Endpunkte: `/.well-known/{hhttps-configuration,jwks.json,openid-configuration,hhttps-role-assurance}`.

## 3. Routen-Karte `server/server.js`

| Zeilen | Gruppe | Routen |
|---|---|---|
| 371–530 | Middleware | json/urlencoded 2 MB, cors, helmet, Rate-Limit, Identity-Cookie, static |
| 728–1373 | Discovery, Info, Signaturen | `/.well-known/*`, `/hhttps/info`, `/hhttps/check`, `/hhttps/sign-text`, `/hhttps/verify-text`, `/hhttps/signatures*`, `/s/:slug` |
| 1374–2399 | OAuth/OIDC + Consent | `openid-configuration`, `oauth/authorize`, `oauth/approve`, `oauth/token`, `oauth/userinfo`, `oauth/revoke`, `renderConsentPage` |
| 2400–3096 | Identität / Session / E-Mail / WebAuthn / GitHub | `tokenSurface`, `webauthn/*`, `token/refresh`, `session/email/start`, `session/start`, `email/*`, `verify/github/*` |
| 3097–3767 | Rollen / Alter / eID / Karte / Revoke / Validate | `role/declare`, `age/upgrade`, `age/direct`, `eid/upgrade`, `role/card`, `revoke*`, `validate`, `protected` |
| 3768–3939 | Maschinen / Webhooks | `machine/register`, `machine/token`, `webhooks*` |
| 3940–4775 | Developer-Portal / Admin / Stats | `whoami`, `developers/clients*`, `admin/*`, `stats` |

## 4. Arbeitspakete (AP)

| AP | Modul | Dateien (Zeilenbereiche) | LOC ca. |
|---|---|---|---|
| AP1 | Kern, Middleware, Signaturen, Rollenmodell, Schlüssel | `server/server.js` L1–1373; `server/keys.js`; `server/roles.js`, `roles.eaa.js`, `roles.i18n.js`, `roles.taxonomy*.js`; `server/webhooks.js` | 2.900 |
| AP2 | OAuth 2.1 / OIDC Provider + Consent | `server/server.js` L1374–2399; `server/oauth-params.js`; `server/identity.js` (buildIdentityClaims, methodFlags) | 1.200 |
| AP3 | Identität, Session, E-Mail-Anker, WebAuthn, GitHub-Verify | `server/server.js` L2400–3096; `server/identity.js`; `server/email.js` | 1.800 |
| AP4 | Rollen-/Alters-/eID-Verifikation, Karten, Revoke, Validate, EUDI-Verifier | `server/server.js` L3097–3767; `server/external-verify.js`; `server/eudi-verifier/{index,backend-client,errors}.js`; `server/eudi-verifier/docker/docker-compose.yaml` | 1.900 |
| AP5 | Maschinen-/Workload-Identität, PoP, Webhooks, Developer-Portal, Admin | `server/server.js` L3768–4829; `server/workload-identity.js`; `server/pop-verify.js`; `server/wp-plugin-registration.js`; `developers/*.html`, `developers/assets/*` | 3.000 |
| AP6 | Persistenz, Migrationen, Betrieb | `server/db.js`; `server/sql/*.sql`; `server/privacy-pass/migrations.js`; `server/scripts/*`; `scripts/*`; `.github/workflows/ci.yml`; `server/package.json` | 3.000 |
| AP7 | Privacy Pass (Issuer/Verifier/Wallet) + SDK | `server/privacy-pass/*.js`; `server/privacy-pass/public/wallet.html`; `server/sdk/client.{js,py}` | 3.500 |
| AP8 | Frontend, Sites, Browser-Extension | `server/public/*`; `sites/*.html`; `extension/*` | 9.000 |

Tests (`server/test/**`) werden je AP vom Reviewer „Korrektheit“ auf Abdeckung mitbetrachtet.

## 5. Bekannte offene Punkte (vor dem Review)

- Issues #20, #21, #24 (Follow-ups Feature email-anchored-identity), #30 (Node läuft als root), #32 (Keystore-Passwort in docker-compose).
- 59 ESLint-Warnungen (Legacy) bei 0 Fehlern; siehe `01-automatische-checks.md`.
- CI führt keine Unit-/Integrationstests aus (nur Syntax-Checks).

## 6. Ausgeschlossen

`node_modules`, `examples/**/__pycache__`, Bilder, `docs/**` (Reviewgegenstand ist Code), `server/keys/`, `server/privacy-pass/keys/`.

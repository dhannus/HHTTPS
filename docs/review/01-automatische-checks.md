# Review HHTTPS — 01 Automatische Checks (deterministische Gates)

Stand: `main` @ `bf0a82b`, ausgeführt 2026-09-17 in `server/` mit Node 22.22.2 / npm 10.9.7,
PostgreSQL 16 lokal (`TEST_PG_HOST=/var/lib/pgtest`, `EMAIL_DEV_MODE=1`).

| Gate | Befehl | Ergebnis |
|---|---|---|
| Install | `npm ci` | OK, 220 Pakete; Deprecations: `@simplewebauthn/types@9`, `uuid@9`, `eslint@9.39.5` |
| Unit + Integration | `npm test` | **203 / 203 pass**, 0 fail, 34,5 s |
| E2E (Chromium, virtueller Authenticator) | `npm run test:e2e` | **7 / 7 pass**, 10,9 s |
| Lint | `npx eslint .` | **0 Fehler, 59 Warnungen** (54 `no-unused-vars`, 5 `no-useless-escape`) in 16 Dateien |
| Audit | `npm audit` | **5 Schwachstellen**: 1 high, 3 moderate, 1 low |
| Outdated | `npm outdated` | 11 Pakete hinter „latest“, 2 hinter „wanted“ (`express` 4.22.3, `playwright` 1.63.0) |

## npm audit — Details

| Paket | Installiert | Severity | Advisory (Auszug) | Fix |
|---|---|---|---|---|
| `nodemailer` | 6.10.1 | **high** | 12 Advisories, u. a. SMTP-Command-Injection (GHSA-c7w3-x93f-qmm8, GHSA-vvjj-xcjg-gr5g), Zustellung an fremde Domain (GHSA-mm7p-fcc7-pg87, GHSA-wmmp-3585-3rmp, GHSA-cc9r-2j5m-2m83), DoS addressparser (GHSA-rcmh-qjqh-p98v, GHSA-2x7j-588g-ccc2), Datei-Lesen/SSRF über `raw` (GHSA-p6gq-j5cr-w38f) | `nodemailer@10.0.10` (Major) |
| `qs` (via `express`) | 6.x | moderate | GHSA-x5fp-wj9c-mxmx, GHSA-4mjr-xmp4-gh2g | `npm audit fix` (express 4.22.3) |
| `uuid` | 9.0.1 | moderate | GHSA-w5hq-g745-h8pq (nur v3/v5/v6 mit `buf`; Projekt nutzt v4) | `uuid@14` (Major) oder `crypto.randomUUID()` |
| `@simplewebauthn/server` | 9.0.3 | low | GHSA-6hxq-p678-4hr2 (Attestation-Trust-Anchor; Projekt nutzt `attestationType: 'none'`) | `@simplewebauthn/server@14` (Major) |

Bewertung für den Report: `nodemailer` wird als Security-Finding (AP3) aufgenommen; Ausnutzbarkeit hängt davon ab,
ob Nutzereingaben in Absender/Header/Envelope fließen (Verifikator prüft `server/email.js`).

## npm outdated

| Paket | Current | Wanted | Latest |
|---|---|---|---|
| express | 4.22.2 | 4.22.3 | 5.2.1 |
| express-rate-limit | 7.5.1 | 7.5.1 | 8.7.0 |
| helmet | 7.2.0 | 7.2.0 | 8.3.0 |
| nodemailer | 6.10.1 | 6.10.1 | 10.0.10 |
| @simplewebauthn/server | 9.0.3 | 9.0.3 | 14.0.2 |
| @simplewebauthn/browser | 9.0.1 | 9.0.1 | 14.0.0 |
| uuid | 9.0.1 | 9.0.1 | 14.0.2 |
| eslint / @eslint/js / globals | 9.39.5 / 9.39.5 / 15.15.0 | = | 10.10.0 / 10.0.1 / 17.12.0 |
| playwright | 1.56.1 | 1.63.0 | 1.63.0 |

## ESLint

Vollständige Ausgabe: `docs/review/ap/eslint-output.txt`. Alle 59 Warnungen sind Wartbarkeits-Befunde (S4) und werden
im Report je Modul gesammelt, nicht einzeln als Issue.

## CI-Abgleich

`.github/workflows/ci.yml` prüft nur Syntax (`node --check`), Manifest-JSON und Beispiele. `npm test`, `eslint` und
`npm audit` laufen **nicht** in CI → Befund AP6 (Wartbarkeit).

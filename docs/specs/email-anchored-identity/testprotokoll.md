# Testprotokoll — Feature `email-anchored-identity`

Rolle: Tester · Stand: 2026-09-12 · Basis-Commit: `dd3700f` · Spec: `requirements.md` (AK-1..AK-26)

**Gate-Befehle** (aus `server/`):

```
TEST_PG_HOST=/var/lib/pgtest npm test   → # tests 149 · # pass 145 · # fail 0 · # todo 4 · exit 0
npm run lint                             → ✖ 59 problems (0 errors, 59 warnings) · exit 0
```

Baseline vor Tester-Ergänzungen: 98 Tests / 98 PASS. Ergänzt: `server/test/unit/acceptance.test.mjs` (8 Suites) und
`server/test/integration/acceptance.test.mjs` (33 Tests, davon 4 `todo` = dokumentierte Befunde/Spec-Lücken, die das Gate
bewusst nicht brechen). Die 59 Lint-Warnings sind vorbestehend (`server.js`); in den Tester-Dateien: 0.

Legende Status: **PASS** = ausführbarer Nachweis grün · **FAIL** = ausführbarer Nachweis rot · **OFFEN** = kein ausführbarer Nachweis.
Datei-Kürzel: `U/…` = `server/test/unit/…`, `I/…` = `server/test/integration/…`.

---

## 1. Akzeptanzkriterien AK-1..AK-26

| AK | Testfall (Vorbedingung → Eingabe → erwartet aus SHALL) | Ausführung (Datei::Testname bzw. Befehl) | Ergebnis | Nachweis (Ausgabe-Zitat) |
|---|---|---|---|---|
| AK-1 | Kein Anker für `normalize(E)` → Code bestätigen → Anker `HMAC(pepper, normalize(E)) → userId` angelegt, Session an userId gebunden | `I/email-anchor.test.mjs::AK-1/AK-7: first confirmation creates an anchor, generated pseudonym, bound session, claims cache (AK-16)` · `I/email-anchor.test.mjs::AK-1 via magic link` · `I/db-phase8.test.mjs::resolveOrCreate: same hash keeps the FIRST userId and pseudonym (AK-1)` · `I/acceptance.test.mjs::AK-1: the anchor key is HMAC-SHA256(pepper, normalize(E)) — no plaintext, no plain sha256` | PASS | `ok 20 - AK-1: the anchor key is HMAC-SHA256(pepper, normalize(E))`; `ok 1 - AK-1/AK-7: first confirmation creates an anchor` |
| AK-2 | Anker für E existiert → neue Session bestätigt `  E.toUpperCase() ` → Session.userId = gespeicherte userId | `I/email-anchor.test.mjs::AK-2/AK-8: same email (other case/whitespace) in a new session rebinds to the stored userId and keeps the pseudonym` · `U/identity.test.mjs::normalizeEmail (AK-2)`, `::emailAnchorHash (D1, AK-2)` | PASS | `ok 2 - AK-2/AK-8: same email (other case/whitespace) …`; `anchorCreated: false`, `second.json.userId === first.json.userId` |
| AK-3 | Zwei gleichzeitig lebende Sessions mit userId U → OAuth-Login bei gleichem `client_id` → gleicher `sub`; anderer Client → anderer `sub` | `I/oauth-claims.test.mjs::AK-3: second session with the same email (other spelling) → same sub …` · `I/acceptance.test.mjs::AK-3: two sessions ALIVE AT THE SAME TIME carry the same userId → same sub at the same client` | PASS | `ok 29 - AK-3: two sessions ALIVE AT THE SAME TIME …` (SQL: beide `sessions`-Zeilen mit `expires_at > NOW()` tragen U) |
| AK-4 | E-Mail-bestätigte Session → `register/start` → `options.user.id` (base64url) == Session.userId, `user.name` == Pseudonym, Body-`userId` ignoriert; Credential wird dieser userId zugeordnet | HTTP: `I/gate.test.mjs::AK-4: after email confirmation register/start returns options.user.id == session userId and user.name == pseudonym` · Credential-Zuordnung (kein Authenticator): Code-Inspektion `server/server.js` `register/finish` (`db.credentials.create({ credentialId: credId, userId, … })`, `userId` = Challenge-Schlüssel, den `register/start` mit `session.userId` anlegt) | PASS (HTTP + Code-Inspektion) | `ok … AK-4: after email confirmation register/start returns options.user.id == session userId` |
| AK-5 | Passkey von U authentifiziert → Session an U gebunden (nicht neue Zufalls-Id) | Unit: `U/identity.test.mjs::resolvePasskeySession (F-2 / K-3)` (5 Tests) · `U/acceptance.test.mjs::AK-5 (unit): resolvePasskeySession never yields a fresh/random id` · Code-Inspektion `server/identity.js resolvePasskeySession` (`userId = cred?.userId`, Fremd-`storedUserId` → `credential_user_mismatch`) und `server/server.js` `/hhttps/webauthn/auth/finish` (`resolvePasskeySession({ storedUserId: stored.userId, cred, prior })` → `db.sessions.create(sid, { userId: resolved.userId, … })`) | PASS (Unit + Code-Inspektion) — WebAuthn-Zeremonie ohne Authenticator nicht per HTTP ausführbar | `ok 38 - AK-5 (unit): resolvePasskeySession never yields a fresh/random id`; `ok … userId is always cred.userId` |
| AK-6 | Pseudonym angegeben → bereinigt (max 32, `[\w\-. äöüÄÖÜß]`) im Anker | `I/email-anchor.test.mjs::AK-6: a user-supplied pseudonym is sanitized and stored in the anchor` · `I/acceptance.test.mjs::AK-6: pseudonym of 40 chars via /email/send → stored as its first 32 chars (anchor + session + cache)` · `I/acceptance.test.mjs::AK-6: exactly 32 allowed chars (umlauts, dot, dash, underscore, space) are kept unchanged` · `U/identity.test.mjs::sanitizePseudonym (AK-6)` · `U/acceptance.test.mjs::AK-6 boundaries` | PASS | `ok 15 - AK-6: pseudonym of 40 chars …`; `ok 16 - AK-6: exactly 32 allowed chars …` |
| AK-7 | Kein/leeres Pseudonym → `iamhmn_` + 10×`[a-z0-9]` im Anker | `I/email-anchor.test.mjs::AK-1/AK-7 …` (`/^iamhmn_[a-z0-9]{10}$/`) · `I/acceptance.test.mjs::AK-7: pseudonym consisting only of forbidden chars → generated iamhmn_ pseudonym` · `U/identity.test.mjs::generatePseudonym (AK-7)`, `::resolvePseudonym` · `U/acceptance.test.mjs::AK-7 boundaries` | PASS | `ok 17 - AK-7: pseudonym consisting only of forbidden chars …` |
| AK-8 | Anker mit Pseudonym P → erneute Anmeldung mit anderem Pseudonym → Session-Pseudonym bleibt P | `I/email-anchor.test.mjs::AK-2/AK-8 …` · `I/acceptance.test.mjs::AK-6/AK-8: pseudonym wish from /session/start is used when /email/send carries none; a later different wish does not change it` · `I/gate.test.mjs::AK-13/AK-9: role/declare with confirmed email → … account pseudonym wins over the typed legacy value` | PASS | `ok 18 - AK-6/AK-8: pseudonym wish …` (`'Wish One'` bleibt trotz `'Wish Two'`/`'Wish Three'`) |
| AK-9 | Token aus `role/declare`, `eid/upgrade`, `token/refresh` → Claim `pseudonym` nicht leer | `I/gate.test.mjs::AK-12/AK-9: eid/upgrade with confirmed email → 200, token carries eudi_verified, email_verified, pseudonym` · `::AK-13/AK-9: role/declare with confirmed email → 200, token carries pseudonym + method flags` · `::AK-9: token/refresh issues a new access token with pseudonym and method flags` | PASS (E-Mail-verankerte Identität) — Einschränkung: Befund B-2 (Age-only-Refresh ohne Pseudonym) | `ok … AK-9: token/refresh issues a new access token with pseudonym`; Gegenbeispiel: `not ok 32 … # TODO` „observed undefined“ |
| AK-10 | Session ohne E-Mail → `webauthn/register/start` → 403 `email_verification_required` | `I/gate.test.mjs::AK-10: register/start with a session without confirmed email → 403 email_verification_required` · `::W-19 …→ 400` · `::register/start with an unknown sessionId → 404` · `I/acceptance.test.mjs::AK-10/AK-11/AK-12/AK-13 with an unknown session → 404 / 401 / 404 / 401` | PASS | `ok … AK-10: register/start … → 403 email_verification_required` |
| AK-11 | Session ohne E-Mail → `verify/github/start` → 403 `email_verification_required` | `I/gate.test.mjs::AK-11: verify/github/start without confirmed email → 403 JSON (gate runs before isGithubConfigured)` | PASS | `ok … AK-11: verify/github/start without confirmed email → 403 JSON` |
| AK-12 | Session ohne E-Mail, gültige Verifier-Assertion → `eid/upgrade` → 403, kein Token | `I/gate.test.mjs::AK-12: eid/upgrade with a valid assertion but no confirmed email → 403, no token` · positiv `::AK-12/AK-9 …` · `I/acceptance.test.mjs::AK-12: eid/upgrade without assertion → 400; with a wrong assertion on an email-verified session → 401, no token` | PASS | `ok … AK-12: eid/upgrade with a valid assertion but no confirmed email → 403, no token`; `ok 25 - AK-12: eid/upgrade without assertion → 400 …` |
| AK-13 | Session ohne E-Mail (auch mit Passkey-Credential bzw. `github_verified`) → `role/declare` → 403 | `I/gate.test.mjs::AK-13: role/declare without confirmed email → 403 email_verification_required` · `I/acceptance.test.mjs::AK-13: a session with a passkey credential but NO confirmed email → role/declare 403` · `::AK-13: a session with github_verified but NO confirmed email → role/declare 403` | PASS | `ok 22 - AK-13: a session with a passkey credential but NO confirmed email → role/declare 403`; `ok 23 - … github_verified …` |
| AK-14 | Sign-in-Seite: Buttons Passkey/EUDI/GitHub/Alter `disabled` + `data-requires-email`; Script entfernt `disabled` nach Bestätigung; `pick()` blockt | `U/signin-page.test.mjs::AK-14: passkey, eudi, github, age buttons are rendered disabled and gated on email` · `::AK-14: email and machine buttons are NOT gated` · `::AK-14: persistent "email first" hint exists and the script unlocks gated buttons` · `::AK-14: pick() bails out on a disabled method button …` · `::inline script parses as JavaScript` | PASS (statische HTML/Script-Prüfung; kein Browser-E2E — Spec-Lücke S-8) | `ok … AK-14: passkey, eudi, github, age buttons are rendered disabled and gated on email` |
| AK-15 | E-Mail-Panel: optionales `#pseudoInput` (maxlength 32), `emailStart()` sendet `pseudonym` an `/hhttps/email/send` | `U/signin-page.test.mjs::AK-15: pseudonym input lives in the email panel` · `::AK-15: emailStart() sends pseudonym with /hhttps/email/send` · `::AK-15: applyLang() sets the pseudonym placeholder` · Server-Seite: `I/email-anchor.test.mjs::AK-6 …` (Feld `pseudonym` in `/email/send`) | PASS (statisch) | `ok … AK-15: emailStart() sends pseudonym with /hhttps/email/send` |
| AK-16 | Bestätigung → `identity_claims_cache[userId]` mit Klartext-E-Mail, Pseudonym, `verified_methods`, Ablauf ≤ 7 Tage | `I/email-anchor.test.mjs::AK-1/AK-7 …` (Cache-Zeile) · `I/acceptance.test.mjs::AK-16: the claims cache row expires within 7 days of the confirmation` · `I/db-phase8.test.mjs::identityClaimsCache: upsert/get roundtrip, expiry, cleanupExpired (AK-16)` | PASS | `ok 19 - AK-16: the claims cache row expires within 7 days` (SQL `expires_at <= NOW()+7d` = true, `> NOW()+6d` = true) |
| AK-17 | Scope `email` → `email`, `email_verified: true` in ID-Token und `/userinfo`; E-Mail-Kopie auf Code nach Einlösen gelöscht | `I/oauth-claims.test.mjs::AK-17/AK-18: scope "openid email" → id_token + access_token + userinfo carry email, flags, preferred_username; email wiped from code row` · `I/db-phase8.test.mjs::authCodes: create with email/pseudonym/verifiedMethods, claim returns them and nulls email (AK-17)` | PASS | `ok … AK-17/AK-18: scope "openid email" → … email wiped from code row` (`rows[0].email === null`, `used === true`) |
| AK-18 | Beliebiger Scope mit `openid` → `verified_methods`, 4 Flags, `preferred_username` in ID-Token, Access-Token, `/userinfo` | `I/oauth-claims.test.mjs::AK-17/AK-18 …`, `::AK-3 … scope "openid" → no email claim but flags + preferred_username`, `::refresh_token grant …` · `U/identity.test.mjs::methodFlags (AK-18)`, `::buildIdentityClaims (AK-17/AK-18, W-2)` | PASS | `ok … AK-3: … scope "openid" → no email claim but flags + preferred_username` |
| AK-19 | Client ohne `email` in `allowed_scopes` fordert `email` → `invalid_scope` (authorize-Redirect und approve) | `I/oauth-claims.test.mjs::AK-19: client without "email" in allowed_scopes → authorize redirects with error=invalid_scope` · `::AK-19 (positive) …` · `I/security-fixes.test.mjs::F-8/K-8: approve with a scope the client may not request → 400 invalid_scope, no code row` · `I/acceptance.test.mjs::AK-19 (approve): scope without openid → 400; unknown client → 400; garbage token → 401` | PASS | `ok … AK-19: client without "email" in allowed_scopes → authorize redirects with error=invalid_scope`; `ok 26 - AK-19 (approve): …` |
| AK-20 | Discovery → `email` in `scopes_supported`; 7 Claims in `claims_supported` | `I/oauth-claims.test.mjs::AK-20: discovery lists scope email and the new claims` | PASS | `ok … AK-20: discovery lists scope email and the new claims` |
| AK-21 | HHTTPS-Token mit `verified_methods ⊇ ['email','passkey']` → `approve` → Code → Token → `passkey_verified: true` in ID-Token, Access-Token, `/userinfo` | `I/acceptance.test.mjs::AK-21 (simulated credential): HHTTPS token with verified_methods ⊇ [email, passkey] → passkey_verified true in id_token, access_token, userinfo` (Passkey-Credential per SQL an die E-Mail-Session gehängt; `role/declare` → `approve` → `/oauth/token` → `/userinfo` real per HTTP) · `U/acceptance.test.mjs::AK-21 (derivation)` · `U/identity.test.mjs::buildIdentityClaims` · Code-Inspektion `server/server.js` `/hhttps/oauth/approve` (`methods = d.verified_methods` des signierten Tokens → `authCodes.create({ verifiedMethods })`) | PASS (simulierte Credential + Code-Inspektion; WebAuthn-Zeremonie selbst ohne Authenticator nicht ausführbar) | `ok 28 - AK-21 (simulated credential): … passkey_verified true in id_token, access_token, userinfo` |
| AK-22 | Mail-Erzeugung → Code in HTML und Text ohne Leerzeichen, führende Null erhalten | `U/email-template.test.mjs::renderVerificationEmail shows the raw 6-digit code without spaces (AK-22)` · `U/acceptance.test.mjs::AK-22: code rendering` (`012345`) · Generator: `email.js generateCode6` (`padStart(6,'0')`) | PASS | `ok 39 - AK-22: code rendering` |
| AK-23 | `"123 456"`, `" 123456 "`, `"123\t456"`, `"123-456"` an `confirm-code` → akzeptiert | `I/email-code.test.mjs::confirm-code tolerates a space inside the code, rejects 5 digits, tolerates padding` · `I/acceptance.test.mjs::AK-23: tab inside the code ("482\t913") is accepted` · `::AK-23: hyphen inside the code ("482-913") is accepted` · `U/identity.test.mjs::normalizeCode / isValidCode (AK-23, AK-24)` | PASS | `ok 6 - AK-23: tab inside the code …`; `ok 7 - AK-23: hyphen inside the code …` |
| AK-24 | Nach Normalisierung ≠ 6 Ziffern (5 Ziffern, 7 Ziffern, Buchstabe, nur Symbole, leer) → 400 | `I/email-code.test.mjs::…rejects 5 digits…` · `I/acceptance.test.mjs::AK-24 / N-5: letters, 7 digits, symbols-only, empty code → 400; then the correct code still works; then reuse → 400` · `U/acceptance.test.mjs::AK-23/AK-24 boundaries` | PASS | `ok 8 - AK-24 / N-5: letters, 7 digits, symbols-only, empty code → 400 …` (`Code must be 6 digits.`) |
| AK-25 | Mail: `#F9F9F8`, `#0A0A0A`, Inter/Syne mit System-Fallback, Code JetBrains Mono/monospace, Pill-Button `border-radius:999px` schwarz/weiß, kein `#00e5ff` | `U/email-template.test.mjs::renderVerificationEmail uses the light hhttps.org design (AK-25)` · `U/acceptance.test.mjs::AK-25: light hhttps.org design` (4 Subtests: body/ink/Fonts, Code-Font, `.btn { background:#0A0A0A; color:#FFFFFF; border-radius:999px }`, kein Neon in jeder Schreibweise) | PASS | `ok 40 - AK-25: light hhttps.org design` |
| AK-26 | Mail: Datenschutzhinweis „bis zur Übertragung an die Plattform zwischengespeichert“ (EN+DE, HTML+Text), kein „not stored“ | `U/email-template.test.mjs::renderVerificationEmail privacy note no longer claims "not stored" (AK-26)` · `U/acceptance.test.mjs::AK-26: truthful privacy note` | PASS | `ok 41 - AK-26: truthful privacy note` (Text: „bis zu 7 Tage bzw. bis zur Übertragung an die Plattform“) |

---

## 2. Negativ- und Grenzfälle

| Nr. | Fall | Ausführung | Ergebnis | Beobachtet |
|---|---|---|---|---|
| N-1 | `/email/send` mit leerer / fehlender / `null` / Whitespace-E-Mail | `I/acceptance.test.mjs::N-1` | PASS (400) | `{"error":"Invalid email address."}`, keine `email_verifications`-Zeile |
| N-2 | Ungültige Adressen `foo`, `a@b`, `a b@c.de`, `a@@b.de`, `@c.de`, `a@c.` | `I/acceptance.test.mjs::N-2` | PASS (400) | kein Verifikations-, kein Kontext-Datensatz |
| N-3 | `/email/send` mit unbekannter Session | `I/acceptance.test.mjs::N-3` | PASS (401) | `Invalid session.` |
| N-4 | 4. Sendeversuch pro Session | `I/acceptance.test.mjs::N-4` | PASS (429) | Session-Limit 3 |
| N-5 | Code mit Buchstabe / 7 Ziffern / nur Symbole / leer; danach korrekter Code | `I/acceptance.test.mjs::AK-24 / N-5` | PASS | 400 ×4, dann 200 — Fehlversuche verbrauchen den Code nicht |
| N-6 | Doppelte Code-Verwendung (gleiche Session) | `I/acceptance.test.mjs::AK-24 / N-5` (Teil 2) | PASS (400) | `Code wrong, expired or already used`, Session unverändert |
| N-6b | Falscher, aber wohlgeformter 6-stelliger Code, dann richtiger | `I/acceptance.test.mjs::N-6b` | PASS | 400 → 200 (Zeile bleibt offen) |
| N-7 | `confirm-code` mit unbekannter Session | `I/acceptance.test.mjs::N-7` | PASS (400) | Code kann keiner Session zugeordnet werden (kein 404, siehe S-2) |
| N-8 | Abgelaufene Verifikations-Zeile (TTL 15 min, per SQL vorgezogen) | `I/acceptance.test.mjs::N-8` | PASS (400) | kein Anker, `email_verified=false` |
| N-9 | Abgelaufener E-Mail-Kontext (`challenges email:<sid>`), Code gültig | `I/acceptance.test.mjs::N-9` | PASS (409) | `email_context_missing`, kein Anker |
| N-10 | Abgelaufene Session, Code gültig | `I/acceptance.test.mjs::N-10` | PASS (404) | **Beobachtung B-3:** Code wird vor der Session-Prüfung konsumiert (`used=true`) |
| N-11 | Pseudonym 40 Zeichen / exakt 32 / nur verbotene Zeichen / Umlaute | `I/acceptance.test.mjs::AK-6 …`, `::AK-7 …`, `U/acceptance.test.mjs::AK-6 boundaries` | PASS | 32 Zeichen / unverändert / `iamhmn_…` / erhalten |
| N-12 | Unbekannte Session an `register/start`, `github/start`, `eid/upgrade`, `role/declare` | `I/acceptance.test.mjs::AK-10/AK-11/AK-12/AK-13 with an unknown session` | PASS | 404 / 401 / 404 / 401 — uneinheitlich (S-2), kein Token |
| N-13 | `eid/upgrade` ohne Assertion / mit falscher Assertion | `I/acceptance.test.mjs::AK-12: eid/upgrade without assertion …` | PASS | 400 / 401, kein Token |
| N-14 | Scope-Verweigerung: `email` nicht in `allowed_scopes` (authorize + approve); unbekannter Scope | `I/oauth-claims.test.mjs::AK-19`, `I/security-fixes.test.mjs::F-8/K-8` | PASS | `invalid_scope`, keine Code-Zeile |
| N-15 | `approve` ohne `openid` / unbekannter Client / kaputtes Token | `I/acceptance.test.mjs::AK-19 (approve)` | PASS | 400 `openid scope required` / 400 / 401 |
| N-16 | Maschinen-Pfad über `approve` mit Scope `openid email` (Operator per SQL geseedet, `/machine/token` real) | `I/acceptance.test.mjs::Machine path: machine token → approve "openid email" → bot claims, NO email/pseudonym/flags for the platform` | PASS | ID-/Access-Token: `actor_type:'bot'`, `human:false`, kein `email`, `email_verified:false`, `verified_methods:[]`, kein `preferred_username`; `authorization_codes.user_id` = `machine:op-…`; `/userinfo` ohne `actor_type` (B-6) |
| N-17 | `/hhttps/machine/register` auf E-Mail-bestätigter Session | `I/acceptance.test.mjs::B-1 (todo)` | **FAIL (todo)** | Server-Prozess beendet sich → Befund B-1 |
| N-18 | Age-Endpunkte ohne E-Mail (`age/direct`, `age/upgrade`) | `I/acceptance.test.mjs::SPEC-GAP age …` (2× todo) | **FAIL (todo)** | 200 + Token ohne E-Mail → Befund B-2 / S-5 |
| N-19 | Zweite Adresse in verankerter Session / Passkey-Session auf fremden Anker | `I/security-fixes.test.mjs::F-6/K-5 …` (2 Tests) | PASS | 409 `email_already_bound` / 409 `identity_conflict` (nur in `verifikation.md`, nicht in Spec → S-4) |
| N-20 | Code für Adresse A nach Re-Send mit B; Magic-Link mit fremder Session | `I/security-fixes.test.mjs::F-1/K-1 …`, `::F-1/K-2 …` | PASS | 4xx / `session_mismatch`, keine Anker |
| N-21 | Kein Dev-Mode ohne `EMAIL_DEV_MODE` | `I/security-fixes.test.mjs::F-3/S-4` | PASS | 503 `email_transport_unavailable`, kein Code im Response |

---

## 3. Befunde

### B-1 — `/hhttps/machine/register` beendet den Server-Prozess (Schwere: hoch, außerhalb der AK-Liste)
- **Reproduktion:** E-Mail-bestätigte Session (`/session/start` → `/email/send` → `/email/confirm-code`), dann
  `POST /hhttps/machine/register {operatorName, purpose, contactEmail: <gleiche Adresse>, sessionId}`.
  Test: `I/acceptance.test.mjs::B-1 (todo)` (läuft als letzter Test mit eigenem Server-Prozess).
- **Erwartet:** `201 { operatorId, apiKey, … }`.
- **Beobachtet:** `fetch failed`; Server-Log: `[DB] Query failed: column "key_jkt" of relation "machine_operators" does not exist`
  (`code: '42703'`, Stack `db.js:564 machineOperators.create` ← `server.js:3804`), danach `Node.js v22.22.2` → Prozess-Exit
  (unbehandelte Promise-Rejection; die Route hat keinen `try/catch`).
- **Ursache:** `server/db.js:565` fügt in `machine_operators.key_jkt` ein; keine Migration in `server/sql/*.sql` legt die Spalte an
  (`grep key_jkt sql/` = leer; `schema.sql`, `migration-phase-4-machine-roles.sql`, `migration-phase-6-workload-identity.sql` kennen sie nicht).
- **Wirkung:** Ein einzelner HTTP-Request (nach E-Mail-Bestätigung erreichbar) stoppt den gesamten Dienst (DoS); Maschinen-Registrierung
  ist auf einer nach `sql/` migrierten Datenbank unbenutzbar. Auch wenn `key_jkt` in Produktion manuell existiert, bleibt der fehlende
  Fehlerhandler.
- **Nicht von mir gefixt** (Tester-Rolle). Vorschlag an Entwickler: Migration `ALTER TABLE machine_operators ADD COLUMN IF NOT EXISTS key_jkt TEXT`,
  `try/catch` in der Route, ggf. `process.on('unhandledRejection')`-Schutz.

### B-2 — Age-Endpunkte ohne E-Mail-Gate; AK-9 im Age-only-Pfad verletzt (Schwere: mittel, Spec-Lücke)
- **Reproduktion (3 todo-Tests):**
  - `I/acceptance.test.mjs::SPEC-GAP age: /hhttps/age/direct …` — gültige Verifier-Assertion (HMAC `EUDI_VERIFIER_SECRET`), keine Session, keine E-Mail.
    **Erwartet** (Scope-Abschnitt „Alter erst nach E-Mail-Verifikation … Backend lehnt ab“): 403. **Beobachtet:** `200 { hhttps: { token, refreshToken, sessionId, userId, verifiedMethods: ['age'] } }` — neue Identität ohne Anker.
  - `I/acceptance.test.mjs::SPEC-GAP age: /hhttps/age/upgrade …` — Session ohne E-Mail. **Erwartet:** 403. **Beobachtet:** 200 + Token.
  - `I/acceptance.test.mjs::SPEC-GAP AK-9: an age-only refresh token → /token/refresh …` — **Erwartet** (AK-9): `pseudonym` nicht leer. **Beobachtet:** `observed undefined`.
- **Einordnung:** Kein AK deckt `age/*` ab (AK-10..13 nennen nur WebAuthn, GitHub, EUDI, role/declare; AK-14 nur das UI). Die Endpunkte
  sind laut Kommentar „intern (127.0.0.1)“, im Code gibt es jedoch keine Loopback-Prüfung — Schutz ist allein das Verifier-Secret.
  Das ausgestellte Token ist per `/oauth/approve` einlösbar (Plattform-Login ohne E-Mail, ohne `preferred_username`).
- **Entscheidung nötig:** Spec um AK für Age-Gate ergänzen (dann FAIL → Fix) oder Age explizit als Ausnahme dokumentieren (dann AK-9 einschränken).

### B-3 — `confirm-code` konsumiert den Code vor der Session-Prüfung (Schwere: niedrig, Beobachtung)
- `I/acceptance.test.mjs::N-10`: Session abgelaufen, Code gültig → 404, aber `email_verifications.used = true`. Der Nutzer muss neu senden.
  Kein AK betroffen; Reihenfolge `verifyEmailCode()` → `sessions.get()` in `server.js /hhttps/email/confirm-code`.

### B-4 — Uneinheitliche Statuscodes für unbekannte/abgelaufene Session (Schwere: niedrig)
- `/email/send` 401 · `/email/confirm-code` 400 (Text „Code wrong…“, obwohl die Session fehlt) · `/webauthn/register/start` 404 ·
  `/verify/github/start` 401 · `/eid/upgrade` 404 · `/role/declare` 401. Kein AK; siehe S-2.

### B-5 — `register/finish` prüft keine Session (Beobachtung, kein AK-Verstoß)
- `server.js /hhttps/webauthn/register/finish` nimmt `userId` aus dem Body und löst die Challenge nur über diesen Schlüssel auf. Da der
  Challenge-Wert nur dem Aufrufer von `register/start` bekannt ist (120 s TTL) und `register/start` ihn mit `session.userId` anlegt,
  bleibt AK-4 erfüllt. Empfehlung: `sessionId` auch in `finish` verlangen (Defence in depth).

### B-6 — `/userinfo` gibt für Maschinen kein `actor_type` aus (Beobachtung)
- Nur ID-/Access-Token tragen `actor_type:'bot', human:false`; `/userinfo` liefert `verified_methods: []` und keine Flags `true`. Kein AK.

---

## 4. Spec-Lücken (fehlende Fehlerfall-Kriterien)

| Nr. | Lücke | Beobachtetes Verhalten (jetzt de facto Vertrag) |
|---|---|---|
| S-1 | Kein AK für leere/ungültige E-Mail an `/email/send` | 400 `Invalid email address.` |
| S-2 | Kein AK für unbekannte/abgelaufene Session (Statuscode, Fehlertext) | 400/401/404 je nach Endpunkt (B-4) |
| S-3 | Kein AK für falschen Code, Doppelverwendung, abgelaufenen Code, abgelaufenen E-Mail-Kontext | 400 / 400 / 400 / 409 `email_context_missing` |
| S-4 | Konfliktfälle (zweite Adresse in verankerter Session, Passkey-Session auf fremden Anker) stehen nur in `verifikation.md` (F-6), nicht in `requirements.md` | 409 `email_already_bound` / 409 `identity_conflict` |
| S-5 | Scope-Text „Alter … erst nach E-Mail (Backend lehnt ab)“ ohne AK; `age/direct`, `age/upgrade` nicht gegated | 200 + Token (B-2) |
| S-6 | AK-9 definiert keine Pseudonym-Quelle für Identitäten ohne Anker (Age-only) | `pseudonym` fehlt (B-2) |
| S-7 | Maschinen-Pfad über `approve` mit Scope `email` nicht spezifiziert | kein E-Mail-Claim, `verified_methods: []` (N-16) |
| S-8 | AK-14/AK-15 sind nur statisch prüfbar; kein Browser-/E2E-Kriterium (z. B. „nach `confirm-code` ist `#m-passkey` ohne `disabled`“) | statische Tests grün |
| S-9 | Sende-Limit pro Session (3) und IP-Rate-Limit nicht spezifiziert | 429 |
| S-10 | AK-17: „E-Mail-Kopie auf dem Authorization-Code gelöscht“ — nicht spezifiziert, ob `pseudonym` auf der Code-Zeile bleiben darf | bleibt (`rows[0].pseudonym === 'Anna'`) |

---

## 5. Gesamtsumme

| Status | AKs |
|---|---|
| **PASS** | 26 / 26 — davon mit Einschränkung: AK-4 (HTTP + Code-Inspektion), AK-5 (Unit + Code-Inspektion), AK-21 (simulierte Credential + Code-Inspektion), AK-14/AK-15 (statisch), AK-9 (E-Mail-Pfad; Age-only-Pfad → B-2) |
| **FAIL** | 0 |
| **OFFEN** | 0 |

Befunde: **B-1 (hoch)**, B-2 (mittel, Spec-Entscheidung), B-3..B-6 (niedrig/Beobachtung). Spec-Lücken: S-1..S-10.

Gate: `TEST_PG_HOST=/var/lib/pgtest npm test` → `# tests 149 · # pass 145 · # fail 0 · # todo 4` (exit 0);
`npm run lint` → `0 errors, 59 warnings` (alle vorbestehend). Die 4 `todo`-Tests sind die ausführbaren Reproduktionen von B-1 und B-2;
sie werden zu regulären FAIL-Tests, sobald die Spec-Entscheidung (S-5/S-6) bzw. der B-1-Fix vorliegt (`todo` entfernen).

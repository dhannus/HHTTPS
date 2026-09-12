# Verifikation der Review-Findings `email-anchored-identity`

Basis: Branch `claude/kind-pasteur-kweqf1` @ HEAD `a9e330b`, Diff `git diff main...HEAD`.
Verifikator: statische Analyse + Reproduktion gegen lokale Postgres 16 (`/var/lib/pgtest`).
Reproskripte (nicht im Repo): `scratchpad/verify/{k1,k5}.test.mjs`, P-1 per psql.
Bestehende Suite: **67/67 grün** (`TEST_PG_HOST=/var/lib/pgtest node --test`).

Legende Status: **BESTÄTIGT** / **VERWORFEN** / **TEILWEISE**.
Duplikate zusammengeführt: K-1=S-1, K-3=S-2, K-2=S-3, K-5=S-6, K-8=S-9b, P-2=W-11=S-10,
P-4=W-4, P-7=W-23.

## Ergebnis-Tabelle

| Finding | Status | Beleg / Repro | Schwere (Verifikator) | Fix-Empfehlung (minimal) |
|---|---|---|---|---|
| **K-1 / S-1** Anker-Übernahme | **BESTÄTIGT** | `server.js:2758` /email/send überschreibt `email:<sid>`-Kontext (`db.challenges.create(emailContextId,…)`); `confirm-code` liest den letzten Kontext (`readEmailContext`, 2850). Repro `k1.test.mjs`: Code für A → Anker für **B** angelegt, keiner für A. | **Kritisch** | In `bindSessionToEmailAnchor` den emailHash der konsumierten Verifikationszeile gegen `emailAnchorHash(ctx.email)` prüfen; Kontext an die konkrete Versand-Zeile koppeln (Kontext-Key inkl. Adress-Hash oder Verifikations-Row-ID). |
| **K-3 / S-2** auth/finish userId | **BESTÄTIGT** | `server.js:2507` `userId: stored.userId \|\| cred.userId`; `stored.userId` = Body-`userId` aus auth/start (`2437 challenges.create(sessionId, …, userId,…)`). Repro `k5.test.mjs` Test 2: Angreifer-`userId` landet in der Challenge-Zeile. Roh-`userId` wird als `ouid` im OAuth-Refresh-JWT verteilt (`1848`). | **Kritisch** | `userId: cred.userId` erzwingen; Body-`userId` in auth/start ignorieren oder gegen `cred.userId` prüfen (Mismatch → 401). priorMerge nur bei `prior.userId === cred.userId`. |
| **K-2 / S-3** Magic-Link Session-Bindung | **BESTÄTIGT** | `server.js:2799` /email/verify: `session` aus `req.query`, `result.sessionId` (Mail-Ursprung) nie verglichen; `verifyEmailToken` konsumiert nur per Token. Pre-Hijacking per Opfer-Klick (Kontext = URL-Session). | **Hoch** | `result.sessionId === req.query.session` erzwingen → sonst `session_mismatch`; Anker-Bindung im Link-Pfad an die Ursprungssession koppeln. |
| **S-4** Dev-Mode Fail-open | **BESTÄTIGT** | `email.js:123 createTransport` → ohne SMTP **und** ohne `/usr/sbin/sendmail` `null`; `sendVerificationEmail` liefert `devMode:true, code, rawToken` (369–372); /email/send gibt `devCode/devToken` an den Aufrufer (2790). Kein `NODE_ENV`/`EMAIL_DEV_MODE`-Guard. sendmail-Binary hier real abwesend. | **Hoch** | Dev-Mode nur bei `EMAIL_DEV_MODE=1 && NODE_ENV!=='production'`; sonst 503, kein Code in der Antwort. |
| **S-7** HTML-Injection in Mail (`role`) | **BESTÄTIGT** | `role` aus Body ungeprüft (`server.js:2782`), `roleLabel` gibt unbekannte Rolle roh zurück (`roles.i18n.js:370 ?? roleId`), unescaped in Subject **und** Body (`email.js:282` `<div class="ib-val">${label}</div>`). Repro: `<img src=x onerror=…>` erscheint roh in Subject+HTML. Mail geht an body-`email` (Opferadresse möglich → Phishing vom vertrauenswürdigen Absender). | **Mittel–Hoch** | `role` gegen `ROLES` whitelisten (Default `citizen`); `escapeHtml` auf Label/Domain/Level im Template. |
| **K-5 / S-6** Cross-Anker / Zweitadresse | **BESTÄTIGT** | `identityAnchors.resolveOrCreate` (`db.js:406`) `ON CONFLICT (email_hash)` deckt `UNIQUE(user_id)` nicht ab. Repro `k5.test.mjs` Test 1: 2. Adresse in verankerter Session → **HTTP 500 `anchor_bind_failed`** (23505). Bei fremdem Anker außerdem Session mit `credential` von U1, `userId` U2. | **Mittel** | Vor `resolveOrCreate`: bereits verankerte Session (userId ≠ frische uuid) oder Session mit `credentialId` → 409 `email_already_bound` / `identity_conflict`; kein Rebinding bei vorhandenem Credential. |
| **S-5** Pepper-Fallback in Produktion | **BESTÄTIGT** | `identity.js:15` warnt nur, nutzt `'dev-pepper'`; `external-verify.js:48` wirft dagegen. Ohne Pepper: wörterbuch-angreifbarer Anker, Rotation trennt Anker still. | **Mittel** | In `production` ohne `HHTTPS_VERIFICATION_PEPPER` beim Boot werfen (analog external-verify). |
| **K-6** Boot-Migration nicht awaited | **BESTÄTIGT** | `db.js:396` `ensurePhase8Schema().catch(()=>{})` fire-and-forget beim Import; `main()` (`server.js:4737`) awaitet sie nicht, Fehler verschluckt → `app.listen` vor Migration. | **Mittel** | In `main()` `await db.ensurePhase8Schema()` vor `listen`; bei Fehler `exit(1)`. |
| **K-4** Passkey für Wiederkehrer | **BESTÄTIGT** | UI `passkeyRun` (index.html:585) ruft immer erst `register/start`; `register/start` setzt `excludeCredentials` aus vorhandenen Creds derselben stabilen `userId` (`server.js:2364`) → `InvalidStateError` → catch → generischer Fehler. Wiederkehrer (gleiche E-Mail = gleiche userId) kann Passkey nie nutzen. | **Mittel** | Bei vorhandenen Credentials für die userId direkt `auth/start` statt `register/start`. |
| **K-8 / S-9b** approve ohne allowed_scopes | **BESTÄTIGT** | `/oauth/approve` (`server.js:1490`) prüft nur `openid`; `allowed_scopes`-Check nur in `/authorize` (1462). Direkter approve-Call mit `scope=email` liefert E-Mail auf die Code-Zeile trotz fehlendem Grant (AK-19 verletzt). | **Niedrig–Mittel** | Gleicher `deniedScopes`-Check in approve → 400 `invalid_scope`. |
| **W-7** toter `pseudo:<code>`-Fallback | **BESTÄTIGT** | approve schreibt Challenge nur bei `cleanPseudo && !accountPseudonym` (`1560`); dann ist aber `codePseudonym = accountPseudonym \|\| cleanPseudo = cleanPseudo` (1531) bereits auf der Code-Zeile. In token (`1746`) gewinnt `claimed.pseudonym` → `_preferredUsername` nie load-bearing. | **Niedrig** (Wartbarkeit; Reviewer „hoch") | `pseudo:<code>`-Write in approve und Read in token entfernen; D3 anpassen. |
| **P-1** authCodes.claim CTE | **BESTÄTIGT (Vorschlag valide)** | Ist: `connect()`+BEGIN+2×UPDATE+COMMIT (`db.js:1136`). CTE-Vorschlag in PG16 per psql getestet: `WITH old AS (SELECT email …) UPDATE … SET used=TRUE,email=NULL … RETURNING a.*, (SELECT email FROM old)` liefert `email_before` und setzt `email=NULL` in **einem** Statement (Row nur 1× geändert → zulässig). | **Niedrig** (Perf) | claim() durch das Einzel-Statement (`q(...)`, kein Pool-Client) ersetzen. |
| **P-2 / W-11 / S-10** Boot-Migration mit Datenupdate | **BESTÄTIGT** | `ensurePhase8Schema` führt die **komplette** SQL-Datei bei jedem Boot aus (`db.js:387 readFileSync`), inkl. DDL (ACCESS EXCLUSIVE auf sessions/authorization_codes), `UPDATE oauth_clients … += email` (SQL:65) und `OWNER TO`. Kein Applied-Check; nicht awaited. Opt-out (Block entfernen) wirkungslos, da Boot immer die committete Datei fährt → entferntes `email` je Client wird re-added. | **Mittel** | Applied-Check (information_schema) vor DDL; `UPDATE oauth_clients` aus dem Boot-Pfad in einen expliziten Migrationsschritt; awaiten (s. K-6). |
| **P-4 / W-4** pseudonym nicht in sessions.create | **BESTÄTIGT** | `db.sessions.create` (`db.js:148`) schreibt `pseudonym` nicht; Extra-`update` an 3 Stellen (`server.js:2523, 2637, 2681`). | **Niedrig** (Wartbarkeit) | `pseudonym` als optionale Spalte in `sessions.create`. |
| **P-7 / W-23** Test-Ports/Parallelität | **BESTÄTIGT** | `helpers/server.mjs:122` `port = 3900 + rnd(1000)` (Kollisionsrisiko), je Integrationsdatei eigener Boot; parallele Migrationen. | **Niedrig** | Port 0 / OS-Zuweisung oder Retry; ggf. serielle Suites. |
| **W-1** inline Pseudonym-Sanitizing 4× | **BESTÄTIGT** | `server.js:1530, 2618, 2666, 3008` wiederholen `.replace(/[^\w\-. äöüÄÖÜß]/gu,'')` statt `sanitizePseudonym`. | Niedrig | Überall `sanitizePseudonym` nutzen. |
| **W-2** Identity-Claims-Aufbau 3× | **BESTÄTIGT** | code-grant (`1758`), refresh-grant (`1637`), userinfo (`1887`) bauen dasselbe Bündel. | Niedrig | `buildIdentityClaims` in identity.js. |
| **W-8** session/email/start Duplikat | **TEILWEISE** | Endpoint lebt und wird in `/info` beworben (`833`), aber die UI nutzt nur `/session/start`. Kein toter Code (geroutet), jedoch unbenutztes Duplikat; Kommentar an /session/start ok. | Niedrig | Endpoint entfernen oder als Alias dokumentieren; /info bereinigen. |
| **W-12** .env.example ohne Pepper | **BESTÄTIGT** | `server/.env.example` listet kein `HHTTPS_VERIFICATION_PEPPER`, obwohl es jetzt Identitätsstabilität trägt. | Mittel (Doku) | Pepper mit Warnhinweis ergänzen. |
| **W-13** Lockfile/npm-vs-pnpm | **BESTÄTIGT** | `.gitignore` ignoriert jetzt `server/package-lock.json` (Diff); README/CONTRIBUTING sagen `npm`, tasks/design/STAND `pnpm`; README ohne Test-Abschnitt. | Mittel (Doku) | Lockfile committen, Toolwahl vereinheitlichen, Test-Abschnitt ergänzen. |
| **W-14** email.js Header veraltet | **BESTÄTIGT** | `email.js:5 „legacy flow"`, `:22 „Zero personal data storage."` – nicht mehr wahr (Klartext-Cache). | Mittel (Doku) | Header korrigieren. |
| **W-15** zero-PII-Aussagen unwahr | **BESTÄTIGT** | `docs/security.md:55` „sessions … No (no PII)", Storage-Tabelle nennt `identity_claims_cache` nicht; `docs/spec.md:36` „Zero PII storage."; `server.js:686/2552/3261` „zero-PII"-Kommentare. Klartext-E-Mail wird jetzt gecacht. | Mittel (Doku) | Aussagen zu Klartext-Cache (≤7 Tage) präzisieren; Tabelle ergänzen. |
| **W-16** README/oauth-integration Scope email fehlt | **BESTÄTIGT** | `docs/oauth-integration.md` nur `openid role`; `README.md:292` „three custom scopes" – `email` + neue Claims fehlen. | Mittel (Doku) | Scope `email`, `preferred_username`, `*_verified`, `verified_methods` dokumentieren. |
| **W-17** CHANGELOG ohne Phase-8 | **BESTÄTIGT** | `CHANGELOG.md` Kopf `0.4.1`, kein Phase-8-Eintrag (Breaking: register/start braucht sessionId; 403-Gates; Migration; Env). | Mittel (Doku) | Changelog-Eintrag inkl. Breaking-Hinweise. |
| **W-18** /hhttps/info Katalog veraltet | **BESTÄTIGT** | `server.js:829` listet nicht `email/confirm-code`, `oauth/{authorize,approve,token,userinfo}`, Gates; bewirbt `session/email/start`. | Niedrig (Doku) | Endpoint-Katalog aktualisieren. |
| **W-19** register/start ohne sessionId → 403 | **BESTÄTIGT** | `server.js:2352`: ohne `sessionId` bleibt `session=null` → `requireEmailVerified(null)` → 403 `email_verification_required` statt 400 `sessionId required`. | Niedrig | Fehlt `sessionId` → 400 mit klarer Meldung. |
| **W-30 / (S-8 Datenschutz)** Test-Voraussetzungen / Cache-Wahrheit | **TEILWEISE** | W-30: Testvoraussetzungen nur in `STAND.md` (Textstelle existiert) → BESTÄTIGT (Doku). S-8: `identity_claims_cache`-Zeile wird bei Transfer **nicht** gelöscht (nur `email` auf der Code-Zeile via `claim()`), lebt bis Ablauf ≤7 Tage; Mail-Hinweis „bis zur Übertragung" daher leicht ungenau. | Niedrig (Doku) | Hinweis „bis zu 7 Tage bzw. bis zur Übertragung"; Test-Prereqs in README. |
| **K-7** #emailCode maxlength=6 | **BESTÄTIGT** | `index.html:222 maxlength="6"` → Einfügen von „123 456" wird gekürzt; AK-23-Toleranz im UI unerreichbar (Server toleriert). | Niedrig | `maxlength` entfernen / client-seitig normalisieren. |
| **K-9** Magic-Link-Rückkehr nicht ausgewertet | **BESTÄTIGT** | Kein `location.search`/`URLSearchParams`-Handling in `index.html` (grep leer) → `?email_verify=success&session=…` ignoriert, Methoden bleiben disabled. | Niedrig | URL-Params lesen, sessionId übernehmen, `markConfirmed('email')`. |
| **P-3** confirm-code sequentielle Roundtrips | **TEILWEISE** | Mehrere await-Schritte (verify, session.get, ctx, bind, delete); Detailzahl nicht exakt geprüft. Optimierbar, unkritisch. | Niedrig | Unabhängige Reads/Writes bündeln. |
| **P-5** approve liest Cache stets | **BESTÄTIGT** | `server.js:1540` liest Cache auch ohne Scope `email`/ohne Pseudonym-Bedarf. | Niedrig | Cache-Read nur bei Scope `email` oder fehlendem Token-Pseudonym. |
| **P-6** JWT-Wachstum / redundante Flags | **VERWORFEN** | Die `*_verified`-Booleans **und** `verified_methods` sind durch **AK-18 ausdrücklich gefordert** (beide liefern). Keine Redundanz zum Streichen; JWT-Größe ist Nicht-Ziel. | — | Kein Fix. |
| **W-3/W-5/W-6/W-9/W-10/W-20/W-21/W-22/W-24..W-29** | **BESTÄTIGT (Wartbarkeit, low)** | Textstellen/Muster im Diff vorhanden (Token-Surface 3×; 15-min-TTL doppelt email.js/server.js; kopierte Test-Helfer; toter `&pseudonym=`-Redirect `2795`; `getByUserId` nur in Tests; Cache-TTL 7d vs D5 „=REFRESH_TTL" identisch=7d aber Kommentar; uneinheitliche Fehlerformate; challenges-Zweckentfremdung nicht in design.md; unvollständiges Test-Cleanup / feste Adressen; geteilte-DB-Seiteneffekt; Regex-gekoppelte signin-Tests; doppelte Test-DB-Konfig; doppelte Code-Normalisierung; CSS `.pseudo` ohne Regel). | Niedrig | Sammel-Refactor, nicht deploy-blockierend. |

## Nicht bestätigt / relativiert
- **P-6** verworfen (Spec verlangt beide Claim-Formen, AK-18).
- **W-8** nur teilweise (Endpoint geroutet+beworben, nicht „tot").
- **W-7** bestätigt als toter Fallback, aber Schwere „niedrig" (Wartbarkeit), nicht „hoch".
- **S-8** Datenschutz-Hinweis nur *leicht* ungenau (Cache lebt bis Ablauf, nicht „nur bis Transfer").

## W-20 Detail
`identityClaimsCache.upsert` Default `ttlMs = 7*24*3600*1000` (`db.js:437`) == `REFRESH_TTL` (7d) — D5 „= REFRESH_TTL" ist inhaltlich erfüllt, nur fest verdrahtet statt aus der Konstante abgeleitet. Niedrig.

---

# Priorisierte, deduplizierte Fix-Liste (max. 2 Runden)

## Runde 1 — VOR Deploy zwingend (Sicherheit)

**F-1 (KRITISCH) — Anker-Bindung an den nachgewiesenen Adress-Besitz koppeln.**
Findings: K-1/S-1, K-2/S-3. Dateien: `server/server.js` (`/email/send`, `/email/confirm-code`, `/email/verify`, `bindSessionToEmailAnchor`).
- Kontext an die konkrete Verifikationszeile binden (Kontext-Key inkl. Adress-Hash oder Referenz auf die `email_verifications`-Row); in `bindSessionToEmailAnchor` `emailAnchorHash(ctx.email)` gegen die konsumierte Zeile prüfen (`sha256(normalize(ctx.email))` == `email_verifications.email`).
- `/email/verify`: `result.sessionId === req.query.session` erzwingen, sonst `session_mismatch`.

**F-2 (KRITISCH) — Passkey-Auth an `cred.userId` binden.**
Findings: K-3/S-2. Datei: `server/server.js` (`/webauthn/auth/finish`, `/webauthn/auth/start`).
- `userId: cred.userId` (Body-`userId` aus auth/start verwerfen bzw. gegen `cred.userId` prüfen → Mismatch 401).
- priorMerge nur wenn `prior.userId === cred.userId`.

**F-3 (HOCH) — Dev-Mode nicht in Produktion fail-open.**
Findings: S-4. Datei: `server/email.js` (`createTransport`/`sendVerificationEmail`), ggf. `server.js` /email/send.
- Dev-Antwort (`devCode`/`devToken`) nur bei `EMAIL_DEV_MODE=1 && NODE_ENV!=='production'`; sonst 503 ohne Code.

**F-4 (HOCH) — Pepper in Produktion erzwingen.**
Findings: S-5. Datei: `server/identity.js` (+ Boot in `server.js:main`).
- Ohne `HHTTPS_VERIFICATION_PEPPER` in `production` beim Boot werfen (analog `external-verify.js`).

**F-5 (MITTEL–HOCH) — Mail-Injection schließen.**
Findings: S-7. Dateien: `server/server.js` (/email/send), `server/email.js` (`renderVerificationEmail`).
- `role` gegen `ROLES` whitelisten (Default `citizen`); `escapeHtml` auf Label/Domain/Level/Subject.

**F-6 (MITTEL) — Konflikte sauber beantworten statt 500.**
Findings: K-5/S-6. Dateien: `server/server.js` (`bindSessionToEmailAnchor`), `server/db.js` (`identityAnchors`).
- Vor Rebinding: Session mit `credentialId` oder bereits verankerter `userId` → 409 `email_already_bound`/`identity_conflict`; `UNIQUE(user_id)`-Verstoß abfangen.

**F-7 (MITTEL) — Boot-Migration awaiten + Datenupdate aus dem Boot-Pfad.**
Findings: K-6, P-2/W-11/S-10. Dateien: `server/server.js` (`main`), `server/db.js` (`ensurePhase8Schema`), `server/sql/migration-phase-8-…sql`.
- `await db.ensurePhase8Schema()` vor `listen`, Fehler → `exit(1)`.
- Applied-Check vor DDL; `UPDATE oauth_clients … += email` aus dem Boot-Pfad in einen expliziten, einmaligen Migrationsschritt.

**F-8 (NIEDRIG–MITTEL) — Scope-Check in approve.**
Findings: K-8/S-9b. Datei: `server/server.js` (`/oauth/approve`).
- Gleicher `deniedScopes`-Check wie in `/authorize` → 400 `invalid_scope`.

## Runde 2 — Korrektheit/UX + Wartbarkeit/Doku (nicht deploy-blockierend)

**F-9 (MITTEL, UX) — Passkey für Wiederkehrer.**
Findings: K-4, K-9, K-7. Datei: `server/public/index.html`.
- Bei vorhandenen Credentials direkt `auth/start`; Magic-Link-Rückkehr (`?email_verify=success&session=`) auswerten; `maxlength` am Code-Feld entfernen/normalisieren.
- W-19: `register/start` ohne `sessionId` → 400.

**F-10 (NIEDRIG, Perf/Refactor).**
Findings: P-1, P-3, P-4/W-4, P-5, P-7/W-23, W-1, W-2, W-3, W-5, W-6, W-7. Dateien: `server/db.js`, `server/server.js`, `server/identity.js`, `server/test/helpers/*`.
- `authCodes.claim` → verifizierter Einzel-Statement-CTE.
- `pseudonym` in `sessions.create`; `pseudo:<code>`-Fallback entfernen; `sanitizePseudonym`/`buildIdentityClaims` zentralisieren; Cache-Read in approve nur bei Bedarf; Test-Ports/Helfer entkoppeln.

**F-11 (MITTEL, Doku).**
Findings: W-12..W-18, W-30, S-8, W-8, W-20..W-22, W-24..W-30. Dateien: `server/.env.example`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/security.md`, `docs/spec.md`, `docs/oauth-integration.md`, `server/email.js` (Header), `docs/specs/.../design.md`.
- Pepper in `.env.example`; zero-PII-Aussagen und Storage-Tabelle um `identity_claims_cache` korrigieren; Scope `email` + neue Claims dokumentieren; Phase-8-Changelog; /info-Katalog; Lockfile committen + npm/pnpm vereinheitlichen + Test-Abschnitt; Mail-Datenschutzhinweis „bis zu 7 Tage".

---

### Deploy-Gate
Zwingend vor Deploy (Sicherheit): **F-1, F-2, F-3, F-4, F-5, F-6, F-7, F-8**.
Doku/Wartbarkeit (kann nachgezogen werden): **F-9, F-10, F-11**.

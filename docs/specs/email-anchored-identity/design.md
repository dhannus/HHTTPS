# Design: `email-anchored-identity`

## Betroffene Pakete / Dateien
Alles im Paket `server/` (kein Monorepo-Split): `server.js`, `db.js`, `email.js`, `identity.js` (neu),
`sql/migration-phase-8-email-anchored-identity.sql` (neu), `public/index.html`, `test/**` (neu),
`package.json`, `eslint.config.js` (neu).

## Ist-Zustand (Befund)
- `POST /hhttps/session/start` und `/session/email/start` erzeugen pro Session eine neue `userId = uuid()`; nichts bindet dieselbe Person über Sessions hinweg. `sub = pairwise(userId, clientId)` ist deshalb pro Login anders.
- `webauthn/register/start` erzeugt eine neue `userId`, wenn der Client keine mitgibt; die Sign-in-Seite gibt keine mit → jeder Besuch registriert einen neuen Passkey auf einer neuen Id.
- `oauth/approve` schreibt `verificationMethod: d.roleLevel` (immer `null`); `verified_methods` aus dem HHTTPS-Token werden nicht in den Authorization-Code übernommen → ID-Token/`userinfo` enthalten keine Methoden-Flags. Das ist Daniels beobachteter Fehler („Passkey wird beim Issuer nicht erkannt“).
- `sessions` hat keine Spalte `pseudonym`; `session.pseudonym` wird gelesen, aber nie geschrieben.
- Mail: `codePretty = '123 456'`; `verifyEmailCode` verlangt `^\d{6}$` nach `trim()` → kopierter Code mit Leerzeichen scheitert. Template ist dunkles Neon-Design.
- `createTransport()` liefert auf Linux immer einen `sendmail`-Transport, auch ohne `sendmail`-Binary → kein Dev-Mode, `/email/send` 500. `dotenv` wird importiert, fehlt aber in `package.json`.

## Architektur-Entscheidungen

**D1 — Identitätsanker = HMAC der normalisierten E-Mail.**
Tabelle `identity_anchors(email_hash TEXT PK, user_id TEXT UNIQUE, pseudonym TEXT NOT NULL, created_at, last_seen_at)`.
`email_hash = HMAC-SHA256(pepper, normalize(email))`, `normalize = trim + toLowerCase` (keine Punkt-/Plus-Normalisierung).
Pepper: `HHTTPS_VERIFICATION_PEPPER` (existiert bereits für GitHub-Anker); ohne Pepper Warnung + Fallback `'dev-pepper'` — **nur außerhalb `production`**: F-4 (S-5) `assertPepperConfigured()` lässt den Boot in `NODE_ENV=production` ohne Pepper mit Fehler abbrechen. Der Pepper darf nie ohne Neuberechnung aller `email_hash` rotiert werden (dokumentiert in `.env.example`).
Auflösung ausschließlich nach erfolgreichem Code (bzw. Magic-Link): kein Auto-Linking ohne Besitznachweis (Pre-Hijacking-Schutz aus der Recherche).

**D2 — Session-Umbindung statt Konto-Merge.**
Bei Bestätigung: `anchor = identityAnchors.resolveOrCreate(hash, {userId: session.userId, pseudonym})`. Existiert der Anker, wird `sessions.user_id` auf `anchor.user_id` gesetzt (neue `sessions.update`-Spalten `userId`, `pseudonym`). Die vorher zufällige `userId` der Session wird verworfen (sie trug noch keine Credentials, da andere Methoden erst nach E-Mail freigeschaltet sind).
Klartext-E-Mail bleibt im Anker **nicht** gespeichert (nur Hash); Klartext geht in den Cache (D5).

*Kopplung Kontext ↔ Verifikationszeile (F-1, K-1/S-1, K-2/S-3):* `/email/send` invalidiert zuerst alle offenen `email_verifications` der Session (nur der letzte Versand bleibt gültig) und parkt dann Klartext-Adresse + Pseudonym-Wunsch als Kontext (D5). Beim Einlösen (Code oder Link) prüft `emailContextMatches(ctx, verification)`, dass `sha256(normalize(ctx.email))` gleich dem `email`-Hash der **konsumierten** `email_verifications`-Zeile ist — sonst `409 email_context_mismatch` (bzw. Redirect `reason=email_context_mismatch`). Damit kann ein Code für Adresse A die Session nie an einen Kontext für Adresse B binden. Der Magic-Link (`/email/verify`) bindet ausschließlich die Session, für die er ausgestellt wurde: `result.sessionId !== req.query.session` → `session_mismatch`.

*409-Regeln (F-6, K-5/S-6) in `bindSessionToEmailAnchor`:*
- `email_already_bound` — die Session ist bereits verankert (`session.emailVerified`) und der vorhandene Anker (`identityAnchors.getByUserId`) hat einen anderen `email_hash`. Eine zweite, andere Adresse in derselben Session wird abgelehnt, statt `UNIQUE(user_id)` zu verletzen (vorher 500 `anchor_bind_failed`).
- `identity_conflict` — die Session trägt bereits einen anderen Nachweis (`credentialId`/`hasPasskey`, `githubVerified`, `eudiVerified`) und der aufgelöste Anker gehört zu einer anderen `userId`. Eine Session mit Credential von U1 wird nie still auf U2 umgebunden.
Beide Fehler werden als `409 {error:<code>}` bzw. Redirect `reason=<code>` beantwortet; die Session bleibt unverändert.

**D3 — Pseudonym ist Konto-Eigenschaft.**
Erstanlage: bereinigtes Nutzer-Pseudonym oder generiert `iamhmn_` + 10× `[a-z0-9]` (`crypto.randomInt`). Danach unveränderlich in diesem Feature. Es reist: Anker → Session (`sessions.pseudonym`) → HHTTPS-Access-/Refresh-Token (`pseudonym`) → `oauth/approve` (Token-Wert hat Vorrang vor Consent-Eingabe; Fallback: `identity_claims_cache.pseudonym`, dann die bereinigte Consent-Eingabe) → Authorization-Code (`pseudonym`) → ID-/Access-Token/`userinfo` als `preferred_username`. Die Code-Zeile deckt alle Fälle ab; der frühere `pseudo:<code>`-Challenge-Umweg war tot (W-7, Verifikation: `_preferredUsername` nie load-bearing) und ist in F-10 entfernt — er ist **kein** Teil des Designs mehr. `oauth/token`, der Refresh-Grant und `userinfo` bauen das Claim-Bündel über `buildIdentityClaims({methods, pseudonym, email, scopes})` in `identity.js` (W-2); die HHTTPS-Token-Oberfläche (`verified_methods`, Flags, `domain_name`, `pseudonym`) kommt in `role/declare`, `eid/upgrade`, `token/refresh` aus `tokenSurface()` (W-3).

**D4 — E-Mail-zuerst-Gate serverseitig.**
Helfer `requireEmailVerified(session)` → 403 `{error:'email_verification_required'}` in `webauthn/register/start` (Body-Parameter `sessionId` Pflicht; `userId` wird aus der Session genommen, ein Legacy-`userId`-Body wird ignoriert; W-19, F-10: fehlendes `sessionId` → `400 {error:'sessionId required'}`, erst danach greift das 403-Gate), `verify/github/start`, `eid/upgrade`, `role/declare`. `webauthn/auth/finish` bleibt offen (Nachweis per Passkey), aber F-2 (K-3/S-2): die `userId` kommt ausschließlich aus der Credential-Zeile (`resolvePasskeySession` in `identity.js`); weicht die in `auth/start` geparkte Body-`userId` ab → `401 credential_user_mismatch`; eine `priorSessionId`/`emailSessionId` wird nur gemerged, wenn `prior.userId === cred.userId` (fremde Vorsessions werden weder gemerged noch gelöscht).
UI: Buttons Passkey/EUDI/GitHub/Alter `disabled` bis `markConfirmed('email')`.

**D5 — Klartext-Cache bis zur Übertragung.**
Tabelle `identity_claims_cache(user_id TEXT PK, email TEXT NOT NULL, pseudonym TEXT, verified_methods TEXT (JSON), updated_at, expires_at)`; Upsert bei jeder Code-/Link-Bestätigung; `cleanupExpired` löscht abgelaufene Zeilen.
*Tatsächliche Lebensdauer (W-20, S-8):* `expires_at` = **fest 7 Tage** ab der letzten Bestätigung (`identityClaimsCache.upsert`, Default `ttlMs = 7*24*3600*1000`) — zahlenmäßig gleich `REFRESH_TTL`, aber **nicht** daraus abgeleitet; eine Änderung von `REFRESH_TTL` ändert die Cache-TTL nicht. Die Cache-Zeile wird bei der Übertragung an eine Plattform **nicht** gelöscht (ein Nutzer, der in der Woche mehrere Plattformen anmeldet, wird aus derselben Zeile bedient); gelöscht wird nur durch Ablauf. „Bis zur Übertragung“ gilt für die Kopie auf dem Authorization-Code (s. u.). Datenschutzhinweis in der Mail entsprechend: „bis zur Übertragung, höchstens 7 Tage“.
*E-Mail-Kontext in `challenges` (W-22):* Zwischen `/email/send` und der Bestätigung liegt die Klartext-Adresse zusätzlich als Zeile `email:<sessionId>` in der Tabelle `challenges` (`challenge` = JSON `{email, pseudonym}`, `context = 'email-pending'`, TTL `EMAIL_CONTEXT_TTL_MS` = **15 min** = Gültigkeit der Verifikations-Mail). Grund: `email_verifications` speichert nur `sha256(email)`, AK-16 braucht aber den Klartext für den Cache. Die Zeile wird bei jedem `/email/send` überschrieben und nach erfolgreicher Bindung gelöscht (`db.challenges.delete`), sonst läuft sie ab. Sie ist damit — neben dem Cache und der Code-Zeile — der dritte Ort mit Klartext und in `docs/security.md` (Storage) aufgeführt.
`oauth/approve` liest den Cache per `userId`, schreibt `email` (nur bei Scope `email`), `pseudonym`, `verified_methods` (JSON) in `authorization_codes` (neue Spalten). `oauth/token` überträgt sie in ID-/Access-Token und setzt beim Claim `email = NULL` auf der Code-Zeile (übertragen ⇒ gelöscht; Code-TTL 60 s). `userinfo` liest ausschließlich aus dem Access-Token (stateless wie bisher); beim OAuth-Refresh-Grant reisen die Claims (inkl. `email` bei Scope `email`) im signierten Refresh-JWT (S-9, bewusst stateless, 30 Tage beim Client).
Methoden-Flags: aus `verified_methods` werden `email_verified`, `passkey_verified`, `github_verified`, `eudi_verified` abgeleitet (Helfer `methodFlags(methods)` in `identity.js`). Quelle der Wahrheit für die Methoden ist das signierte HHTTPS-Token (`d.verified_methods`), nicht der Cache; der Cache liefert nur E-Mail (und Pseudonym-Fallback).

**D6 — Scope `email`.**
`SCOPES_KNOWN` + Discovery + Consent-Label erweitert. Der `allowed_scopes`-Check läuft in `/authorize` **und** `/approve` (F-8, K-8/S-9b). Migration hängt `"email"` an `allowed_scopes` bestehender Clients an (Annahme aus der Spec) — seit F-7 (K-6, P-2/W-11/S-10) aber **nur im OPERATOR-Abschnitt** der Migrationsdatei, den der Betreiber einmalig per `psql` ausführt; der Boot (`db.ensurePhase8Schema`, in `main()` vor `listen` awaited, Fehler → `exit(1)`) führt nur den BOOT-DDL-Abschnitt aus, und nur wenn der Applied-Check (`authorization_codes.verified_methods` + `identity_claims_cache`) fehlschlägt. Default für neue Clients (`createDraft`/`create`) enthält `email`.

**D7 — Code-Mail.**
`codePretty` entfällt → `code6` roh. `normalizeCode(input)` entfernt `[\s-]`, dann `^\d{6}$`. Template-Shell für die Verifikations-Mail auf helle Palette umgestellt (Tokens aus `public/index.html`: `--bg #F9F9F8`, `--ink #0A0A0A`, `--ink-2 #5C5C5C`, `--line-subtle #E6E6E4`, Pill-Button). Die Plattform-Registrierungs-Mails (Phase 3b) behalten die alte Shell (Nicht-Ziel) — daher parametrisierte Shell `emailShell({ theme:'light' })`.
Datenschutzhinweis wahrheitsgemäß angepasst (Cache bis Übertragung).

**D8 — Dev-Transport (fail closed, F-3 / S-4).** `createTransport()` nutzt `sendmail` nur, wenn `/usr/sbin/sendmail` existiert. Gibt es weder SMTP noch sendmail, gilt: Dev-Mode (Code/Token/Link in der API-Antwort `devCode`/`devToken`/`devVerifyUrl`) **nur** wenn `emailDevModeAllowed()` = `EMAIL_DEV_MODE === '1' && NODE_ENV !== 'production'`; sonst wirft `sendVerificationEmail` `email_transport_unavailable` und `/email/send` antwortet `503 {error:'email_transport_unavailable'}` ohne Code. Integrationstests setzen `EMAIL_DEV_MODE=1` explizit (`test/helpers/server.mjs`); in Produktion ist die Variable wirkungslos.

**D9 — Test- und Lint-Infrastruktur.**
`node --test` (kein zusätzliches Framework). `test/unit/*.test.mjs` (reine Funktionen aus `identity.js`, `email.js`-Template), `test/integration/*.test.mjs` starten `server.js` als Kindprozess gegen eine lokale Postgres (env `TEST_PG_HOST`, Skip wenn nicht gesetzt) und sprechen HTTP. ESLint 9 Flat-Config, `recommended`, `no-empty` mit `allowEmptyCatch`, `no-unused-vars` als `warn` (Legacy-Code). Gates: `npm test` und `npm run lint` (Paketmanager ist npm mit `package-lock.json`; `pnpm test`/`pnpm lint` laufen identisch — W-13). Voraussetzungen und Aufruf stehen in README („Tests lokal ausführen“) und CONTRIBUTING (W-30).

**D10 — Login-Hint durchreichen (AK-29..AK-32, Songbird).**
`GET /hhttps/oauth/authorize` nimmt `login_hint` (nur wenn `normalizeEmail` + `/^[^\s@]+@[^\s@]+\.[^\s@]+$/` und ≤ 254 Zeichen) und `pseudonym` (`sanitizePseudonym`) in die Consent-Params auf; ungültige Werte werden ohne Fehler weggelassen (nie geechot; die Einbettung läuft über `URLSearchParams` und ist damit URL-kodiert). Die Consent-Seite befüllt `#pseudoInput` per DOM und hängt beide Werte in `relogin()` als eigene Query-Parameter an `/?returnTo=…`. Die Sign-in-Seite (`handleLoginHint()`, nach `handleEmailVerifyReturn()`) öffnet das E-Mail-Panel, befüllt Felder, entfernt `login_hint`/`pseudonym` per `history.replaceState` **vor** dem Senden (kein erneutes Auto-Senden bei Reload; `returnTo` bleibt für `maybeReturnTo()`), und ruft `emailStart()` genau einmal. Der Hint ist nur Vorbefüllung, keine Identitätsbindung — der Code geht nur an die Adresse, die der Nutzer tatsächlich absendet und bestätigt.

## Bewusste Nicht-Ziele
Siehe requirements.md §2. Zusätzlich: kein Umbau des EUDI-Verifiers, keine Pseudonym-Eindeutigkeit, keine Anker-Migration für Alt-Sessions (es gab nie stabile Ids).

## Sicherheitsinvarianten (aus der Recherche, hier durchgesetzt)
1. Linking nur nach Besitznachweis (Code) — AK-1/2; der Nachweis muss zur angefragten Adresse und zur ausstellenden Session gehören (F-1). 2. Kein Auto-Merge auf Selbstauskunft; keine Umbindung einer Session mit fremdem Nachweis (F-6, `identity_conflict`); Passkey-Identität nur aus der Credential-Zeile (F-2). 3. Pseudonym gewährt nichts (AK-8: es identifiziert nicht, es wird nur angezeigt). 4. Codes sind kurzlebig/single-use (bestehend); nur der letzte Versand einer Session ist gültig. 5. Cache-Zeilen ablaufend (fest 7 Tage), E-Mail-Kontext 15 min, E-Mail auf dem Code beim Claim gelöscht. 6. Pepper in Produktion Pflicht (F-4); Dev-Mode nur explizit außerhalb Produktion (F-3); Mail-Inhalte gegen Whitelist/escaped (F-5); `allowed_scopes` auch in `/approve` (F-8).

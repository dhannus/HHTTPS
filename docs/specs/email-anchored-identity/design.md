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
Pepper: `HHTTPS_VERIFICATION_PEPPER` (existiert bereits für GitHub-Anker); ohne Pepper Warnung + Fallback `'dev-pepper'`.
Auflösung ausschließlich nach erfolgreichem Code (bzw. Magic-Link): kein Auto-Linking ohne Besitznachweis (Pre-Hijacking-Schutz aus der Recherche).

**D2 — Session-Umbindung statt Konto-Merge.**
Bei Bestätigung: `anchor = identityAnchors.resolveOrCreate(hash, {userId: session.userId, pseudonym})`. Existiert der Anker, wird `sessions.user_id` auf `anchor.user_id` gesetzt (neue `sessions.update`-Spalten `userId`, `pseudonym`). Die vorher zufällige `userId` der Session wird verworfen (sie trug noch keine Credentials, da andere Methoden erst nach E-Mail freigeschaltet sind).
Klartext-E-Mail bleibt im Anker **nicht** gespeichert (nur Hash); Klartext geht in den Cache (D5).

**D3 — Pseudonym ist Konto-Eigenschaft.**
Erstanlage: bereinigtes Nutzer-Pseudonym oder generiert `iamhmn_` + 10× `[a-z0-9]` (`crypto.randomInt`). Danach unveränderlich in diesem Feature. Es reist: Anker → Session (`sessions.pseudonym`) → HHTTPS-Access-/Refresh-Token (`pseudonym`) → `oauth/approve` (Token-Wert hat Vorrang vor Consent-Eingabe) → Authorization-Code (`pseudonym`) → ID-/Access-Token/`userinfo` als `preferred_username`. Der bisherige `pseudo:<code>`-Challenge-Umweg bleibt als Fallback, wenn das Token kein Pseudonym trägt.

**D4 — E-Mail-zuerst-Gate serverseitig.**
Helfer `requireEmailVerified(session)` → 403 `{error:'email_verification_required'}` in `webauthn/register/start` (neuer Body-Parameter `sessionId`; `userId` wird aus der Session genommen, Legacy-`userId`-Body wird ignoriert wenn `sessionId` vorhanden), `verify/github/start`, `eid/upgrade`, `role/declare`. `webauthn/auth/finish` bleibt offen (Nachweis per Passkey, dessen `cred.userId` bereits stabil ist); die Merge-Logik bleibt.
UI: Buttons Passkey/EUDI/GitHub/Alter `disabled` bis `markConfirmed('email')`.

**D5 — Klartext-Cache bis zur Übertragung.**
Tabelle `identity_claims_cache(user_id TEXT PK, email TEXT NOT NULL, pseudonym TEXT, verified_methods TEXT (JSON), updated_at, expires_at)`; TTL 7 Tage (= REFRESH_TTL), Upsert bei jeder Code-Bestätigung; `cleanupExpired` löscht abgelaufene Zeilen.
`oauth/approve` liest den Cache per `userId`, schreibt `email` (nur bei Scope `email`), `pseudonym`, `verified_methods` (JSON) in `authorization_codes` (neue Spalten). `oauth/token` überträgt sie in ID-/Access-Token und setzt beim Claim `email = NULL` auf der Code-Zeile (übertragen ⇒ gelöscht). `userinfo` liest ausschließlich aus dem Access-Token (stateless wie bisher).
Methoden-Flags: aus `verified_methods` werden `email_verified`, `passkey_verified`, `github_verified`, `eudi_verified` abgeleitet (Helfer `methodFlags(methods)` in `identity.js`). Quelle der Wahrheit für die Methoden ist das signierte HHTTPS-Token (`d.verified_methods`), nicht der Cache; der Cache liefert nur E-Mail (und Pseudonym-Fallback).

**D6 — Scope `email`.**
`SCOPES_KNOWN` + Discovery + Consent-Label erweitert. Migration hängt `"email"` an `allowed_scopes` bestehender Clients an (Annahme aus der Spec); Default für neue Clients (`createDraft`/`create`) enthält `email`.

**D7 — Code-Mail.**
`codePretty` entfällt → `code6` roh. `normalizeCode(input)` entfernt `[\s-]`, dann `^\d{6}$`. Template-Shell für die Verifikations-Mail auf helle Palette umgestellt (Tokens aus `public/index.html`: `--bg #F9F9F8`, `--ink #0A0A0A`, `--ink-2 #5C5C5C`, `--line-subtle #E6E6E4`, Pill-Button). Die Plattform-Registrierungs-Mails (Phase 3b) behalten die alte Shell (Nicht-Ziel) — daher parametrisierte Shell `emailShell({ theme:'light' })`.
Datenschutzhinweis wahrheitsgemäß angepasst (Cache bis Übertragung).

**D8 — Dev-Transport.** `createTransport()` nutzt `sendmail` nur, wenn `/usr/sbin/sendmail` existiert; sonst Dev-Mode (Code in der API-Antwort `devCode`). Damit sind Integrationstests ohne SMTP möglich.

**D9 — Test- und Lint-Infrastruktur.**
`node --test` (kein zusätzliches Framework). `test/unit/*.test.mjs` (reine Funktionen aus `identity.js`, `email.js`-Template), `test/integration/*.test.mjs` starten `server.js` als Kindprozess gegen eine lokale Postgres (env `TEST_PG_HOST`, Skip wenn nicht gesetzt) und sprechen HTTP. ESLint 9 Flat-Config, `recommended`, `no-empty` mit `allowEmptyCatch`, `no-unused-vars` als `warn` (Legacy-Code). Gates: `pnpm test` und `pnpm lint`.

## Bewusste Nicht-Ziele
Siehe requirements.md §2. Zusätzlich: kein Umbau des EUDI-Verifiers, keine Pseudonym-Eindeutigkeit, keine Anker-Migration für Alt-Sessions (es gab nie stabile Ids).

## Sicherheitsinvarianten (aus der Recherche, hier durchgesetzt)
1. Linking nur nach Besitznachweis (Code) — AK-1/2. 2. Kein Auto-Merge auf Selbstauskunft. 3. Pseudonym gewährt nichts (AK-8: es identifiziert nicht, es wird nur angezeigt). 4. Codes sind kurzlebig/single-use (bestehend). 5. Cache-Zeilen ablaufend, E-Mail auf dem Code beim Claim gelöscht.

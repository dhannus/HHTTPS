# AP5 — Korrektheit

Geprüfte Dateien: server/server.js L3768–4829 (/hhttps/machine/*, /hhttps/webhooks*, apexDomain*, authenticatedUser, requireUser, requireAdmin, requirePortalUser, isValidRedirectUri, generateClientId, /hhttps/whoami, /hhttps/developers/*, /hhttps/admin/*, /hhttps/stats, serializeClient*, renderSimplePage, main()); server/workload-identity.js; server/pop-verify.js; server/wp-plugin-registration.js; developers/index.html, register.html, dashboard.html, admin.html, developers/assets/portal.js, portal.css. Zum Verständnis gelesen (keine Findings dort): server/db.js (challenges, tokens, machineOperators, oauthClients, admins, clientStats), server/webhooks.js, server/server.js L640–711 (issueAccessToken, issueRefreshToken, checkTokenValid), server/public/workload.html, server/sql/migration-phase-6-workload-identity.sql, server/test/**.

Stand: `main` @ `bf0a82b`, Zeilennummern per `grep -n`/`sed -n` verifiziert.

---

### [S2] [Korrektheit] server/server.js:L3970-3982 — `authenticatedUser` akzeptiert Refresh-Tokens (7 Tage TTL) als Portal-/Admin-Credential
**Begründung:** `authenticatedUser` ruft `checkTokenValid` (L702–711) auf, das Tokens mit `sub === 'refresh'` ausdrücklich durchlässt (`if (!await db.refreshTokens.get(decoded.jti)) throw …` — sonst OK). Der Refresh-Token trägt laut `issueRefreshToken` (L684–688) `userId`, `role`, `trustScore` und `verified_methods`. Damit liefert L3976 `userId: d.uid || d.userId || d.sub` die echte user_id und L3979 die Methodenliste inkl. `'passkey'`. `requirePortalUser` (L4029) und `requireAdmin` (L3999) unterscheiden nicht nach Token-Typ.
**Auswirkung:** Ein Refresh-Token (Lebensdauer `REFRESH_TTL` = 7 Tage statt 1 h) funktioniert als vollwertiger Bearer für alle `/hhttps/developers/*`- und `/hhttps/admin/*`-Routen sowie `/hhttps/whoami`. Die Trennung „Access-Token = Zugriff, Refresh-Token = nur Erneuerung“ ist im Portal aufgehoben; Revocation des Access-Tokens (z. B. Sign-out über `portal.js` L218–225 revoked zwar beide, aber nur wenn der Client mitspielt) schützt diese Endpunkte nicht.
**Empfehlung:** In `authenticatedUser` nach `checkTokenValid` `if (d.sub === 'refresh') throw new Error('refresh token not accepted as bearer')` (bzw. `sub !== 'human-verified'` prüfen), oder `checkTokenValid` einen Parameter `allowRefresh=false` geben und nur `/hhttps/token/refresh` `true` setzen lassen.

### [S2] [Korrektheit] server/server.js:L4302-4345 + server/db.js:L927-944 / L902-913 — E-Mail-Wechsel bei `verified`-Client führt in einen Zustand, aus dem die E-Mail nie mehr bestätigbar ist
**Begründung:** PATCH mit neuem `contact_email` ruft `updateContactEmail` (db.js L927) auf: `email_verified_at = NULL`, neuer Token, und `verification_status = CASE WHEN 'verified' THEN 'unverified' ELSE 'email_pending' END` (L935–938). Der Klick auf den Bestätigungslink landet in `/hhttps/developers/confirm-email` (L4239) → `confirmEmail` (db.js L902), dessen UPDATE nur bei `verification_status = 'email_pending'` greift (L910). Für den Fall `verified → unverified` ist das UPDATE ein No-op: `email_verified_at` bleibt NULL, `email_token` bleibt gesetzt, die HTML-Seite meldet trotzdem „Email confirmed ✓“ (L4262). Zusätzlich setzt `updateContactEmail` `verified` nicht zurück, d. h. `verified = TRUE` und `verification_status = 'unverified'` stehen gleichzeitig (Consent-Seite L1991 zeigt weiter „Verifizierte Plattform“).
**Auswirkung:** Der Owner kann die Plattform nach einem Mail-Wechsel nie wieder auf `verified` bringen (`submit-review` L4440 verlangt `email_verified_at`, Blocker `email_not_verified` bleibt dauerhaft), der Bestätigungslink lügt, und die Tabelle ist inkonsistent (`verified`-Flag vs. Status). `resend-email` (L4490) ist ebenfalls blockiert, da es Status `email_pending` verlangt.
**Empfehlung:** `updateContactEmail` immer auf `'email_pending'` setzen und `verified = FALSE` mitschreiben (bzw. `confirmEmail` per `WHERE email_verified_at IS NULL` statt Status-Bedingung arbeiten lassen und den Zielstatus aus dem vorherigen Zustand ableiten). Response von `confirm-email` nur bei `rowCount > 0` als Erfolg rendern.

### [S3] [Korrektheit] server/workload-identity.js:L1-260 + server/server.js:L3768-3886 — Workload-Identity-Modul ist nirgends eingebunden; die dazugehörigen Routen existieren nicht, werden aber von UI und Migration referenziert
**Begründung:** `server.js` importiert `workload-identity.js` nicht (grep `workload` in server.js: 0 Treffer); es gibt keine Route `/hhttps/machine/workload/{bind,unbind,list}` und kein `/hhttps/machine/exchange`. Gleichzeitig ruft die ausgelieferte Seite `server/public/workload.html` genau diese Endpunkte auf (L180, L233, L254; L117 dokumentiert `/hhttps/machine/exchange`), und `server/sql/migration-phase-6-workload-identity.sql` beschreibt den Flow als vorhanden.
**Auswirkung:** Alle Aufrufe aus `workload.html` enden mit 404; `bindWorkload`, `findBinding`, `verifyOidcToken` etc. sind toter, ungetesteter Code. Das im Migrations-Header dokumentierte Feature ist nicht erreichbar.
**Empfehlung:** Entweder Router mounten (`mountWorkloadIdentity(app, …)` mit den vier Routen im Machine-Block hinter L3886) und Integrationstests ergänzen, oder Modul, Migration und `workload.html` entfernen bzw. als „nicht aktiv“ kennzeichnen.

### [S3] [Korrektheit] server/pop-verify.js:L110-115 — Check-then-Act auf der PoP-Nonce ohne atomares Löschen → Replay im Parallelfenster
**Begründung:** `verifyPoP` liest die Challenge (`db.challenges.get(chId)`, L111), vergleicht und löscht dann separat (`db.challenges.delete(chId)`, L115). `challenges.delete` (db.js L140) gibt keinen `rowCount` zurück und wird nicht ausgewertet. Zwei gleichzeitige Requests mit demselben PoP-JWS lesen beide die noch vorhandene Nonce und passieren beide.
**Auswirkung:** Die als „single-use“ deklarierte Nonce (Kommentar L115, Kopfzeile L22 „Anti-Replay“) ist im Race-Fenster mehrfach verwendbar; ein abgefangenes PoP-Proof kann innerhalb der 120 s parallel wiederverwendet werden.
**Empfehlung:** `DELETE … WHERE challenge_id = $1 AND challenge = $2 AND expires_at > NOW() RETURNING 1` in einem Statement ausführen und `rowCount === 1` als Erfolgsbedingung verwenden (db.js `challenges.consume(id, value)`).

### [S3] [Korrektheit] server/pop-verify.js:L83 / L136 — PoP-Pfad nutzt `verifyToken` statt `checkTokenValid`: widerrufene/abgelaufene DB-Tokens werden akzeptiert
**Begründung:** `mountPopVerify` bekommt aus `main()` (server.js L4807) nur `verifyToken` (Signatur + `exp`). `/hhttps/pop/challenge` (L136) und `verifyPoP` (L83) prüfen daher weder `revoked_tokens` noch `tokens.exists(jti)`, anders als jede andere tokenprüfende Route (`checkTokenValid`, server.js L702).
**Auswirkung:** Ein per `/hhttps/revoke` widerrufener Maschinen-Token besteht den PoP-Nachweis weiterhin, solange die JWT-Signatur gültig ist; die Revocation-Semantik des Servers gilt für PoP-geschützte Endpunkte nicht.
**Empfehlung:** `checkTokenValid` (async) statt `verifyToken` in die Deps geben und `verifyPoP`/`/pop/challenge` `await verifyToken(token)` verwenden lassen.

### [S3] [Korrektheit] server/server.js:L4362-4369 + server/db.js:L1085-1092 vs. developers/dashboard.html:L252-253 — Dashboard bietet „Delete“ für `unverified` an, Server lehnt es mit 409 ab
**Begründung:** `deleteIfDraft` löscht nur `verification_status IN ('draft','email_pending')` (db.js L1090). Das Dashboard zeigt den Löschen-Button für `email_pending` **und** `unverified` (dashboard.html L252–253: `canDelete = … 'email_pending' || … 'unverified'`).
**Auswirkung:** Für jede Plattform mit bestätigter E-Mail erscheint ein Delete-Button, der immer mit `cannot_delete` (409) fehlschlägt. Der Nutzer kann eine noch nie geprüfte Plattform nicht loswerden; 3-pro-Tag-Limit (L4160) wird durch Karteileichen verbraucht.
**Empfehlung:** Server und UI angleichen — entweder `'unverified'` in `deleteIfDraft` aufnehmen (sinnvoll: noch nicht reviewt) oder `canDelete` in dashboard.html auf `email_pending` beschränken.

### [S3] [Korrektheit] server/server.js:L4353-4356 + server/db.js:L946-957 — PATCH kann `description`/`logo_url` nicht leeren; UI meldet trotzdem „Saved ✓“
**Begründung:** Das Dashboard sendet beim Leeren der Felder `description: null` und `logo_url: null` (dashboard.html L419–425). `updateMetadata` schreibt `COALESCE($3, description)` bzw. `COALESCE($5, logo_url)` mit `description || null` / `logoUrl || null` (db.js L954–956) — `null` bedeutet „nicht ändern“, nicht „löschen“. Die Route validiert `description === null` sogar explizit als zulässig (L4316).
**Auswirkung:** Ein gelöschtes Logo/eine gelöschte Beschreibung bleibt in der DB und wird weiter auf der Consent-Seite gezeigt; Antwort ist 200 mit dem alten Wert, das Frontend meldet Erfolg.
**Empfehlung:** In der Route zwischen `undefined` (nicht ändern) und `null` (leeren) unterscheiden und `updateMetadata` nur die tatsächlich übergebenen Spalten dynamisch setzen (kein COALESCE).

### [S3] [Korrektheit] server/server.js:L4587-4620 — `reject`/`suspend` ohne Zustandsprüfung; verlässt die dokumentierte Zustandsmaschine
**Begründung:** Die Zustandsmaschine (Kommentar L3926–3939) erlaubt `pending_review → rejected` und `verified/unverified/pending_review → suspended`. `approve` prüft den Status (L4568), `reject` (L4593–4594) und `suspend` (L4614–4615) nicht: `adminReject`/`adminSuspend` überschreiben jeden Status, auch `email_pending`, `rejected` oder `suspended` (Grund wird dabei überschrieben, `reviewed_at` neu gesetzt).
**Auswirkung:** Ein Client in `email_pending` kann nach `suspend` weder gelöscht (`deleteIfDraft`) noch die Mail erneut angefordert werden (`resend-email` verlangt `email_pending`); der Owner ist ohne Weg zurück. Ein `rejected`-Client kann erneut „rejected“ werden, wodurch der ursprüngliche Grund im Audit-Log-Detail zwar liegt, in der Tabelle aber verloren geht.
**Empfehlung:** Wie bei `approve` einen Guard einbauen: `reject` nur aus `pending_review`, `suspend` nur aus `verified|unverified|pending_review`, sonst 409 `wrong_state`.

### [S3] [Korrektheit] server/server.js:L3889-3891, L3906-3910, L4080-4116, L4239-4275, L4280-4299, L4302-4358, L4362-4369, L4373-4438, L4440-4488, L4537-4553, L4555-4653 + server/pop-verify.js:L132-169 + server/wp-plugin-registration.js:L195-281 — async Handler ohne try/catch: DB-Fehler lassen den Request hängen
**Begründung:** Express 4 fängt Rejections aus `async`-Handlern nicht. Nur `/machine/register`, `/machine/token` und POST `/webhooks` haben try/catch; alle anderen Routen des Pakets (Webhooks GET/DELETE, whoami, developers/*, admin/*, /hhttps/stats L4735, pop/*, plugin/*) rufen `await db.…` ungeschützt auf. Der globale `process.on('unhandledRejection')` (L4820) loggt nur — es wird keine Antwort gesendet. Konkrete Auslöser ohne Angreiferaufwand: `?token=a&token=b` an `/developers/confirm-email` (L4240: `token` ist dann ein Array → pg-Parameterfehler), `?status[]=x` an `/admin/clients` (L4625), `?days=abc` an `/developers/clients/:id/stats` (L4544: `Math.min(NaN, 90)` → `'NaN days'::interval` → SQL-Fehler).
**Auswirkung:** Der Client wartet bis zum Socket-Timeout (nginx 60 s) auf eine Antwort statt 500 zu bekommen; im Portal bleibt der Button „Saving…“/„Loading…“ hängen. Bei DB-Ausfall keine saubere Fehlerantwort.
**Empfehlung:** Einen `wrap = fn => (req,res,next) => fn(req,res,next).catch(next)`-Helper einführen und alle async-Routen damit registrieren plus einen Express-Error-Handler mit `res.status(500).json({error:'internal'})`; Query-Parameter mit `typeof === 'string'` bzw. `Number.isFinite` validieren.

### [S3] [Korrektheit] server/server.js:L3768-3833 (Machine-Register) — fehlende Tests für die zentralen AP5-Fehlerpfade
**Begründung:** `server/test/**` enthält keinen einzigen Test für `/hhttps/developers/*`, `/hhttps/admin/*`, `/hhttps/whoami`, `/hhttps/webhooks*`, `/hhttps/pop/*` und `/hhttps/plugin/*` (grep über `server/test`: 0 Treffer). Getestet sind nur `/machine/token` (Happy-Path, acceptance L443) und `/machine/register` (201, acceptance L573). Ungetestet sind damit u. a.: die Zustandsmaschine (E-Mail-Wechsel → confirm, Finding oben), `deleteIfDraft`-Status, PoP-Nonce-Single-Use, WP-Auto-Approval-Bedingung (wp-plugin-registration.js L266–273), `requirePortalUser` mit Refresh-Token.
**Auswirkung:** Die beiden S2-Findings und mehrere S3 in diesem Paket wären mit einfachen Integrationstests aufgefallen; Regressionen im Portal bleiben unbemerkt (CI führt zudem gar keine Tests aus, siehe 01-automatische-checks.md).
**Empfehlung:** Integrationsdatei `developers.test.mjs` mit: Register→Confirm→DNS(mock)→Submit→Approve, E-Mail-Wechsel auf `verified`, Delete in jedem Status, Refresh-Token an `/whoami` → 401; `pop.test.mjs` mit doppelter Nonce-Verwendung.

### [S3] [Korrektheit] server/server.js:L3816-3820 — ungültiges `publicKeyJwk` wird stillschweigend verworfen; Operator glaubt, sein Key sei gebunden
**Begründung:** `jwkThumbprint(publicKeyJwk)` (L82–89) gibt bei jedem nicht-P-256-EC-JWK oder Tippfehler `null` zurück; `machineOperators.create` speichert `key_jkt = NULL`. Die 201-Antwort (L3822–3831) enthält keinen Hinweis, ob ein Thumbprint gespeichert wurde; erst `/machine/token` liefert dann ein Token ohne `cnf` (L3865), und `/pop/challenge` antwortet `token_not_bound`.
**Auswirkung:** Ein Operator, der ein (z. B. RSA- oder falsch serialisiertes) JWK mitschickt, bekommt nie ein PoP-fähiges Token und muss neu registrieren (neuer `operatorId`/`apiKey`), da es keine Update-Route für den Key gibt.
**Empfehlung:** Wenn `publicKeyJwk` gesetzt, aber `keyJkt === null` → 400 `invalid_public_key_jwk`; `keyJkt` in der Antwort zurückgeben.

### [S4] [Korrektheit] server/server.js:L3912-3918 — `/hhttps/webhooks/verify` wirft bei nicht-String-Eingaben (500 statt 400)
**Begründung:** `payload`, `signature`, `secret` werden nur auf Truthiness geprüft; `crypto.createHmac('sha256', secret).update(payload)` wirft `TypeError` bei Objekt/Zahl (`{"payload":{"a":1},"secret":1,…}`). Der Handler ist synchron, Express antwortet mit 500-HTML.
**Auswirkung:** Falsche Statusklasse; kein Sicherheitsproblem.
**Empfehlung:** `typeof … !== 'string'` → 400 prüfen; Vergleich per `crypto.timingSafeEqual` (gleiche Länge vorausgesetzt).

### [S4] [Korrektheit] server/server.js:L3893-3904 + server/webhooks.js:L20 — `events` ohne Array-Prüfung → 400 mit interner Fehlermeldung
**Begründung:** `const { events = ['*'] } = req.body` greift nur bei `undefined`; bei `"events":"token.issued"` oder `null` wirft `events.find` in `registerWebhook` einen `TypeError`, der als `{ error: 'events.find is not a function' }` zurückgegeben wird.
**Auswirkung:** Unklare API-Fehlermeldung; Status 400 stimmt zufällig.
**Empfehlung:** `if (!Array.isArray(events)) return 400 'events must be an array'` in der Route.

### [S4] [Korrektheit] server/wp-plugin-registration.js:L116-120 — Fehlermeldung „must be a valid HTTPS URL“ deckt sich nicht mit der Prüfung
**Begründung:** `apexDomainFromUrl` (L38–51) hängt bei fehlendem Schema `https://` davor und akzeptiert `http://…` ebenso; geprüft wird nur, ob ein Apex ermittelbar ist. Gleiches gilt für server.js L4131 (`apexDomainFromUrl` L3941–3949 nimmt jeden Hostnamen). `homepage_url = "http://example.org"` oder `"example.org"` passiert, `setupUrl` (L165) und `confirm-email`-Link (server.js L4257) werden dann aus einem Nicht-https-/schemalosen Wert gebaut.
**Auswirkung:** Irreführende Fehlermeldung; bei schemalosem Wert entsteht ein relativer `setupUrl` („example.org/wp-admin/…“) in der Bestätigungsmail.
**Empfehlung:** `new URL(homepage_url).protocol === 'https:'` erzwingen oder die Meldung anpassen.

### [S4] [Korrektheit] server/server.js:L4544 — `days`-Parameter ohne Untergrenze/NaN-Schutz
**Begründung:** `Math.min(parseInt(req.query.days || '30', 10), 90)` erlaubt `0`, negative Werte und `NaN` (siehe try/catch-Finding); `'-5 days'::interval` liefert Zukunftsdaten, `0` liefert nur heute.
**Auswirkung:** Leere/unsinnige Statistik statt 400; bei `NaN` SQL-Fehler.
**Empfehlung:** `Number.isInteger(days) && days >= 1 && days <= 90`, sonst 400 oder Default 30.

---

## Zusammenfassung

| Severity | Anzahl |
|---|---|
| S1 | 0 |
| S2 | 2 |
| S3 | 9 |
| S4 | 4 |

Gesamteindruck: Der Maschinen-/PoP-Kern (Thumbprint, ES256-JWS-Verifikation, DER-Encoding, htu/htm-Bindung) ist sauber und nachvollziehbar implementiert; die Register-/Token-Routen sind nach #7 korrekt gegen DB-Fehler abgesichert. Die Schwächen liegen in der Zustandsführung des Developer-Portals (E-Mail-Wechsel bei verifizierten Clients endet in einer Sackgasse, Admin-Aktionen ignorieren die Zustandsmaschine, UI und Server erlauben unterschiedliche Aktionen) sowie in der Token-Typ-Prüfung: `authenticatedUser` behandelt Refresh-Tokens wie Access-Tokens. Dazu kommt totes, aber von UI und Migration referenziertes Workload-Identity-Modul und das vollständige Fehlen von Tests für Portal, Admin, Webhooks, PoP und Plugin-Registrierung.

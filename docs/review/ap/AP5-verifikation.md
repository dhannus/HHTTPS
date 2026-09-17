# AP5 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b (HEAD 6804b89 enthält nur docs/-Änderungen; `git diff --stat bf0a82b HEAD -- server developers` ist leer, Zeilennummern gelten unverändert)

Methode: Jede Datei:Zeile per `sed -n`/`grep -n` geöffnet; Behauptungen zu Laufzeitverhalten per Node-Repro (`crypto.createHmac` mit Zahl, `parseInt('abc')`, `'string'.find`, RSA-JWK an `jwkThumbprint`, Apex-Berechnung der Plugin-Kopie) und per `psql -h /var/lib/pgtest -U hhttps` (`'NaN days'::interval`) geprüft. Express-Version: `^4.18.2` (server/package.json L20) — async-Rejections werden NICHT an Express weitergereicht. Projektdateien wurden nicht verändert.

ID-Vergabe in Reihenfolge K (AP5-01…15), S (AP5-16…27), P (AP5-28…36), W (AP5-37…50).

## Bestätigte Findings

### AP5-01 [S2] [Korrektheit] server/server.js:L3970-3982 — `authenticatedUser` akzeptiert Refresh-Tokens (7 Tage) als Portal-/Admin-Credential
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `checkTokenValid` (L702-711) lässt `decoded.sub === 'refresh'` ausdrücklich durch, sofern `db.refreshTokens.get(jti)` existiert. `issueRefreshToken` (L680-699) schreibt `userId`, `role`, `trustScore`, `verified_methods` in den Refresh-Token. `authenticatedUser` (L3973-3981) bildet daraus `userId: d.uid || d.userId || d.sub` und `verifiedMethods` — der Refresh-Token liefert also eine vollwertige Identität inkl. `'passkey'`. Weder `requireUser` (L3985-3997), `requireAdmin` (L3999-4007) noch `requirePortalUser` (L4029-4043) prüfen den Token-Typ. Keine Gegenmaßnahme in Middleware oder Tests gefunden (`grep sub === 'refresh'` nur in L704 und L880).
**Auswirkung:** Ein Refresh-Token (REFRESH_TTL = 7 d, L94) ist ein 7-Tage-Bearer für `/hhttps/whoami`, alle `/hhttps/developers/*`- und `/hhttps/admin/*`-Routen. Revocation des Access-Tokens schützt diese Endpunkte nicht. Hinweis: AP1-S meldet dieselbe Ursache (L702-711) für `/hhttps/check`, `/sign-text`, `/signatures`; Ursache ist `checkTokenValid`, die Auswirkung auf Portal/Admin gehört zu AP5.
**Empfehlung:** In `authenticatedUser` nach `checkTokenValid`: `if (d.sub === 'refresh') throw new Error('refresh token not accepted as bearer')` — oder `checkTokenValid(token, { allowRefresh })` mit Default `false`, nur `/hhttps/token/refresh` setzt `true`. Gemeinsam mit dem AP1-Fix umsetzen.

### AP5-02 [S2] [Korrektheit] server/server.js:L4331-4348 + server/db.js:L927-944 / L902-913 — E-Mail-Wechsel bei `verified`-Client führt in einen unbestätigbaren Zustand
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `updateContactEmail` (db.js L927-944): `email_verified_at = NULL`, neuer Token, `verification_status = CASE WHEN 'verified' THEN 'unverified' ELSE 'email_pending' END`; `verified` wird NICHT zurückgesetzt. `confirmEmail` (db.js L902-913) hat `WHERE … AND verification_status = 'email_pending'` → für den `unverified`-Fall ein No-op (kein `rowCount`-Check). Die Route `/hhttps/developers/confirm-email` (L4239-4275) rendert nach `await db.oauthClients.confirmEmail(...)` (L4249) bedingungslos „Email confirmed ✓“. `submit-review` (L4453) verlangt `email_verified_at`, `resend-email` (L4499) verlangt Status `email_pending` → beide dauerhaft blockiert. Consent-Seite L1991 zeigt weiterhin `client.verified ? 'Verifizierte Plattform'`.
**Auswirkung:** Owner kann die Plattform nach Mail-Wechsel nie wieder verifizieren; Bestätigungsseite lügt; `verified = TRUE` und `verification_status = 'unverified'` stehen inkonsistent nebeneinander und das Vertrauenssiegel bleibt im Consent-Screen sichtbar.
**Empfehlung:** `updateContactEmail` immer auf `'email_pending'` setzen und `verified = FALSE` mitschreiben; `confirmEmail` per `WHERE email_verified_at IS NULL` mit `RETURNING`/`rowCount` arbeiten lassen und die Erfolgsseite nur bei `rowCount === 1` rendern.

### AP5-03 [S3] [Korrektheit] server/workload-identity.js:L1-260 + server/server.js:L3768-3886 — Workload-Identity-Modul ist nicht eingebunden; referenzierte Routen existieren nicht
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rn workload server/*.js server/test` trifft außer dem Modul selbst nichts; Import-Block server.js L1-71 enthält kein `workload-identity`. Keine Route `/hhttps/machine/workload/*` oder `/hhttps/machine/exchange`. Gleichzeitig ruft `server/public/workload.html` L180 (`/hhttps/machine/workload/list`), L233 (`bind`), L254 (`unbind`) diese Endpunkte auf und L117 dokumentiert `/hhttps/machine/exchange`; `server/sql/migration-phase-6-workload-identity.sql` L8-13 beschreibt den Flow als vorhanden.
**Auswirkung:** Ausgelieferte Seite endet in 404; 260 Zeilen sicherheitsrelevanter, ungetesteter Code (OIDC-Verifikation, JWKS-Fetch) driftet; Migration legt in jeder Installation eine tote Tabelle an.
**Empfehlung:** Entweder Router mounten (bind/exchange/unbind/list im Machine-Block hinter L3886) mit Integrationstests — dann vorher AP5-22 und AP5-36 beheben — oder Modul, Migration und `workload.html` entfernen bzw. als „nicht aktiv“ kennzeichnen.

### AP5-04 [S3] [Korrektheit] server/pop-verify.js:L110-115 — Check-then-Act auf der PoP-Nonce, kein atomares Löschen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L110 `const stored = await db.challenges.get(chId)`, L111-113 Vergleich, L115 `await db.challenges.delete(chId)` — zwei getrennte Statements. `db.challenges.delete` (db.js L140-142) führt nur `DELETE … WHERE challenge_id = $1` aus, gibt nichts zurück, wird nicht ausgewertet. Challenge-TTL 120 s (L152). Zwei parallele Requests mit demselben PoP-JWS lesen beide die noch vorhandene Nonce.
**Auswirkung:** „Single-use“ (Kommentar L115, Header L22) gilt nur seriell; im Parallelfenster ist ein abgefangener Proof mehrfach nutzbar.
**Empfehlung:** `db.challenges.consume(id, value)` mit `DELETE … WHERE challenge_id = $1 AND challenge = $2 AND expires_at > NOW()` und `rowCount === 1` als Erfolgsbedingung; Vergleich und Löschung in einem Statement.

### AP5-05 [S3] [Korrektheit/Sicherheit] server/pop-verify.js:L83, L136 + server/server.js:L4807 — PoP-Pfad nutzt `verifyToken` statt `checkTokenValid`: widerrufene Tokens bestehen den PoP-Nachweis
**Urteil:** BESTÄTIGT (Severity unverändert; S-Finding AP5-19 hierher zusammengeführt)
**Beleg:** `main()` L4807: `mountPopVerify(app, { db, verifyToken, RP_ID, BASE_URL })` — nur `verifyToken` (Signatur + exp, keys.js). `verifyPoP` L83 `decoded = verifyToken(token)` (synchron), `/hhttps/pop/challenge` L136 ebenso. Weder `db.revokedTokens.has` noch `db.tokens.exists` werden aufgerufen; `checkTokenValid` (server.js L702-711) ist die Referenzprüfung aller anderen Routen.
**Auswirkung:** Ein per `/hhttps/revoke` widerrufener Maschinen-Token (MACHINE_TTL 24 h) passiert Challenge-Ausgabe und `/hhttps/pop/demo` bis zum JWT-`exp` — exakt der Kompromittierungsfall, für den PoP gedacht ist.
**Empfehlung:** `checkTokenValid` in die Deps geben, in `verifyPoP`/`challenge` `await verifyToken(token)` verwenden (Fehler → `token_invalid`).

### AP5-06 [S3] [Korrektheit] server/server.js:L4362-4369 + server/db.js:L1085-1092 vs. developers/dashboard.html:L252-253 — Dashboard bietet „Delete“ für `unverified`, Server antwortet 409
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** db.js L1090 `verification_status IN ('draft', 'email_pending')`; dashboard.html L252-253 `canDelete = … === 'email_pending' || … === 'unverified'`. Route L4366-4367 antwortet bei `rowCount === 0` mit 409 `cannot_delete`.
**Auswirkung:** Für jede Plattform mit bestätigter E-Mail ein Button, der immer fehlschlägt; nie geprüfte Plattformen sind nicht entfernbar und belegen das 3/24h-Limit (L4160).
**Empfehlung:** `'unverified'` in `deleteIfDraft` aufnehmen (noch nicht reviewt) oder `canDelete` auf `email_pending` beschränken.

### AP5-07 [S3] [Korrektheit] server/server.js:L4353-4356 + server/db.js:L946-957 — PATCH kann `description`/`logo_url` nicht leeren; UI meldet „Saved ✓“
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** dashboard.html L419-421 sendet `description: … || null`, `logo_url: … || null`. Route L4316 akzeptiert `description === null` explizit. `updateMetadata` (db.js L949-956): `COALESCE($3, description)` mit Parameter `description || null` → `null` = „nicht ändern“. Response L4358 liefert den alten Wert mit 200.
**Auswirkung:** Gelöschtes Logo/Beschreibung bleibt gespeichert und erscheint weiter im Consent-Screen (L2125); Frontend zeigt Erfolg.
**Empfehlung:** `undefined` (nicht ändern) von `null` (leeren) unterscheiden; `updateMetadata` nur übergebene Spalten dynamisch setzen.

### AP5-08 [S3] [Korrektheit] server/server.js:L4587-4620 (+ Kommentar L3926-3939) — `reject`/`suspend` ohne Zustandsprüfung; Zustandsmaschine nur im Kommentar und im UI
**Urteil:** BESTÄTIGT (Severity unverändert; W-Finding AP5-41 hierher zusammengeführt)
**Beleg:** `approve` prüft L4568 `!== 'pending_review'`; `reject` (L4587-4602) und `suspend` (L4605-4619) laden nur den Client und rufen `adminReject`/`adminSuspend` (db.js L1010-1035) auf, die jeden Status überschreiben (inkl. `rejection_reason`, `reviewed_at`). Ergänzend aus AP5-41: Kommentar L3933 beginnt mit `draft`, `createDraft` (db.js L871) setzt aber direkt `'email_pending'`; `draft` existiert nur noch in `deleteIfDraft` L1090. admin.html L138-151 (`actionsFor`) rendert die Aktionen zustandsabhängig — die Regel lebt nur im UI.
**Auswirkung:** `email_pending` → `suspended` macht den Client für den Owner unerreichbar (weder `deleteIfDraft` noch `resend-email` greifen); erneutes `reject` überschreibt den ursprünglichen Grund in der Tabelle; per curl sind undokumentierte Übergänge möglich.
**Empfehlung:** `ALLOWED_TRANSITIONS = { reject: ['pending_review'], suspend: ['verified','unverified','pending_review'] }` und `assertTransition()` vor allen drei Admin-Routen (409 `wrong_state`); Kommentar auf Startzustand `email_pending` korrigieren.

### AP5-09 [S3] [Korrektheit] server/server.js:L3889-3891, L3906-3910, L4080-4116, L4239-4275, L4280-4299, L4302-4358, L4362-4369, L4373-4438, L4440-4488, L4537-4553, L4555-4653, L4735-4744 + server/pop-verify.js:L132-169 + server/wp-plugin-registration.js:L195-281 — async Handler ohne try/catch: DB-Fehler lassen den Request hängen
**Urteil:** BESTÄTIGT (Severity unverändert; zwei der drei genannten Auslöser korrigiert)
**Beleg:** Express `^4.18.2` (package.json L20) fängt async-Rejections nicht; kein `app.use((err, req, res, next) …)` in server.js; `process.on('unhandledRejection')` (L4820) loggt nur. try/catch existiert nur in `/machine/register`, `/machine/token`, POST `/webhooks` und um einzelne DB-Calls in `developers/clients` (L4171), `resend-email` (L4508, L4521). Auslöser geprüft: (a) `?days=abc` an `/developers/clients/:id/stats` → L4544 `Math.min(parseInt('abc'), 90)` = `NaN` (Node-Repro) → `getDaily` (db.js L1155) `('NaN' || ' days')::interval` → psql: `ERROR: invalid input syntax for type interval: "NaN days"` → **bestätigt**. (b) `?token=a&token=b` an `confirm-email`: node-pg serialisiert das Array zu `'{"a","b"}'` (Repro `prepareValue`) → Textvergleich, kein Fehler, 404 → **kein Auslöser**. (c) `?status[]=x` an `/admin/clients`: analog, leere Liste, kein Fehler → **kein Auslöser**. Ein echter DB-Ausfall trifft alle genannten Routen.
**Auswirkung:** Client wartet bis zum Proxy-Timeout statt 500; Portal-Buttons bleiben in „Saving…/Loading…“ hängen.
**Empfehlung:** `wrap = fn => (req,res,next) => fn(req,res,next).catch(next)` für alle async-Routen plus zentraler Error-Handler `res.status(500).json({ error: 'internal' })`; `days` validieren (siehe AP5-15).

### AP5-10 [S3] [Korrektheit] server/server.js:L3768-3833, L3888-3913, L4121-4653 + server/pop-verify.js:L1-172 + server/wp-plugin-registration.js:L1-282 — Keine Tests für Portal, Admin, whoami, Webhooks, PoP und Plugin-Registrierung
**Urteil:** BESTÄTIGT (Severity unverändert; W-Finding AP5-42 hierher zusammengeführt)
**Beleg:** `grep -rln "pop/\|plugin/\|webhooks\|developers/clients\|admin/clients\|whoami" server/test` → keine Treffer. Abgedeckt sind nur `/hhttps/machine/token` (acceptance.test.mjs L448) und `/hhttps/machine/register` (L573-601). Fixture `server/test/helpers/{db,server,identity-flow}.mjs` existiert.
**Auswirkung:** AP5-01, -02, -04, -06, -07, -08 wären mit einfachen Integrationstests aufgefallen; Refactorings (AP5-38/39) sind nicht abgesichert.
**Empfehlung:** `developers.test.mjs` (Register → Confirm → DNS-Mock → Submit → Approve; E-Mail-Wechsel auf `verified`; Delete je Status; Refresh-Token an `/whoami` → 401), `pop.test.mjs` (Nonce doppelt, revoked Token), Unit-Tests für `verifyPoP`/`rawToDer`/`jwkThumbprint`, Smoke-Tests für Webhooks-CRUD und `/plugin/*` inkl. Auto-Verify.

### AP5-11 [S3] [Korrektheit] server/server.js:L3816-3820 — Ungültiges `publicKeyJwk` wird stillschweigend verworfen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `jwkThumbprint` (L82-89) gibt für alles außer EC/P-256 mit x,y `null` zurück (Repro mit RSA-JWK → `null`); L3816 `keyJkt = jwkThumbprint(publicKeyJwk)` wird ohne Prüfung in `machineOperators.create` geschrieben; 201-Antwort L3822-3831 enthält kein `keyJkt`. `/machine/token` L3865 setzt `cnf` nur bei `op.key_jkt`; `/pop/challenge` antwortet dann `token_not_bound` (pop-verify L141-142). Keine Update-Route für den Key.
**Auswirkung:** Operator mit Tippfehler/RSA-Key merkt den Fehler erst beim PoP und muss neu registrieren (neuer operatorId/apiKey).
**Empfehlung:** `publicKeyJwk` gesetzt, aber `keyJkt === null` → 400 `invalid_public_key_jwk`; `keyJkt` in der Antwort zurückgeben.

### AP5-12 [S4] [Korrektheit] server/server.js:L3906-3912 — `/hhttps/webhooks/verify` wirft bei Nicht-String-Eingaben (500 statt 400)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L3908 nur Truthiness-Prüfung; L3910 `crypto.createHmac('sha256', secret).update(payload)`. Node-Repro: `createHmac('sha256', 1)` → `TypeError: The "key" argument must be of type string …`. Handler synchron → Express-Default-Error-Handler, 500-HTML.
**Auswirkung:** Falsche Statusklasse, kein Sicherheitsproblem.
**Empfehlung:** `typeof … !== 'string'` → 400; Vergleich per `crypto.timingSafeEqual`.

### AP5-13 [S4] [Korrektheit] server/server.js:L3893-3904 + server/webhooks.js:L20 — `events` ohne Array-Prüfung → 400 mit interner Fehlermeldung
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L3894 `const { url, events = ['*'], secret } = req.body` — Default greift nur bei `undefined`; webhooks.js L20 `events.find(...)`. Node-Repro: `'token.issued'.find` → `"token.issued".find is not a function`; L3903 gibt `{ error: e.message }` zurück; `null` wirft ebenso.
**Auswirkung:** Unklare API-Fehlermeldung; Status 400 nur zufällig korrekt.
**Empfehlung:** `if (!Array.isArray(events)) return 400 'events must be an array'`.

### AP5-14 [S4] [Korrektheit] server/wp-plugin-registration.js:L116-120 + server/server.js:L4131-4134 — Fehlermeldung „must be a valid HTTPS URL“ deckt sich nicht mit der Prüfung
**Urteil:** BESTÄTIGT (Severity unverändert; S-Finding AP5-27 hierher zusammengeführt)
**Beleg:** Plugin `apexDomainFromUrl` L42 hängt `https://` vor schemalose Werte; Repro: `http://example.org` → `example.org`, `example.org` → `example.org`. server.js `apexDomainFromUrl` (L3941-3949) → `normalizeApexDomain` (L607-624) akzeptiert jeden Hostnamen. Beide Routen melden dennoch `homepage_url must be a valid HTTPS URL` (L119 / L4133). `setupUrl` (Plugin L165) wird aus dem Rohwert gebaut → bei `example.org` relativer Link in der Mail.
**Auswirkung:** Irreführende Meldung; `http://`- oder schemalose Homepages sind als (verifizierte) Plattform möglich; relative Setup-Links in der Bestätigungsmail.
**Empfehlung:** `new URL(homepage_url).protocol === 'https:'` erzwingen (beide Stellen) oder Meldung anpassen.

### AP5-15 [S4] [Korrektheit] server/server.js:L4544 — `days`-Parameter ohne Untergrenze/NaN-Schutz
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `Math.min(parseInt(req.query.days || '30', 10), 90)`; `0`, negative Werte und `NaN` passieren. `getDaily` (db.js L1155) `CURRENT_DATE - ('-5' || ' days')::interval` → Zukunftsdatum → leere Statistik; `NaN` → SQL-Fehler (psql bestätigt) → Hänger (AP5-09).
**Auswirkung:** Unsinnige Statistik statt 400; bei `NaN` hängender Request.
**Empfehlung:** `Number.isInteger(days) && days >= 1 && days <= 90`, sonst 400 oder Default 30.

### AP5-16 [S2] [Sicherheit] server/server.js:L3889-3911 — Webhook-Registrierung, -Auflistung und -Löschung vollständig unauthentifiziert; GET liefert alle HMAC-Secrets
**Urteil:** BESTÄTIGT (Severity unverändert) — **Dublette zu AP1-S** (dort als server/webhooks.js:L41-43 „listWebhooks liefert Secret“ und L17-18 gemeldet). Die Routen liegen in AP5; hier ist das führende Finding, AP1-S-Eintrag sollte auf AP5-16 verweisen.
**Beleg:** L3889-3891 `app.get('/hhttps/webhooks', limit.webhooks, …)` → `res.json({ webhooks: await listWebhooks() })`; `db.webhooks.list` (db.js L657-669) mappt `secret: r.secret`. L3893 POST und L3906-3910 DELETE haben ebenfalls nur `limit.webhooks` (`rl(20, 60*60_000)`, L428); kein `requireUser`/`requireAdmin`, keine Owner-Spalte in `webhooks` (db.js L648-652 `INSERT … (webhook_id, url, events, secret)`). `removeWebhook` (webhooks.js L36-38) löscht jede ID.
**Auswirkung:** Jeder kann alle Webhook-URLs fremder Betreiber inkl. HMAC-Secret lesen (→ gültig signierte gefälschte `token.issued/revoked`-Events), fremde Webhooks löschen (DoS für Integrationen) und beliebige eigene Webhooks anlegen, die bei jedem Token-Ereignis beliefert werden.
**Empfehlung:** Routen mit `requireUser`/`requireAdmin` schützen, Webhooks an Owner-ID binden, `list`/`delete` darauf filtern; Secret nur einmal bei Registrierung ausgeben, in der Liste nie mehr.

### AP5-17 [S2] [Sicherheit] server/wp-plugin-registration.js:L81-88, L103-107 — Rate-Limit der Plugin-Registrierung per `X-Forwarded-For` umgehbar; In-Memory-Map wächst unbegrenzt
**Urteil:** BESTÄTIGT (Severity unverändert; P-Finding AP5-28 hierher zusammengeführt — gleiche Zeilen, gleiche Ursache)
**Beleg:** L103 `req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip` — erster XFF-Eintrag. nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` (scripts/deploy-all.sh L289/298/307/316/325) ergänzt den Client-Header nur; `app.set('trust proxy', 1)` (server.js L102) würde `req.ip` korrekt liefern. `regHits` (L81) ist eine modulglobale `Map` ohne Sweep; Einträge werden nur beim erneuten Treffer desselben Keys gefiltert (L84), nie entfernt. Route ist unauthentifiziert, legt pro Aufruf eine `oauth_clients`-Zeile an (L144) und sendet eine Mail an frei wählbares `contact_email` mit frei wählbarem `site_name`/`homepage_url` (L167-174).
**Auswirkung:** 5/h-Limit ist wirkungslos → Mail-Bombing/Phishing mit Issuer-Absender, unbegrenzte `oauth_clients`-Zeilen, plus Heap-Wachstum der pm2-Instanz durch einen Map-Eintrag pro erfundenem XFF-Wert (OOM-Restart).
**Empfehlung:** `req.ip` bzw. den vorhandenen `express-rate-limit`-Limiter (`limit.email` oder `rl(5, 3600_000)`) verwenden; `regHits` entfernen.

### AP5-18 [S3] [Sicherheit] server/server.js:L3893-3904 + server/webhooks.js:L17-18, L67-77 — Webhook-Ziel-URL ohne Schema-/Host-Restriktion (blindes SSRF)
**Urteil:** BESTÄTIGT (Severity unverändert) — **Dublette zu AP1-S** (dort S2 auf server/webhooks.js:L17-18). Die Registrierungsroute liegt in AP5; Fix gehört in webhooks.js (AP1) *und* an die Route (AP5-16). S3 hier bleibt vertretbar, da die Ausnutzung auf der fehlenden Authentifizierung (AP5-16) aufsetzt; nach dem AP5-16-Fix verbleibt ein authentifizierter SSRF-Vektor.
**Beleg:** webhooks.js L18 `try { new URL(url); } catch { throw … }` — einzige Prüfung. L67 `fetch(wh.url, { method: 'POST', …, signal: AbortSignal.timeout(8000) })`, Default `redirect: 'follow'`, 3 Versuche (L64, L88-91). `deliveries`/`failures` sind über `GET /hhttps/webhooks` lesbar (AP5-16) → Erreichbarkeits-Orakel.
**Auswirkung:** Issuer als POST-Proxy gegen Loopback/Link-Local/interne Dienste; Amplifikation gegen Dritte.
**Empfehlung:** Nur `https:`, Hostname auflösen und private/Loopback/Link-Local/ULA ablehnen, `redirect: 'manual'`, Webhooks pro Owner begrenzen.

### AP5-20 [S3] [Sicherheit] server/server.js:L4302-4358 — PATCH in jedem Status erlaubt, auch `pending_review`/`verified` (TOCTOU gegenüber Admin-Review)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Handler L4302-4358 prüft Ownership (L4306-4309) und Feldformate, nie `client.verification_status`. `updateMetadata` (db.js L946-958) schreibt `name`, `description`, `redirect_uris`, `logo_url`, `impressum_url` ohne Statusänderung (Kommentar L946: „must preserve verification_status“). dashboard.html L250 blendet „Edit“ nur bei `pending_review` aus — reine UI-Regel.
**Auswirkung:** Nach/kurz vor „Approve“ können Name, Impressum und Redirect-URIs geändert werden; das Vertrauenssiegel (L1991) bezieht sich auf andere Daten als die geprüften.
**Empfehlung:** PATCH in `pending_review` → 409; bei `verified` sicherheitsrelevante Felder nur mit Rückfall auf `unverified`.

### AP5-21 [S3] [Sicherheit] server/server.js:L3970-3982, L4080-4116 — `authenticatedUser` akzeptiert Maschinen-Token; alle Operatoren erhalten `userId: 'machine'`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Maschinen-Token (L3853-3866) tragen `sub: 'machine'`, kein `uid`/`userId`, werden in `db.tokens` angelegt (L3868-3870) → `checkTokenValid` L707 `tokens.exists(jti)` passt. L3976 `userId: d.uid || d.userId || d.sub` → `'machine'`. `requireUser` (L3985-3997) prüft nur `u.userId`; `actorType` wird nirgends ausgewertet. `/hhttps/whoami` (L4080-4116) nutzt nur `requireUser` und liefert L4114-4116 `grant_admin_command: … --grant machine …`. `requirePortalUser` blockt Maschinen heute nur, weil `verified_methods` fehlt und `admins` keinen Eintrag `'machine'` hat (db.js L1100-1106).
**Auswirkung:** Kein unmittelbarer Bypass; ein einziger `--grant machine` (vom whoami-Output nahegelegt) gäbe allen Bots Admin-Rechte; jede künftige `requireUser`-Route behandelt alle Bots als denselben Nutzer.
**Empfehlung:** In `requireUser`/`authenticatedUser` `sub === 'machine'` bzw. `actorType === 'bot'` mit 403 ablehnen; `grant_admin_command` für Maschinen-Token nicht ausgeben.

### AP5-22 [S4] [Sicherheit] server/workload-identity.js:L173, L197 — OIDC-Audience-Prüfung entfällt bei Binding ohne `expected_audience`
**Urteil:** BESTÄTIGT (herabgestuft von S3 wegen Nichterreichbarkeit: Modul ist nicht gemountet, siehe AP5-03; vor einer Aktivierung wieder S3)
**Beleg:** L197 `expectedAudience || null` wird gespeichert; L173 `audience: expectedAudience` an `jwt.verify` — jsonwebtoken prüft `aud` nur, wenn `options.audience` gesetzt ist; bei `undefined`/`null` keine Prüfung. Kein Import des Moduls in server.js.
**Auswirkung:** Nach Aktivierung: CI-OIDC-Tokens, die für Dritte ausgestellt wurden, würden gegen HHTTPS akzeptiert.
**Empfehlung:** `expected_audience` in `bindWorkload` verpflichtend (Default `BASE_URL`); in `verifyOidcToken` bei fehlender Audience abbrechen. Als Vorbedingung in AP5-03 aufnehmen.

### AP5-23 [S3] [Sicherheit] server/server.js:L4125-4126, L4311, L4353-4356 — `logo_url`/`impressum_url` serverseitig nicht validiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** POST L4125-4126 und PATCH L4311/L4354-4355 reichen `impressum_url`, `logo_url` ohne Prüfung an `createDraft`/`updateMetadata` durch (keine `new URL`, keine Längenprüfung). Nur dashboard.html L408-413 prüft clientseitig `^https?://`. `impressum_url` wird in dashboard.html L290 als `href` gerendert (`escapeHtml` verhindert kein `javascript:`); `logo_url` in L2125 als `<img src>` — CSP `imgSrc: ["'self'", 'data:']` (L401) blockt fremde Hosts, `data:`-URIs bis Body-Limit sind erlaubt. `impressum_url` ist Pflichtkriterium für `verified` (L4456).
**Auswirkung:** Self-XSS/`javascript:`-Links im Dashboard und in der Admin-Liste; Pflichtkriterium „Impressum“ ist ohne Format-Garantie.
**Empfehlung:** Beide Felder mit `new URL()` parsen; Impressum nur `https:`, Logo `https:` bzw. `data:image/*` mit Längenlimit, sonst 400.

### AP5-24 [S4] [Sicherheit] server/server.js:L4184, L4415, L4513, L4526 — Interne Fehlermeldungen 1:1 an den Client
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L4184 `creation_failed, message: err.message` (pg-Fehler inkl. Spalten-/Constraint-Namen), L4415 `err.code || err.message` (Resolver), L4513 `token_refresh_failed, message: err.message`, L4526 `send_failed, message: err.message` (SMTP-Text). Dasselbe Muster in wp-plugin-registration.js L160, L237.
**Auswirkung:** Information Disclosure (Schema, SMTP-Host, Resolver) an Portal-Nutzer bzw. beim Plugin-Pfad an Unauthentifizierte.
**Empfehlung:** Generische Codes ausgeben, Details nur ins Log.

### AP5-25 [S4] [Sicherheit] server/server.js:L4114-4116 — `/hhttps/whoami` gibt absoluten Server-Dateipfad aus
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L4114-4116 `grant_admin_command: '/var/www/hhttps/scripts/make-admin.sh --grant ${u.userId} …'` für jeden `requireUser`-Aufrufer inkl. Maschinen-Token (AP5-21).
**Auswirkung:** Preisgabe von Deploy-Pfad und Admin-Tooling.
**Empfehlung:** Nur ausgeben, wenn `admins` leer ist (Bootstrap) oder der Aufrufer Admin ist.

### AP5-26 [S4] [Sicherheit] server/server.js:L3847 — API-Key-Hash-Vergleich nicht timing-sicher
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L3846-3848 `keyHash = sha256(apiKey)`; `if (keyHash !== op.api_key_hash)`. Timing leakt nur Hash-Bytes; praktisch nicht ausnutzbar.
**Auswirkung:** Konventionsabweichung, Defense-in-depth.
**Empfehlung:** `crypto.timingSafeEqual(Buffer.from(keyHash,'hex'), Buffer.from(op.api_key_hash,'hex'))`.

### AP5-29 [S3] [Performance] server/wp-plugin-registration.js:L102-160 + server/sql/schema.sql:L192-206 — Unauthentifizierte Registrierung schreibt pro Request eine Zeile + Mail; abgelaufene `email_pending`-Drafts werden nie gelöscht
**Urteil:** BESTÄTIGT (herabgestuft von S2: der unbegrenzte Aufruf ist Folge von AP5-17 und dort bewertet; eigenständig bleibt das fehlende Aufräumen)
**Beleg:** L144 `createDraft` und L167 `sendPlatformRegistrationEmail` ohne Auth und ohne vorherige Bestätigung. `cleanup_expired()` (schema.sql L192-206) kennt `oauth_clients` nicht; `deleteIfDraft` (db.js L1085) wird nur vom Owner über `DELETE /developers/clients/:id` aufgerufen — für `owner_user_id = 'wp-plugin'` nie. Portal-Pfad hat dagegen Passkey-Pflicht und `countRecentByOwner` (L4160).
**Auswirkung:** `oauth_clients` wächst dauerhaft mit Spam-Drafts; `/admin/clients` (LIMIT 200) und `/admin/stats` (GROUP BY) zeigen bzw. scannen zunehmend Leichen.
**Empfehlung:** Limiter aus AP5-17; Obergrenze offener `email_pending`-Drafts pro Apex; `cleanup_expired()` um `DELETE FROM oauth_clients WHERE verification_status='email_pending' AND email_token_expires_at < NOW() - INTERVAL '7 days'` erweitern.

### AP5-30 [S3] [Performance] server/server.js:L4735-4744 — Öffentlicher `/hhttps/stats` führt pro Aufruf acht ungecachte Queries aus, inkl. vier `COUNT(*)` und Laden aller Webhook-Zeilen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L4735 `app.get('/hhttps/stats', async …)` ohne eigenen Limiter (nur `limit.global`, 300/min, L436-437) und ohne Cache; L4737-4744 `stats.getAll`, `rolesDeclared.distribution`, `tokens.count`, `refreshTokens.count`, `credentials.count`, `revokedTokens.count`, `machineOperators.count`, `listWebhooks().then(w => w.length)` (= `SELECT * FROM webhooks WHERE active = TRUE`, db.js L657, inkl. Secret). `grep -i delete` über `revoked_tokens` in db.js/schema.sql: kein Treffer → Tabelle wächst monoton.
**Auswirkung:** Antwortzeit skaliert linear mit Tabellengrößen; ein Client kann 300 req/min × 8 Queries auf den gemeinsamen Pool legen.
**Empfehlung:** 30-60 s Modul-Cache + `Cache-Control: public, max-age=60`; Webhooks per `SELECT COUNT(*)` zählen.

### AP5-31 [S3] [Performance] server/wp-plugin-registration.js:L215-231 + server/server.js:L4393-4400 — DNS-TXT-Lookups ohne Timeout und ohne Rate-Limit
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Plugin L228 `new Resolver()` ohne Optionen, L231 `resolveTxt` ohne Signal; Route L215 ohne Limiter und ohne Auth (nur `client_id`, das dem Registrierer bekannt ist). server.js L4393-4395 identisch (Resolver ohne `timeout`/`tries`), Route L4373 nur `requirePortalUser`, kein eigener Limiter. Beide schreiben pro Aufruf `touchDnsCheck`.
**Auswirkung:** Nicht antwortende Nameserver der eigenen Zone halten pro Request einen Handler über c-ares-Default-Timeouts offen; beim Plugin-Pfad reicht ein selbst registrierter Client.
**Empfehlung:** `new Resolver({ timeout: 3000, tries: 1 })`, per-Route-Limiter (`rl(10, 60_000)`), Mindestabstand über `dns_last_checked_at`.

### AP5-32 [S4] [Performance] server/server.js:L4393-4395 — Dynamischer Import, `new Resolver()` und `setServers()` pro Request
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L4393 `const { Resolver } = await import('dns/promises')`, L4394-4395 Instanz + `setServers` im Handler; Plugin L228 ebenfalls Instanz pro Request (statischer Import L30).
**Auswirkung:** Geringer Overhead; zusammen mit AP5-31/AP5-39 beheben.
**Empfehlung:** Modulweiter Resolver mit Timeout, geteilt zwischen beiden Modulen.

### AP5-33 [S4] [Performance] server/server.js:L3868-3871 — Zwei unabhängige Writes im Token-Pfad sequenziell
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L3868-3870 `await db.tokens.create(...)`, L3871 `await db.machineOperators.incrementTokensIssued(operatorId)` — keine Datenabhängigkeit.
**Auswirkung:** Ein zusätzlicher Pool-Roundtrip pro Token-Ausgabe (60/min/IP).
**Empfehlung:** `Promise.all([...])`.

### AP5-34 [S4] [Performance] server/server.js:L4622-4636 + developers/admin.html:L261-274 — `/hhttps/admin/clients` `LIMIT 200` ohne Pagination; UI partitioniert clientseitig
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L4626-4631 `SELECT * … ORDER BY created_at DESC LIMIT 200`; admin.html `partition()` L261-274 sortiert alle Zeilen im Browser nach Status. Ab dem 201. Client fehlen Einträge (Abschnitt nach `created_at`, nicht nach Status).
**Auswirkung:** Große und gleichzeitig unvollständige Antwort; Queue-Zähler im UI falsch.
**Empfehlung:** `?status=`/`?offset=`-Pagination; Queue separat über `/admin/clients/pending`.

### AP5-35 [S4] [Performance] developers/assets/portal.js:L391-401, L621-626 — Admin-Check bei jedem Seitenaufruf über `/hhttps/admin/stats`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `verifyAdmin()` L391-401 `fetch('/hhttps/admin/stats')`, nur `res.ok` ausgewertet; `initNav()` L621-626 ruft es bei jedem Login-Zustand. `/admin/stats` (L4640-4653) führt für Admins `GROUP BY` + `adminActions.listRecent(20)` aus.
**Auswirkung:** Unnötige DB-Last pro Seitenaufruf für Admins.
**Empfehlung:** `verifyAdmin()` auf `GET /hhttps/whoami` (`is_admin`) umstellen.

### AP5-36 [S4] [Performance] server/workload-identity.js:L125, L158-161 — JWKS-Fetch ohne Timeout; jeder unbekannte `kid` erzwingt sofortigen Re-Fetch
**Urteil:** BESTÄTIGT (Severity unverändert; aktuell nicht erreichbar, siehe AP5-03)
**Beleg:** L125 `fetch(cfg.jwksUri, { headers })` ohne `signal`; L158-161 bei Kid-Miss `getProviderKeys(provider, { forceRefresh: true })` ohne Mindestabstand.
**Auswirkung:** Nach Aktivierung: beliebig viele ausgehende Provider-Requests durch erfundene `kid`s.
**Empfehlung:** `AbortSignal.timeout(5000)`; Force-Refresh auf 1×/60 s pro Provider drosseln. Als Vorbedingung in AP5-03 aufnehmen.

### AP5-38 [S3] [Wartbarkeit] server/wp-plugin-registration.js:L35-78 vs. server/server.js:L600-624, L3941-3960, L4047-4069 — Vier Helfer-Kopien mit abweichender Semantik
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Kommentar L32-33 bestätigt die bewusste Duplizierung. `TWO_PART_TLDS`: Plugin L35-36 = 10 Einträge, server.js L600-605 = 23. Repro der Plugin-Funktion: `https://stadt.gov.uk` → `gov.uk` (server.js: `stadt.gov.uk`) → `expected_host = _hhttps-verify.gov.uk` (L184/L227). `isValidRedirectUri`: Plugin L71-78 (jedes Protokoll bei `localhost`, `127.0.0.1` abgelehnt, kein Längenlimit, Fragment verboten) vs. server.js L4047-4057 (`https:` oder `http:`+`localhost|127.0.0.1`, ≤ 500 Zeichen). `generateClientId`: Plugin L65-69 (Slug 24, `wp-`-Präfix) vs. L4061-4069 (Slug 32).
**Auswirkung:** Derselbe `oauth_clients`-Datensatz wird je nach Pfad nach anderen Regeln validiert; `.gov.uk`-Sites können den TXT-Record über den Plugin-Pfad nie setzen.
**Empfehlung:** Helfer in `server/client-registration.js` auslagern, Kopien löschen.

### AP5-39 [S3] [Wartbarkeit] server/server.js:L4374-4432 + server/wp-plugin-registration.js:L215-281 — DNS-TXT-Prüfung nahezu zeilengleich dupliziert, mit unterschiedlichem Resolver
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Beide Handler: Client laden, `dns_token`/Apex prüfen, `resolveTxt('_hhttps-verify.<apex>')`, `parts.join('').trim() === dns_token.trim()`, `touchDnsCheck`, gleiches Fehlerobjekt. server.js L4394-4395 `setServers(['1.1.1.1','8.8.8.8'])`, Plugin L228 System-Resolver. Auto-Approve nur im Plugin (L262-273).
**Auswirkung:** Split-DNS/Propagation liefert pfadabhängig unterschiedliche Ergebnisse; Timeouts (AP5-31) müssen doppelt eingebaut werden.
**Empfehlung:** `verifyDnsToken(client)` in `server/dns-verify.js`, `maybeAutoVerify(client)` daneben.

### AP5-40 [S4] [Wartbarkeit] server/server.js:L4621-4653 — Roh-SQL und JSON-Parsing im Admin-Handler statt in db.js; kein `is_active`-Filter
**Urteil:** BESTÄTIGT (herabgestuft von S3: `grep "SET is_active\|is_active = FALSE"` über db.js/server.js/scripts liefert keinen Schreiber — die beschriebene 404-Folge ist derzeit nicht auslösbar; bleibt Kapselungsbruch)
**Beleg:** L4626-4631 und L4644-4648 sind die einzigen `db.pool().query`-Aufrufe im Routen-Code; L4633-4634 wiederholt das `JSON.parse`-Muster aus db.js (L829, L840, L896, L1052, L1067). Roh-Query filtert nicht auf `is_active = TRUE`, `db.oauthClients.get` (L824-826) schon.
**Auswirkung:** Schemaänderungen an `oauth_clients` müssen in server.js nachgezogen werden; sobald ein `is_active=FALSE`-Pfad entsteht, divergieren Liste und Aktionen.
**Empfehlung:** `db.oauthClients.listAll({ status, limit })`, `countByStatus()` und gemeinsamer `parseClientRow()`.

### AP5-43 [S4] [Wartbarkeit] server/server.js:L3774-3911 — Fehlerformat der Machine-/Webhook-Routen (Freitext) weicht vom Portal-Format (snake_case + `message`) ab; `/webhooks/verify` ohne Limiter
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L3774, L3844, L3846, L3850, L3894, L3909, L3911 Freitext in `error`; L3903 `{ error: e.message }`; L3778 mischt `error: 'operator_email_required', detail`. Ab L4128 durchgängig `{ error: '<code>', message }`. portal.js L490 liest `data.message || data.error`. L3906 `app.post('/hhttps/webhooks/verify', (req, res)` ohne `limit.webhooks`.
**Auswirkung:** `error` ist kein stabiler Code; Textänderungen brechen Client-Vergleiche.
**Empfehlung:** Einheitlich `{ error: '<snake_code>', message }`; Limiter auch auf `/webhooks/verify`.

### AP5-44 [S4] [Wartbarkeit] server/server.js:L3823, L3877, L3890, L3899, L4750, L4809 + wp-plugin-registration.js:L132, L139 + pop-verify.js:L129, L152-153 — Magic Strings/Numbers ohne Konstante
**Urteil:** BESTÄTIGT (Severity unverändert; Zählung korrigiert)
**Beleg:** `grep -c "version: '0.5.0'" server/server.js` = 22 (Reviewer: 23); Boot-Banner L4809 `HHTTPS v4.1`. E-Mail-Regex 4× (L3777, L4146, L4333, Plugin L132). `48 * 3600 * 1000` 4× (L4165, L4338, L4507, Plugin L139). `'wp-plugin'` L4256, Plugin L153/L197/L217. Deploy-Pfad L4115. pop-verify L129 `300`, L152-153 `120_000`/`120`.
**Auswirkung:** Versionsbump/Regeländerung erfordert Suchen-und-Ersetzen über drei Dateien; Banner und API-Version widersprechen sich.
**Empfehlung:** `HHTTPS_VERSION`, `EMAIL_RE`, `EMAIL_TOKEN_TTL_MS`, `WP_PLUGIN_OWNER_ID`, `POP_CHALLENGE_TTL_S`, `POP_IAT_SKEW_S` in `constants.js`.

### AP5-45 [S4] [Wartbarkeit] server/server.js:L82-89 vs. server/pop-verify.js:L41-45, L172 — `jwkThumbprint` doppelt definiert; pop-verify exportiert es bereits
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Beide kanonisieren `{crv,kty,x,y}` → SHA-256/base64url; pop-verify.js L172 `export { verifyPoP, jwkThumbprint }`; server.js L2 importiert nur `mountPopVerify`. pop-verify L31-38 handgeschriebene `b64uDecode/Encode`, obwohl L44 bereits `'base64url'` nutzt.
**Auswirkung:** Zwei Wahrheiten für `cnf.jkt`.
**Empfehlung:** `import { mountPopVerify, jwkThumbprint } from './pop-verify.js'`, lokale Kopie löschen; `Buffer.from(s, 'base64url')`.

### AP5-46 [S4] [Wartbarkeit] server/server.js:L2-3, L4806-4807 — Zusatzmodule per Patch-Marker und uneingerückt in `main()` gemountet
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2-3 Imports vor dem Doc-Header mit `// POP-VERIFY` / `// WP-PLUGIN-REG`; L4806-4807 in Spalte 0 innerhalb von `main()` nach `ensureBootSchema()`, während alle anderen Routen auf Modulebene registriert sind. `RP_ID` wird an `mountPopVerify` übergeben, aber nicht genutzt (AP5-50).
**Auswirkung:** Routen an unerwarteter Stelle; Formatierer stolpern.
**Empfehlung:** Imports einsortieren, Mounts neben L523-529, Marker entfernen.

### AP5-47 [S4] [Wartbarkeit] developers/assets/portal.js:L282-287, L411-426, L638-639 + developers/dashboard.html:L109 + developers/index.html:L264-282 — Veraltete v4-Kommentare, ungenutzte Deprecated-Aliase, timing-abhängiger Admin-Hint
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** portal.js L411-412 „gate page if the identity has no confirmed e-mail“, dashboard.html L109 „shows gate page if e-mail unconfirmed“, index.html L264 „signed in but no confirmed e-mail“ — Regel ist seit L246 `PORTAL_REQUIRED_METHOD = 'passkey'`. `isDeveloper` (L284-286) und `requireDeveloper` (L424-426) exportiert (L638-639), `grep` in `developers/*.html`: kein Aufrufer. index.html L281 `setTimeout(renderHint, 600)`.
**Auswirkung:** Irreführung beim nächsten Umbau; toter Export; Race im UI.
**Empfehlung:** Kommentare anpassen, Aliase entfernen, Hint an `verifyAdmin().then(...)` hängen.

### AP5-48 [S4] [Wartbarkeit] developers/register.html:L337, L346-352 + developers/dashboard.html:L405-407 — Formularfelder ohne Backend-Pendant; Client-Regel „https-only“ strenger als Server
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** register.html L346-347 Kommentar „backend has no separate fields … fold them into the description“; Server L4125-4126 akzeptiert nur `name, description, homepage_url, redirect_uris, contact_email, impressum_url, logo_url`. register.html L337 und dashboard.html L405 `!/^https:\/\//i.test(u)`, Server `isValidRedirectUri` L4053 erlaubt `http://localhost`.
**Auswirkung:** Strukturierte Angaben als Freitext; lokale Redirect-URIs werden vom Frontend blockiert.
**Empfehlung:** Felder streichen oder in `metadata`-JSONB modellieren; Client-Validierung an `isValidRedirectUri` angleichen.

### AP5-49 [S4] [Wartbarkeit] sites/spec.html:L964-1141, docs/spec.md:L147-157 — Endpunkt-Doku ohne `/hhttps/pop/*`, `/hhttps/plugin/*`, `/hhttps/whoami`, `resend-email`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -n "pop/challenge\|plugin/register\|hhttps/whoami\|resend-email" docs/spec.md sites/spec.html README.md` → keine Treffer. sites/spec.html dokumentiert machine/developers/admin (L964-1141); docs/spec.md nur machine (L147, L429).
**Auswirkung:** Integratoren müssen Servercode lesen; `HHTTPS-PoP`-Headerformat ist nur im Modul-Header dokumentiert.
**Empfehlung:** Vier Endpunktgruppen in beiden Dokumenten ergänzen.

### AP5-50 [S4] [Wartbarkeit] server/server.js:L3945, L4054, L4633-4634; server/pop-verify.js:L129 — ESLint-Warnungen (Sammelfinding)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** docs/review/ap/eslint-output.txt: server.js `3945:12`, `4054:12`, `4633:68`, `4634:69` `'e' is defined but never used`; pop-verify.js `129:28 'RP_ID' is assigned a value but never used`.
**Auswirkung:** Lint-Rauschen; unnötige Dep `RP_ID` in `mountPopVerify`.
**Empfehlung:** `catch {` ohne Binding; `RP_ID` aus Deps (L4807) und Destructuring (L129) entfernen.

## Verworfen
- (keine)

## Zusammengeführt
- AP5-19 [S3] [Sicherheit] server/pop-verify.js:L83, L136 — PoP ignoriert Revocation-Liste → in AP5-05 (identische Ursache und Zeilen).
- AP5-27 [S4] [Sicherheit] server/server.js:L4132-4135 + wp-plugin-registration.js:L116-120 — „HTTPS URL“-Meldung vs. Prüfung → in AP5-14 (identisch).
- AP5-28 [S2] [Performance] server/wp-plugin-registration.js:L81-87 — `regHits`-Map wächst unbegrenzt, XFF-Key → in AP5-17 (gleiche Zeilen, gleiche Ursache; Heap-Aspekt dort aufgenommen).
- AP5-37 [S3] [Wartbarkeit] server/workload-identity.js:L1-260 — Modul ist toter Code → in AP5-03 (identisch).
- AP5-41 [S3] [Wartbarkeit] server/server.js:L3926-3937 — Zustandsmaschine nur von `approve` durchgesetzt, `draft` existiert nicht → in AP5-08 (gleiche Ursache; `draft`-Hinweis dort ergänzt).
- AP5-42 [S3] [Wartbarkeit] pop-verify/wp-plugin/server.js — keine Tests für PoP, Plugin, Webhooks, Portal, Admin, whoami → in AP5-10 (identisch).

Querverweise auf andere AP (keine Zusammenführung, da Route bzw. Ursache in anderem AP liegt):
- AP5-16 / AP5-18 ↔ AP1-S (server/webhooks.js L17-18 SSRF, L41-43 Secret in `listWebhooks`): Route in AP5, Modul in AP1. AP5-16 ist das führende Finding; AP1-S-Einträge sollten darauf verweisen.
- AP5-01 ↔ AP1-S (server/server.js L702-711 Refresh-Token als Bearer für `/check`, `/sign-text`, `/signatures`): gemeinsame Ursache `checkTokenValid`, gemeinsam fixen.

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit | 15 | 15 | 0 | 0 |
| Sicherheit | 12 | 10 | 0 | 2 |
| Performance | 9 | 8 | 0 | 1 |
| Wartbarkeit | 14 | 11 | 0 | 3 |
| **Gesamt** | **50** | **44** | **0** | **6** |

Je Severity bestätigt: S1 0, S2 4 (AP5-01, AP5-02, AP5-16, AP5-17), S3 18, S4 22.
Herabstufungen: AP5-22 S3→S4 (nicht gemountet), AP5-29 S2→S3 (Amplifikation in AP5-17 bewertet), AP5-40 S3→S4 (kein `is_active=FALSE`-Schreiber).

# AP7 — Performance

Geprüfte Dateien: server/privacy-pass/index.js, issuer.js, issuance.js, verifier.js, verifier-internal.js, verifications.js, verifications-api.js, role-requirements.js, keys.js, well-known.js, demo.js, migrations.js; server/privacy-pass/public/wallet.html; server/sdk/client.js; server/sdk/client.py; server/test/e2e/wallet.e2e.test.mjs. Zum Verständnis gelesen (keine Findings): server/server.js (Middleware L371–530, Cleanup L713–724), server/db.js (pool/q/sessions.get), server/sql/schema.sql (cleanup_expired L192–206), node_modules/body-parser.

Stand: `main` @ `bf0a82b`.

---

### [S3] [Performance] server/privacy-pass/migrations.js:L473-484 — pp_issuance_log wird nie bereinigt und wächst mit jedem /issue-Aufruf unbegrenzt
**Begründung:** Jeder erfolgreiche `POST /privacy-pass/issue` schreibt eine Zeile (`logIssuance`, issuance.js L390–397). Gelesen wird ausschließlich das 24-h-Fenster (`getRecentIssuanceCount`, issuance.js L378–388). Es gibt keinen Lösch-Pfad: `cleanup_expired()` (server/sql/schema.sql L192–206) und der 5-Minuten-Intervall in server/server.js L714–724 kennen keine `pp_*`-Tabelle; `grep -rn pp_issuance_log server/` liefert nur Insert/Select. Die Migration legt zwar Indizes an (L480–483), aber keinerlei Retention.
**Auswirkung:** Tabelle und beide Indizes wachsen linear mit der Nutzung (1 Zeile pro Batch, pro Credential und Tag maximal 1–10). Bei realistischem Wachstum bleibt die Fensterabfrage dank `(credential_id, issued_at DESC)`-Index zwar schnell, aber Speicher, VACUUM-Aufwand und Backup-Größe steigen dauerhaft; die Daten außerhalb des 24-h-Fensters haben keinen Nutzen mehr und sind zudem ein (pseudonymes) Nutzungsprotokoll pro Credential.
**Empfehlung:** In `db.cleanupExpired()` bzw. `cleanup_expired()` ein `DELETE FROM pp_issuance_log WHERE issued_at < NOW() - INTERVAL '2 days'` aufnehmen (oder die Retention in `runMigrations()` als eigenen Cleanup-Hook registrieren).

### [S3] [Performance] server/privacy-pass/verifications.js:L95-100 — pp_email_pending: nicht bestätigte Links werden nie gelöscht, obwohl ein Ablaufindex existiert
**Begründung:** `createEmailPending` legt pro `POST /privacy-pass/email/start` eine Zeile mit `expires_at = NOW()+15min` an. Gelöscht wird nur beim erfolgreichen Konsum (`consumeEmailPending`, L110–113, `DELETE … WHERE token_hash=$1 AND expires_at > NOW()`). Abgelaufene oder nie angeklickte Links bleiben dauerhaft liegen. Die Migration legt `pp_email_pending_expires_idx` (migrations.js L531–532) an, der von keiner Query genutzt wird — der vorgesehene Cleanup wurde offenbar nie implementiert.
**Auswirkung:** Jede Eingabe einer Mail-Adresse in der Wallet (auch Tippfehler, Wiederholungen, Missbrauch — siehe nächstes Finding) hinterlässt eine unlöschbare Zeile inkl. `credential_id`, `email_hash`, `email_domain`. Die Tabelle wächst unbegrenzt; da nur nach PK gesucht wird, bleibt die Latenz stabil, aber Speicher/VACUUM und Datenschutz (Hash + Domain + Credential-Zuordnung ohne Ablauf) leiden.
**Empfehlung:** `DELETE FROM pp_email_pending WHERE expires_at < NOW()` in den periodischen Cleanup aufnehmen (nutzt den bereits vorhandenen Index).

### [S3] [Performance] server/privacy-pass/verifications-api.js:L262-335 — /email/start hat keinen eigenen Rate-Limiter: pro Aufruf DB-Insert + SMTP-Versand, nur durch das globale 300/min/IP-Limit begrenzt
**Begründung:** Der Handler prüft nur Session-Existenz (L276), erzeugt dann eine `pp_email_pending`-Zeile (L298) und ruft `sendPrivacyPassVerification` (L312) auf. server/server.js definiert `limit.email = rl(30, 60min)` (L428) für die eigenen `/hhttps/email/*`-Routen; der Privacy-Pass-Router (server.js L523) ist davon nicht erfasst, es greift nur `limit.global` (300/min). Ein einziger gültiger `sessionId` genügt, um bis zu 300 Mails/min an beliebige Adressen zu senden (die Domain-Prüfung L286 greift nur bei Rollen mit Pattern; `citizen` hat keines).
**Auswirkung:** SMTP-Transport (nodemailer, synchron `await` im Request-Pfad) und Tabelle wachsen im Takt des globalen Limits; bei ~5 gleichzeitigen IPs mehrere Sekunden Mail-Versand pro Sekunde Event-Loop-Belegung und Reputationsschaden beim Mail-Provider. Überschneidung mit Sicherheit (Mail-Bombing), hier als Last-/Wachstumsproblem gemeldet.
**Empfehlung:** `limit.email` (oder einen eigenen `rl(5, 15min)`) auf `/privacy-pass/email/start` mounten und zusätzlich pro `credential_id` eine Obergrenze offener `pp_email_pending`-Zeilen prüfen (z. B. max. 3 im 15-min-Fenster) bevor gesendet wird.

### [S3] [Performance] server/privacy-pass/issuance.js:L244 — Router-eigene Body-Limits (32 kB / 8 kB / 4 kB / 1 kB-Fallback) sind wirkungslos, es gilt das globale 2-MB-Limit
**Begründung:** server/server.js L371 registriert `express.json({ limit: '2mb' })` vor allen Routern. body-parser überspringt weitere Parser, sobald `req._body` gesetzt ist (node_modules/body-parser/lib/types/json.js L106). Damit sind `issuanceRouter.use(express.json({ limit: '32kb' }))` (L244), `verificationsRouter.use(express.json({ limit: '8kb' }))` (verifications-api.js L239) und die 4-kB-Parser für `/verify` und `/redeem` (index.js L77–78) tote Konfiguration. `/issue` prüft zwar `requests.length <= 10` (L274), aber jedes Element kann bis zu ~2 MB Base64 sein; `Buffer.from(requests[i], 'base64')` (L332) dekodiert das erst vollständig, bevor die Längenprüfung (L333) ablehnt. Gleiches gilt für `Buffer.from(b64,'base64')` in verifier.js L442/L484.
**Auswirkung:** Ein Angreifer kann den Issuer mit 2-MB-JSON-Bodies beschäftigen (JSON-Parse + Base64-Decode je Request), obwohl der Modulautor ausdrücklich 4–32 kB vorgesehen hat; ~500× mehr Parse-Arbeit pro Request als beabsichtigt, nur begrenzt durch 300 req/min/IP.
**Empfehlung:** Entweder das globale JSON-Limit deutlich senken und große Bodies nur an den Routen erlauben, die sie brauchen, oder die Privacy-Pass-Router vor dem globalen Parser mounten bzw. eine `Content-Length`-Prüfung als Middleware vorschalten. Zusätzlich in `/issue` die String-Länge (`requests[i].length === 72`) vor dem Base64-Decode prüfen.

### [S4] [Performance] server/privacy-pass/verifier.js:L497-501 — pp_redeemed wächst dauerhaft (ein Nonce pro eingelöstem Token), ohne Rotations- oder Zeitgrenze
**Begründung:** Jede Einlösung fügt eine Zeile ein; Tokens haben kein Ablaufdatum, deshalb muss ein Nonce prinzipiell bis zur Schlüsselrotation gespeichert bleiben. Es existiert aber weder eine Schlüsselrotation (keys.js lädt genau einen Key pro Rolle) noch ein Cleanup; `pp_redeemed_at_idx` (migrations.js L567–568) wird von keiner Query verwendet.
**Auswirkung:** Bei erfolgreichem Betrieb (10 Tokens/Credential/Tag) wächst die Tabelle proportional zur Nutzung, Speicher/VACUUM steigen; PK-Insert bleibt O(log n). Kein akutes Problem, aber ein Betriebsplan fehlt.
**Empfehlung:** Nonce-Zeilen an `token_key_id`/Rolle binden und bei Schlüsselrotation löschen, oder eine dokumentierte Retention (z. B. 1 Jahr) plus ungenutzten Index entfernen.

### [S4] [Performance] server/privacy-pass/verifications.js:L152-159 — Recovery-Codes werden mit 10 sequentiellen Einzel-INSERTs geschrieben
**Begründung:** Schleife mit `await db.pool().query(INSERT …)` pro Code, nach vorherigem `DELETE` (L147–150). Nicht transaktional: bricht ein Insert ab, sind alte Codes bereits gelöscht und nur ein Teil der neuen vorhanden.
**Auswirkung:** 11 Roundtrips statt 1–2 pro `/recovery/generate`; seltene Operation, daher gering.
**Empfehlung:** Ein Multi-Row-`INSERT … VALUES ($1,$2),($3,$4),…` (oder `unnest`) innerhalb einer Transaktion zusammen mit dem DELETE.

### [S4] [Performance] server/privacy-pass/public/wallet.html:L9 — Render-blockierendes externes Skript von unpkg.com ohne `defer`/`async` im `<head>`
**Begründung:** `<script src="https://unpkg.com/@simplewebauthn/browser@9.0.1/…">` steht synchron im `<head>` vor 590 Zeilen CSS/HTML; die eigentliche Wallet-Logik ist ein `type="module"`-Skript (L602), das ohnehin deferred lädt. Bei langsamer/blockierter Drittquelle bleibt die Seite bis zum Timeout weiß; das e2e-Testsetup muss die URL extra stubben (wallet.e2e.test.mjs L38–41).
**Auswirkung:** First Paint der Wallet hängt an der Verfügbarkeit und Latenz eines fremden CDN; Ausfall von unpkg = Wallet nicht nutzbar.
**Empfehlung:** Bundle lokal unter `/privacy-pass/lib/` ausliefern (wie `voprf.js`) und mit `defer` laden, oder im Modul-Skript per `import` einbinden.

### [S4] [Performance] server/sdk/client.js:L65-83 — JWKS-Refresh ohne In-Flight-Deduplizierung; gleichzeitige `verifyLocal`-Aufrufe lösen parallele Discovery+JWKS-Fetches aus
**Begründung:** `getJwks()` prüft `fresh` und startet sonst `discover()` + Fetch; ein laufender Fetch wird nicht geteilt. In der empfohlenen Middleware-Nutzung (L253–279) treffen bei Kaltstart oder TTL-Ablauf N parallele Requests → N Discovery- und N JWKS-Requests an den Issuer, und jeder Abschluss ruft `_keyCache.clear()` (L81), sodass bereits importierte Keys mehrfach neu importiert werden. Gleiches Muster in server/sdk/client.py L127–155 (dort zusätzlich ohne Locking bei Threads).
**Auswirkung:** Kurzzeitige Lastspitzen auf `/.well-known/*` des Issuers pro Stunde und Verbraucher; bei vielen Integratoren summiert sich das. Funktional harmlos.
**Empfehlung:** Laufendes Fetch-Promise in `this._jwksPromise` halten und wiederverwenden, bis es erfüllt ist; `_keyCache` nur leeren, wenn sich das Key-Set tatsächlich geändert hat.

### [S4] [Performance] server/privacy-pass/issuer.js:L171-194 — Öffentliche VOPRF-Endpunkte (P-384 Scalar-Mult + DLEQ-Proof) nur durch das globale IP-Limit geschützt
**Begründung:** `/token-request` (blindEvaluate inkl. DLEQ-Proof, L185), `/verify` und `/redeem` (evaluate mit Hash-to-Curve, verifier-internal.js L584) sind unauthentifiziert und CPU-gebunden in reinem JS (`@cloudflare/voprf-ts`, Event-Loop-blockierend, mehrere ms pro Aufruf). Es gilt nur `limit.global` (300/min/IP, server.js L420/L436).
**Auswirkung:** Pro IP ~1–2 s CPU/min erreichbar; erst bei verteilten Quellen spürbar. Kein akuter Engpass, aber der Issuer teilt sich den einen Event-Loop mit OAuth/WebAuthn.
**Empfehlung:** Eigene, engere Limiter für `/token-request`, `/verify`, `/redeem` (z. B. 60/min) und den Verifier-Pfad perspektivisch in einen Worker-Thread auslagern.

---

## Zusammenfassung

Findings: S1: 0 · S2: 0 · S3: 4 · S4: 5.

Der Privacy-Pass-Code ist im Request-Pfad schlank: alle Filterspalten sind indiziert (`pp_issuance_log(credential_id, issued_at)`, partieller Index auf `pp_attribute_verifications`, PK-Zugriffe bei `pp_email_pending`/`pp_redeemed`/`pp_recovery_codes`, `credentials(user_id)`), VOPRF-Server-Instanzen werden gecacht, Schlüssel werden nur beim Start synchron gelesen, die Discovery-Dokumente tragen `Cache-Control`, und es gibt keine Pool-Client-Leaks (durchgängig `pool().query`). Die wesentlichen Schwächen sind betrieblicher Natur: keine der fünf `pp_*`-Tabellen hat einen Cleanup (obwohl Ablaufindizes angelegt wurden), die modul-eigenen Body-Limits werden vom globalen 2-MB-Parser überstimmt, und `/email/start` ist ohne eigenes Limit ein DB-/SMTP-Lastverstärker. Die SDKs cachen JWKS/Discovery korrekt; nur die Deduplizierung paralleler Refreshes fehlt.

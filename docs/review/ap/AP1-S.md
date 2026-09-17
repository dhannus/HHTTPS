# AP1 — Sicherheit

Geprüfte Dateien: server/server.js L1–1373 (Middleware, sendJson, Cookies, HHTTPS-Header, Rate-Limits, /.well-known/*, /hhttps/esco/suggest, /hhttps/info, /hhttps/check, /hhttps/sign-text, /hhttps/verify-text, /hhttps/signatures*, /hhttps/s/:slug, /s/:slug), server/keys.js, server/roles.js, server/roles.eaa.js, server/roles.i18n.js, server/roles.taxonomy.js, server/roles.taxonomy.i18n.js, server/roles.taxonomy.test.mjs, server/webhooks.js. Zum Verständnis gelesen (keine Findings dort): server/db.js (tokens, refreshTokens, signatures, webhooks, sessions), server/server.js L1800–1830 (OAuth-Access-Token), L2606–2640 (token/refresh), L3840–3912 (machine/token, webhooks-Routen), L4824.

Stand: `main` @ `bf0a82b`. Zeilennummern per `cat -n`/`sed -n` verifiziert.

---

### [S2] [Sicherheit] server/webhooks.js:L17-18 — Webhook-URL wird nur syntaktisch geprüft: SSRF gegen interne Netze/Metadaten-Endpunkte
**Begründung:** `registerWebhook` akzeptiert jede URL, die `new URL(url)` parst — kein Schema-Allowlist (http/https), kein Ausschluss von Loopback/Link-Local/privaten Netzen, keine Redirect-Sperre. `deliverWithRetry` (L67-77) ruft dann `fetch(wh.url, { method: 'POST', body })` mit Default `redirect: 'follow'` auf. Die registrierende Route `POST /hhttps/webhooks` (server.js L3893-3904) ist unauthentifiziert (nur `limit.webhooks`, 20/h pro IP). Der Angreifer kontrolliert Host, Port, Pfad und Query; der Body ist ein festes JSON, ein Timeout von 8 s ist gesetzt.
```js
try { new URL(url); } catch { throw new Error('Invalid webhook URL.'); }
```
**Auswirkung:** Blinder SSRF vom Server aus: POST-Requests an `http://127.0.0.1:5432`, `http://169.254.169.254/...`, interne Admin-/Health-Endpunkte oder den eudi-verifier-Backend-Port (docker-compose), ausgelöst durch jeden `token.issued`/`token.revoked`/`role.declared`-Event. Über `recordDelivery`/`GET /hhttps/webhooks` (Feld `failures`/`deliveries`, `lastDelivery`) lässt sich zusätzlich Erreichbarkeit interner Ports ausspähen (Port-Scan-Orakel). Bis zu 3 Versuche pro Event verstärken den Effekt.
**Empfehlung:** In `registerWebhook` nur `https:` (ggf. `http:` nur in Dev) zulassen, Hostnamen gegen Loopback/RFC1918/Link-Local/ULA/`.internal`/`localhost` prüfen (nach DNS-Auflösung, z. B. per `dns.lookup` + IP-Range-Check), `redirect: 'manual'` bzw. `'error'` im `fetch` setzen und die Registrierung an eine Authentifizierung (Developer-Portal/Admin) binden.

### [S2] [Sicherheit] server/webhooks.js:L41-43 — `listWebhooks()` liefert das HMAC-Secret jedes Webhooks zurück und wird ungeschützt ausgeliefert
**Begründung:** `listWebhooks` gibt `dbWebhooks.list()` unverändert weiter; `db.webhooks.list` (db.js L657-668) mappt `secret: r.secret` in jedes Objekt. Der Aufrufer `GET /hhttps/webhooks` (server.js L3889-3891) sendet das Array 1:1 an jeden anonymen Client. Ebenso enthält `registerWebhook` (L32) das Secret im Rückgabewert — beim Anlegen ist das gewollt, in der Liste nicht.
**Auswirkung:** Jeder Dritte erhält alle registrierten Webhook-URLs (inkl. fremder interner Endpunkte) und die zugehörigen HMAC-Secrets. Damit kann er gültig signierte, gefälschte `token.issued`/`token.revoked`-Events an fremde Empfänger schicken; die Signatur `HHTTPS-Webhook-Sig` bietet dann keinen Schutz mehr. Zusätzlich können Webhooks fremder Betreiber per `DELETE /hhttps/webhooks/:id` (id aus der Liste) gelöscht werden.
**Empfehlung:** `listWebhooks` soll das Secret nie zurückgeben (im Mapping weglassen oder maskieren, z. B. `secret: undefined`, nur `secret_hint`), Secrets nur gehasht/verschlüsselt speichern, und Listen-/Lösch-Routen an den Eigentümer (Client-/Admin-Auth) binden.

### [S3] [Sicherheit] server/server.js:L702-711 + L880-935 — Refresh-Tokens werden von `/hhttps/check`, `/hhttps/sign-text` und `/hhttps/signatures` als vollwertige Identitäts-Bearer akzeptiert
**Begründung:** `checkTokenValid` behandelt `sub === 'refresh'` explizit als gültig (prüft nur `refreshTokens.get`). `/hhttps/check` (L880-882) unterscheidet danach nur `d.sub === 'machine'`; ein 7-Tage-Refresh-Token (L680-699, enthält `role`, `trustScore`, `verified_methods`) fällt in den Human-Zweig und liefert `status: 'verified', human: true`. Dasselbe gilt für `/hhttps/sign-text` (L965-968) und `/hhttps/signatures` (L1095-1098); dort wird zudem `signerId = d.uid || d.userId || d.sub` (L1122, L1340) aus dem Refresh-Token übernommen.
**Auswirkung:** Token-Typ-Verwechslung: Das langlebige Refresh-Token, das laut Design nur an `/hhttps/token/refresh` gehört, wird zu einem 7 Tage gültigen Bearer-Nachweis bei Drittplattformen und zum Signier-Credential. Ein geleaktes Refresh-Token ist damit direkt nutzbar (kein Umweg über Refresh, keine Sichtbarkeit in `tokens_issued`), und die Header enthalten `HHTTPS-Method: undefined`.
**Empfehlung:** In `/hhttps/check`, `/hhttps/sign-text`, `/hhttps/signatures` und `/hhttps/signatures/:slug/revoke` nach `checkTokenValid` `d.sub === 'refresh'` mit 401 abweisen (oder `checkTokenValid` einen Parameter `allowRefresh` geben, der nur von `/token/refresh` gesetzt wird).

### [S3] [Sicherheit] server/server.js:L485-511 — Identity-Cookie-Middleware prüft keine Revocation und keinen Token-Typ
**Begründung:** Für jede Anfrage wird das Cookie nur mit `verifyToken` (Signatur + `exp`) geprüft; weder `db.revokedTokens.has` noch `db.tokens.exists` werden aufgerufen (im Gegensatz zu `checkTokenValid`). Die Typ-Prüfung ist eine Negativliste (`sub !== 'refresh'`, `actorType !== 'bot'`): Text-Signatur-JWTs (`sub: 'text-signature'`, L975-986), OAuth-Access-Tokens für Dritt-Clients (`sub: pairwiseId`, `aud: client_id`, L1809-1830) und OAuth-Refresh-Tokens werden als Identität akzeptiert, da `verifyToken` (keys.js L164-173) weder `iss` noch `aud` prüft.
**Auswirkung:** Nach `/hhttps/revoke` zeigt hhttps.org dem Browser bis zu 1 h weiterhin `HHTTPS-Status: verified`, Rolle, Trust-Score und Methoden-Header; ein revoked Token wirkt in der Issuer-eigenen Oberfläche weiter. Ein in ein Cookie gesetztes OAuth-Access-Token (5 min) oder eine Text-Signatur wird ebenfalls als eingeloggte Identität dargestellt. Auswirkung ist auf die eigene Origin beschränkt (Cookie ist HttpOnly/SameSite=Lax), daher S3.
**Empfehlung:** Positivliste: nur `sub === 'human-verified'` mit vorhandener `jti` akzeptieren, und (ggf. gecached) `revokedTokens.has(jti)` prüfen; bei Revocation `clearIdentityCookie` aufrufen.

### [S3] [Sicherheit] server/server.js:L392-403 — CSP erlaubt `'unsafe-inline'` für Skripte und `unpkg.com` als Script-Quelle
**Begründung:** `scriptSrc: ["'self'", "'unsafe-inline'", 'unpkg.com', 'fonts.googleapis.com']` und `scriptSrcAttr: ["'unsafe-inline'"]` heben den XSS-Schutz der CSP praktisch auf; `unpkg.com` erlaubt das Laden beliebiger npm-Pakete von einer öffentlichen CDN ohne SRI. Diese Policy gilt global für alle Seiten, inklusive Consent-Page, Developer-Portal, Admin und `sendJson`-HTML-Viewer.
**Auswirkung:** Jede HTML-Injection irgendwo auf der Origin (z. B. in AP2/AP5-Seiten, die Nutzerdaten rendern) wird direkt zu ausführbarem JavaScript; ein Angreifer mit Kontrolle über ein unpkg-Paketnamen-Fragment (`unpkg.com/<paket>`) kann externen Code nachladen. Der Kommentar (L390-391) begründet dies nur mit `onclick=`-Handlern in index.html.
**Empfehlung:** Inline-Handler in den statischen Seiten durch `addEventListener` ersetzen, `'unsafe-inline'` durch Nonces/Hashes (helmet unterstützt `(req,res) => \`'nonce-${res.locals.nonce}'\``) ersetzen und `unpkg.com` entfernen bzw. auf konkrete Pfade mit SRI beschränken.

### [S3] [Sicherheit] server/server.js:L1180-1185 — First-Seen-Lock einer Signatur kann von jedem anonymen Aufrufer mit beliebiger Domain gesetzt werden
**Begründung:** `GET /hhttps/s/:slug` ist öffentlich; sobald `?domain=` mitgegeben wird und `sig.first_seen_at` noch leer ist, schreibt `db.signatures.setFirstSeen(slug, reqDomain)` die Domain dauerhaft (db.js L764-771, `WHERE first_seen_at IS NULL`). Es gibt keinen Nachweis, dass der Aufrufer die Domain besitzt oder die Signatur dort tatsächlich gesehen hat; die Slugs sind über den Marker `#hhttps:s:hp-…` öffentlich bekannt.
**Auswirkung:** Ein Angreifer „reserviert“ das `firstSeen`-Feld fremder Signaturen mit einer beliebigen Domain (z. B. `evil.com`), bevor die echte Plattform verifiziert. Konsumenten, die `firstSeen` als Provenienz-Hinweis auswerten, erhalten falsche Daten; das Feld kann so zur Diffamierung („zuerst gesehen auf …“) genutzt werden. Kein Auth-Bypass, daher S3.
**Empfehlung:** `firstSeen` nur aus einem vertrauenswürdigen Signal setzen (z. B. `Origin`/`Referer`-Header der verifizierenden Plattform, oder nur bei `reqDomain === sig.bound_domain`), oder das Feld als rein informativ/unbestätigt kennzeichnen.

### [S4] [Sicherheit] server/server.js:L116-155,L325-357 — `sendJson`-HTML-Viewer interpoliert `title`, `subtitle` und `req.path` ohne HTML-/JS-Escaping
**Begründung:** Nur der JSON-Body wird escaped (L140-147); `${title}` (L155, L329), `${opts.subtitle}` (L330) und `${req.path}` (L325, L333, L357 — letzteres innerhalb eines JS-String-Literals in `<script>`) werden roh eingefügt. Verifiziert: Express liefert für `GET /x'<script>` den Pfad unverändert in `req.path` (Node akzeptiert `'`, `<`, `>` im Request-Target). In den aktuellen AP1-Aufrufern ist der Wert praktisch nicht angreifbar (feste Routen; `/hhttps/s/:slug` validiert den Slug mit `^hp-[A-Z0-9-]+$`, `role_label`/`role_icon` stammen aus dem statischen `ROLES`), daher nur S4.
**Auswirkung:** Sobald ein künftiger Aufrufer ein nutzerkontrolliertes `subtitle`/`title` übergibt oder eine Route mit freiem Parameter `sendJson` nutzt, entsteht Reflected XSS — verschärft durch die CSP mit `'unsafe-inline'`.
**Empfehlung:** `title`, `subtitle` und `req.path` durch eine `escapeHtml`-Funktion leiten (für L357 zusätzlich `JSON.stringify(req.path)` statt String-Literal) und den Fetch-Pfad aus `location.pathname` im Browser statt aus dem Server-Template beziehen.

### [S4] [Sicherheit] server/server.js:L1266,L1326 — `/hhttps/signatures/batch` und `/hhttps/signatures/:slug/revoke` ohne endpoint-spezifisches Rate-Limit
**Begründung:** Alle anderen Signatur-/Check-Endpunkte tragen `limit.check` (120/min); die beiden Routen nutzen nur den globalen Limiter (300/min). Batch führt pro Request bis zu 100 Slug-Lookups plus `stats.increment` aus, Revoke führt Signaturprüfung + DB-Update aus.
**Auswirkung:** Anonyme Slug-Enumeration (bis 30.000 Slugs/min pro IP gegen den 32^10-Raum — praktisch nicht brechbar, aber DB-Last) und Token-Brute-Force gegen Revoke mit höherer Rate als bei `/hhttps/check`.
**Empfehlung:** `limit.check` (oder ein eigener, kleinerer Limiter) an beide Routen hängen.

### [S4] [Sicherheit] server/server.js:L938,L1002,L1062,L1158,L1352 — Rohe `e.message` aus `checkTokenValid`/DB-Fehlern an den Client
**Begründung:** Die catch-Blöcke geben `error: e.message` zurück. `checkTokenValid` (L702-711) wirft nicht nur JWT-Fehler, sondern reicht auch pg-Fehler (`db.revokedTokens.has`, `db.tokens.exists`) ungefiltert weiter, z. B. `relation "tokens" does not exist`, `connect ECONNREFUSED 127.0.0.1:5432` oder Timeout-Meldungen — als HTTP 401.
**Auswirkung:** Interne Infrastruktur-Details (DB-Host/Port, Tabellennamen, Schema-Zustand) werden anonymen Clients preisgegeben; DB-Ausfall wird als „ungültiges Token“ maskiert (falsches Signal für Plattformen).
**Empfehlung:** Nur JWT-Fehlerklassen (`JsonWebTokenError`, `TokenExpiredError`) und die eigenen Meldungen (`Token revoked`, `Token nicht aktiv`) durchreichen; sonstige Fehler loggen und generisch `token_check_failed` mit 500/503 melden.

### [S4] [Sicherheit] server/server.js:L774-795 — Öffentlicher ESCO-Proxy ohne Timeout und ohne eigenes Rate-Limit
**Begründung:** `GET /hhttps/esco/suggest` ruft `fetch(url)` gegen `ec.europa.eu` ohne `AbortSignal.timeout` auf (im Gegensatz zu webhooks.js L76) und ist unauthentifiziert; nur der globale Limiter (300/min) greift. `q` wird korrekt `encodeURIComponent`-kodiert, `lang` ist auf `de|en` beschränkt — kein SSRF.
**Auswirkung:** Missbrauch als anonymer Request-Verstärker gegen die EU-API (Reputations-/Sperr-Risiko für die Server-IP); hängende Upstream-Verbindungen halten Sockets bis zum OS-Timeout offen.
**Empfehlung:** `signal: AbortSignal.timeout(5000)`, `limit.check` oder ein eigener Limiter, kurzer serverseitiger Cache pro `(lang,q)`.

### [S4] [Sicherheit] server/server.js:L468-479 — `readIdentityCookie` wirft bei fehlerhaft kodiertem Cookie-Wert eine `URIError`
**Begründung:** `decodeURIComponent(part.slice(i + 1).trim())` läuft ohne try/catch in der globalen Middleware (L488). Ein Cookie `hhttps_identity=%E0%A4%A` führt für diesen Browser zu einer synchronen Exception → Express-Default-Handler → HTTP 500 auf jeder Route, bis das Cookie manuell gelöscht wird.
**Auswirkung:** Nur Self-DoS des betroffenen Browsers (fremde Cookies lassen sich nicht setzen), aber ohne `NODE_ENV=production` liefert der Default-Handler zudem den Stacktrace (Pfadnamen) aus.
**Empfehlung:** Dekodierung in try/catch kapseln und bei Fehler `clearIdentityCookie(res)` aufrufen und `null` zurückgeben.

---

## Zusammenfassung

Anzahl je Severity: **S1: 0 · S2: 2 · S3: 4 · S4: 5** (gesamt 11).

Der Kern (Middleware, Header-Erzeugung mit `hdrSafe`, Slug-/Domain-Validierung, ES256-Schlüsselhandling mit `algorithms: ['ES256']`, 0600-Dateirechte, parametrisierte SQL in allen gelesenen db.js-Funktionen, Zufall aus `crypto.randomBytes`) ist solide gebaut; Header-/CRLF-Injection, SQL-Injection und Open Redirects wurden in AP1 nicht gefunden. Die beiden gewichtigen Punkte liegen im Webhook-Modul: Registrierung beliebiger URLs ohne Netz-/Schema-Filter (SSRF) und die Rückgabe der HMAC-Secrets über die öffentliche Liste. Darunter sind die fehlende Trennung der Token-Typen (Refresh-Token als Bearer, Identity-Cookie ohne Revocation/Typ-Positivliste) und die faktisch wirkungslose CSP die Themen, die sich quer durch die anderen APs auswirken.

# AP1 — Performance

Geprüfte Dateien: server/server.js (L1–1373), server/keys.js, server/roles.js, server/roles.eaa.js, server/roles.i18n.js, server/roles.taxonomy.js, server/roles.taxonomy.i18n.js, server/roles.taxonomy.test.mjs, server/webhooks.js. Zum Verständnis gelesen (keine Findings): server/db.js, server/sql/schema.sql, server/sql/migration-phase-2.5.sql.

Stand: `648aff0`.

### [S2] [Performance] server/server.js:L435-436 — `/hhttps/info` ist vom globalen Rate-Limit ausgenommen und führt pro Aufruf sechs `COUNT(*)`-Queries ohne Caching aus
**Begründung:** Die Global-Limiter-Middleware überspringt `/hhttps/info` explizit:
```js
if (req.path === '/' || req.path === '/hhttps/info') return next();
limit.global(req, res, next);
```
Der Handler (L799-805) ruft dann `Promise.all([db.credentials.count(), db.tokens.count(), db.refreshTokens.count(), db.sessions.count(), db.revokedTokens.count(), db.machineOperators.count()])` auf. `credentials.count()` (db.js L91) und `revokedTokens.count()` (db.js L314) sind ungefilterte `SELECT COUNT(*)` → Full-Table-Scan; `tokens/refresh_tokens/sessions.count()` filtern auf `expires_at > NOW()`, was bei überwiegend gültigen Zeilen ebenfalls einen Großteil der Tabelle liest. Es gibt keinen In-Memory-Cache und keinen `Cache-Control`-Header; jeder Aufruf trifft die Datenbank.
**Auswirkung:** Ein unauthentifizierter Client kann ohne jede Drosselung 6 Scan-Queries pro Request auslösen. Mit wachsendem `revoked_tokens` (siehe Finding unten, wird nie bereinigt) und `credentials` wird das zum billigsten Weg, den Pool (max 20) zu belegen und alle anderen Endpunkte (inkl. `/hhttps/check`) auszubremsen.
**Empfehlung:** `/hhttps/info` nicht vom globalen Limiter ausnehmen (bzw. eigenen `rl(60)`) und die Zählwerte mit einem kleinen TTL-Cache (z. B. 30–60 s, Modul-Variable) oder per `Cache-Control: public, max-age=60` bedienen. Alternativ `pg_class.reltuples`-Schätzung für die ungefilterten Counts.

### [S3] [Performance] server/server.js:L866 — Jeder `/hhttps/check`-Aufruf schreibt synchron in die Hot-Row `stats.check_calls`, noch vor jeder Token-Prüfung
**Begründung:** `await db.stats.increment('check_calls')` steht als erste Anweisung des Handlers, also auch für Requests ohne Token (L870-875) und für ungültige Tokens. `stats.increment` (db.js L1321-1327) ist ein `INSERT … ON CONFLICT DO UPDATE` auf eine einzelne Zeile (`metric` = PK). Dasselbe Muster wiederholt sich in L883 (`machine_checks`), L666 (`tokens_issued`), L1138, L1178, L1320, L1345.
**Auswirkung:** Alle `/hhttps/check`-Aufrufe serialisieren sich auf dem Row-Lock derselben Zeile; jeder UPDATE erzeugt ein Dead-Tuple (MVCC) → die kleine `stats`-Tabelle bläht sich bei hoher Check-Frequenz auf und Autovacuum läuft dauernd. Der Check-Endpunkt ist der Kern-Pfad des Protokolls („1 Request pro Seitenaufruf auf Plattformseite“); die Latenz enthält damit einen zusätzlichen Schreib-Roundtrip plus Lock-Wartezeit, bevor überhaupt validiert wird.
**Empfehlung:** Zähler im Prozess akkumulieren (Map metric → n) und alle N Sekunden bzw. ab Schwellwert gebündelt mit `increment(metric, by)` flushen; im Handler `fire-and-forget` (kein `await`) und erst nach der Token-Prüfung zählen.

### [S3] [Performance] server/server.js:L704 / L714-724 — `revoked_tokens` wird auf jedem Check gelesen, aber nie bereinigt; die Tabelle wächst unbegrenzt
**Begründung:** `checkTokenValid` (L702-711) fragt `db.revokedTokens.has(jti)` bei jeder Validierung ab (ebenso L1023 in `/hhttps/verify-text`). Der 5-Minuten-Cleanup (L714-724) ruft nur `cleanup_expired()` (schema.sql L192-206: tokens, refresh_tokens, sessions, challenges, email_verifications) plus `identity_claims_cache` (db.js L1344) auf. Für `revoked_tokens` existiert im gesamten `server/` kein `DELETE` (grep). Die Tabelle hat kein `expires_at`, nur `revoked_at` (schema.sql L95-102). Ein widerrufener Access-Token ist nach `ACCESS_TTL` (1 h), ein Refresh-Token nach `REFRESH_TTL` (7 d) ohnehin durch `jwt.verify` abgelehnt — der Eintrag ist danach wertlos.
**Auswirkung:** Mit jedem `/hhttps/revoke` und jedem Logout wächst die Tabelle dauerhaft; der PK-Lookup bleibt zwar O(log n), aber `revokedTokens.count()` in `/hhttps/info` (siehe S2 oben) scannt sie komplett, und Backups/VACUUM/Index-Größe wachsen ohne Grenze.
**Empfehlung:** Im Cleanup-Job `DELETE FROM revoked_tokens WHERE revoked_at < NOW() - INTERVAL '8 days'` (≥ REFRESH_TTL + Puffer) ergänzen — der Index `revoked_tokens_revoked_at_idx` existiert bereits.

### [S3] [Performance] server/webhooks.js:L80 / L86 — Jeder Zustellversuch schreibt eine `webhook_deliveries`-Zeile; die Tabelle wird nie bereinigt
**Begründung:** `deliverWithRetry` ruft pro Versuch `dbWebhooks.recordDelivery(...)` auf (Erfolg L80, Fehler L86; bis zu 3 Zeilen pro Event und Webhook). `recordDelivery` (db.js L685-699) macht ein `INSERT` plus ein `UPDATE webhooks`. Für `webhook_deliveries` gibt es keinerlei Retention (kein `DELETE` im Code, nicht in `cleanup_expired()`). `fireEvent` wird bei jeder Token-Ausgabe (`token.issued`, server.js L3189) sowie `identity.verified`, `token.revoked`, `card.issued` etc. ausgelöst.
**Auswirkung:** Bei aktiven Webhooks entstehen pro Login mehrere Audit-Zeilen; ein dauerhaft fehlschlagender Webhook produziert 3 Zeilen pro Event bis zur Deaktivierung. Die Tabelle wächst linear mit dem Traffic ohne Obergrenze.
**Empfehlung:** Retention im Cleanup-Job (`DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - INTERVAL '30 days'`; Index `webhook_deliveries_delivered_at_idx` existiert) oder nur den letzten Versuch pro Event protokollieren.

### [S3] [Performance] server/server.js:L774-796 — ESCO-Typeahead-Proxy ruft die externe API ohne Timeout und ohne Cache pro Tastendruck auf
**Begründung:** `/hhttps/esco/suggest` macht für jeden Request `await fetch(url, …)` (L781) gegen `ec.europa.eu` — ohne `AbortSignal.timeout`, ohne Deduplizierung identischer `q`/`lang`-Werte, ohne Response-Cache. Der Endpunkt ist nur durch das globale Limit (300/min/IP) gedrosselt; die UI sendet pro Tastendruck ab 2 Zeichen.
**Auswirkung:** Hängt die ESCO-API (oder antwortet langsam), bleibt jede Node-Anfrage bis zum undici-Default (Header-Timeout 300 s) offen; ein Client kann so mit wenigen hundert Requests hunderte offene Sockets/Handler binden. Bei normalem Betrieb wird jede populäre Abfrage („Arzt“, „Lehrer“) immer wieder extern geholt, obwohl das Ergebnis über Tage stabil ist. `resolveEsco` in roles.taxonomy.js L156-168 hat dasselbe Muster (kein Timeout), ist aktuell aber nirgends aufgerufen (nur importiert, server.js L56).
**Empfehlung:** `signal: AbortSignal.timeout(3000)` setzen, Ergebnisse in einem begrenzten LRU/TTL-Cache (z. B. 500 Einträge, 24 h, Key `lang:q`) halten und einen eigenen Limiter (z. B. `rl(60)`) vorschalten.

### [S4] [Performance] server/server.js:L1171-1184 — `/hhttps/s/:slug` macht vier sequentielle DB-Roundtrips, davon zwei Schreibzugriffe pro öffentlichem Lesezugriff
**Begründung:** `await db.signatures.get(slug)` (L1171), danach `await db.signatures.incrementVerify(slug)` (L1177), `await db.stats.increment('signatures_verified')` (L1178) und ggf. `await db.signatures.setFirstSeen(...)` (L1184) — alle nacheinander, obwohl die drei letzten voneinander unabhängig sind und das Ergebnis nicht brauchen (die Antwort rechnet `verify_count + 1` lokal, L1216).
**Auswirkung:** Antwortlatenz = Summe von 3–4 Roundtrips; jede Verifikation erzeugt zusätzlich eine UPDATE-Version der `signatures`-Zeile und der `stats`-Hot-Row. Öffentliche Verifikations-Links werden von Crawlern/Extension wiederholt aufgerufen.
**Empfehlung:** Die Zähler-Updates ohne `await` bzw. via `Promise.allSettled` nebenläufig absetzen; `incrementVerify` und `setFirstSeen` in ein einzelnes `UPDATE … SET verify_count = verify_count + 1, first_seen_at = COALESCE(first_seen_at, NOW()) …` zusammenfassen.

### [S4] [Performance] server/server.js:L702-711 — `checkTokenValid` führt zwei sequentielle Einzel-Lookups pro Prüfung aus
**Begründung:** Erst `await db.revokedTokens.has(jti)` (L704), dann `await db.tokens.exists(jti)` bzw. `refreshTokens.get` (L706/L708). Beide sind PK-Lookups, aber seriell; zusammen mit dem Stats-Increment (L866) hat ein `/hhttps/check` drei Roundtrips.
**Auswirkung:** Verdoppelte DB-Latenz auf dem heißesten Pfad; unter Last mehr gleichzeitig belegte Pool-Verbindungen.
**Empfehlung:** Beide Abfragen mit `Promise.all` parallelisieren oder in eine Query zusammenführen (`SELECT EXISTS(...) AS revoked, EXISTS(...) AS active`).

### [S4] [Performance] server/server.js:L488-513 — Identity-Cookie-Middleware verifiziert den ES256-Token synchron auf jedem Request, auch für statische Assets
**Begründung:** Die Middleware läuft vor `express.static` (L519) und ruft für jeden Request mit `hhttps_identity`-Cookie `verifyToken` (keys.js L164-172: `jwt.decode` + `jwt.verify`, synchrone ECDSA-P-256-Prüfung) auf. Bei einem abgelaufenen Cookie wird für jedes Asset erneut verifiziert und `clearCookie` gesetzt; das Ergebnis wird nicht pro Request gecacht.
**Auswirkung:** Pro HTML-Seite mit n Assets n synchrone Signaturprüfungen (~0,1–0,3 ms je) auf dem Event-Loop. Bei heutigem Traffic vernachlässigbar, skaliert aber linear mit Seitenaufrufen eingeloggter Nutzer.
**Empfehlung:** Middleware nur für Dokument-Requests (`Accept: text/html`) oder nicht-statische Pfade ausführen, bzw. `express.static` vor die Cookie-Middleware ziehen.

### [S4] [Performance] server/server.js:L1109-1113 — Slug-Kollisionsprüfung mit zwei seriellen Queries pro Versuch statt Insert-Konflikt
**Begründung:** `while (await db.signatures.slugExists(slug) || await db.signatures.isReservedSlug(slug))` fragt bei jeder Signaturerstellung zwei Tabellen ab, obwohl `id` PK ist und ein Insert-Konflikt (`ON CONFLICT DO NOTHING` + `rowCount`) die Existenzprüfung kostenlos mitliefert. Reserved-Slugs beginnen zudem nie mit `hp-` (migration-phase-2.5.sql L77-79), der zweite Lookup kann also nie treffen.
**Auswirkung:** Zwei überflüssige Roundtrips pro Signatur; keine Skalierungsgefahr.
**Empfehlung:** `isReservedSlug` entfernen und Kollision über den PK-Konflikt beim `INSERT` behandeln.

### [S4] [Performance] server/keys.js:L179-192 — `getJWKS()` exportiert die Key-Objekte bei jedem Aufruf neu
**Begründung:** `pubKey.export({ format: 'jwk' })` wird für den aktiven und jeden retired Key pro Request ausgeführt; das Ergebnis ändert sich nur bei `rotateKeys()`/`forgetRetiredKey()`.
**Auswirkung:** Gering — der Endpunkt sendet `Cache-Control: max-age=3600` (server.js L759). Nur relevant für Verifier, die den Header ignorieren.
**Empfehlung:** JWKS-Objekt memoisieren und in `rotateKeys`/`forgetRetiredKey` invalidieren.

## Zusammenfassung

S1: 0 · S2: 1 · S3: 4 · S4: 5

Der Kern-Pfad ist strukturell in Ordnung: `db.q()` nutzt `pool.query` (keine Client-Leaks), der Rate-Limiter (express-rate-limit 7 MemoryStore) evicted pro Fenster, es gibt keine unbegrenzten In-Memory-Maps, keine `*Sync`-Aufrufe im Request-Pfad (nur beim Boot in keys.js) und der 5-Minuten-Cleanup deckt die TTL-Tabellen ab. Die belastbaren Probleme sind (1) der ungedrosselte, uncachte `/hhttps/info`-Endpunkt mit sechs Table-Counts, (2) das Hot-Row-Statistik-Muster, das auf jedem `/hhttps/check` synchron schreibt, und (3) zwei Tabellen (`revoked_tokens`, `webhook_deliveries`), die nie bereinigt werden und mit dem Traffic unbegrenzt wachsen. Der ESCO-Proxy braucht Timeout und Cache, bevor er breiter genutzt wird.

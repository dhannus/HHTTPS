# AP1 — Korrektheit

Geprüfte Dateien: server/server.js L1–1373 (Middleware, Cookies, HHTTPS-Header, sendJson, Rate-Limits, /.well-known/*, /hhttps/info, /hhttps/check, /hhttps/sign-text, /hhttps/verify-text, /hhttps/signatures*, /hhttps/s/:slug, /s/:slug, /hhttps/esco/suggest); server/keys.js; server/roles.js; server/roles.eaa.js; server/roles.i18n.js; server/roles.taxonomy.js; server/roles.taxonomy.i18n.js; server/roles.taxonomy.test.mjs; server/webhooks.js. Zum Verständnis gelesen (keine Findings): server/db.js (signatures, webhooks), server/sql/migration-phase-2.5.sql, server/package.json, server/test/**.

Stand: `main` @ `bf0a82b`. Zeilennummern per `grep -n`/`sed -n` im aktuellen Stand geprüft.

---

### [S3] [Korrektheit] server/server.js:L468-478 — `readIdentityCookie` wirft bei fehlerhaft kodiertem Cookie-Wert und macht jede Seite zum 500
**Begründung:** Der Cookie-Reader ruft `decodeURIComponent(part.slice(i + 1).trim())` (L475) ohne try/catch auf. Enthält der Wert von `hhttps_identity` eine ungültige Prozent-Sequenz (z. B. `%E0`), wirft `decodeURIComponent` eine `URIError`. Die Middleware L485-514 ist synchron und fängt nur `verifyToken` (L491) ab, nicht den Reader → Express-Default-Handler antwortet 500. Der Server selbst schreibt den Cookie als rohes JWT (keine `%`-Zeichen), d. h. die Dekodierung ist überflüssig; ein von einer anderen Anwendung auf derselben Domain/Subdomain oder manuell gesetzter Wert genügt für den Fehlerpfad.
**Auswirkung:** Betroffener Browser erhält für **alle** Requests (statische Seiten, API, `/`) einen 500, solange der Cookie existiert (bis 1 h, HttpOnly → nicht per JS löschbar; `clearIdentityCookie` wird in diesem Pfad nicht erreicht).
**Empfehlung:** `decodeURIComponent` entfernen (Rohwert zurückgeben) oder in try/catch kapseln und bei Fehler `null` liefern + `clearIdentityCookie(res)`.

### [S3] [Korrektheit] server/server.js:L799-806 — Async-Handler ohne try/catch: DB-Fehler führt zu hängendem Request statt Fehlerantwort (auch L866, L1164-1186, L1266-1276)
**Begründung:** Express 4 (package.json: `"express": "^4.18.2"`) fängt Promise-Rejections aus `async`-Handlern nicht. Betroffen in AP1: `/hhttps/info` (`await Promise.all([...count()])` L802-805), `/hhttps/check` (`await db.stats.increment('check_calls')` L866 liegt **vor** dem try-Block L877), `/hhttps/s/:slug` (`await db.signatures.get(slug)` L1169), `/hhttps/signatures/batch` (`await db.signatures.getMany(cleanSlugs)` L1276). Der globale `process.on('unhandledRejection')` (L4824) loggt nur. Bei `batch` ist der Fehlerpfad sogar durch Eingabe auslösbar: `slugs: [["hp-ABC"]]` passiert den Filter L1275 (`RegExp.test` stringifiziert das Array zu `hp-ABC`), pg serialisiert das verschachtelte Array zu `{{"hp-ABC"}}`, der Cast `::varchar[]` schlägt fehl → Rejection → keine Antwort.
**Auswirkung:** Client wartet bis zu seinem eigenen Timeout, keine 5xx-Antwort, kein Retry-Signal; bei DB-Störung hängen alle Aufrufe der Landing-Page-Statistik (`/hhttps/info`, vom Rate-Limit ausgenommen L435).
**Empfehlung:** Die vier Handler vollständig in try/catch legen (bzw. einen `asyncHandler`-Wrapper einführen) und mit `res.status(500).json(...)` antworten; in `batch` zusätzlich `typeof s === 'string'` im Filter prüfen.

### [S3] [Korrektheit] server/server.js:L1039-1045 — `expired`-Antwort in `/hhttps/verify-text` ist unerreichbar; abgelaufene Textsignaturen liefern 401 statt `{status:'expired', match:true}`
**Begründung:** `verifyToken(signature)` (L1015) ruft `jwt.verify` ohne `ignoreExpiration` auf (keys.js L172). Da `/hhttps/sign-text` `exp: d.exp` in die Signatur schreibt (L983), wirft `jwt.verify` bei Ablauf `TokenExpiredError` („jwt expired“) — geprüft mit jsonwebtoken 9. Der catch (L1046-1048) antwortet 401 `{hhttps:{status:'invalid'}}`. Der Zweig `if (d.exp * 1000 < Date.now())` (L1039) wird nie erreicht.
**Auswirkung:** Die dokumentierte Semantik „Signature expired (text unchanged)“ (Text unverändert, Signatur nur abgelaufen) ist für Verifizierer nicht unterscheidbar von einer gefälschten/ungültigen Signatur; die Browser-Extension kann abgelaufene, aber echte Signaturen nicht als solche anzeigen.
**Empfehlung:** In `verify-text` mit `jwt.verify(..., { ignoreExpiration: true })` (eigene Option in `verifyToken`) prüfen und die Ablaufprüfung explizit wie in L1039 behandeln; alternativ `TokenExpiredError` im catch gesondert abfangen und `jwt.decode` für die Ausgabe nutzen.

### [S3] [Korrektheit] server/webhooks.js:L14-25 — Event-Katalog passt nicht zu den tatsächlich gefeuerten Events; Abonnenten erhalten die realen Ereignisse nie
**Begründung:** `VALID_EVENTS = ['token.issued','token.revoked','role.declared','*']` und `'*'` wird auf genau diese drei Events expandiert (L23-25). server.js feuert aber `identity.verified` (L3188), `age.verified` (L3372), `eudi.verified` (L3572) und `card.issued` (L3656); `role.declared` wird nirgends gefeuert (grep über server/). `findForEvent` filtert per `$1 = ANY(events)` (db.js L670-672) → für die vier realen Events matcht nie ein Webhook; eine Registrierung mit `events: ['card.issued']` wird mit „Unbekanntes Event“ abgewiesen.
**Auswirkung:** Webhook-Feature ist für alle Ereignisse außer `token.issued`/`token.revoked` funktionslos; `role.declared` ist ein totes Abo. Integratoren erhalten keine Fehlermeldung, sondern schlicht keine Zustellung.
**Empfehlung:** `VALID_EVENTS` auf die tatsächlich gefeuerten Events erweitern (und `'*'`-Expansion daraus ableiten), `role.declared` entfernen oder in `/hhttps/role/declare` feuern; Katalog in `/hhttps/info` und Doku angleichen.

### [S3] [Korrektheit] server/server.js:L379-389 — CORS `exposedHeaders` enthält die v0.5-Methoden-Header nicht; Cross-Origin-Clients können `HHTTPS-Verified-Methods` & Co. nicht lesen
**Begründung:** `setHHTPPS` setzt seit v0.5 `HHTTPS-Verified-Methods` (L581), pro Methode `HHTTPS-Email-Verified`, `HHTTPS-Passkey-Verified`, `HHTTPS-Github-Verified`, `HHTTPS-Eudi-Verified`, `HHTTPS-Domain-Verified` sowie `HHTTPS-Domain` (L582-590, Namen aus `VERIFICATION_METHODS` in roles.js L110-137). In der `exposedHeaders`-Liste L380-387 fehlen alle diese Header (ebenso `HHTTPS-RAL`/`HHTTPS-Role-ISCO08` aus roles.eaa.js L52-58). Ohne `Access-Control-Expose-Headers` liefert `response.headers.get()` im Browser für fremde Origins `null`.
**Auswirkung:** Plattformen, die `/hhttps/check` per `fetch` aus dem Browser aufrufen, sehen die „Trademark“-Header nicht — die Header-Schnittstelle ist cross-origin unvollständig; nur der JSON-Body funktioniert.
**Empfehlung:** `exposedHeaders` aus `VERIFICATION_METHODS` ableiten (`Object.values(...).flatMap(m => [m.header, m.valueHeader].filter(Boolean))`) plus `HHTTPS-Verified-Methods`, `HHTTPS-RAL`, `HHTTPS-Role-ISCO08` ergänzen.

### [S3] [Korrektheit] server/roles.taxonomy.js:L92-127 — Reserved-Erkennung per Substring/Präfix liefert Falsch-Positive und falsche Registry-Keys
**Begründung:** `guardReservedRole` prüft `n.includes(stem)` in Listenreihenfolge (L116-118) und ISCO-Präfixe in Objektreihenfolge (L120-125). Konkret reproduziert (node, aktueller Stand): `"Nursery teacher"` → reserved/`nursing` (Stem `nurse`), `"Tierpfleger"` → reserved/`nursing` (Stem `pfleger`), `"Staatsanwältin"` → key `lawyer` statt `police`/prosecutor (Stem `anwaelt` steht vor `staatsanwalt`), ISCO `2612` (Richter) ohne Schlüsselwort → key `notary` (Präfix `'261'` in `notary` L84 wird vor `judge` L88 geprüft), ISCO `3352` (Steuerprüfer) → reserved/`police` (Präfix `'335'` L86 umfasst alle „Regulatory government associate professionals“).
**Auswirkung:** `sanitizeCustomRole` lehnt legitime freie Rollen ab (`reason: 'reserved'`, /hhttps/role/card L3625 antwortet 400), und der zurückgegebene `key` steuert `sourceHint`/`remedy` („Rechtsanwaltskammer“ für eine Staatsanwältin, „Notarkammer“ für einen Richter) — falsche Nutzerführung.
**Empfehlung:** Stems auf Wortgrenzen matchen (`\b`-Regex oder Token-Vergleich nach `normalize`), spezifischere Stems/Präfixe zuerst prüfen (längster Treffer gewinnt), und `'261'`/`'335'` durch die konkreten 4-stelligen ISCO-Codes ersetzen.

### [S3] [Korrektheit] server/server.js:L1089-1141 — Domain wird ohne Längenprüfung in `bound_domain VARCHAR(120)` geschrieben; Überlauf endet als 401 mit PG-Fehlertext
**Begründung:** `normalizeApexDomain` (L607-624) begrenzt die Länge nicht (Regex `^[a-z0-9.\-]+$`), ein Label darf laut Regex beliebig lang sein (z. B. 130× `a` + `.com`). `db.signatures.create` (L1126-1141) schlägt mit `value too long for type character varying(120)` fehl, der catch L1155-1157 antwortet `401 { error: <pg-Fehlertext> }`.
**Auswirkung:** Falscher Statuscode (401 „unauthorized“ für einen Validierungsfehler), interner DB-Fehlertext wird an den Client durchgereicht; Slug wurde bereits erzeugt/geprüft, Zähler nicht erhöht — kein Datenschaden, aber irreführende API-Semantik.
**Empfehlung:** In `normalizeApexDomain` `h.length > 253` bzw. Label-Länge > 63 → `null` (RFC 1035), und im catch zwischen Token-Fehlern (401) und sonstigen Fehlern (400/500) unterscheiden.

### [S3] [Korrektheit] server/server.js:L774-796 — ESCO-Proxy ruft `fetch` ohne Timeout auf; hängender Upstream blockiert den Request unbegrenzt
**Begründung:** `await fetch(url, { headers: ... })` (L781) ohne `signal: AbortSignal.timeout(...)`. Node-`fetch` hat keinen Default-Timeout; bei nicht antwortendem `ec.europa.eu` wartet der Handler bis zum TCP-Timeout des Betriebssystems. webhooks.js macht es korrekt (`AbortSignal.timeout(8000)`, L79).
**Auswirkung:** Typeahead-Requests des Rollen-Formulars hängen minutenlang; jeder Tastendruck des Nutzers öffnet einen weiteren hängenden Request und belegt Verbindungen des globalen Rate-Limits (300/min).
**Empfehlung:** `signal: AbortSignal.timeout(5000)` ergänzen; der bestehende catch liefert dann sauber `{ results: [], error: 'esco_unreachable' }`.

### [S3] [Korrektheit] server/server.js:L865-1351 — Kern-Endpunkte (`/hhttps/check`, sign-/verify-text, signatures*, /s/:slug, Discovery/JWKS, Identity-Cookie) haben keinen einzigen Test
**Begründung:** `grep` über `server/test/**` findet keine Referenz auf `/hhttps/check`, `sign-text`, `verify-text`, `/hhttps/signatures`, `/hhttps/s/`, `/s/hp-`, `hhttps_identity`, `jwks.json`, `hhttps-configuration`, `hhttps-role-assurance` oder `esco/suggest`. Getestet werden nur `/hhttps/info` (Smoke) und die AP2-AP4-Flows. Die in diesem Review gefundenen Fehlerpfade (unerreichbarer `expired`-Zweig L1039, Batch-Hang L1275, Cookie-500 L475) wären mit einfachen Integrationstests aufgefallen.
**Auswirkung:** Der Protokoll-Kern (`/hhttps/check` ist der von Plattformen aufgerufene Endpunkt) und die Signatur-Lebenszyklen (create → verify → wrong-domain → revoke → batch) können ohne Regressionserkennung geändert werden.
**Empfehlung:** Integrationstests in `server/test/integration/` für `/hhttps/check` (kein Token / gültig / revoked / machine), sign-/verify-text (match, modified, revoked, expired) und den Signatur-Lebenszyklus inkl. Domain-Binding ergänzen.

### [S4] [Korrektheit] server/package.json:L11 — `roles.taxonomy.test.mjs` liegt außerhalb des `npm test`-Globs und wird nie ausgeführt
**Begründung:** `"test": "node --test \"test/unit/**/*.test.mjs\" \"test/integration/**/*.test.mjs\""`; die Datei liegt unter `server/roles.taxonomy.test.mjs` (Kopfkommentar L2-3: „Run: node roles.taxonomy.test.mjs“). Sie nutzt `assert` + `console.log`, nicht `node:test`.
**Auswirkung:** Die 9 Prüfungen der RAL-/Reserved-Logik laufen weder in `npm test` noch in CI; die in Finding 6 beschriebenen Falsch-Positive (`Tierpfleger`, `Nursery teacher`) sind nicht abgedeckt.
**Empfehlung:** Datei nach `test/unit/roles.taxonomy.test.mjs` verschieben und auf `node:test` (`test()`/`describe()`) umstellen.

### [S4] [Korrektheit] server/server.js:L1331-1341 — `reason` beim Signatur-Revoke ungeprüft in `revoke_reason VARCHAR(120)`; >120 Zeichen → 401 mit PG-Fehlertext
**Begründung:** `const reason = req.body?.reason` (L1331) wird ohne Typ-/Längenprüfung an `db.signatures.revoke` (L1341) gegeben; bei >120 Zeichen wirft pg, der catch L1349 antwortet `401 { error: 'value too long …' }` — der Nutzer war aber korrekt authentifiziert.
**Auswirkung:** Falscher Statuscode, Revoke schlägt still fehl (Signatur bleibt gültig), Client erhält keine verwertbare Fehlermeldung.
**Empfehlung:** `typeof reason === 'string' ? reason.slice(0, 120) : null` vor dem DB-Aufruf.

### [S4] [Korrektheit] server/keys.js:L142-150 — `forgetRetiredKey` ist nicht restart-fest; `rotateKeys`/`forgetRetiredKey` haben keinen Aufrufer
**Begründung:** `forgetRetiredKey` löscht den kid nur aus der In-Memory-Map (`_retired.delete(kid)`, L146), die Datei `keys/retired/<kid>.pem` bleibt liegen. `loadRetiredKeys` (L58-70) liest beim nächsten Start alle `.pem` wieder ein → der Schlüssel erscheint erneut im JWKS. Zudem gibt es im Repo (grep über *.js/*.mjs/*.sh, ohne node_modules) keinen Aufrufer von `rotateKeys` oder `forgetRetiredKey` — die Rotation ist nur per REPL/Eigenskript auslösbar.
**Auswirkung:** Ein bewusst aus dem JWKS entfernter Alt-Schlüssel wird nach Deploy/Neustart wieder veröffentlicht (Kommentar L138-140 verspricht das Gegenteil); operativ ist die dokumentierte Rotation nicht ausführbar.
**Empfehlung:** In `forgetRetiredKey` die Datei umbenennen/löschen (oder eine `.forgotten`-Markierung), und ein `scripts/rotate-keys.mjs` bereitstellen.

### [S4] [Korrektheit] server/server.js:L412-417 — Rate-Limit-Handler meldet `retryAfter` als volles Fenster statt Restzeit
**Begründung:** `retryAfter: Math.ceil(windowMs / 1000)` ist konstant (z. B. 3600 für `email`), unabhängig davon, wann das Fenster endet. express-rate-limit liefert den korrekten Wert in `req.rateLimit.resetTime` bzw. im `RateLimit-Reset`-Header (`standardHeaders: true`).
**Auswirkung:** Clients, die dem JSON-Feld folgen, warten bis zu 60 min zu lang (E-Mail-Limit), obwohl der Header bereits eine kürzere Restzeit ausweist — Header und Body widersprechen sich.
**Empfehlung:** `retryAfter: Math.max(1, Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000))` verwenden.

### [S4] [Korrektheit] server/server.js:L868 — `Authorization`-Header wird nur bei exakt `Bearer ` (Groß-/Kleinschreibung) akzeptiert (ebenso L951, L1078, L1329)
**Begründung:** `req.headers['authorization']?.replace('Bearer ', '')` entfernt das Schema nur bei exakter Schreibweise; RFC 9110 §11.1 definiert das Auth-Schema als case-insensitiv (`bearer <tok>` ist gültig, viele HTTP-Clients normalisieren so). Der String `bearer eyJ…` wird dann als Token an `verifyToken` gegeben → 401 „jwt malformed“.
**Auswirkung:** Standardkonforme Clients erhalten `invalid` für gültige Tokens.
**Empfehlung:** Gemeinsame Helper-Funktion `bearerFrom(req)` mit `/^bearer\s+(.+)$/i`.

### [S4] [Korrektheit] server/server.js:L333-357 — HTML-Viewer von `sendJson` verwirft den Query-String; „Raw JSON“/„Kopieren“ liefern ein anderes Ergebnis als die angezeigte Seite
**Begründung:** Links und `fetch` verwenden `${req.path}?format=json`; `req.path` enthält keine Query. Für `/hhttps/s/:slug?domain=example.com` zeigt der Viewer z. B. `wrong-domain`, der Raw-Link liefert `verified` (Domain-Check entfällt L1180). Zudem setzt der erste Aufruf `first_seen` (L1183-1185) und erhöht `verify_count` (L1176) ein zweites Mal.
**Auswirkung:** Irreführende Anzeige beim manuellen Prüfen einer Signatur mit Domain-Parameter; Zähler doppelt.
**Empfehlung:** `req.originalUrl` mit angehängtem `format=json` (via `URLSearchParams`) verwenden.

### [S4] [Korrektheit] server/server.js:L751 — Discovery meldet `supported_verification` aus dem Legacy-Katalog `VERIFICATION_LEVELS` statt der v0.5-Methoden
**Begründung:** `supported_verification: Object.keys(VERIFICATION_LEVELS)` listet 25 Level (`press-card`, `bar-association-id`, …), von denen laut roles.js L200-215 die meisten `implemented: false` sind; das tatsächliche v0.5-Modell (`VERIFICATION_METHODS`: email, passkey, domain, github, eudi, age) und `HHTTPS-Verified-Methods` werden nicht beworben. `/hhttps/info` (L811-812) beschreibt dagegen `features: ['webauthn','roles-esco-dynamic','email-verification', …]`.
**Auswirkung:** Discovery-Dokument und Wire-Format (`verified_methods[]` im Token, Header) sind inkonsistent; Clients können die tatsächlich möglichen Methoden nicht aus der Discovery ableiten.
**Empfehlung:** `supported_verification_methods: Object.keys(VERIFICATION_METHODS)` (+ Header-Namen) ausgeben und `VERIFICATION_LEVELS` als `legacy_role_levels` kennzeichnen oder weglassen.

### [S4] [Korrektheit] server/server.js:L485-514 — Identity-Cookie-Middleware prüft weder Revocation noch Existenz des Tokens
**Begründung:** Es wird nur `verifyToken` (Signatur/Ablauf, L491) geprüft, nicht `checkTokenValid` (L680-689: `revokedTokens.has`, `tokens.exists`). `clearIdentityCookie` wird nur im Revoke-Aufruf desselben Browsers gesetzt (L3693). Wird das Token über einen anderen Client/Admin revoked, liefert hhttps.org dem Browser bis zum Cookie-Ablauf (1 h) weiterhin `HHTTPS-Status: verified`.
**Auswirkung:** Widersprüchliche Zustände zwischen `/hhttps/check` (401 „Token revoked“) und den Seiten-Headern derselben Origin (verified); Entwickler-Feature zeigt falsche Identität.
**Empfehlung:** Für die Cookie-Middleware `checkTokenValid` (mit kleinem In-Memory-Cache) verwenden oder zumindest `revokedTokens.has` prüfen; bei Fehler Cookie löschen.

### [S4] [Korrektheit] server/server.js:L607-624 — `normalizeApexDomain` behandelt IPv4-Adressen als Domains („192.168.0.1“ → „0.1“)
**Begründung:** Die Regex L612 lässt Ziffern/Punkte zu, danach werden die letzten zwei Labels als Apex genommen (L623). Für `http://10.0.0.5/`-Bindings (Intranet-Demos) wird `0.5` gespeichert; alle IPs mit gleicher Endung matchen.
**Auswirkung:** Domain-Binding für IP-Hosts ist wirkungslos bzw. kollidiert; Slug-Verifikation mit `?domain=10.0.0.5` meldet fälschlich `verified`.
**Empfehlung:** `net.isIP(h)` → IP unverändert zurückgeben (oder `null` und 400).

### [S4] [Korrektheit] server/webhooks.js:L20-25 — `events` wird ohne Typprüfung verwendet; String statt Array erzeugt eine TypeError-Meldung als 400-Text
**Begründung:** `events.find(...)` (L20) wirft bei `events: "token.issued"` (String) `events.find is not a function`; der Aufrufer L3893-3902 gibt `e.message` als 400 weiter. Zusätzlich: `deactivateIfFailing(wh.id, 10)` (L95) wird pro fehlgeschlagenem Event erst nach 3 Versuchen aufgerufen, `failures` zählt aber jeden Versuch (db.js L695-699) → Deaktivierung effektiv nach dem 4. fehlgeschlagenen Event (12 Failures), nicht „nach 10 Failures“ wie L93-96 kommentiert.
**Auswirkung:** Unverständliche Fehlermeldung für Integratoren; Abschaltschwelle weicht von Doku/Kommentar ab.
**Empfehlung:** `if (!Array.isArray(events) || !events.length) throw new Error('events must be a non-empty array')`; Schwelle auf Event-Basis zählen oder Kommentar/Doku anpassen.

### [S4] [Korrektheit] server/roles.i18n.js:L307 — Deutsche Übersetzung markiert EUDI-Altersnachweis als „Geplant“, kanonisch ist er live
**Begründung:** DE-Katalog: `'eudi-wallet': { …, note: '… Geplant.' }`; roles.js L322-326 (`available: true`, „live today“). Zudem fehlt `'av-app'` (roles.js L327-331) im DE-Katalog (Fallback Englisch, funktional ok).
**Auswirkung:** Deutsche UI zeigt eine verfügbare Methode als geplant an.
**Empfehlung:** Note aktualisieren, `av-app` ergänzen.

---

## Zusammenfassung

- **S1 Critical:** 0
- **S2 High:** 0
- **S3 Medium:** 9
- **S4 Low:** 10

Gesamteindruck: Der Kern (Token-Ausgabe, `checkTokenValid`, Header-Setzung, Slug-Signaturen) ist logisch sauber und defensiv gegen ungültige Tokens; kritische Auth-Bypässe oder Datenverlust-Pfade habe ich in AP1 nicht gefunden. Die belastbaren Mängel liegen bei unbehandelten Fehlerpfaden (async-Handler ohne try/catch, Cookie-Decoder, ESCO-Fetch ohne Timeout), einem unerreichbaren `expired`-Zweig, der Diskrepanz zwischen Webhook-Katalog und gefeuerten Events sowie der zu groben Reserved-Role-Heuristik. Auffällig ist, dass der gesamte Signatur- und `/hhttps/check`-Pfad ohne automatisierte Tests ist — mehrere der Findings wären mit einfachen Integrationstests sichtbar geworden.

# AP1 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b (Arbeitsbaum e9b0a93; `git diff bf0a82b..HEAD -- server/` leer, Code identisch)

Prüfmittel: `sed -n`/`grep -n` gegen den aktuellen Stand, Repro-Skripte im Scratchpad (jsonwebtoken 9.0.3, express 4.22.2, express-rate-limit 7.5.1), Test-PostgreSQL unter `/var/lib/pgtest` (Rolle `hhttps`, DB `hhttps`). Keine Projektdateien geändert.

IDs in Reihenfolge K (AP1-01…20), S (AP1-21…31), P (AP1-32…41), W (AP1-42…65).

Hinweis zu Webhooks: Die Route-Seite (unauthentifiziertes `GET/POST/DELETE /hhttps/webhooks`, server.js L3889-3910) wird in **AP5** verifiziert. Hier werden nur die `webhooks.js`-Anteile bewertet (URL-Validierung/SSRF, Secret-Rückgabe von `listWebhooks`, Event-Katalog, Retry-Logik).

## Bestätigte Findings

### AP1-01 [S4] [Korrektheit] server/server.js:L468-478 — `readIdentityCookie` wirft bei fehlerhaft kodiertem Cookie-Wert `URIError` → 500 auf jeder Route
**Urteil:** BESTÄTIGT (herabgestuft von S3: Fehlerpfad ist nur durch den eigenen Browser bzw. eine Anwendung auf derselben Origin/Subdomain auslösbar, kein Fremdangriff; Cookie ist per Browser-UI löschbar). AP1-31 (S, S4) hierher zusammengeführt.
**Beleg:** L475 `return decodeURIComponent(part.slice(i + 1).trim());` ohne try/catch; Aufruf L488 in der synchronen Middleware L485-514, deren try/catch (L490-508) nur `verifyToken` umschließt. Repro: `decodeURIComponent('%E0')` → `URIError`. Express 4 fängt synchrone Middleware-Throws und antwortet per Default-Handler 500 (ohne `NODE_ENV=production` inkl. Stacktrace).
**Auswirkung:** Betroffener Browser erhält 500 für alle Requests, solange das Cookie existiert; `clearIdentityCookie` wird nicht erreicht. Server schreibt selbst nie `%`-Zeichen (rohes JWT), Dekodierung ist überflüssig.
**Empfehlung:** `decodeURIComponent` entfernen oder in try/catch kapseln; bei Fehler `clearIdentityCookie(res)` und `null` zurückgeben.

### AP1-02 [S3] [Korrektheit] server/server.js:L799-806 — Async-Handler ohne try/catch: DB-Fehler führt zu hängendem Request statt 5xx (auch L866, L1164-1170, L1266-1276)
**Urteil:** BESTÄTIGT (Severity unverändert), mit Korrektur: der behauptete Eingabe-Trigger im Batch existiert nicht.
**Beleg:** Express 4.22.2 (installiert) fängt Promise-Rejections aus `async`-Handlern nicht. `/hhttps/info` L802-805 `await Promise.all([...count()])` ohne try; `/hhttps/check` L866 `await db.stats.increment('check_calls')` liegt vor dem try (L877); `/hhttps/s/:slug` L1169 `await db.signatures.get(slug)` ohne try; `/hhttps/signatures/batch` L1276 `await db.signatures.getMany(cleanSlugs)` ohne try. `process.on('unhandledRejection')` L4824 loggt nur.
**Widerlegt:** `slugs: [["hp-ABC"]]` passiert zwar den Regex-Filter (`/^hp-[A-Z0-9\-]+$/i.test(['hp-ABC'])` → `true`, geprüft), aber PostgreSQL akzeptiert das verschachtelte Array: `SELECT $1::varchar[]` mit `[['hp-ABC']]` → `{"a":[["hp-ABC"]]}` und `SELECT * FROM signatures WHERE id = ANY($1::varchar[])` → 0 Zeilen, **kein Fehler** (gegen Test-PG ausgeführt). Der Fehlerpfad ist also nur bei DB-Störung (Pool erschöpft, Verbindungsabbruch, fehlende Tabelle) erreichbar, nicht per Eingabe.
**Auswirkung:** Bei DB-Störung hängen Client-Requests bis zu deren eigenem Timeout ohne Statuscode; `/hhttps/info` ist zudem vom globalen Limiter ausgenommen (L435).
**Empfehlung:** Vier Handler vollständig in try/catch (oder `asyncHandler`-Wrapper) mit `res.status(500)`; im Batch zusätzlich `typeof s === 'string'` im Filter (Hygiene, kein Bug).

### AP1-03 [S3] [Korrektheit] server/server.js:L1039-1045 — `expired`-Zweig in `/hhttps/verify-text` unerreichbar; abgelaufene Textsignaturen liefern 401 `invalid`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `/hhttps/sign-text` L983 schreibt `exp: d.exp` in die Signatur. `verifyToken` (keys.js L164-173) ruft `jwt.verify(token, key, { algorithms: ['ES256'] })` ohne `ignoreExpiration` auf. Repro mit jsonwebtoken 9.0.3: Token mit `exp = now-10s` → `jwt.verify` wirft `TokenExpiredError: jwt expired`. Damit landet L1015 im catch L1046-1048 (401 `{hhttps:{status:'invalid'}}`); L1039 `if (d.exp * 1000 < Date.now())` wird nie erreicht.
**Auswirkung:** Semantik „Signature expired (text unchanged)“ nicht verfügbar; Extension kann echte-aber-abgelaufene Signaturen nicht von gefälschten unterscheiden.
**Empfehlung:** `verifyToken(token, { ignoreExpiration: true })`-Option für `verify-text` und Ablauf explizit prüfen; oder `TokenExpiredError` im catch gesondert behandeln und `jwt.decode` für die Ausgabe nutzen.

### AP1-04 [S3] [Korrektheit] server/webhooks.js:L14-25 — Event-Katalog passt nicht zu den gefeuerten Events
**Urteil:** BESTÄTIGT (Severity unverändert). AP1-57 (W, S3) hierher zusammengeführt.
**Beleg:** webhooks.js L14 `VALID_EVENTS = ['token.issued','token.revoked','role.declared','*']`, L23-25 `'*'`-Expansion auf dieselben drei. server.js feuert `identity.verified` (L3188), `token.issued` (L3189), `age.verified` (L3372), `eudi.verified` (L3572), `card.issued` (L3656), `token.revoked` (L3690). `role.declared` wird nirgends gefeuert (grep). `findForEvent` filtert per `$1 = ANY(events)` (db.js L670-672).
**Auswirkung:** Vier von sechs Events können nicht abonniert werden (Registrierung mit `card.issued` → 400 „Unbekanntes Event“), `role.declared` ist ein totes Abo; keine Fehlermeldung für Integratoren.
**Empfehlung:** Eine exportierte `WEBHOOK_EVENTS`-Konstante als einzige Quelle; `fireEvent` validiert dagegen; `'*'` daraus expandieren; `role.declared` entfernen oder feuern.

### AP1-05 [S3] [Korrektheit] server/server.js:L379-389 — CORS `exposedHeaders` enthält die v0.5-Methoden-Header nicht
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L380-387 listet nur die Legacy-Header (Protocol-Version … Age-Method). `setHHTPPS` setzt seit v0.5 L581 `HHTTPS-Verified-Methods` und L582-590 pro Methode `m.header` (`HHTTPS-Email-Verified`, `-Passkey-`, `-Domain-`, `-Github-`, `-Eudi-Verified`, roles.js L120-146) sowie `HHTTPS-Domain`. Keiner davon steht in `exposedHeaders`; `HHTTPS-RAL`/`HHTTPS-Role-ISCO08` (roles.eaa.js L53-58) ebenfalls nicht.
**Auswirkung:** Cross-Origin-`fetch` auf `/hhttps/check` sieht die Methoden-Header nicht (`headers.get()` → `null`); nur der JSON-Body ist vollständig.
**Empfehlung:** `exposedHeaders` aus `VERIFICATION_METHODS` ableiten plus `HHTTPS-Verified-Methods`, `HHTTPS-RAL`, `HHTTPS-Role-ISCO08`.

### AP1-06 [S3] [Korrektheit] server/roles.taxonomy.js:L92-127 — Reserved-Erkennung per Substring/Präfix liefert Falsch-Positive und falsche Registry-Keys
**Urteil:** BESTÄTIGT (Severity unverändert). AP1-55 (W, S3, ISCO-Präfix `'261'`) hierher zusammengeführt (gleiche Ursache: Reihenfolge-abhängiges `startsWith`/`includes`).
**Beleg:** Repro mit `guardReservedRole` (aktueller Stand):
- `"Nursery teacher"` → `{reserved:true, matched:'nurse', key:'nursing'}`
- `"Tierpfleger"` → `{reserved:true, matched:'pfleger', key:'nursing'}`; `sanitizeCustomRole('Tierpfleger')` → `{ok:false, reason:'reserved'}`
- `"Staatsanwältin"` → `key:'lawyer'` (Stem `anwaelt` vor `staatsanwalt`, L96 vs L98)
- ISCO `2612` ohne Text → `key:'notary'` (Präfix `'261'` in `notary` L84 wird vor `judge` L88 geprüft)
- ISCO `3352` / `"Steuerprüfer"` → `key:'police'` (Präfix `'335'` L86)
Aufrufer: `/hhttps/role/card` server.js L3611 (`sanitizeCustomRole`) und L3621-3629 (`guardReservedRole` → 400 mit `remedy` aus `RESERVED_REGISTRY[key].sourceHint`).
**Auswirkung:** Legitime freie Rollen werden abgelehnt; `remedy` nennt die falsche Kammer („Rechtsanwaltskammer“ für Staatsanwältin, „Notarkammer“ für Richter).
**Empfehlung:** Wortgrenzen-Match, längster Stem/Präfix gewinnt, `'261'`/`'335'` durch konkrete 4-stellige Codes ersetzen; Test, der jedes Registry-Präfix auf seinen eigenen Key auflöst.

### AP1-07 [S4] [Korrektheit] server/server.js:L1089-1141 — Domain ohne Längenprüfung in `bound_domain VARCHAR(120)`; Überlauf endet als 401 mit PG-Fehlertext
**Urteil:** BESTÄTIGT (herabgestuft von S3: kein Datenschaden, nur falscher Statuscode; das Durchreichen von `e.message` ist in AP1-29 gesondert erfasst)
**Beleg:** `normalizeApexDomain` L607-624: Regex `^[a-z0-9.\-]+$` ohne Längenlimit; Repro `'a'.repeat(130)+'.com'` → 134 Zeichen zurückgegeben. migration-phase-2.5.sql L40 `bound_domain VARCHAR(120)`. `db.signatures.create` L1126-1141 im try, catch L1157-1159 antwortet `401 { error: e.message }`.
**Auswirkung:** 401 für einen Validierungsfehler, PG-Fehlertext an den Client.
**Empfehlung:** RFC-1035-Grenzen (253 gesamt, 63 pro Label) in `normalizeApexDomain`; im catch Token-Fehler (401) von sonstigen (400/500) trennen.

### AP1-08 [S3] [Korrektheit] server/server.js:L774-796 — ESCO-Proxy `fetch` ohne Timeout (und ohne eigenes Rate-Limit/Cache)
**Urteil:** BESTÄTIGT (Severity unverändert). AP1-30 (S, S4) und AP1-36 (P, S3) hierher zusammengeführt.
**Beleg:** L781 `await fetch(url, { headers: { accept: 'application/json' } })` — kein `signal`. Vergleich webhooks.js L76 `signal: AbortSignal.timeout(8000)`. Nur `limit.global` (300/min) greift; kein Cache. `q` ist `encodeURIComponent`-kodiert, `lang` auf `de|en` beschränkt → kein SSRF.
**Auswirkung:** Hängender Upstream hält Sockets/Handler bis zum undici-Default offen; jeder Tastendruck des Typeahead öffnet einen weiteren Request; anonymer Verstärker gegen die EU-API.
**Empfehlung:** `signal: AbortSignal.timeout(3000–5000)`, eigener Limiter (`rl(60)`), kleiner TTL-Cache pro `lang:q`.

### AP1-09 [S3] [Korrektheit] server/server.js:L865-1351 — Kern-Endpunkte ohne einen einzigen Test
**Urteil:** BESTÄTIGT (Severity unverändert). AP1-59 (W, S3) hierher zusammengeführt.
**Beleg:** `grep -rn "hhttps/check|sign-text|verify-text|hhttps/signatures|/hhttps/s/|hhttps_identity|jwks|hhttps-configuration|esco/suggest|normalizeApex|webhook" server/test` → keine Treffer (einziger `.well-known`-Treffer ist `openid-configuration` in oauth-claims.test.mjs, AP2). smoke.test.mjs deckt nur `/hhttps/info`. `.github/workflows/ci.yml` führt nur `node --check` aus.
**Auswirkung:** AP1-02/03/17 wären mit einfachen Integrationstests aufgefallen; Refactorings aus AP1-43…45 sind ohne Netz.
**Empfehlung:** Unit-Tests für `normalizeApexDomain`, `hashTextLoose`, `generateSlug`, `setHHTPPS`; Integrationstests für `check`, `sign-/verify-text`, Signatur-Lebenszyklus, `verifyToken` mit retired kid.

### AP1-10 [S4] [Korrektheit] server/package.json:L11 — `roles.taxonomy.test.mjs` außerhalb des `npm test`-Globs
**Urteil:** BESTÄTIGT (Severity unverändert). AP1-56 (W, S3) hierher zusammengeführt; S4 belassen, da die 9 Checks manuell bestehen und nur die Automatisierung fehlt.
**Beleg:** package.json L11 `node --test "test/unit/**/*.test.mjs" "test/integration/**/*.test.mjs"`; Datei liegt unter `server/roles.taxonomy.test.mjs`, nutzt `assert` + `console.log` (L5, L12), importiert `guardReservedRole`/`CUSTOM_ROLE_ID` ungenutzt (L7-8, ESLint).
**Auswirkung:** AP1-06 ist nicht abgedeckt, obwohl eine Testdatei existiert.
**Empfehlung:** Nach `test/unit/` verschieben, auf `node:test` umstellen.

### AP1-11 [S4] [Korrektheit] server/server.js:L1331-1341 — `reason` beim Signatur-Revoke ungeprüft in `revoke_reason VARCHAR(120)`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L1331 `const reason = req.body?.reason;` ohne Typ/Länge; L1341 `db.signatures.revoke(slug, signerId, reason)`; migration-phase-2.5.sql L61 `revoke_reason VARCHAR(120)`; catch L1351 `401 { error: e.message }`.
**Auswirkung:** Authentifizierter Revoke schlägt mit 401 und PG-Text fehl; Signatur bleibt gültig.
**Empfehlung:** `typeof reason === 'string' ? reason.slice(0, 120) : null`.

### AP1-12 [S4] [Korrektheit] server/keys.js:L142-150 — `forgetRetiredKey` nicht restart-fest; Rotations-API ohne Aufrufer
**Urteil:** BESTÄTIGT (Severity unverändert). AP1-58 (W, S3) hierher zusammengeführt; S4 belassen: Rotation ist per `node -e "import('./keys.js').then(k=>k.rotateKeys())"` ausführbar, und ein wieder veröffentlichter *öffentlicher* Altschlüssel ist kein Sicherheitsproblem, nur ein Dokumentationswiderspruch.
**Beleg:** L146 `_retired.delete(kid)` nur In-Memory, Datei bleibt (Kommentar L145). `loadRetiredKeys` L57-70 liest beim Start alle `retired/*.pem` erneut. `grep -rn "rotateKeys\|forgetRetiredKey"` außerhalb keys.js: keine Treffer. Ebenfalls unbenutzt: `getPublicKey`, `getPrivateKey`, `getKid`, `getRetiredKids` (L194-197).
**Auswirkung:** „Vergessen“ gilt nur bis zum Neustart; kein Skript/Runbook für die dokumentierte Rotation.
**Empfehlung:** Datei nach `retired/archived/` verschieben oder Kommentar korrigieren; `scripts/rotate-keys.mjs` ergänzen.

### AP1-13 [S4] [Korrektheit] server/server.js:L412-417 — Rate-Limit-Handler meldet `retryAfter` als volles Fenster
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L415 `retryAfter: Math.ceil(windowMs / 1000)` konstant. express-rate-limit 7.5.1 stellt `req.rateLimit.resetTime` (Date) bereit und berechnet den `RateLimit-Reset`-Header selbst aus der Restzeit (`dist/index.cjs` L37-40 `getResetSeconds`).
**Auswirkung:** Body (`3600`) und Header widersprechen sich beim E-Mail-Limit um bis zu 60 min.
**Empfehlung:** `Math.max(1, Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000))`.

### AP1-14 [S4] [Korrektheit] server/server.js:L868 — `Authorization` nur bei exakt `Bearer ` (Groß-/Kleinschreibung) akzeptiert (auch L951, L1078, L1329)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Vier identische `req.headers['authorization']?.replace('Bearer ', '')` (L868, L951, L1078, L1329). `bearer eyJ…` wird unverändert als Token an `verifyToken` gereicht → `jwt malformed` → 401.
**Auswirkung:** RFC-9110-konforme Clients mit kleingeschriebenem Schema erhalten `invalid`.
**Empfehlung:** Helfer `bearerFrom(req)` mit `/^bearer\s+(.+)$/i` (zusammen mit AP1-43).

### AP1-15 [S4] [Korrektheit] server/server.js:L333-357 — HTML-Viewer von `sendJson` verwirft den Query-String
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L333 `href="${req.path}?format=json"`, L357 `fetch('${req.path}?format=json')`; `req.path` enthält keine Query. Für `/hhttps/s/:slug?domain=x` entfällt beim Raw-Link der Domain-Check (L1180 `req.query.domain`) und `incrementVerify`/`setFirstSeen` (L1177-1185) laufen erneut.
**Auswirkung:** Viewer zeigt `wrong-domain`, Raw-Link `verified`; Zähler doppelt.
**Empfehlung:** `req.originalUrl` + `URLSearchParams` verwenden.

### AP1-16 [S4] [Korrektheit] server/server.js:L751 — Discovery meldet `supported_verification` aus dem Legacy-Katalog `VERIFICATION_LEVELS`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L751 `supported_verification: Object.keys(VERIFICATION_LEVELS)` (25 Einträge, roles.js L72-98); `VERIFICATION_CHECKS` L225-262 markiert 14 davon `implemented: false`. Das v0.5-Modell `VERIFICATION_METHODS` (email, passkey, domain, github, eudi, age) wird nicht beworben.
**Auswirkung:** Discovery und Wire-Format (`verified_methods[]`, `HHTTPS-Verified-Methods`) inkonsistent.
**Empfehlung:** `supported_verification_methods: Object.keys(VERIFICATION_METHODS)`; Legacy-Liste kennzeichnen oder entfernen (siehe AP1-50).

### AP1-17 [S3] [Korrektheit] server/server.js:L485-514 — Identity-Cookie-Middleware prüft weder Revocation noch Token-Typ (Negativliste)
**Urteil:** BESTÄTIGT (hochgestuft von S4 auf S3 durch Zusammenführung mit AP1-24 (S, S3): neben der fehlenden Revocation akzeptiert die Negativliste auch fremde Token-Typen)
**Beleg:** L491 nur `verifyToken` (Signatur + `exp`); kein `db.revokedTokens.has`, kein `db.tokens.exists` (anders als `checkTokenValid` L702-711). Typprüfung L492 `d.sub !== 'refresh' && !(d.actorType === 'bot')` ist eine Negativliste: Text-Signaturen (`sub: 'text-signature'`, L975-986) und OAuth-Access-Tokens für Drittclients (`sub: pairwiseId`, `aud: client_id`, L1809-1830) passieren, da `verifyToken` (keys.js L164-173) weder `iss` noch `aud` prüft. `clearIdentityCookie` nur im Revoke desselben Browsers (L3693).
**Auswirkung:** Nach `/hhttps/revoke` über einen anderen Client zeigt hhttps.org bis zu 1 h `HHTTPS-Status: verified`; ein in das Cookie gesetztes OAuth-Access-Token/Text-Signatur-JWT wird als Identität dargestellt. Wirkung auf die eigene Origin beschränkt (HttpOnly, SameSite=Lax) → S3, nicht höher.
**Empfehlung:** Positivliste `sub === 'human-verified'` + `jti` vorhanden; `revokedTokens.has(jti)` (ggf. gecached) prüfen; bei Fehler Cookie löschen.

### AP1-18 [S4] [Korrektheit] server/server.js:L607-624 — `normalizeApexDomain` behandelt IPv4-Adressen als Domains
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Repro: `normalizeApexDomain('192.168.0.1')` → `'0.1'` (Regex L612 lässt Ziffern/Punkte zu, L623 nimmt die letzten zwei Labels).
**Auswirkung:** Domain-Binding für IP-Hosts wirkungslos; alle IPs mit gleicher Endung kollidieren.
**Empfehlung:** `net.isIP(h)` → IP unverändert zurückgeben oder `null`.

### AP1-19 [S4] [Korrektheit] server/webhooks.js:L20-25 — `events` ohne Typprüfung; Deaktivierungsschwelle weicht vom Kommentar ab
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L20 `events.find(...)` wirft bei String `events.find is not a function`; server.js L3904 reicht `e.message` als 400 weiter. Retry: `deliverWithRetry` ruft `recordDelivery(...'failed')` pro Versuch (L86, db.js L697 `failures + 1`), `deactivateIfFailing(wh.id, 10)` erst nach dem 3. Versuch (L95) → Deaktivierung nach Event 4 bei 12 Failures, nicht bei 10 (Kommentar L94/L96).
**Auswirkung:** Unverständliche Fehlermeldung; Schwelle nicht wie dokumentiert.
**Empfehlung:** `Array.isArray(events) && events.length`-Prüfung; Schwelle pro Event zählen oder Kommentar anpassen.

### AP1-20 [S4] [Korrektheit] server/roles.i18n.js:L307 — DE-Übersetzung markiert EUDI-Altersnachweis als „Geplant“; `av-app` fehlt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L307 `'eudi-wallet': { …, note: '… Geplant.' }`; roles.js L346-350 `available: true`. `av-app` (roles.js L351-355) fehlt im DE-Katalog (Fallback Englisch).
**Auswirkung:** Deutsche UI zeigt eine live verfügbare Methode als geplant.
**Empfehlung:** Note aktualisieren, `av-app` ergänzen.

### AP1-21 [S2] [Sicherheit] server/webhooks.js:L17-18 — Webhook-URL nur syntaktisch geprüft: SSRF gegen interne Netze
**Urteil:** BESTÄTIGT (Severity unverändert; Bewertung hier nur für `webhooks.js`. Die fehlende Authentifizierung der registrierenden Route `POST /hhttps/webhooks` (server.js L3893-3904, nur `limit.webhooks` 20/h/IP) wird in **AP5** verifiziert — sie ist die Voraussetzung dafür, dass S2 statt S3 gilt.)
**Beleg:** L18 `try { new URL(url); } catch { throw new Error('Invalid webhook URL.'); }` — kein Schema-Allowlist, kein Loopback/RFC1918/Link-Local-Ausschluss. `deliverWithRetry` L67-77 `fetch(wh.url, { method:'POST', … })` mit Default `redirect: 'follow'`, 3 Versuche (L64, L88-91), Timeout 8 s (L76). Auslöser: jedes `token.issued`/`token.revoked`-Event (server.js L3189, L3690). `recordDelivery` speichert `status_code` (db.js L685-690); `GET /hhttps/webhooks` liefert `failures`/`deliveries`/`lastDelivery` → Erreichbarkeits-Orakel.
**Auswirkung:** Blinder SSRF-POST an `127.0.0.1:*`, `169.254.169.254`, den eudi-verifier-Backend-Port etc.; Port-Scan-Orakel über die Liste.
**Empfehlung:** In `registerWebhook` nur `https:` (Dev: `http:`), Host nach DNS-Auflösung gegen private/Loopback/Link-Local/ULA prüfen, `redirect: 'error'` im `fetch`; Registrierung an Auth binden (AP5).

### AP1-22 [S2] [Sicherheit] server/webhooks.js:L41-43 — `listWebhooks()` liefert das HMAC-Secret jedes Webhooks zurück
**Urteil:** BESTÄTIGT (Severity unverändert; Bewertung hier für `webhooks.js`/`db.js`. Dass die Liste unauthentifiziert über `GET /hhttps/webhooks` (server.js L3889-3891) ausgeliefert wird, verifiziert **AP5**.)
**Beleg:** L42 `return await dbWebhooks.list();` unverändert; db.js L657-668 mappt `secret: r.secret` in jedes Objekt. Secrets werden im Klartext gespeichert (db.js L650-653). `registerWebhook` L32 gibt das Secret ebenfalls zurück (beim Anlegen gewollt).
**Auswirkung:** Jeder Leser der Liste erhält URL + Secret aller Webhooks und kann gültig signierte `token.issued`-Events fälschen; ids aus der Liste erlauben `DELETE /hhttps/webhooks/:id`.
**Empfehlung:** `listWebhooks` ohne `secret` (nur `secret_hint`), Secrets gehasht/verschlüsselt speichern; Route-Auth in AP5.

### AP1-23 [S3] [Sicherheit] server/server.js:L702-711 + L880-935 — Refresh-Tokens werden von `/hhttps/check`, `/hhttps/sign-text`, `/hhttps/signatures`, `…/revoke` als Identitäts-Bearer akzeptiert
**Urteil:** BESTÄTIGT (Severity unverändert), mit Detailkorrektur.
**Beleg:** `checkTokenValid` L705-707 behandelt `sub === 'refresh'` als gültig (nur `refreshTokens.get`). `/hhttps/check` L880 prüft danach nur `d.sub === 'machine'`; ein Refresh-Token (7 d, L680-699, enthält `role`, `trustScore`, `verified_methods`) fällt in den Human-Zweig (L895-934) → `status:'verified', human:true`. Gleiches Muster in `/hhttps/sign-text` L965-968, `/hhttps/signatures` L1095-1098, `/hhttps/signatures/:slug/revoke` L1339-1340 (`signerId = d.uid || d.userId || d.sub`).
**Korrektur:** Der Header lautet nicht `HHTTPS-Method: undefined`, sondern `none` — `method: d.method` ist `undefined`, wodurch der Destructuring-Default `method = 'none'` (L537) greift.
**Auswirkung:** Langlebiges Refresh-Token wird zum 7-Tage-Bearer bei Drittplattformen und zum Signier-Credential; nicht in `tokens_issued` sichtbar.
**Empfehlung:** `d.sub === 'refresh'` in den vier Endpunkten mit 401 abweisen bzw. `checkTokenValid(token, { allowRefresh })`.

### AP1-25 [S3] [Sicherheit] server/server.js:L392-403 — CSP erlaubt `'unsafe-inline'` für Skripte und `unpkg.com` als Script-Quelle
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L396 `scriptSrc: ["'self'", "'unsafe-inline'", 'unpkg.com', 'fonts.googleapis.com']`, L397 `scriptSrcAttr: ["'unsafe-inline'"]`; global über `app.use(helmet(...))`, Begründung L390-391 („onclick= in index.html“). Kein SRI, keine Nonces.
**Auswirkung:** CSP bietet keinen XSS-Schutz für irgendeine Seite der Origin (inkl. AP1-27-Viewer, Consent, Portal); beliebige npm-Pakete von unpkg ladbar.
**Empfehlung:** Inline-Handler ersetzen, Nonces/Hashes, `unpkg.com` entfernen oder auf konkrete Pfade mit SRI beschränken.

### AP1-26 [S3] [Sicherheit] server/server.js:L1180-1185 — First-Seen-Lock einer Signatur von jedem anonymen Aufrufer mit beliebiger Domain setzbar
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `GET /hhttps/s/:slug` ohne Auth; L1183-1185 `if (!sig.first_seen_at && reqDomain) await db.signatures.setFirstSeen(slug, reqDomain)`; db.js L764-771 `WHERE first_seen_at IS NULL`. Kein Abgleich mit `bound_domain`, kein Origin/Referer-Nachweis. Slugs sind über den Marker `#hhttps:s:hp-…` öffentlich.
**Auswirkung:** `firstSeen` fremder Signaturen mit `evil.com` belegbar; Feld als Provenienz-Signal wertlos bzw. diffamierend nutzbar.
**Empfehlung:** Nur bei `reqDomain === sig.bound_domain` (oder vertrauenswürdigem Signal) setzen; sonst Feld als unbestätigt kennzeichnen.

### AP1-27 [S4] [Sicherheit] server/server.js:L116-155,L325-357 — `sendJson`-Viewer interpoliert `title`, `subtitle`, `req.path` ohne Escaping
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Nur der JSON-Body wird escaped (L140-147). `${title}` L155/L329, `${opts.subtitle}` L330, `${req.path}` L325/L333 und L357 (innerhalb eines JS-String-Literals in `<script>`) roh. Repro mit Express 4.22.2: Request-Target `/x'<script>alert(1)</script>` → `req.path` = `"/x'<script>alert(1)</script>"` unverändert. Aktuelle AP1-Aufrufer: feste Pfade bzw. Slug per `^hp-[A-Z0-9-]+$` validiert, `subtitle` aus DB-Feldern `role_icon`/`role_label`, die aus dem statischen `ROLES` stammen (L1123-1125) → derzeit nicht ausnutzbar.
**Auswirkung:** Latent: jeder künftige Aufrufer mit nutzerkontrolliertem Parameter wird Reflected XSS, verschärft durch AP1-25.
**Empfehlung:** `escapeHtml` für `title`/`subtitle`/`req.path`; L357 `JSON.stringify(req.path)` bzw. `location.pathname` im Browser.

### AP1-28 [S4] [Sicherheit] server/server.js:L1266,L1326 — `/hhttps/signatures/batch` und `…/:slug/revoke` ohne endpoint-spezifisches Rate-Limit
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L1266 `app.post('/hhttps/signatures/batch', async …)` und L1326 `app.post('/hhttps/signatures/:slug/revoke', async …)` ohne `limit.check`; alle anderen Signatur-/Check-Routen tragen `limit.check` (L865, L950, L1007, L1077). Batch: bis 100 Slugs pro Request (L1272).
**Auswirkung:** 30.000 Slug-Lookups/min/IP (DB-Last, Enumeration praktisch aussichtslos bei 32^10); Token-Brute-Force gegen Revoke mit 300/min statt 120/min.
**Empfehlung:** `limit.check` an beide Routen.

### AP1-29 [S4] [Sicherheit] server/server.js:L938,L1002,L1062,L1158,L1352 — Rohe `e.message` aus `checkTokenValid`/DB-Fehlern an den Client
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Alle fünf catch-Blöcke antworten `error: e.message`. `checkTokenValid` L702-711 wirft neben JWT-Fehlern auch pg-Fehler aus `db.revokedTokens.has`/`db.tokens.exists` ungefiltert (als 401). Beispiele in AP1-07/AP1-11 (`value too long …`).
**Auswirkung:** Infrastruktur-Details (Host/Port, Tabellennamen) an anonyme Clients; DB-Ausfall als „ungültiges Token“ maskiert.
**Empfehlung:** Nur `JsonWebTokenError`/`TokenExpiredError` und eigene Meldungen durchreichen; sonst 500/503 `token_check_failed`.

### AP1-32 [S3] [Performance] server/server.js:L435-436 — `/hhttps/info` vom globalen Rate-Limit ausgenommen und führt pro Aufruf sechs `COUNT(*)` ohne Cache aus
**Urteil:** BESTÄTIGT (herabgestuft von S2: `COUNT(*)` auf den heutigen Tabellengrößen (zero-PII-Modell, wenige Tausend Zeilen) kostet Millisekunden; der belastbare Kern ist die fehlende Drosselung, nicht die Query-Kosten. Wächst `revoked_tokens` (AP1-34) unbegrenzt, wird es zum S2.)
**Beleg:** L435 `if (req.path === '/' || req.path === '/hhttps/info') return next();` L802-805 `Promise.all([db.credentials.count(), db.tokens.count(), db.refreshTokens.count(), db.sessions.count(), db.revokedTokens.count(), db.machineOperators.count()])`. `credentials.count()` (db.js L91) und `revokedTokens.count()` (db.js L314) sind ungefilterte `SELECT COUNT(*)`. Kein Cache, kein `Cache-Control`. Pool `max: 20` (db.js L36).
**Auswirkung:** Anonymer, ungedrosselter Weg, 6 Queries pro Request abzusetzen und den Pool zu belegen.
**Empfehlung:** Eigener Limiter (`rl(60)`) statt Ausnahme; 30–60-s-TTL-Cache der Zähler oder `Cache-Control: public, max-age=60`.

### AP1-33 [S3] [Performance] server/server.js:L866 — Jeder `/hhttps/check`-Aufruf schreibt synchron in die Hot-Row `stats.check_calls`, vor jeder Token-Prüfung
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L866 `await db.stats.increment('check_calls');` als erste Anweisung, auch für Requests ohne Token (L870-875). db.js L1321-1327 `INSERT … ON CONFLICT (metric) DO UPDATE` auf eine Zeile. Weitere Vorkommen L883, L666, L1138, L1178, L1320, L1345.
**Auswirkung:** Row-Lock-Serialisierung aller Checks, Dead-Tuples/Autovacuum auf `stats`, zusätzlicher Schreib-Roundtrip vor der Validierung im Kernpfad.
**Empfehlung:** Zähler im Prozess akkumulieren und periodisch mit `increment(metric, by)` flushen; im Handler fire-and-forget nach der Prüfung.

### AP1-34 [S3] [Performance] server/server.js:L704 / L714-724 — `revoked_tokens` wird auf jedem Check gelesen, aber nie bereinigt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L704 `db.revokedTokens.has(decoded.jti)` pro Validierung (auch L1023). Cleanup L714-724 ruft nur `cleanup_expired()` (schema.sql L192-206: tokens, refresh_tokens, sessions, challenges, email_verifications) + `identity_claims_cache` (db.js L1344). `grep "DELETE FROM revoked_tokens"` in server/ → kein Treffer. Tabelle hat `revoked_at` mit Index (schema.sql L95-102), kein `expires_at`. Ein Eintrag ist nach `REFRESH_TTL` (7 d) wertlos, da `jwt.verify` dann ohnehin ablehnt.
**Auswirkung:** Unbegrenztes Wachstum mit jedem Revoke/Logout; `revokedTokens.count()` in `/hhttps/info` scannt komplett (AP1-32).
**Empfehlung:** Im Cleanup `DELETE FROM revoked_tokens WHERE revoked_at < NOW() - INTERVAL '8 days'`.

### AP1-35 [S3] [Performance] server/webhooks.js:L80 / L86 — Jeder Zustellversuch schreibt eine `webhook_deliveries`-Zeile; keine Retention
**Urteil:** BESTÄTIGT (Severity unverändert; S3 bleibt, weil Webhooks anonym registrierbar sind (AP5) und ein absichtlich fehlschlagender Webhook 3 Zeilen pro Event erzeugt)
**Beleg:** L80 (`success`) und L86 (`failed`) je `recordDelivery` pro Versuch, bis 3 pro Event (L64). db.js L685-699: `INSERT` + `UPDATE webhooks`. Kein `DELETE` auf `webhook_deliveries` im Code, nicht in `cleanup_expired()`. Index `webhook_deliveries_delivered_at_idx` existiert (schema.sql L174).
**Auswirkung:** Lineares Wachstum mit Traffic × aktiven Webhooks.
**Empfehlung:** Retention im Cleanup (`delivered_at < NOW() - INTERVAL '30 days'`).

### AP1-37 [S4] [Performance] server/server.js:L1171-1184 — `/hhttps/s/:slug` macht vier sequentielle DB-Roundtrips, davon zwei Schreibzugriffe pro Lesezugriff
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L1169 `await db.signatures.get`, L1177 `await …incrementVerify`, L1178 `await db.stats.increment`, L1184 `await …setFirstSeen` — sequentiell; Antwort rechnet `verify_count + 1` lokal (L1216).
**Auswirkung:** Latenz = Summe der Roundtrips; UPDATE-Versionen auf `signatures` und `stats` pro öffentlichem Aufruf.
**Empfehlung:** Zähler-Updates ohne `await`/`Promise.allSettled`; `incrementVerify` + `setFirstSeen` in ein `UPDATE … COALESCE(first_seen_at, NOW())` zusammenführen.

### AP1-38 [S4] [Performance] server/server.js:L702-711 — `checkTokenValid` mit zwei sequentiellen Einzel-Lookups
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L704 `await db.revokedTokens.has`, dann L706/L708 `await db.refreshTokens.get` bzw. `db.tokens.exists`. Mit L866 drei Roundtrips pro `/hhttps/check`.
**Auswirkung:** Verdoppelte DB-Latenz im heißesten Pfad.
**Empfehlung:** `Promise.all` oder eine Query mit zwei `EXISTS`.

### AP1-39 [S4] [Performance] server/server.js:L488-513 — Identity-Cookie-Middleware verifiziert ES256 synchron auf jedem Request, auch für statische Assets
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Middleware L485-514 vor `express.static` L519; `verifyToken` (keys.js L164-173, `jwt.decode` + `jwt.verify`) pro Request mit Cookie; bei abgelaufenem Cookie zusätzlich `clearCookie` je Asset.
**Auswirkung:** n Signaturprüfungen pro Seite mit n Assets; heute vernachlässigbar.
**Empfehlung:** `express.static` vor die Middleware ziehen oder nur für Dokument-Requests ausführen.

### AP1-40 [S4] [Performance] server/server.js:L1109-1113 — Slug-Kollisionsprüfung mit zwei seriellen Queries pro Versuch; `isReservedSlug` kann nie treffen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L1113 `while (await db.signatures.slugExists(slug) || await db.signatures.isReservedSlug(slug))`. `reserved_slugs` enthält nur `hhttps, admin, root, null, undefined, login, …` (migration-phase-2.5.sql L77-83), Slugs beginnen immer mit `hp-` (L630) → zweiter Lookup ist tot. `id` ist PK.
**Auswirkung:** Zwei überflüssige Roundtrips pro Signatur.
**Empfehlung:** `isReservedSlug` entfernen; Kollision über PK-Konflikt beim `INSERT`.

### AP1-41 [S4] [Performance] server/keys.js:L179-192 — `getJWKS()` exportiert die Key-Objekte bei jedem Aufruf neu
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L180-185 `pubKey.export({ format: 'jwk' })` pro Key pro Aufruf; Ergebnis ändert sich nur bei `rotateKeys`/`forgetRetiredKey`. `Cache-Control: max-age=3600` (server.js L759) mildert.
**Auswirkung:** Gering.
**Empfehlung:** Memoisieren, in Rotation invalidieren.

### AP1-42 [S3] [Wartbarkeit] server/server.js:L109-366 — `sendJson` ist ein 258-Zeilen-Handler mit ~230 Zeilen eingebettetem HTML/CSS/JS
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Funktion L116-366: Negotiation L118-131, Regex-Highlighter L136-143, Template-Literal L146-365 inkl. CSS-Palette und Copy-Script. server.js hat 4.829 LOC.
**Auswirkung:** Nicht isoliert testbar (siehe AP1-27), Diff-Rauschen bei Stiländerungen.
**Empfehlung:** `server/views/json-viewer.js` mit `renderJsonPage(...)`; `sendJson` behält Negotiation.

### AP1-43 [S3] [Wartbarkeit] server/server.js:L867-869, L950-952, L1077-1079, L1328-1330 — Token-Extraktion viermal identisch kopiert; Signer-ID-Kette `d.uid || d.userId || d.sub` doppelt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Vier identische Dreizeiler (siehe AP1-14). `grep -n "uid\b\|\.uid" server.js` → nur Lesezugriffe L1122, L1340; kein ausgestelltes Token setzt `uid`. `sub` ist bei Access-Tokens die Konstante `'human-verified'` (L651) → Fallback erzeugt keine eindeutige Signer-ID.
**Auswirkung:** Änderungen (AP1-14, AP1-23) an sechs Stellen; nicht-eindeutige Signer-ID bei fehlendem `userId` unbemerkt.
**Empfehlung:** `extractToken(req)`, `signerIdOf(decoded)` ohne `sub`-Fallback (→ 401).

### AP1-44 [S3] [Wartbarkeit] server/server.js:L1166, L1275, L1334, L1359 — Slug-Regex viermal dupliziert und inkonsistent zum Generator
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Vier Vorkommen `/^hp-[A-Z0-9\-]+$/i` (ESLint `no-useless-escape` an genau diesen Zeilen, eslint-output.txt). `generateSlug` L628-637 erzeugt `hp-XXX-XXXX-XXX` aus `SLUG_ALPHABET` (ohne 0/1/I/O/L); die Validierung akzeptiert beliebige Länge/Zeichen.
**Auswirkung:** Zwei Wahrheiten für „gültiger Slug“; Formatwechsel an fünf Stellen.
**Empfehlung:** `SLUG_RE` neben `SLUG_ALPHABET`, überall verwenden.

### AP1-45 [S3] [Wartbarkeit] server/server.js:L1219-1257 vs. L1291-1312 — Signatur-Statusauswertung in Einzel- und Batch-Endpunkt doppelt implementiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Beide prüfen `revoked_at` → `binding_type === 'web' && reqDomain && bound_domain !== reqDomain` → `binding_type === 'document' && textPreview` + `hashTextStrict`. Bereits divergent: Einzel liefert `revokeReason`, `hhttps.expected/observed`, `warning`; Batch `expected/observed` flach, ohne `revokeReason`; Einzel zählt Verify/First-Seen (L1177-1185), Batch nicht.
**Auswirkung:** Zwei Antwortformate für dieselbe Aussage; neue Prüfungen doppelt.
**Empfehlung:** `evaluateSignature(sig, { reqDomain, textPreview })` extrahieren.

### AP1-46 [S3] [Wartbarkeit] server/server.js:L770-793 — ESCO-Suche dupliziert `resolveEsco`/`ESCO_API`; `resolveEsco` importiert, aber nie verwendet
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L775-777 baut die ESCO-URL von Hand, L780 parst `_embedded.results` — identisch zu roles.taxonomy.js L156-168 (`ESCO_API` L154). `grep -n resolveEsco server/server.js` → nur Import L56 (ESLint unused).
**Auswirkung:** Timeout/Fehlerbehandlung (AP1-08) müssen doppelt gepflegt werden.
**Empfehlung:** `searchEsco(text, { language, limit, fetchImpl })` in roles.taxonomy.js, im Handler verwenden.

### AP1-47 [S4] [Wartbarkeit] server/server.js:L4-22 — Datei-Header beschreibt v4.1 mit „14 roles“ und widerspricht dem aktuellen Modell
**Urteil:** BESTÄTIGT (herabgestuft von S3: reiner Kommentar/Startlog, kein Laufzeiteffekt)
**Beleg:** L5 „HHTTPS v4.1“, L20-22 „14 roles (citizen, journalist, …)“; roles.js L46-55 stellt klar, dass `ROLES` nur `citizen` enthält. Phasen-Marker L594, L826, L1066, L1363; Startlog L4809-4815 „v4.1“. package.json `description` nennt ebenfalls „14 roles“.
**Auswirkung:** Falsche Architekturbeschreibung für Einsteiger.
**Empfehlung:** Header auf Ist-Zustand kürzen, Startlog auf Versionskonstante (AP1-49).

### AP1-48 [S3] [Wartbarkeit] server/server.js:L955, L1082 vs. L1333; L938, L1002, L1062 — Inkonsistente Statuscodes und Fehlerformate zwischen Signatur-Endpunkten
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Fehlendes Token: L955/L1082 `400 {error:'token required'}`, L1333 `401` gleicher Text. Ungültig: L938 `401 {hhttps:{status:'invalid',human:false}, error}`, L1002 `401 {error}`, L1062 `401 {hhttps:{status:'invalid'}, error}`. Deutsch: L706 `'Refresh-Token nicht aktiv'`, L708 `'Token nicht aktiv'`; jsonwebtoken-Text `jwt expired` ungefiltert (siehe AP1-29).
**Auswirkung:** Clients müssen pro Endpunkt andere Fehlerpfade parsen; Sprachmix.
**Empfehlung:** `apiError(res, status, code, detail)` mit stabilen Codes.

### AP1-49 [S4] [Wartbarkeit] server/server.js:L324, L486, L551, L732, L808, L874, … — Protokollversion `'0.5.0'` 27-mal als Literal
**Urteil:** BESTÄTIGT (herabgestuft von S3: mechanische Ersetzung, kein Laufzeitrisiko)
**Beleg:** `grep -c "'0.5.0'\|v0.5.0" server/server.js` → 27. Daneben roles.taxonomy.js L267 `version: '0.5'`, webhooks.js L73 `HHTTPS-Webhook/4.1`, package.json `4.1.0`.
**Auswirkung:** Versionssprung fehleranfällig; Discovery/Header/Body können auseinanderlaufen.
**Empfehlung:** `PROTOCOL_VERSION`-Konstante.

### AP1-50 [S3] [Wartbarkeit] server/roles.js:L208-288 — `VERIFICATION_CHECKS`/`resolveVerification` toter Code; `VERIFICATION_LEVELS` nur noch als Label-Map genutzt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rn "resolveVerification\|VERIFICATION_CHECKS\|verificationCheckNote" server` → Definitionen (roles.js L225, L268), Import server.js L39 (ESLint unused), roles.i18n.js L23/L382-388 (`verificationCheckNote` ohne Aufrufer). `VERIFICATION_LEVELS[x]?.label` an L923, L1116, L1797 der einzige Lesezugriff; `trustScore`/`level` wirkungslos. `baseTrust` (L268) unbenutzt.
**Auswirkung:** ~100 Zeilen Regel-Logik beschreiben nicht existierendes Verhalten (siehe auch AP1-16).
**Empfehlung:** Entfernen; `VERIFICATION_LEVELS` als Label-Map dokumentieren; Importe L39-41 streichen.

### AP1-51 [S3] [Wartbarkeit] server/roles.js:L143 vs. server/server.js:L571 — Header `HHTTPS-Age-Verified` hat zwei Eigentümer
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** server.js L571 `if (ageVerified !== null) res.setHeader('HHTTPS-Age-Verified', String(ageVerified));` (kann `'false'` sein); Schleife L580-590 überschreibt bei `'age'` in `verifiedMethods` mit `'true'` (`VERIFICATION_METHODS.age.header` roles.js L143). Beide Optionen werden in `/hhttps/check` L897-906 übergeben.
**Auswirkung:** Token mit `age_verified:false` und `verified_methods` mit `age` → Header `true`; zwei Quellen.
**Empfehlung:** Einen Eigentümer festlegen.

### AP1-52 [S4] [Wartbarkeit] server/roles.i18n.js:L47-239 — 14 Rollen-Übersetzungen für nicht mehr existierende Rollen-IDs
**Urteil:** BESTÄTIGT (herabgestuft von S3: nicht erreichbare Daten, kein Fehlverhalten; `roleLabel` fällt für unbekannte IDs korrekt zurück)
**Beleg:** DE-Katalog L47 `journalist` … L226 `craftsman`. `localizeRole` L341-343 gibt für fehlende `ROLES[roleId]` `null`, `localizeRoles` L361-365 iteriert nur `ROLES` (= `citizen`). Einziger produktiver Nutzer des Moduls: `roleLabel` in email.js L39/L131-132/L367/L879.
**Auswirkung:** ~190 Zeilen suggerieren das entfernte 14-Rollen-Modell.
**Empfehlung:** Auf `citizen` reduzieren oder als ESCO-Hinweisdatei umbenennen.

### AP1-53 [S3] [Wartbarkeit] server/roles.taxonomy.i18n.js:L1-71 — Modul wird nirgends importiert; `kind`-Katalog übersetzt Werte, die `resolveRole` nie erzeugt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rn "roles.taxonomy.i18n" server` → nur Kommentare (roles.taxonomy.js L5, roles.i18n.js). `kind` L25-30 (`status`, `legal_entity`, `sector`) vs. roles.taxonomy.js L196 `kind: 'occupation'` fest. `SUPPORTED_LOCALES`/`DEFAULT_LOCALE` L13-14 duplizieren roles.i18n.js L28-29.
**Auswirkung:** Das als „CRITICAL UI CONTRACT“ (L7-8) deklarierte RAL0-Wording wird nirgends ausgeliefert.
**Empfehlung:** Anbinden (`?lang=` in Rollen-Endpunkten) oder entfernen.

### AP1-54 [S3] [Wartbarkeit] server/roles.eaa.js:L17, L51-59 — Modul ohne Laufzeit-Aufrufer; `setRoleHeaders` verlangt ein nicht exportiertes `hdrSafe`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Einziger Import: roles.taxonomy.test.mjs L10. `setRoleHeaders(res, {ral, role}, hdrSafe = (v) => String(v))` L53; `hdrSafe` ist Closure in `setHHTPPS` (server.js L544-549), nicht exportiert. Default würde Umlaute ungefiltert setzen (`ERR_INVALID_CHAR`, vgl. Kommentar server.js L540-543). `guardReservedRole` L17 importiert, unbenutzt (ESLint).
**Auswirkung:** Toter Pfad mit im Ernstfall nicht nutzbarer Schnittstelle; EAA-Read-Logik nicht am echten Kartenendpunkt (L3620ff.) angebunden.
**Empfehlung:** `hdrSafe` als exportierte Utility; Modul anbinden oder entfernen.

### AP1-60 [S4] [Wartbarkeit] server/server.js:L828-855, L728-752 — Handgepflegter Endpunkt-Katalog in `/hhttps/info` und Discovery unvollständig
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `endpoints` L828-855 nennt weder `sign-text`, `verify-text`, `POST /hhttps/signatures`, `GET /hhttps/s/:slug`, `signatures/batch`, `…/revoke`, `GET /s/:slug`, `esco/suggest` noch `/.well-known/hhttps-role-assurance`; Discovery L728-752 ebenso (nur `roles_model.discovery`/`esco_suggest`). L835 `session/email/start` als „legacy name“ ohne Ablaufdatum.
**Auswirkung:** Signatur-Endpunkte nur im Extension-Code dokumentiert.
**Empfehlung:** Katalog aus zentraler Routen-Tabelle generieren oder ergänzen.

### AP1-61 [S4] [Wartbarkeit] server/server.js:L535, L1080 — Funktionsname `setHHTPPS` (Tippfehler), ungenutzter Parameter `token`, still ignoriertes Feld `mode`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L535 `function setHHTPPS(res, opts = {})`; `token = null` L536 destrukturiert, nie verwendet (ESLint L535); `/hhttps/check` übergibt ihn L899. L1080 `const { text, mode, bindingType, domain } = req.body || {};` — `mode` unbenutzt (ESLint), Client mit `mode:'document'` erhält `web`-Binding.
**Auswirkung:** Suchen nach „HHTTPS“ übersieht die Funktion; API akzeptiert ein Feld ohne Wirkung.
**Empfehlung:** Umbenennen, `token`-Option entfernen, `mode` verarbeiten oder ablehnen.

### AP1-62 [S4] [Wartbarkeit] server/server.js:L482-509 vs. L879-886 — Mapping „dekodiertes Token → `setHHTPPS`-Optionen“ doppelt; Cookie-Pfad ohne Methoden-Header
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Middleware L493-504 und `/hhttps/check` L897-906 bauen dasselbe Objekt; nur die Check-Variante übergibt `verifiedMethods`/`domainValue`. Der Kommentar L463-471 nennt die Methoden-Header als Zweck des Cookie-Features.
**Auswirkung:** Cookie-Pfad liefert keine `HHTTPS-*-Verified`-Header; Drift bereits vorhanden.
**Empfehlung:** `headerOptsFromToken(decoded)` extrahieren.

### AP1-63 [S4] [Wartbarkeit] server/server.js:L959, L1086, L1111, L1119, L1272, L753 — Magic Numbers ohne benannte Konstante
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `100_000` L959/L1086 (je eigener Fehlertext), `120`/`117` L1119, `5` L1111, `100` L1272, `5 * 60 * 1000` L724 (Cleanup-Intervall; die im Rohbefund genannte L753 ist falsch, korrigiert).
**Auswirkung:** Limits nicht zentral einsehbar.
**Empfehlung:** Konstanten neben den TTLs (L93-96).

### AP1-64 [S4] [Wartbarkeit] server/webhooks.js:L18, L21, L64, L73, L76, L89, L95 — Sprachmix in Fehlermeldungen und verstreute Konstanten im Delivery-Pfad
**Urteil:** BESTÄTIGT (Severity unverändert; die `Array.isArray(events)`-Lücke ist in AP1-19 erfasst)
**Beleg:** L18 `'Invalid webhook URL.'` vs. L21 `'Unbekanntes Event: …'`, beide via server.js L3904 an den Client. `MAX = 3` L64 in der Funktion, `8000` L76, `1000 * Math.pow(2, attempt)` L89, `10` L95 (Default auch db.js L701), `HHTTPS-Webhook/4.1` L73.
**Auswirkung:** Uneinheitliche API-Fehler; Retry-Policy nicht auf einen Blick.
**Empfehlung:** Konstanten-Block, englische Fehlercodes.

### AP1-65 [S4] [Wartbarkeit] server/server.js:L39-57, L535, L612, L792, L1080, L1166, L1254, L1275, L1310, L1334, L1359; server/roles.js:L268; server/roles.eaa.js:L17; server/roles.taxonomy.test.mjs:L7-8 — Gesammelte ESLint-Warnungen im AP1-Bereich
**Urteil:** BESTÄTIGT (Severity unverändert; Sammelfinding)
**Beleg:** docs/review/ap/eslint-output.txt (Abschnitte `server/roles.eaa.js` L53, `server/roles.js` L56, `server/roles.taxonomy.test.mjs` L59, `server/server.js` L63ff.): `no-unused-vars` für `VERIFICATION_CHECKS`, `resolveVerification`, `TRUST_BANDS`, `trustBand`, `HUMAN_CONFIRMED_THRESHOLD`, `resolveEsco`, `CUSTOM_ROLE_ID`, `token`, `e`, `mode`, `baseTrust`, `guardReservedRole`; `no-useless-escape` `\-` an L612, L1166, L1275, L1334, L1359 — die Zeilen decken sich mit dem aktuellen Stand (AP1-44).
**Auswirkung:** Lint-Rauschen verdeckt neue Warnungen.
**Empfehlung:** Bereinigen, danach `--max-warnings 0` in CI.

## Verworfen
- (keine — alle Findings hatten Datei:Zeile und einen im Code existierenden Pfad; Teilbehauptungen wurden in AP1-02 (Batch-Trigger), AP1-23 (`HHTTPS-Method: undefined`) und AP1-63 (L753) korrigiert)

## Zusammengeführt
- AP1-24 [S3] [Sicherheit] server/server.js:L485-511 — Identity-Cookie ohne Revocation/Typ-Positivliste → in AP1-17 (gleiche Ursache; AP1-17 auf S3 hochgestuft).
- AP1-30 [S4] [Sicherheit] server/server.js:L774-795 — ESCO-Proxy ohne Timeout/Rate-Limit → in AP1-08.
- AP1-31 [S4] [Sicherheit] server/server.js:L468-479 — `readIdentityCookie` URIError → in AP1-01.
- AP1-36 [S3] [Performance] server/server.js:L774-796 — ESCO-Proxy ohne Timeout/Cache → in AP1-08.
- AP1-55 [S3] [Wartbarkeit] server/roles.taxonomy.js:L84, L88, L120-126 — ISCO-Präfix `'261'` überdeckt `2611`/`2612` → in AP1-06 (Teilfall derselben Heuristik).
- AP1-56 [S3] [Wartbarkeit] server/roles.taxonomy.test.mjs:L1-78 — Tests laufen nicht in `npm test` → in AP1-10.
- AP1-57 [S3] [Wartbarkeit] server/webhooks.js:L14-25 — Event-Registry vs. gefeuerte Events → in AP1-04.
- AP1-58 [S3] [Wartbarkeit] server/keys.js:L109-150, L194-197 — Rotations-API ohne Aufrufer, `forgetRetiredKey` nicht persistent → in AP1-12.
- AP1-59 [S3] [Wartbarkeit] server/server.js:L728-1361 — Keine Tests für Kern-Endpunkte → in AP1-09.

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit (K) | 20 | 20 | 0 | 0 |
| Sicherheit (S) | 11 | 8 | 0 | 3 |
| Performance (P) | 10 | 9 | 0 | 1 |
| Wartbarkeit (W) | 24 | 19 | 0 | 5 |
| **Gesamt** | **65** | **56** | **0** | **9** |

Bestätigt je Severity: S1 0, S2 2, S3 25, S4 29.

Severity-Änderungen: herabgestuft AP1-01 (S3→S4), AP1-07 (S3→S4), AP1-32 (S2→S3), AP1-47 (S3→S4), AP1-49 (S3→S4), AP1-52 (S3→S4); hochgestuft AP1-17 (S4→S3).

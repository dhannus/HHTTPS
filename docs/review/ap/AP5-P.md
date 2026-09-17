# AP5 — Performance

Geprüfte Dateien: server/server.js L3768–4829 (/hhttps/machine/*, /hhttps/webhooks*, authenticatedUser/requireUser/requireAdmin/requirePortalUser, /hhttps/whoami, /hhttps/developers/*, /hhttps/admin/*, /hhttps/stats, serializeClient*, renderSimplePage, main()); server/workload-identity.js; server/pop-verify.js; server/wp-plugin-registration.js; developers/index.html, register.html, dashboard.html, admin.html; developers/assets/portal.js, portal.css. Zum Verständnis gelesen (keine Findings dort): server/db.js (oauthClients, challenges, tokens, admins, cleanupExpired), server/sql/schema.sql, migration-phase-3b.sql, migration-phase-6-workload-identity.sql, server/webhooks.js, server/server.js L412–430 (Rate-Limiter), L702–725 (checkTokenValid, Cleanup-Timer).

Stand: `main` @ `bf0a82b`. Zeilennummern per `grep -n`/`sed -n` verifiziert.

---

### [S2] [Performance] server/wp-plugin-registration.js:L81-87 — In-Memory-Rate-Limit-Map `regHits` wächst unbegrenzt, Schlüssel ist ein vom Client frei wählbarer Header
**Begründung:** `regHits` ist eine modulglobale `Map`, in die für jeden neuen Schlüssel ein Array angelegt wird. Der Schlüssel kommt aus L103 `req.headers['x-forwarded-for']?.split(',')[0]` — d. h. direkt aus dem Request-Header, nicht aus `req.ip` (das dank `trust proxy 1` nur den nginx-gesetzten Wert nähme). Einträge werden nie entfernt: Der Filter `now - t < 3600_000` (L84) läuft nur für den *gleichen* Schlüssel beim nächsten Treffer, leere Arrays bleiben als Map-Einträge liegen, es gibt keinen Sweep-Timer.
```js
const regHits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (regHits.get(ip) || []).filter(t => now - t < 3600_000);
  if (arr.length >= 5) { regHits.set(ip, arr); return true; }
  arr.push(now); regHits.set(ip, arr);
```
**Auswirkung:** Jeder Request auf `POST /hhttps/plugin/register` (unauthentifiziert) mit einem neuen `X-Forwarded-For`-Wert erzeugt einen dauerhaften Map-Eintrag (String-Key bis 2 MB Body-unabhängig, Header-Länge nur durch Node-Header-Limit begrenzt). Ein einfacher Scanner mit zufälligen XFF-Werten lässt den Heap des pm2-Prozesses bis zum OOM-Restart wachsen; gleichzeitig ist das Limit wirkungslos (jeder Request = neuer Key), womit auch die Folgekosten aus dem nächsten Finding unbegrenzt anfallen.
**Empfehlung:** Den vorhandenen `express-rate-limit`-Mechanismus aus server.js nutzen (z. B. `limit.email` oder ein eigener `rl(5, 3600_000)`), der den Store selbst aufräumt und `req.ip` (trust proxy) verwendet; die eigene Map und den XFF-Zugriff entfernen.

### [S2] [Performance] server/wp-plugin-registration.js:L102-160 — Unauthentifizierte Registrierung schreibt pro Request eine `oauth_clients`-Zeile und versendet eine E-Mail; nie bestätigte Drafts werden nirgends gelöscht
**Begründung:** `POST /hhttps/plugin/register` verlangt keine Authentifizierung und keine vorherige E-Mail-Bestätigung. Nach den Format-Prüfungen folgt direkt `db.oauthClients.createDraft(...)` (L126) und `sendPlatformRegistrationEmail(...)` (L148). Das einzige Bremsmittel ist die oben beschriebene, per Header umgehbare Map. Ein Aufräumen abgelaufener `email_pending`-Zeilen existiert nicht: `cleanup_expired()` (server/sql/schema.sql L192–206) kennt `oauth_clients` nicht, und `db.oauthClients.deleteIfDraft` (db.js L1085) wird nur manuell vom Owner über `DELETE /hhttps/developers/clients/:id` aufgerufen — für `owner_user_id = 'wp-plugin'` also nie. Zum Vergleich: der Portal-Pfad `POST /hhttps/developers/clients` (server.js L4120–4174) ist durch Passkey-Pflicht und `countRecentByOwner` (max. 3/24 h) gebunden.
**Auswirkung:** Realistischer Bot-Traffic füllt `oauth_clients` dauerhaft mit Leichen (jede Zeile inkl. Token-Spalten und JSON-Felder) und erzeugt pro Request einen SMTP-Versand. Die Admin-Endpunkte, die die Tabelle scannen (`/hhttps/admin/stats` GROUP BY, `/hhttps/admin/clients` LIMIT 200 ohne Pagination, `listPendingReview`), werden entsprechend langsamer bzw. zeigen nur noch Spam-Drafts.
**Empfehlung:** Serverseitiges Rate-Limit über `express-rate-limit` (vgl. vorheriges Finding) plus eine harte Obergrenze offener `email_pending`-Drafts pro Apex-Domain (`SELECT COUNT(*) … WHERE homepage_url-Apex = $1 AND verification_status='email_pending'`), und `cleanup_expired()` bzw. den 5-Minuten-Timer in server.js L714 um `DELETE FROM oauth_clients WHERE verification_status='email_pending' AND email_token_expires_at < NOW() - INTERVAL '7 days'` erweitern.

### [S3] [Performance] server/server.js:L4735-4744 — Öffentlicher `/hhttps/stats` führt pro Aufruf acht ungecachte Queries aus, darunter vier `COUNT(*)`-Scans und das Laden aller Webhook-Zeilen
**Begründung:** Der Endpunkt hat keinen eigenen Limiter (nur `limit.global`, 300/min/IP) und keinen Cache. Pro Request laufen `db.stats.getAll()`, `rolesDeclared.distribution()` (GROUP BY über `roles_declared`), `tokens.count()`, `refreshTokens.count()`, `credentials.count()`, `revokedTokens.count()` (COUNT(*) ohne WHERE — `revoked_tokens` wird nirgends bereinigt, `grep DELETE FROM revoked_tokens` liefert keinen Treffer), `machineOperators.count()` sowie L4743 `listWebhooks().then(w => w.length)`, das per `SELECT * FROM webhooks WHERE active = TRUE` alle Zeilen inkl. Secret lädt, nur um sie zu zählen.
```js
      db.tokens.count(), db.refreshTokens.count(),
      db.credentials.count(), db.revokedTokens.count(),
      db.machineOperators.count(),
      listWebhooks().then(w => w.length)
```
**Auswirkung:** COUNT(*) in PostgreSQL ist ein Heap-/Index-Scan; mit wachsenden `tokens`/`revoked_tokens`-Tabellen skaliert die Antwortzeit linear, und ein einzelner Client kann mit 300 req/min dauerhaft ~2.400 Scans/min auf dem Pool erzeugen und die Latenz der Auth-Endpunkte (die denselben Pool nutzen) beeinflussen.
**Empfehlung:** Ergebnis 30–60 s in einer Modulvariablen cachen und `Cache-Control: public, max-age=60` setzen (wie bei `/.well-known/*` in L759); Webhook-Zählung durch `SELECT COUNT(*) FROM webhooks WHERE active` ersetzen.

### [S3] [Performance] server/wp-plugin-registration.js:L215-231 und server/server.js:L4393-4400 — DNS-TXT-Lookups pro Request ohne Timeout und ohne Rate-Limit
**Begründung:** Beide dns-check-Routen erzeugen pro Aufruf einen neuen `Resolver()` und rufen `resolveTxt()` auf. Weder Konstruktor-Optionen (`new Resolver({ timeout, tries })`) noch ein `AbortSignal` sind gesetzt, d. h. es gilt der c-ares-Default (mehrere Sekunden × Retries). `POST /hhttps/plugin/dns-check/:clientId` ist unauthentifiziert (nur `client_id` nötig, das dem Aufrufer von `/hhttps/plugin/register` bekannt ist) und ohne eigenen Limiter; `POST /hhttps/developers/clients/:id/dns-check` ist auf Passkey-Nutzer beschränkt, hat aber ebenfalls nur `limit.global`. Jeder Aufruf schreibt zusätzlich `touchDnsCheck` (UPDATE) und bei Fehler denselben Pfad nochmals.
**Auswirkung:** Ein Aufrufer, der seine eigene Zone auf einen nicht antwortenden Nameserver delegiert, hält pro Request einen Handler mehrere Sekunden offen; bei 300 req/min (global limit) sind das hunderte gleichzeitig hängende Requests und ebenso viele Resolver-Sockets. Für den WP-Pfad reicht dafür ein einziger selbst registrierter Client.
**Empfehlung:** `new Resolver({ timeout: 3000, tries: 1 })` (in beiden Dateien), eine per-Route-Limitierung (z. B. `rl(10, 60_000)`), und im WP-Pfad zusätzlich eine Mindestpause über `dns_last_checked_at` (z. B. 30 s), bevor erneut resolved wird.

### [S4] [Performance] server/server.js:L4393-4395 — `await import('dns/promises')`, `new Resolver()` und `setServers()` werden bei jedem Request wiederholt
**Begründung:** Der dynamische Import wird zwar vom Modul-Loader gecacht, aber Resolver-Instanz und Server-Konfiguration werden pro Aufruf neu aufgebaut; wp-plugin-registration.js importiert `Resolver` statisch, hat aber dieselbe Instanz-pro-Request-Struktur (L228).
**Auswirkung:** Geringer Overhead pro Aufruf; kein Nutzeffekt, da der Resolver zustandslos ist.
**Empfehlung:** Einen modulweiten Resolver (mit Timeout, siehe vorheriges Finding) einmal anlegen und in beiden Modulen wiederverwenden.

### [S4] [Performance] server/server.js:L3868-3871 — Zwei unabhängige Schreibzugriffe im Token-Pfad sequenziell statt parallel
**Begründung:** `await db.tokens.create({...})` und `await db.machineOperators.incrementTokensIssued(operatorId)` hängen nicht voneinander ab, laufen aber nacheinander; `/hhttps/machine/token` ist der heiße Pfad für Bots (60/min/IP).
**Auswirkung:** Eine zusätzliche Pool-Roundtrip-Latenz pro Token-Ausgabe.
**Empfehlung:** `await Promise.all([db.tokens.create(...), db.machineOperators.incrementTokensIssued(operatorId)])`.

### [S4] [Performance] server/server.js:L4622-4636 — `/hhttps/admin/clients` liefert `SELECT * … LIMIT 200` ohne Pagination; admin.html lädt und partitioniert alles clientseitig
**Begründung:** Die Admin-Seite ruft `HHTTPS.api.admin.platforms()` (ohne Status-Filter) auf und sortiert in `partition()` (developers/admin.html L261–274) im Browser. Ab dem 201. Client fehlen Einträge stillschweigend (die Warteschlange wird über `created_at DESC` abgeschnitten, nicht über `pending_review`).
**Auswirkung:** Bei wachsender Client-Zahl wird die Antwort groß (alle Spalten inkl. `dns_token`, `redirect_uris`-JSON) und gleichzeitig unvollständig; die Queue-Zählung im UI stimmt dann nicht mehr.
**Empfehlung:** `?status=`/`?offset=`-Pagination im Endpunkt, im Admin-UI die Queue separat über `/hhttps/admin/clients/pending` laden und die anderen Tabs lazy per Status-Filter.

### [S4] [Performance] developers/assets/portal.js:L391-401 und L621-626 — Admin-Check bei jedem Seitenaufruf über den teuren `/hhttps/admin/stats`-Endpunkt
**Begründung:** `initNav()` ruft für jeden eingeloggten Besucher jeder Portal-Seite `verifyAdmin()` auf, das `GET /hhttps/admin/stats` nur wegen des HTTP-Status abfragt. Dieser Endpunkt führt `GROUP BY verification_status` über `oauth_clients` plus `adminActions.listRecent(20)` aus — bei Nicht-Admins wird das zwar nach `requireAdmin` (2 Token-Queries + `admins`-Lookup) mit 403 abgebrochen, bei Admins jedoch auf jeder Seite vollständig ausgeführt und das Ergebnis verworfen.
**Auswirkung:** Unnötige DB-Last pro Seitenaufruf; skaliert mit Admin-Anzahl × Seitenwechsel.
**Empfehlung:** `verifyAdmin()` auf `GET /hhttps/whoami` (liefert `is_admin`) umstellen; Ergebnis liegt ohnehin in `localStorage` (`id.is_admin`).

### [S4] [Performance] server/workload-identity.js:L125 und L158-161 — JWKS-Fetch ohne Timeout; jeder unbekannte `kid` erzwingt einen sofortigen Re-Fetch (kein Negativ-Cache)
**Begründung:** `fetch(cfg.jwksUri, …)` hat kein `AbortSignal.timeout`; bei Kid-Miss wird `getProviderKeys(provider, { forceRefresh: true })` ohne Mindestabstand aufgerufen, sodass jeder Token mit erfundenem `kid` einen ausgehenden HTTPS-Request zum Provider auslöst. Hinweis: Das Modul wird derzeit von keiner Datei importiert (`grep -rn workload-identity server --include=*.js` trifft nur die Datei selbst), es ist also aktuell **nicht** im Request-Pfad — daher nur S4.
**Auswirkung:** Sobald ein Exchange-Endpunkt gemountet wird, kann ein Angreifer die Instanz zu beliebig vielen Provider-Requests zwingen und hängende Verbindungen offenhalten.
**Empfehlung:** Vor Aktivierung `AbortSignal.timeout(5000)` setzen und Force-Refresh auf z. B. einmal pro 60 s pro Provider drosseln (Zeitstempel des letzten Refreshs in `_jwksCache` merken).

---

## Zusammenfassung

- S1: 0
- S2: 2
- S3: 2
- S4: 5

Gesamteindruck: Die Datenbankzugriffe im AP5 sind überwiegend sauber (alle Filter-/Join-Spalten von `oauth_clients`, `challenges`, `workload_identities` und `admins` sind indiziert, `/hhttps/developers/clients/:id/stats` nutzt `Promise.all`, `pool().query` wird ohne Client-Leak verwendet, PoP-Challenges sind per `ON CONFLICT` pro (jti, jkt) gedeckelt und laufen über `cleanup_expired()` aus). Der problematische Teil ist das nachträglich angeflanschte WordPress-Plugin-Modul, das auf eine selbstgebaute, header-gesteuerte In-Memory-Rate-Limit-Map setzt und damit sowohl ein Speicherleck als auch unbegrenztes Tabellen-/Mailwachstum ermöglicht; dazu kommen der uncachte öffentliche Stats-Endpunkt mit COUNT(*)-Scans über nie bereinigte Tabellen und die DNS-Lookups ohne Timeout. Die S4-Punkte sind Kleinigkeiten, die sich mit jeweils wenigen Zeilen beheben lassen.

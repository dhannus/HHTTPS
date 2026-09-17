# AP2 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b (Arbeitsbaum identisch mit bf0a82b für `server/`; Zeilennummern per `sed -n`/`grep -n` nachgeprüft)

Methodik: Jedes Finding am Code geprüft; die dynamisch behauptbaren Punkte mit einem Repro-Skript gegen den Test-Postgres belegt (`scratchpad/ap2-repro.test.mjs`, `scratchpad/ap2-race.test.mjs`; Harness aus `server/test/helpers/`). Repro-Ergebnisse werden unten als „Repro:“ zitiert. IDs in Reihenfolge K (01–12), S (13–22), P (23–27), W (28–42).

## Bestätigte Findings

### AP2-01 [S2] [Korrektheit] server/server.js:L1652-1690, L1950-1959; server/db.js:L1270-1306 — Plattform-Widerruf erreicht den OAuth-Refresh-Grant nicht; Refresh-Kette läuft nach „Verbindung trennen“ unbegrenzt weiter
**Urteil:** BESTÄTIGT (Severity unverändert S2; AP2-13 [S-1] zusammengeführt)
**Beleg:** `/hhttps/oauth/revoke` (L1950-1959) ruft nur `db.connectedPlatforms.revoke()` (db.js L1300-1306, `UPDATE … SET revoked_at = NOW()`). Der Refresh-Grant (L1652-1690) prüft Signatur, `rd.sub === 'oauth_refresh'`, `rd.client_id === client_id` (L1669) und `db.refreshTokens.get(rd.jti)` (L1672) — `connected_platforms` wird nie gelesen (grep: einzige Verwendungen L1788 `record`, L1956 `revoke`). `refresh_tokens` hat keine `client_id`-Spalte (schema.sql L81-89), ein gezieltes Entwerten pro (user, client) ist also nicht möglich. `connectedPlatforms.record` setzt zudem `revoked_at = NULL` beim nächsten Code-Exchange (db.js L1280). Jede Rotation legt eine neue jti mit vollen 30 Tagen an (L1680-1685); alle Claims werden aus dem alten JWT übernommen (L1697-1705, L1710-1726).
Repro: `REVOKE: 200 {"status":"revoked"}` → `connected_platforms.revoked_at set: true` → `REFRESH after revoke: 200 access_token issued, email=ap2v-…@example.org`.
**Auswirkung:** Nach dem vom Nutzer erklärten Widerruf kann die Plattform beliebig lange (bei Nutzung mindestens alle 30 Tage: unbegrenzt) frische Access-Tokens inkl. `email`, `preferred_username`, `verified_methods`, Rolle/Trust beziehen; Rollenentzug/Methodenwegfall bei HHTTPS wird nie propagiert („stale attestation“). Die Zusage im Consent-Footer („jederzeit widerrufen“) ist faktisch nicht eingelöst; UI-Zustand („my logins“) und Token-Zustand widersprechen sich.
**Empfehlung:** Im Refresh-Grant `connectedPlatforms.getPairwiseId(rd.ouid, client_id)` (bzw. `revoked_at IS NULL`) prüfen → sonst `invalid_grant`; in `/oauth/revoke` alle OAuth-Refresh-jtis des Paars (user, client) löschen (`client_id`-Spalte auf `refresh_tokens`); absolute Maximallebensdauer der Refresh-Kette; Claims beim Refresh gegen aktuellen Nutzerzustand neu bilden. Test: revoke → refresh_token grant → `invalid_grant`.

### AP2-02 [S3] [Korrektheit] server/server.js:L1380, L1950-1959, L1579 — Beworbener `revocation_endpoint` ist kein RFC-7009-Endpunkt; für Maschinen-Akteure ist der Disconnect zusätzlich ein No-op
**Urteil:** BESTÄTIGT (Severity unverändert S3; AP2-18 [S-6] und AP2-35 [W-8] zusammengeführt)
**Beleg:** Discovery L1380: `revocation_endpoint: ${BASE_URL}/hhttps/oauth/revoke`. Route L1950-1959 verlangt `token` + `client_id` und ruft `checkTokenValid(token)` (L702-711): OAuth-Access-Tokens haben kein `jti` → `db.tokens.exists(undefined)` → 401; OAuth-Refresh-JWTs (`sub:'oauth_refresh'`) → `db.tokens.exists(jti)` → 401. Es wird nie ein Eintrag in `refresh_tokens` gelöscht, der Client wird nicht authentifiziert. Maschinen: `/approve` bildet `userId = 'machine:' + operatorId` (L1579), `/revoke` nutzt `d.uid || d.userId || d.sub` (L1956); das Maschinen-Token (L3852-3854) trägt nur `sub:'machine'`, `operatorId` → UPDATE auf `user_id='machine'` trifft keine Zeile. `docs/oauth-integration.md` erwähnt weder `/revoke` noch den `refresh_token`-Grant (grep leer).
Repro: `REVOKE (RFC7009 style, oauth refresh token): 401 {"error":"Token nicht aktiv"}`.
**Auswirkung:** Standard-OIDC-Clients, die den beworbenen Endpoint nutzen, erhalten immer 401 und können kompromittierte Refresh-Tokens nicht ungültig machen; für Maschinen-Identitäten ist der Nutzer-Disconnect wirkungslos. Einziger funktionierender Widerrufsweg für OAuth-Refresh-JWTs ist das globale `/hhttps/revoke` (L3680-3688 löscht `refresh_tokens` per jti), das aber nicht dokumentiert/beworben ist.
**Empfehlung:** RFC-7009-konformen Endpunkt (Client-Auth wie am Token-Endpoint, `token` + `token_type_hint`, jti aus dem Refresh-JWT löschen, immer 200) und diesen in der Discovery eintragen; Nutzer-Disconnect als `/hhttps/oauth/disconnect` belassen und dort dieselbe user_id-Ableitung wie in `/approve` verwenden; in docs/oauth-integration.md dokumentieren.

### AP2-03 [S3] [Korrektheit] server/server.js:L1672-1686 — Refresh-Token-Rotation ist ein nicht-atomares Check-then-Act; parallele Refreshs mit demselben Token liefern mehrere gültige neue Refresh-Tokens
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** `const active = await db.refreshTokens.get(rd.jti)` (L1672) … `refreshTokens.create(newJti)` (L1680) … `refreshTokens.delete(rd.jti)` (L1686) — drei separate Statements ohne Transaktion oder bedingtes `DELETE … RETURNING`. Vergleich: Code-Claim ist atomar (db.js L1245-1257).
Repro (`ap2-race.test.mjs`, 30 parallele Refreshs mit demselben Token, 5 Runden): `200s: 1 of 30`, `23 of 30`, `30 of 30`, `30 of 30`, `30 of 30` — alle ausgegebenen Nachfolger-jtis sind in `refresh_tokens` aktiv.
**Auswirkung:** Keine Single-Use-Semantik; ein gestohlener Refresh-Token kann parallel zum legitimen Client eingelöst werden, ohne dass eine Wiederverwendung sichtbar wird (Replay-Erkennung nach RFC 6819 §5.2.2.3 greift nicht). Zusammen mit AP2-01 entsteht daraus eine beliebig verzweigende, nicht widerrufbare Token-Familie.
**Empfehlung:** Rotation als eine Anweisung: `DELETE FROM refresh_tokens WHERE jti=$1 AND expires_at > NOW() RETURNING *`; nur bei genau einer Zeile den neuen Token anlegen, sonst `invalid_grant`. Test mit `Promise.all` (genau eine 200).

### AP2-04 [S3] [Korrektheit] server/server.js:L1479, L1561, L1661, L1752, L1775 — `/oauth/authorize`, `/oauth/approve` und `/oauth/token` werfen bei Nicht-String-Parametern (`scope[]`, `client_secret`, `code_verifier` als Array/Objekt/Zahl) einen unbehandelten TypeError; die Anfrage bleibt ohne Antwort hängen, der Authorization-Code ist verbraucht
**Urteil:** BESTÄTIGT (Severity unverändert S3; AP2-05 [K-5] und AP2-16 [S-4] zusammengeführt — gleiche Ursache, gleicher Fix)
**Beleg:** `validateAuthorizeParams` prüft nur `state`/`nonce`/`code_challenge*` auf String (oauth-params.js L23-28, L37-49), `scope` nicht. `(scope || 'openid').split(/\s+/)` L1479 (außerhalb jedes try/catch) bzw. L1561 (dort im try → 500); `crypto.createHash('sha256').update(client_secret)` L1661/L1752 und `.update(code_verifier)` L1775 werfen `ERR_INVALID_ARG_TYPE`. Handler sind `async` unter Express 4.22.2 (`node_modules/express/package.json`), Rejections landen nur bei `process.on('unhandledRejection')` L4824 (Logger). L1775 liegt nach `db.authCodes.claim(code)` (L1759).
Repro: `AUTHORIZE scope[]: HANG` (3 s Timeout, Server danach weiter erreichbar: `/hhttps/info 200`); `TOKEN client_secret=123: HANG`; `TOKEN refresh client_secret={}: HANG`; `TOKEN code_verifier={}: HANG` → `code consumed after hang: true`.
**Auswirkung:** Unauthentifizierte Requests halten Sockets bis zum Timeout offen (Rate-Limit 300/min reicht, um dauerhaft Verbindungen zu belegen); bei `code_verifier`-Typfehler ist der Login für den Nutzer verloren (Code single-use verbraucht, neu autorisieren). Kein Crash.
**Empfehlung:** `scope`, `client_secret`, `code_verifier`, `code`, `redirect_uri`, `refresh_token`, `client_id` auf `typeof === 'string'` prüfen (in oauth-params.js ergänzen) → 400 `invalid_request`; `/token`-Body in try/catch mit 500 `server_error` (wie `/approve` L1636); mittelfristig `asyncHandler`-Wrapper oder Express 5.

### AP2-06 [S4] [Korrektheit] server/server.js:L1552-1575 — `/oauth/approve` erzwingt für Public Clients keinen `code_challenge` (anders als `/oauth/authorize` L1472-1475); Code wird mit `pkce_challenge = NULL` erzeugt und ohne Verifier eingelöst
**Urteil:** BESTÄTIGT (herabgestuft von S3 wegen eingeschränkter Ausnutzbarkeit, s. u.)
**Beleg:** In `/approve` fehlt die Regel `isPublicClient && !code_challenge`; `authCodes.create` schreibt `pkceChallenge: code_challenge` (L1607) → NULL; `/token` überspringt PKCE bei `if (claimed.pkce_challenge)` (L1769).
Repro: `APPROVE no code_challenge: 200 {"redirect":"…?code=hp-…"}` → `TOKEN without code_verifier: 200 [access_token, id_token, refresh_token, …]`.
**Auswirkung:** Inkonsistente Policy zwischen zwei Endpunkten desselben Flows (F-8 hat genau dieses Muster für Scopes gespiegelt). Herabstufung: `/approve` ist nur mit einem gültigen HHTTPS-Nutzer-Token aufrufbar (kein Cookie, kein CSRF-Vektor), die Consent-Seite bekommt ihre `params` nur aus einem bereits von `/authorize` validierten Request — ein Dritter kann die Challenge nicht entfernen. Praktisch schwächt nur der Token-Inhaber seinen eigenen Login gegen Code-Interception.
**Empfehlung:** Nach dem Client-Lookup in `/approve`: `if (!client.client_secret_hash && !code_challenge) → 400 invalid_request` (Text wie L1474); Test analog #31 (d).

### AP2-07 [S3] [Korrektheit] server/server.js:L2179, L2198 (weitere Literale L1987, L2115, L2146) — Consent-Skript verweist hart auf `https://hhttps.org` (Relogin, Token-Refresh) statt auf `BASE_URL`/eigene Origin
**Urteil:** BESTÄTIGT (Severity unverändert S3; AP2-32 [W-5] zusammengeführt)
**Beleg:** L2179 `let url = 'https://hhttps.org/?returnTo=' + …`; L2198 `fetch('https://hhttps.org/hhttps/token/refresh', …)`; der `/approve`-Aufruf im selben Skript ist relativ (L2248, L2271). Alle Server-URLs sonst aus `BASE_URL`/`ORIGIN` (L76-78, Discovery L1377-1381). Test-Harness setzt `RP_ID=localhost`, `BASE_URL=http://localhost:<port>` (test/helpers/server.mjs L27-29); login-hint.test.mjs L122 prüft `relogin()` nur per Regex im HTML.
**Auswirkung:** Auf Staging/Test-Instanzen läuft „Erlauben“ ohne Identität zur Produktions-Anmeldung und kehrt mit einem Produktions-Token zurück (Signatur fremd → 401 → Relogin-Schleife); `tryRefresh` ist cross-origin (CORS `connectSrc 'self'` L400) und liefert immer `null`, ein abgelaufenes Token führt stets zum Relogin, obwohl der Refresh-Token gültig wäre. Der Relogin-/Refresh-Pfad ist so in den Integrationstests nicht durchlaufbar.
**Empfehlung:** `ORIGIN` als Template-Parameter in `renderConsentPage` übergeben (`JSON.stringify(ORIGIN)` ins Skript, `escapeHtml(ORIGIN)` in `href`) oder `window.location.origin` verwenden; alle fünf Literale ersetzen.

### AP2-08 [S3] [Korrektheit] server/test/integration/oauth-claims.test.mjs:L78-96, L179-205; oauth-params.test.mjs; login-hint.test.mjs; acceptance.test.mjs:L119-125 — Fehlerpfade von `/oauth/token`, `/oauth/revoke` und die Refresh-Grant-Bindung sind ungetestet
**Urteil:** BESTÄTIGT (Severity unverändert S3; AP2-36 [W-9] zusammengeführt — mit Korrektur)
**Beleg:** grep über `server/test/` (integration + unit, inkl. security-fixes, db-phase8): kein `client_secret`-Negativfall (alle Test-Clients haben `client_secret_hash NULL`: oauth-claims L54, oauth-params L48, login-hint L40, acceptance L91), kein `code_verifier`-Mismatch, kein `invalid_grant`, kein `unsupported_grant_type`, kein `'plain'`, kein Aufruf von `/hhttps/oauth/revoke`, kein Refresh mit fremder `client_id` oder bereits rotiertem Token, kein `/userinfo` mit abgelaufenem/fremdem Token. Korrektur zu W-9: der Maschinen-Pfad durch `/approve` ist getestet (acceptance.test.mjs L443-476 „Machine path: machine token → approve …“).
**Auswirkung:** Genau die Verzweigungen, die AP2-01, -03, -04, -06, -10 betreffen, sind nicht regressionsgesichert; das Repro-Skript dieser Verifikation hat alle fünf Befunde ohne Änderung am Code sofort nachgewiesen.
**Empfehlung:** `oauth-token-errors.test.mjs` (Harness aus oauth-params.test.mjs) mit: Code-Wiederverwendung, PKCE-Mismatch, client_id-/redirect_uri-Mismatch, Confidential Client ohne/mit falschem Secret, `grant_type=password`, Refresh mit fremder client_id / rotiertem Token, Race (`Promise.all`, genau eine 200), `/revoke` → `revoked_at` gesetzt + anschließender Refresh `invalid_grant`, `/userinfo` mit Refresh-JWT → 401.

### AP2-09 [S4] [Korrektheit] server/server.js:L1840 — `auth_time` im ID-Token ist der Zeitpunkt des Code-Einlösens, nicht der Authentifizierung
**Urteil:** BESTÄTIGT (Severity unverändert S4; AP2-19 [S-7] zusammengeführt)
**Beleg:** L1840 `auth_time: Math.floor(Date.now() / 1000)`; `/approve` prüft das HHTTPS-Token (L1545) und übernimmt dessen `iat` nicht in die Code-Zeile (`authCodes.create` L1601-1623 hat kein solches Feld). Das HHTTPS-Token kann per `/hhttps/token/refresh` (L2606) bzw. per Consent-Skript `tryRefresh` (L2194-2212) aus einem bis zu REFRESH_TTL alten Refresh-Token stammen. Discovery listet `auth_time` in `claims_supported` (L1390).
**Auswirkung:** Relying Parties, die `max_age`/`auth_time` auswerten, erhalten einen falsch-frischen Wert.
**Empfehlung:** `d.iat` in `/approve` in die Code-Zeile schreiben (Spalte `auth_time`) und in `/token` daraus setzen; sonst den Claim aus `claims_supported` streichen und weglassen.

### AP2-10 [S3] [Korrektheit] server/server.js:L1912-1946 — `/oauth/userinfo` akzeptiert jedes serversignierte JWT mit `client_id`-Claim, also auch den 30 Tage gültigen OAuth-Refresh-JWT — selbst nach Rotation/Löschung
**Urteil:** BESTÄTIGT (hochgestuft von S4 auf S3: AP2-17 [S-5] zusammengeführt, dessen Repro die Umgehung von TTL und Rotation belegt)
**Beleg:** Einzige Typprüfung `if (!d.client_id)` (L1919), keine Prüfung von `sub`, `aud` oder `refresh_tokens`. Der Refresh-JWT (L1697-1706, L1887-1896) trägt `client_id`, `scope`, `verified_methods`, `email`, `preferred_username`, `role`, `age_group` — alles, was `/userinfo` liest (L1928-1943).
Repro: Refresh-Token rotiert (alte jti gelöscht), dann `GET /userinfo` mit dem alten Refresh-JWT als Bearer → `200 {"sub":"oauth_refresh","verified_methods":["email","domain"],"email_verified":true,…,"preferred_username":"UI","email":"ap2v-…@example.org"}`.
**Auswirkung:** Die 5-Minuten-TTL der Access-Tokens (OAUTH_TOKEN_TTL) ist für `/userinfo` faktisch 30 Tage; ein geleakter Refresh-JWT ist ein zustandsloses, nicht widerrufbares Userinfo-Credential (E-Mail-Adresse), auch nach Rotation und nach AP2-01-Widerruf. Nebeneffekt: `sub` ist `'oauth_refresh'` statt der pairwise-ID.
**Empfehlung:** Access-Tokens mit `typ`/`token_use: 'access'` signieren und in `/userinfo` positiv prüfen (mindestens `d.sub !== 'oauth_refresh' && d.aud`); Refresh-JWTs mit eigenem `typ`/`aud`, damit sie an keinem anderen Endpunkt verifizieren; RFC-6750-Antwort `401 invalid_token` + `WWW-Authenticate`.

### AP2-11 [S4] [Korrektheit] server/server.js:L1376-1381 — `issuer` aus `RP_ID`, alle Endpunkte aus `BASE_URL`; bei abweichendem `BASE_URL` stimmt die Discovery nicht mit dem Issuer überein
**Urteil:** BESTÄTIGT (Severity unverändert S4)
**Beleg:** L1376 `issuer: https://${RP_ID}` vs. L1377-1381 `${BASE_URL}/…`; `BASE_URL` frei per Env (L78, Default `ORIGIN`). Der Test-Harness erzeugt genau diesen Fall (`RP_ID=localhost`, `BASE_URL=http://localhost:<port>`, helpers/server.mjs L27-29): Discovery-`issuer` = `https://localhost`, Dokument liegt unter `http://localhost:<port>/.well-known/…`. Auch `iss` in Access-/ID-Token nutzt `RP_ID` (L1711, L1810, L1836).
**Auswirkung:** Strikte OIDC-Bibliotheken (Issuer-Mismatch-Check nach Discovery 1.0 §4.3) lehnen Staging-/lokale Instanzen ab.
**Empfehlung:** Eine gemeinsame `ISSUER`-Konstante (aus `BASE_URL`/`ORIGIN`) für Discovery und alle `signToken`-Aufrufe.

### AP2-14 [S4] [Sicherheit] server/server.js:L1387, L1608, L1774-1778; server/oauth-params.js:L10-11, L17 — PKCE-Methode `plain` wird beworben, akzeptiert und ist Default bei fehlender Methode
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4; AP2-42 [W-15] zusammengeführt)
**Beleg:** Discovery L1387 `['S256', 'plain']`; `/approve` L1608 `pkceMethod: code_challenge_method || 'plain'`; `/token` L1776-1777 vergleicht bei `plain` den Verifier im Klartext; oauth-params.js L17 `CODE_CHALLENGE_METHODS = ['S256','plain']`. Herabstufung: das Verhalten ist RFC-7636-konform (§4.3: „Defaults to plain if not present“); die Bezeichnung „OAuth 2.1“ steht nur im Review-Inventar (docs/review/00-inventar.md L45), nicht in Projekt-Doku/README (grep leer) — der Widerspruch zu OAuth 2.1 ist damit ein Härtungs-, kein Konformitätsproblem. Ausnutzung setzt voraus, dass der Client selbst `plain` wählt.
**Auswirkung:** Bei `plain` steht der Verifier im Klartext in der Authorize-URL (History, Proxy-/Server-Logs); Code-Interception bei Public Clients ist dann nicht abgewehrt — genau das Szenario, für das PKCE Pflicht ist (L1472-1476).
**Empfehlung:** `plain` aus `CODE_CHALLENGE_METHODS` und Discovery entfernen, Default `S256` bzw. fehlende Methode → `invalid_request`; PKCE auch für Confidential Clients verlangen; in docs/oauth-integration.md dokumentieren.

### AP2-15 [S3] [Sicherheit] server/server.js:L1412 — Pairwise-HMAC-Schlüssel hat einen öffentlichen, deterministischen Fallback ohne Prod-Guard; `PAIRWISE_SECRET` wird nirgends dokumentiert oder geprüft
**Urteil:** BESTÄTIGT (Severity unverändert S3; AP2-38 [W-11] zusammengeführt)
**Beleg:** L1412 `const secret = process.env.PAIRWISE_SECRET || 'hhttps-pairwise-' + RP_ID;` — grep über das gesamte Repo (ohne node_modules, docs/review): einzige Fundstelle. Kein Boot-Check analog `assertPepperConfigured` (identity.js L31-35), kein .env-Beispiel, kein Deploy-Skript. `subject_type 'public'` nutzt ungeschlüsselt `sha256('public:'+userId)` (L1408). Die Variable wird pro Aufruf im Funktionskörper gelesen statt zentral bei L75-78.
**Auswirkung:** Läuft Prod ohne die Variable, ist der Schlüssel aus dem Quellcode bekannt; wer eine `user_id` kennt, kann die `sub`-Werte für alle Plattformen berechnen und Pseudonyme plattformübergreifend korrelieren. Ein nachträgliches Setzen ändert alle `sub`-Werte (Account-Verlust bei allen Plattformen) — die Fehlkonfiguration wird also mit der Zeit irreversibel.
**Empfehlung:** `PAIRWISE_SECRET` neben L75-78 einlesen und in `main()` für `NODE_ENV=production` erzwingen (wie `assertPepperConfigured`); im Deploy-Runbook/.env-Beispiel dokumentieren; für `public` ebenfalls geschlüsselten HMAC.

### AP2-20 [S4] [Sicherheit] server/server.js:L1661-1663, L1752-1755 — Client-Secret-Vergleich nicht zeitkonstant; Secret ungesalzen gehasht; Prüfung doppelt implementiert
**Urteil:** BESTÄTIGT (Severity unverändert S4)
**Beleg:** `const expected = crypto.createHash('sha256').update(client_secret).digest('hex'); if (expected !== rClient.client_secret_hash)` (L1661-1663) — identisch L1752-1755.
**Auswirkung:** Timing-Leak betrifft nur den Hash-Wert (praktisch nicht ausnutzbar); ungesalzenes SHA-256 ist nur vertretbar, solange Secrets serverseitig hoch-entropisch erzeugt werden (Registrierung: AP5).
**Empfehlung:** `crypto.timingSafeEqual` mit Längenprüfung in einer Hilfsfunktion `authenticateClient(client, secret)` (siehe auch AP2-30).

### AP2-21 [S4] [Sicherheit] server/server.js:L1672-1686 — Refresh-Rotation ohne Reuse-/Familien-Erkennung
**Urteil:** BESTÄTIGT (Severity unverändert S4; bewusst getrennt von AP2-03: dort Atomarität, hier fehlender Familien-Widerruf)
**Beleg:** Eine bereits rotierte jti wird nur mit `invalid_grant` abgewiesen (L1673-1675); es gibt keine Familien-/`replaced_by`-Information in `refresh_tokens` (schema.sql L81-89), die Nachfolger-Kette bleibt gültig.
**Auswirkung:** Wer ein Refresh-Token kopiert und vor dem legitimen Client einlöst, behält die gültige Kette; der Diebstahl wird nicht erkannt (RFC 6819 §5.2.2.3).
**Empfehlung:** Familien-ID pro Erst-Login in `refresh_tokens`; bei Vorlage einer bekannten, aber bereits rotierten jti alle Tokens der Familie löschen.

### AP2-22 [S4] [Sicherheit] server/server.js:L2020-2022; L392-398 (CSP) — Consent-Seite lädt drei Google-Fonts-Familien (render-blockendes Fremd-CSS) auf dem Login-kritischen Pfad
**Urteil:** BESTÄTIGT (Severity unverändert S4; AP2-27 [P-5] zusammengeführt — gleiche Ursache, gleicher Fix; mit Korrektur)
**Beleg:** L2020-2022 `preconnect fonts.googleapis.com/fonts.gstatic.com` + `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Syne…&family=Inter…&family=JetBrains+Mono…">`; CSP erlaubt es (`styleSrc`/`fontSrc` L396-398). Korrektur zu S-10: Helmet 7.2.0 setzt per Default `Referrer-Policy: no-referrer` (helmet/index.mjs L187), `referrerPolicy` ist in server.js nicht deaktiviert (grep leer) — die Consent-URL (`client_id`, `login_hint`) wird nicht als Referrer übertragen. Es bleiben IP-Adresse/User-Agent und der Zeitpunkt jedes OAuth-Logins.
**Auswirkung:** Datenabfluss (IP, Zeitpunkt) an Google auf der Seite, die „Keine persönlichen Daten“ verspricht; zusätzlicher DNS+TLS-Roundtrip zu zwei Fremd-Origins vor dem First Paint; bei blockiertem Google-Fonts-Zugriff (Adblocker, Firmennetz) wartet der Browser bis zum Timeout auf das blockierende Stylesheet (`display=swap` hilft nur beim Font-Teil); JetBrains Mono wird nur für ein `<code>`-Element gebraucht.
**Empfehlung:** Schriften selbst hosten (`/public/fonts`, `font-display: swap`) oder System-Font-Stack; Google-Hosts aus der CSP entfernen.

### AP2-23 [S2] [Performance] server/server.js:L1601-1623, L714-724; server/db.js:L1245-1266, L1339-1347; server/sql/schema.sql:L192-206 — `authorization_codes` wird bei jeder Autorisierung befüllt, aber nie bereinigt; der vorhandene Cleanup ist nirgends eingehängt
**Urteil:** BESTÄTIGT (Severity unverändert S2)
**Beleg:** `/approve` → `db.authCodes.create` (L1601); `claim()` setzt nur `used = TRUE` (db.js L1248-1250); `authCodes.cleanup()` (db.js L1264-1267) wird nirgends aufgerufen (grep `authCodes.cleanup` über `server/`: nur die Definition); `cleanup_expired()` (schema.sql L199-203) kennt `tokens`, `refresh_tokens`, `sessions`, `challenges`, `email_verifications`; `cleanupExpired()` in db.js L1339-1347 ergänzt nur `identity_claims_cache`. Pro Zeile bis zu 2×2048 Zeichen `state`/`nonce` (oauth-params.js L13-14), `pkce_challenge`, `redirect_uri` (500), `verified_methods` (JSON), ggf. `email`.
Repro: nach dem Repro-Lauf `authorization_codes rows: {"n":7,"used":7,…}` — eingelöste Codes bleiben als `used`-Zeilen liegen.
**Auswirkung:** Tabelle + PK-Index + `idx_authcodes_expires` wachsen linear mit allen jemals gestarteten Logins (inkl. abgebrochener); Autovacuum/Backups werden stetig teurer. Nie eingelöste Codes behalten `email` im Klartext unbegrenzt (die Wipe-Logik in `claim()` greift nur beim Einlösen) — das widerspricht der Datenminimierungs-Zusage und rechtfertigt S2.
**Empfehlung:** `db.authCodes.cleanup()` in das 5-Minuten-Intervall (server.js L714-724) aufnehmen oder `DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour'` in `cleanup_expired()` ergänzen; Ergebnis in die `[CLEANUP]`-Ausgabe zählen.

### AP2-24 [S3] [Performance] server/server.js:L1788, L1860-1861, L1866, L1883 — Token-Endpunkt führt nach der Validierung fünf serielle Schreibzugriffe aus, davon zwei auf globale Hot-Rows der `stats`-Tabelle
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** Nach `authCodes.claim` (L1759) nacheinander `await`ed: `connectedPlatforms.record` (L1788), `stats.increment('oauth_tokens_issued')` (L1860), `stats.increment('oauth_logins')` (L1861), `clientStats.recordLogin` (L1866), `refreshTokens.create` (L1883). `stats.increment` = `INSERT … ON CONFLICT (metric) DO UPDATE` auf eine Zeile pro Metrik (db.js L1320-1326) → Row-Lock-Serialisierung aller Token-Exchanges an zwei Zeilen.
**Auswirkung:** 5 zusätzliche serielle Roundtrips im wichtigsten Endpunkt; unter paralleler Last serialisieren sich alle Code-Exchanges an den `stats`-Zeilen. Kein Ausfall, vermeidbarer Durchsatzdeckel.
**Empfehlung:** Statistik-Aufrufe zusammenfassen (`UPDATE stats … WHERE metric IN (…)`) und vom Antwortpfad entkoppeln (`Promise.all(...).catch(log)` ohne `await` vor `res.json`); `connectedPlatforms.record` parallel zu `refreshTokens.create`.

### AP2-25 [S4] [Performance] server/server.js:L1625-1626; server/db.js:L854-856 — `/approve` schreibt pro Login die `oauth_clients`-Zeile neu (`touchLastUsed`) und eine globale Stats-Hot-Row, seriell vor der Antwort
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: nur zwei Schreibzugriffe, Lock nur pro Client, gleiches Muster wie im gesamten Server — siehe `issueAccessToken` L667; messbar nur bei hoher Parallelität)
**Beleg:** L1625 `await db.oauthClients.touchLastUsed(client_id)` → `UPDATE oauth_clients SET last_used_at = NOW() WHERE client_id = $1` (db.js L854-856, neue Tupel-Version der breiten Zeile); L1626 `await db.stats.increment('oauth_authorizations')`. Davor bereits `checkTokenValid` (3 Queries), `oauthClients.get`, ggf. `identityClaimsCache.get`, `authCodes.create`.
**Auswirkung:** Zusätzliche Latenz im Consent-Klick, Bloat auf `oauth_clients` proportional zur Login-Zahl.
**Empfehlung:** `touchLastUsed` drosseln (`… AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')`) und beide Aufrufe nach `res.json` ohne `await` (Fehler nur loggen).

### AP2-26 [S4] [Performance] server/server.js:L1454, L1556, L1745; server/db.js:L822-831 — `oauthClients.get` (`SELECT *` + 2× `JSON.parse`) läuft dreimal pro Login-Flow ohne Cache
**Urteil:** BESTÄTIGT (Severity unverändert S4)
**Beleg:** Alle drei Aufrufe laden die vollständige Zeile über PK und parsen `redirect_uris`/`allowed_scopes` (db.js L822-831).
**Auswirkung:** Drei vermeidbare Roundtrips pro Login; Mikro-Optimierung.
**Empfehlung:** Optionaler kurzer TTL-Cache mit Größenbegrenzung — oder bewusst so lassen (sofortige Wirkung von `is_active`) und im Code dokumentieren.

### AP2-28 [S3] [Wartbarkeit] server/server.js:L1641-1909 — Token-Endpoint ist ein 268-Zeilen-Handler mit zwei komplett inline ausformulierten Grants
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** `app.post('/hhttps/oauth/token')` L1641 bis L1909; Refresh-Grant L1652-1735 mit `return` mitten im Handler, Code-Grant L1737-1908 (Client-Auth, Claim, PKCE, Access-, ID-, Refresh-Token, drei Statistiken). `code`, `redirect_uri`, `code_verifier` aus L1642-1649 sind im Refresh-Zweig ungenutzt.
**Auswirkung:** Claim-Änderungen müssen an bis zu vier Stellen im selben Handler nachgezogen werden; Grants nicht isoliert testbar (vgl. AP2-08).
**Empfehlung:** `handleRefreshGrant`/`handleCodeGrant` (Dispatch über `grant_type`) plus Helfer `authenticateClient`, `issueOAuthAccessToken`, `issueOAuthRefreshToken`; in `server/oauth.js` verschieben.

### AP2-29 [S3] [Wartbarkeit] server/server.js:L1697-1727, L1808-1830, L1884-1896 — Access- und Refresh-JWT werden im Code- und im Refresh-Zweig jeweils komplett doppelt zusammengesetzt; `age_group`-Block sechsfach, Bot-Block dreifach
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** Access-Claims L1711-1727 ≙ L1808-1830; Refresh-Claims L1697-1706 ≙ L1884-1896 (nur `rd.*` vs. `claimed.*`); Kommentar L1709 „dieselben Claims wie im Code-Zweig“. `age_group`-Block: L1702-1704, L1723-1726, L1826-1829, L1853-1855, L1892-1894, L1939-1941; Bot-Block L1721, L1822, L1835. Die vom Reviewer genannte Asymmetrie ist real: Refresh-JWT enthält `age_group` ohne Scope-Prüfung (L1702, L1892), Access-Token nur mit Scope (L1723, L1826).
**Auswirkung:** Drift-Risiko bei jeder Claim-Änderung (3–6 Stellen); die vorhandene Asymmetrie zeigt, dass es bereits passiert.
**Empfehlung:** Reine Funktion `buildOAuthTokenClaims({ source, scopes, pairwiseId, clientId })` mit Sub-Helfern `ageClaims(src, scopes)`/`actorClaims(src)` (analog `buildIdentityClaims`); beide Zweige rufen nur `signToken(build…)`.

### AP2-30 [S3] [Wartbarkeit] server/server.js:L1478-1492 / L1561-1575 und L1659-1665 / L1749-1757 — Scope-Validierung in `/authorize` und `/approve` sowie Client-Secret-Prüfung in beiden Grants dupliziert
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** Beide Routen splitten `scope`, prüfen `includes('openid')`, filtern gegen `SCOPES_KNOWN` und `client.allowed_scopes` mit identischen Fehlertexten; Kommentar L1565 „F-8: same scope policy as /authorize“ dokumentiert die frühere Divergenz. Secret-Prüfung L1659-1665 ≙ L1749-1757. AP2-06 (PKCE-Regel nur in `/authorize`) ist genau die nächste Divergenz dieser Art.
**Auswirkung:** Jede neue Scope-/Auth-Regel muss an zwei Stellen synchron gehalten werden.
**Empfehlung:** `validateScopes(scopeString, client)` und `authenticateClient(client, secret)` nach oauth-params.js (dort liegt `validateAuthorizeParams`); dort auch die String-Typprüfung aus AP2-04.

### AP2-31 [S3] [Wartbarkeit] server/server.js:L1990-2367; server/test/unit/consent-page.test.mjs:L12-24 — `renderConsentPage` ist ein 378-Zeilen-Template-Literal mit ~150 Zeilen eingebettetem Browser-JS und ~100 Zeilen CSS
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** CSS L2016-2106, HTML, Skript inkl. i18n L2149-2364 in einem String; ESLint prüft das eingebettete JS nicht (ESLint-Lauf meldet für den Bereich nur L1944/L1969, s. AP2-41). Unit-Test sucht per `src.indexOf('function renderConsentPage(')`/`indexOf('</html>')` (consent-page.test.mjs L16-23, mit Kommentar zum falschen Endmarker L18-21). `/approve`-Body doppelt L2248-2262 und L2271-2284; Scope-Labels doppelt (Server L2002-2008 vs. `CONSENT_I18N.de` L2317-2321).
**Auswirkung:** Syntaxfehler im Consent-Skript fallen erst im Browser auf; regex-basierte Tests brechen bei Umformatierung.
**Empfehlung:** Skript/CSS als statische Dateien (`public/consent.js`, `consent.css`), Params per `<script type="application/json">`; `postApprove(token)` als Funktion; Labels nur aus `CONSENT_I18N`.

### AP2-33 [S3] [Wartbarkeit] server/server.js:L1534-1563, L1915-1920, L1952-1959, L2267-2268 — Fehlerformate/Statuscodes der OAuth-Routen sind untereinander inkonsistent (RFC-Codes vs. Freitext)
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** `/approve`: `{error:'token required'}` 401 (L1534), `e.message` 401 (L1547), `'unknown client'` (L1557), `'redirect_uri mismatch'` (L1559), `'openid scope required'` (L1563) neben `invalid_scope`+`error_description` (L1569, L1573) und `server_error` (L1636). `/userinfo`: `'unauthorized'` (L1915), 403 `'not an oauth access token'` (L1920), `invalid_token` (L1945) ohne `WWW-Authenticate`. `/revoke`: `'token + client_id required'` (L1952), 401 `e.message` (L1959). `/token` durchgehend RFC-Codes. Das Consent-Skript erkennt Ablauf per Regex `/expired|jwt/i` auf dem Fehlertext (L2267-2268).
**Auswirkung:** Clients/SDKs können OAuth-Fehler nicht einheitlich auswerten; Textvergleich im Frontend ist fragil.
**Empfehlung:** Für alle `/hhttps/oauth/*`-Routen nur `{ error: <RFC-6749/6750-Code>, error_description }`; Token-Ablauf als `invalid_token`.

### AP2-34 [S3] [Wartbarkeit] server/server.js:L1718, L1817, L1936 vs. L1391, L1700, L1846, L1890 — Claim-Name `trustScore` (camelCase) im Access-Token, `trust_score` (snake_case) in ID-Token, Refresh-JWT, Discovery und `/userinfo`
**Urteil:** BESTÄTIGT (Severity unverändert S3)
**Beleg:** Access-Token `trustScore:` L1718/L1817; `/userinfo` liest `d.trustScore` und gibt `trust_score` aus (L1936); ID-Token L1846, Refresh-JWT L1700/L1890 und `claims_supported` L1391 nennen `trust_score`. Repro (Access-Token-Keys): `…,role,trustScore,verified_methods,…` — alle anderen Claims snake_case.
**Auswirkung:** Resource-Server, die den Access-Token direkt dekodieren, finden den Discovery-Claim nicht; beim Umbau auf eine gemeinsame Claim-Funktion (AP2-29) ist die Abweichung ein Stolperstein.
**Empfehlung:** Access-Token auf `trust_score` umstellen, `trustScore` übergangsweise parallel; Claim-Namen als Konstanten.

### AP2-37 [S4] [Wartbarkeit] server/server.js:L1494-1499, L1527-1529 — Veraltete Kommentare beschreiben den Consent-Flow mit Passkey/Cookie/Extension statt localStorage-Identität
**Urteil:** BESTÄTIGT (Severity unverändert S4)
**Beleg:** L1494-1498 „picked up from a cookie OR (when the browser extension is installed) from localStorage … asks the user to identify (passkey)“; L1527-1528 „after the user has authenticated (passkey)“. Tatsächlich: `localStorage.getItem('hhttps_identity')` (L2225), ohne Identität `relogin()` zur E-Mail-Anmeldung (L2231-2232, L2177). Ticket-Marker (`Phase 8`, `AK-nn`, `F-8`, `W-7`, `P-5`, `D3/D5`) ohne Verweisziel im Repo (L1391, L1584, L1603, L1795, L1861).
**Auswirkung:** Irreführung neuer Entwickler.
**Empfehlung:** Beide Kommentare auf den realen Ablauf umschreiben; Marker durch Links auf docs/specs ersetzen.

### AP2-39 [S4] [Wartbarkeit] server/server.js:L2370-2374; server/email.js:L810-818 — `escapeHtml` in zwei Modulen doppelt implementiert — und bereits auseinandergelaufen
**Urteil:** BESTÄTIGT (Severity unverändert S4; Korrektur: die Implementierungen sind nicht identisch)
**Beleg:** server.js L2370-2374 ersetzt `& < > "`; email.js L810-818 zusätzlich `'` → `&#39;`. server.js-Variante wird in Consent-Seite, WP-Registrierung (L4265-4273) und `renderSimplePage` (L4715, L4728) genutzt.
**Auswirkung:** Genau die vom Reviewer befürchtete Drift (Apostroph-Escaping) ist schon eingetreten; Attribute in einfachen Anführungszeichen wären in server.js nicht sicher.
**Empfehlung:** Eine `escapeHtml` (die vollständigere aus email.js) in ein Util-Modul exportieren und aus beiden Dateien importieren.

### AP2-40 [S4] [Wartbarkeit] server/server.js:L1978-1988 — `renderOAuthError` ist eine zweite, abweichende Fehlerseite ohne Escaping und mit altem Farbschema
**Urteil:** BESTÄTIGT (Severity unverändert S4)
**Beleg:** L1986 interpoliert `${message}` ohne `escapeHtml`; alle fünf Aufrufer (L1449, L1452, L1456, L1459, L1970) übergeben derzeit nur konstante Strings — kein aktueller XSS, aber eine Falle. Farben `#F8F1E4/#C97D5B/'Fraunces'` (L1980-1984) vs. Consent-Design `Syne/Inter` (L2017-2030); `lang="de"` mit englischem Text; `renderSimplePage` (L4713-4728) existiert bereits mit `escapeHtml(title)`.
**Auswirkung:** Zwei Fehlerseiten-Layouts; Escaping-Lücke bei der ersten dynamischen Nachricht.
**Empfehlung:** `renderOAuthError` auf `renderSimplePage` delegieren, `message` durch `escapeHtml`.

### AP2-41 [S4] [Wartbarkeit] server/server.js:L1944, L1969, L2314, L2332 — ESLint-Warnungen und toter i18n-Schlüssel im AP (Sammelfinding)
**Urteil:** BESTÄTIGT (Severity unverändert S4)
**Beleg:** `npx eslint server.js` im Bereich L1374-2399: `1944:12 warning 'e' is defined but never used`, `1969:12 warning 'e' is defined but never used`. `consent.noIdentity` ist nur definiert (L2314 DE, L2332 EN); `t('consent.…')`-Aufrufe im Skript: nur `processing`, `errorPrefix`, `allow` (L2218, L2296, L2298); fehlende Identität führt direkt zu `relogin()` (L2231-2232).
**Auswirkung:** Lint-Rauschen; toter Übersetzungstext.
**Empfehlung:** `catch {` ohne Binding; `consent.noIdentity` entfernen.

## Verworfen
- AP2-12 [S4] [Korrektheit] server/server.js:L1545, L1615 — `/oauth/approve` akzeptiert HHTTPS-Refresh-Tokens (`sub:'refresh'`), die kein `roleLevel` tragen → `verification_method = NULL` → VERWORFEN: Die Annahme (Refresh-Token wird von `checkTokenValid` durchgelassen, L704-706) stimmt, Repro: `APPROVE with refresh token: 200`. Die behauptete Auswirkung (abweichende `verification_method`-Claims je nach eingereichtem Token) ist im aktuellen Stand aber nicht erreichbar: alle vier `issueAccessToken`-Aufrufer setzen `roleLevel: null` (L2632, L3172, L3345, L3551), d. h. auch das HHTTPS-Access-Token hat kein `roleLevel`, und `/approve` schreibt in beiden Fällen `verification_method = NULL` (L1615). Repro: `id_token verification_method: null` mit Refresh-Token und ebenso `null` mit Access-Token. Dass `/approve` Refresh-Tokens akzeptiert, bleibt ein Design-Smell, ist aber ohne beobachtbare Folge; bei einer späteren Wiedereinführung von `roleLevel` ist der Punkt neu zu bewerten.

## Zusammengeführt
- AP2-05 [K-5, `/authorize` `scope`-Array → Hang] → in AP2-04 (gleiche Ursache: fehlende String-Typprüfung + async-Handler ohne Fehlerbehandlung; gleicher Fix).
- AP2-13 [S-1, Refresh-Grant ignoriert Plattform-Trennung] → in AP2-01 (identischer Befund; Zusatzempfehlungen — Maximallebensdauer, Claims neu bilden — übernommen).
- AP2-16 [S-4, Nicht-String-Parameter → hängende Requests] → in AP2-04 (identisch; DoS-Aspekt übernommen).
- AP2-17 [S-5, `/userinfo` akzeptiert Refresh-JWT] → in AP2-10 (identisch; Repro und Severity-Begründung übernommen, AP2-10 auf S3 hochgestuft).
- AP2-18 [S-6, `revocation_endpoint` nicht RFC 7009 + Maschinen-No-op] → in AP2-02 (identisch; Maschinen-user_id-Mismatch übernommen).
- AP2-19 [S-7, `auth_time`] → in AP2-09 (identisch).
- AP2-27 [P-5, Google Fonts render-blockend] → in AP2-22 (gleiche Zeilen L2020-2022, gleicher Fix; Performance-Aspekt übernommen).
- AP2-32 [W-5, hart kodiertes `https://hhttps.org`] → in AP2-07 (identisch; die drei weiteren Literale L1987/L2115/L2146 übernommen).
- AP2-35 [W-8, `/revoke` als `revocation_endpoint`] → in AP2-02 (identisch; Doku-Lücke übernommen).
- AP2-36 [W-9, Test-Lücken] → in AP2-08 (überlappende Fallliste; Korrektur: Maschinen-Pfad ist in acceptance.test.mjs L443 getestet).
- AP2-38 [W-11, `PAIRWISE_SECRET` pro Aufruf gelesen, stiller Fallback] → in AP2-15 (gleiche Ursache, gleicher Fix).
- AP2-42 [W-15, `plain`-Default vs. OAuth-2.1-Bezeichnung] → in AP2-14 (gleiche Zeilen L1387/L1608; Doku-Empfehlung übernommen).

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit (K) | 12 | 10 | 1 | 1 |
| Sicherheit (S) | 10 | 5 | 0 | 5 |
| Performance (P) | 5 | 4 | 0 | 1 |
| Wartbarkeit (W) | 15 | 10 | 0 | 5 |
| **Gesamt** | **42** | **29** | **1** | **12** |

Bestätigt je Severity: S1 0, S2 2 (AP2-01, AP2-23), S3 14 (AP2-02, -03, -04, -07, -08, -10, -15, -24, -28, -29, -30, -31, -33, -34), S4 13 (AP2-06, -09, -11, -14, -20, -21, -22, -25, -26, -37, -39, -40, -41).

Severity-Änderungen: AP2-06 S3→S4 (nur mit eigenem Nutzer-Token ausnutzbar), AP2-10 S4→S3 (Repro: rotierter Refresh-JWT liefert 30 Tage lang E-Mail via `/userinfo`), AP2-14 S3→S4 (RFC-7636-konform, Härtung), AP2-25 S3→S4 (nur zwei Writes, Lock pro Client).

# AP2 — Korrektheit

Geprüfte Dateien: server/server.js L1374–2399 (openid-configuration, pairwiseSubjectId, /hhttps/oauth/authorize, /approve, /token, /userinfo, /revoke, redirectWithError, renderOAuthError, renderConsentPage inkl. Browser-JS, escapeHtml); server/oauth-params.js; server/identity.js (buildIdentityClaims, methodFlags); server/test/integration/oauth-claims.test.mjs, oauth-params.test.mjs, login-hint.test.mjs; server/test/unit/consent-page.test.mjs. Zum Verständnis gelesen (keine Findings): server/db.js (authCodes, refreshTokens, revokedTokens, oauthClients, connectedPlatforms, identityClaimsCache), server/keys.js (signToken/verifyToken), server/server.js L640–712 (issueAccessToken, checkTokenValid), L2606ff (/hhttps/token/refresh), server/sql/migration-phase-3a.sql, server/public/index.html (publishIdentity), server/test/integration/acceptance.test.mjs.

Stand: `main` @ `bf0a82b`. Zeilennummern per `grep -n` im aktuellen Stand geprüft.

---

### [S2] [Korrektheit] server/server.js:L1652-1690 — `/oauth/revoke` trennt die Plattform nur in `connected_platforms`; der 30-Tage-OAuth-Refresh-Token bleibt gültig und der Refresh-Grant prüft weder `revoked_tokens` noch `connected_platforms.revoked_at`.
**Begründung:** `/hhttps/oauth/revoke` (L1950-1958) ruft nur `db.connectedPlatforms.revoke(userId, client_id)` auf, das `revoked_at = NOW()` setzt (db.js L1300-1306). Der Refresh-Grant (L1652-1690) verifiziert die Signatur, prüft `rd.client_id === client_id` und `db.refreshTokens.get(rd.jti)` — sonst nichts. Die Zeile in `refresh_tokens` trägt keine `client_id` (schema.sql L81-89), es gibt also auch keinen Weg, die OAuth-Refresh-Tokens einer (user, client)-Verbindung gezielt zu löschen. Zusätzlich setzt `db.connectedPlatforms.record` beim nächsten `/token`-Aufruf `revoked_at = NULL` (db.js L1280).
**Auswirkung:** Nach „Verbindung widerrufen“ kann die Plattform bis zu 30 Tage weiter frische Access-Tokens (inkl. `email`, `preferred_username`, `verified_methods`) minten; die UI („my logins“) zeigt die Verbindung als widerrufen — inkonsistenter Zustand zwischen `connected_platforms` und `refresh_tokens`, Datenschutzverstoß gegenüber dem dokumentierten Widerruf.
**Empfehlung:** Im Refresh-Grant zusätzlich `db.revokedTokens.has(rd.jti)` und den Zustand von `connected_platforms(user_id, client_id).revoked_at IS NULL` prüfen; in `/oauth/revoke` alle OAuth-Refresh-Tokens des Paares (user, client) entwerten (z. B. `client_id`-Spalte auf `refresh_tokens` oder `revoked_tokens`-Einträge). Test: revoke → refresh_token grant muss `invalid_grant` liefern.

### [S3] [Korrektheit] server/server.js:L1380,L1950-1958 — Discovery bewirbt `/hhttps/oauth/revoke` als `revocation_endpoint`, die Route implementiert aber nicht RFC 7009 (erwartet ein HHTTPS-Session-Token statt des OAuth-Tokens).
**Begründung:** `openid-configuration` L1380 nennt `revocation_endpoint: ${BASE_URL}/hhttps/oauth/revoke`. Ein RFC-7009-Client sendet `token=<access|refresh_token>` (+ Client-Auth). Die Route ruft `checkTokenValid(token)` (L1955) auf: OAuth-Access-Tokens haben kein `jti` → `db.tokens.exists(undefined)` → „Token nicht aktiv“ → 401; OAuth-Refresh-JWTs haben `sub: 'oauth_refresh'` → `db.tokens.exists(jti)` → 401. Nur ein HHTTPS-Nutzer-Token (Sub `human-verified`/`refresh`) kommt durch; `client_id` ist Pflicht, aber der Client wird nicht authentifiziert.
**Auswirkung:** Standard-OIDC-Bibliotheken, die den beworbenen Endpoint nutzen, erhalten immer 401; Plattformen können ihre eigenen Refresh-Tokens gar nicht widerrufen. Inkonsistenz Route ↔ Discovery.
**Empfehlung:** Entweder `revocation_endpoint` aus der Discovery entfernen oder die Route RFC-7009-konform machen (Token-Typ per `token_type_hint`/`sub` erkennen, `refresh_tokens.delete(jti)` bzw. `revokedTokens.add`, Client-Auth wie beim Token-Endpoint, immer 200).

### [S3] [Korrektheit] server/server.js:L1672-1690 — Refresh-Token-Rotation ist ein nicht-atomares Check-then-Act; zwei gleichzeitige Refreshs mit demselben Token liefern zwei gültige neue Refresh-Tokens.
**Begründung:** `const active = await db.refreshTokens.get(rd.jti)` (L1672) und `db.refreshTokens.delete(rd.jti)` (L1686) laufen ohne Transaktion und ohne bedingtes `DELETE … RETURNING`. Treffen zwei Requests parallel ein, sehen beide `active`, beide legen `newJti` an, beide löschen die alte Zeile (zweites DELETE ist ein No-op) und beide erhalten 200 mit je einem neuen, 30 Tage gültigen Refresh-Token.
**Auswirkung:** Die „Rotation“ garantiert keine Single-Use-Semantik; ein gestohlener Refresh-Token kann parallel zum legitimen Client verwendet werden, ohne dass eine Wiederverwendung erkannt wird (RFC 6819 §5.2.2.3 Replay-Detection greift nicht). Der Code-Endpoint löst dasselbe Problem korrekt (atomarer `claim`, db.js L1245-1263).
**Empfehlung:** Rotation als eine Anweisung: `DELETE FROM refresh_tokens WHERE jti=$1 AND expires_at > NOW() RETURNING *` — nur bei einer zurückgegebenen Zeile den neuen Token anlegen; sonst `invalid_grant`.

### [S3] [Korrektheit] server/server.js:L1641-1907 — `/oauth/token` läuft ohne try/catch; nicht-string `client_secret`/`code_verifier` oder ein DB-Fehler nach dem Claim führen zu einer unbeantworteten Anfrage, der Code ist dann verbraucht.
**Begründung:** `crypto.createHash('sha256').update(client_secret)` (L1661, L1752) und `.update(code_verifier)` (L1775) werfen `ERR_INVALID_ARG_TYPE`, wenn der JSON-Body z. B. `{"client_secret": 123}` oder `{"code_verifier": {}}` enthält. Der Handler ist `async` unter Express 4 (package.json: `^4.18.2`); die Rejection landet nur im globalen `process.on('unhandledRejection')`-Logger (L4824), es wird keine Antwort gesendet. Ebenso bleibt jeder Fehler von `db.connectedPlatforms.record` (L1788), `db.stats.increment` (L1860/1861) nach `db.authCodes.claim(code)` (L1759) unbehandelt — der Code ist zu diesem Zeitpunkt bereits single-use verbraucht.
**Auswirkung:** Die Client-Verbindung hängt bis zum Timeout (kein 4xx/5xx), bei `code_verifier`-Typfehler ist der Authorization-Code zusätzlich verloren (Login schlägt fehl, Nutzer muss neu autorisieren). Vergleich: `/approve` (L1551-1638) hat das Muster mit 500 `server_error` korrekt umgesetzt.
**Empfehlung:** Für `client_secret`, `code_verifier`, `code`, `redirect_uri`, `refresh_token` `typeof === 'string'` erzwingen (sonst 400 `invalid_request`) und den Handler-Body in try/catch mit 500 `server_error` einschließen (wie in `/approve`).

### [S3] [Korrektheit] server/server.js:L1479 — `/oauth/authorize` wirft bei `scope` als Array (`?scope=openid&scope=email`) einen TypeError; die Anfrage bleibt unbeantwortet.
**Begründung:** Express/qs liefert für wiederholte Query-Parameter ein Array. `validateAuthorizeParams` prüft nur `state`/`nonce`/`code_challenge*` auf String-Typ (oauth-params.js L23-28, L37-49), `scope` nicht. `(scope || 'openid').split(/\s+/)` (L1479) → `TypeError: scope.split is not a function` im `async`-Handler → unhandledRejection (L4824), keine Antwort, kein Redirect.
**Auswirkung:** Ein leicht fehlkonfigurierter Client (doppelter Scope-Parameter) oder ein simpler Aufruf lässt die Browser-Anfrage hängen statt `invalid_request`/`invalid_scope` an die `redirect_uri` zu liefern.
**Empfehlung:** `typeof scope === 'string'` prüfen und andernfalls `redirectWithError(..., 'invalid_request', 'scope must be a single string')`; gleiches Muster in `/approve` (L1561: nicht-string `scope` führt dort zu 500 statt 400).

### [S3] [Korrektheit] server/server.js:L1552-1575 — `/oauth/approve` erzwingt für Public Clients keinen `code_challenge`, obwohl `/oauth/authorize` das tut (L1472-1475); die PKCE-Pflicht kann durch direkten Approve-Aufruf umgangen werden.
**Begründung:** F-8 hat die Scope-Policy von `/authorize` nach `/approve` gespiegelt (L1564-1575), die PKCE-Regel `isPublicClient && !code_challenge` fehlt in `/approve`. Der Consent-Client-JS sendet ohnehin nur die Parameter aus der URL, aber `/approve` ist eine öffentliche JSON-API (Tests rufen sie direkt auf). Ohne `code_challenge` wird der Code mit `pkce_challenge = NULL` gespeichert, und `/token` überspringt die PKCE-Prüfung (L1769: `if (claimed.pkce_challenge)`).
**Auswirkung:** Für Public Clients (kein Secret) entsteht ein Authorization-Code, den jeder mit `code` + `client_id` + `redirect_uri` einlösen kann — genau der Fall, gegen den PKCE für Public Clients Pflicht ist (OAuth 2.1 §7.5.1). Inkonsistente Regel zwischen zwei Endpunkten desselben Flows.
**Empfehlung:** In `/approve` nach dem Client-Lookup `if (!client.client_secret_hash && !code_challenge) return res.status(400).json({ error: 'invalid_request', error_description: 'PKCE code_challenge is required for public clients.' })` ergänzen; Test analog zu #31 (d).

### [S3] [Korrektheit] server/server.js:L2179,L2198 — Consent-Seiten-JS verweist hart auf `https://hhttps.org` (Relogin, Token-Refresh) statt auf die eigene Origin/`BASE_URL`.
**Begründung:** `relogin()` baut `'https://hhttps.org/?returnTo=' + …` (L2179) und `tryRefresh()` ruft `fetch('https://hhttps.org/hhttps/token/refresh', …)` (L2198). Alle anderen Server-URLs werden aus `BASE_URL`/`RP_ID` gebildet (Discovery L1376-1381), und der `/approve`-Aufruf im selben Script ist relativ (`fetch('/hhttps/oauth/approve')`, L2248).
**Auswirkung:** Auf Staging/Test-Instanzen (anderes `BASE_URL`) leitet „Erlauben“ ohne Identität zur Produktions-Anmeldung um und kehrt mit einem Produktions-Token zur Staging-Consent-Seite zurück (Signatur passt nicht → 401 → erneut Relogin-Schleife); der Refresh-Fetch ist cross-origin und scheitert an CORS, sodass `tryRefresh` immer `null` liefert und ein abgelaufenes Token stets in einen Relogin läuft, obwohl der Refresh-Token gültig wäre.
**Empfehlung:** Origin serverseitig in die Seite geben (`${escapeHtml(BASE_URL)}` bzw. `JSON.stringify(BASE_URL)`) oder `window.location.origin` verwenden.

### [S3] [Korrektheit] server/test/integration/oauth-claims.test.mjs, oauth-params.test.mjs, acceptance.test.mjs — Fehlerpfade von `/oauth/token`, `/oauth/revoke` und der Refresh-Grant-Bindung sind ungetestet.
**Begründung:** Die vorhandenen Tests decken nur den Happy Path von `/token` (oauth-claims L78-96, L179-205; acceptance L119ff) sowie Parameter-Validierung von `/authorize`/`/approve` ab. Ohne Test sind konkret: (a) Code-Wiederverwendung → `invalid_grant` (L1760), (b) falscher `code_verifier`/S256-Mismatch (L1770-1781), (c) `client_id`-/`redirect_uri`-Mismatch beim Einlösen (L1761-1766), (d) Refresh-Grant mit fremder `client_id` (L1669) bzw. mit bereits rotiertem Token (L1672), (e) `/oauth/revoke` überhaupt (L1950-1958), (f) `/userinfo` mit abgelaufenem/fremdem Token (L1912-1948), (g) Confidential Client mit falschem `client_secret` (L1750-1757).
**Auswirkung:** Die sicherheitsrelevanten Verzweigungen des Token-Endpoints (Single-Use, PKCE, Client-Bindung) sind nicht gegen Regressionen abgesichert; die Findings oben (Revoke-Inkonsistenz, Rotations-Race, PKCE-Lücke in `/approve`) wären mit solchen Tests aufgefallen.
**Empfehlung:** Eine `oauth-token-errors.test.mjs` mit den sieben Fällen anlegen (Harness aus oauth-params.test.mjs wiederverwenden); für das Race einen Test mit `Promise.all` zweier Refreshs auf denselben Token (genau eine 200).

### [S4] [Korrektheit] server/server.js:L1840 — `auth_time` im ID-Token ist der Zeitpunkt des Code-Einlösens, nicht der Authentifizierung.
**Begründung:** `auth_time: Math.floor(Date.now() / 1000)` wird beim `/token`-Aufruf berechnet. Die tatsächliche Authentifizierungszeit liegt im HHTTPS-Token (`iat`), das `/approve` (L1545) geprüft hat, wird aber nicht in die Code-Zeile übernommen.
**Auswirkung:** Clients, die `max_age`/`auth_time` auswerten, erhalten einen zu jungen Wert (Sitzung kann Stunden alt sein). Die Discovery listet `auth_time` als unterstützten Claim (L1390).
**Empfehlung:** `d.iat` in `/approve` in die Code-Zeile schreiben (Spalte `auth_time`) und in `/token` daraus setzen; alternativ den Claim aus `claims_supported` streichen.

### [S4] [Korrektheit] server/server.js:L1918-1921 — `/oauth/userinfo` akzeptiert jedes serversignierte JWT mit `client_id`-Claim, also auch den OAuth-Refresh-JWT (`sub: 'oauth_refresh'`).
**Begründung:** Die Prüfung ist nur `verifyToken(token)` + `if (!d.client_id)`. Der Refresh-JWT (L1887-1896) trägt `client_id`, `scope`, `verified_methods`, `preferred_username`, `email` und ist 30 Tage gültig. Er wird ohne `aud`-/Typ-Prüfung akzeptiert; die Antwort enthält dann `sub: 'oauth_refresh'` statt der pairwise-ID.
**Auswirkung:** Falsche Typannahme; ein Client, der versehentlich den Refresh-Token als Bearer sendet, bekommt 200 mit unbrauchbarem `sub` statt 401 `invalid_token`; die Access-Token-TTL von 5 min (L1369) wird für `/userinfo` faktisch auf 30 Tage ausgedehnt.
**Empfehlung:** `if (d.sub === 'oauth_refresh' || !d.aud) return 401` bzw. Access-Tokens mit `typ`/`token_use: 'access'` markieren und darauf prüfen.

### [S4] [Korrektheit] server/server.js:L1376-1381 — `issuer` wird aus `RP_ID`, alle Endpunkte aus `BASE_URL` gebildet; bei abweichendem `BASE_URL` stimmt die Discovery nicht mit dem Issuer überein.
**Begründung:** `issuer: https://${RP_ID}` (L1376) vs. `authorization_endpoint: ${BASE_URL}/…` (L1377ff). `BASE_URL` ist per Env frei setzbar (L78). OIDC Discovery 1.0 §4.3 verlangt, dass das Dokument unter `{issuer}/.well-known/openid-configuration` liegt und `iss` in ID-Tokens exakt `issuer` entspricht.
**Auswirkung:** Auf Instanzen mit `BASE_URL ≠ https://RP_ID` (Staging, lokaler Test mit `http://localhost:PORT`) lehnen strikte OIDC-Bibliotheken (z. B. openid-client) die Discovery wegen Issuer-Mismatch ab.
**Empfehlung:** `issuer` ebenfalls aus `BASE_URL` (bzw. `ORIGIN`) ableiten und in `signToken`-Aufrufen (L1810, L1836) dieselbe Konstante verwenden.

### [S4] [Korrektheit] server/server.js:L1545,L1615 — `/oauth/approve` akzeptiert über `checkTokenValid` auch HHTTPS-Refresh-Tokens (`sub: 'refresh'`); diese haben kein `roleLevel`, der Code erhält dann `verification_method = NULL`.
**Begründung:** `checkTokenValid` (L702-711) lässt `sub === 'refresh'` durch, wenn die jti in `refresh_tokens` aktiv ist. `issueRefreshToken` (L680-700) setzt `role`, `verified_methods`, `pseudonym`, aber kein `roleLevel`; `/approve` schreibt `verificationMethod: … (d.roleLevel || null)` (L1615). Die Consent-Seite sendet zwar `identity.token`, die API ist aber direkt erreichbar.
**Auswirkung:** Je nachdem, welches der beiden Nutzer-Tokens eingereicht wird, unterscheiden sich `verification_method`/`verification_method_label` im ID-Token für denselben Nutzer — inkonsistente Claims.
**Empfehlung:** In `/approve` `d.sub === 'refresh'` ablehnen (401 „access token required“) oder `roleLevel` auch in den Refresh-Token aufnehmen.

---

## Zusammenfassung

- S1: 0
- S2: 1
- S3: 7
- S4: 4

Gesamteindruck: Der Happy Path des Code-Flows ist sauber (atomarer Single-Use-Claim, Scope-Policy an beiden Endpunkten, E-Mail-Wipe nach Transfer, validierte Parameter nach #31). Die Schwächen liegen im Lebenszyklus der Refresh-Tokens: Widerruf einer Plattform erreicht den Refresh-Grant nicht, die Rotation ist nicht atomar, und der beworbene Revocation-Endpoint ist kein RFC-7009-Endpoint. Dazu kommen fehlende Typ-Absicherung in `/token` und `/authorize` (hängende Requests statt 400) und eine Lücke in der PKCE-Pflicht auf `/approve`; die Testabdeckung der Fehlerpfade des Token-Endpoints fehlt fast vollständig.

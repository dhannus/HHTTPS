# AP4 — Korrektheit

Geprüfte Dateien: server/server.js L3097–3767 (`/hhttps/role/declare`, `/hhttps/age/upgrade`, `/hhttps/age/direct`, `/hhttps/eid/upgrade`, `/hhttps/role/card`, `/hhttps/revoke`, `/hhttps/revoke/status`, `/hhttps/validate`, `/hhttps/protected`); server/external-verify.js; server/eudi-verifier/index.js; server/eudi-verifier/backend-client.js; server/eudi-verifier/errors.js; server/eudi-verifier/docker/docker-compose.yaml; server/public/iamhmn-card-issuer.js. Zum Verständnis gelesen (keine Findings): server/db.js (sessions/tokens/refreshTokens/revokedTokens), server/roles.js, server/roles.taxonomy.js, server/identity.js (methodFlags), server/keys.js (verifyToken), server/server.js L415–730 (limit, setHHTPPS, issueAccessToken, issueRefreshToken, checkTokenValid), L2400–2410 (tokenSurface), L2605–2655 (token/refresh), L3840–3872 (machine/token), server/test/**.

---

### [S2] [Korrektheit] server/server.js:L3719-3741 — `/hhttps/validate` bestätigt Maschinen- und Refresh-Tokens als „valid · human:true · actorType:human“
**Begründung:** `checkTokenValid` (L702–711) prüft nur Signatur, Revocation und Existenz in `tokens` bzw. `refresh_tokens`; es prüft weder `sub` noch `human`/`actorType`. Maschinen-Tokens werden mit `sub:'machine', human:false, actorType:'bot'` signiert und ebenfalls in `db.tokens` abgelegt (L3852–3870). Refresh-Tokens (`sub:'refresh'`) werden über `db.refreshTokens.get` akzeptiert. Der Handler antwortet danach unbedingt:
```js
setHHTPPS(res, { status: 'valid', human: true, actorType: 'human', role: d.role, ... });
res.json({ hhttps: { status: 'valid', human: true, actorType: 'human', ... }, claims: {...} });
```
Ein Bot-Token wird damit von der Validierungs-API als menschlich verifiziert ausgewiesen; die Claims `human:false`/`actorType:'bot'` aus dem Token werden überschrieben. Gleiches Muster in `/hhttps/protected` L3753–3760 (`status:'verified', human:true` für jedes gültige Token, Refresh-Token inklusive).
**Auswirkung:** Relying Parties, die `/hhttps/validate` als Server-seitige Prüfung nutzen (laut sites/spec.html das vorgesehene Verfahren), bekommen für Maschinen-Tokens und für Refresh-Tokens (die nie als Zugriffs-Credential gedacht sind) eine positive Human-Bestätigung — die zentrale Zusicherung des Protokolls („human-verified“) ist über diese Route falsch.
**Empfehlung:** In `/hhttps/validate` und `/hhttps/protected` `d.sub === 'human-verified'` (bzw. `d.human === true && d.actorType === 'human'`) verlangen und Refresh-/Maschinen-Tokens mit 401 bzw. mit `human:false, actorType:d.actorType` beantworten; `human`/`actorType` aus dem Token durchreichen statt hart zu setzen.

### [S2] [Korrektheit] server/server.js:L3341-3362 — `/hhttps/age/upgrade` reissued Access- und Refresh-Token ohne `pseudonym` und ohne `*_verified`-Methodenflags; Alter überlebt den Refresh nicht
**Begründung:** Anders als `/hhttps/role/declare` (L3168–3181, nutzt `tokenSurface(session, v, pseudonym)`) und `/hhttps/eid/upgrade` (L3547–3563, `tokenSurface(session, v)` + `pseudonym: session.pseudonym`) baut der Age-Upgrade die Claims von Hand:
```js
verified_methods: v.methods, verification_status: 'verified',
...(session.emailDomain ? { domain_name: session.emailDomain } : {}),
...(priorEudi ? { eudi_verified: true } : {}),
```
Es fehlen `email_verified`/`passkey_verified`/`github_verified` (methodFlags) und `pseudonym` (AK-8/AK-9: stabiles Account-Pseudonym im Token). Der Refresh-Token (L3360–3362) wird ebenfalls ohne `pseudonym` ausgestellt; `/hhttps/token/refresh` (L2626) liest das Pseudonym ausschließlich aus dem Refresh-Token. Zusätzlich behauptet der Kommentar L3358 „so the upgraded surface survives the 1h access-token expiry“, aber `issueRefreshToken` (L680–700) kennt keine Age-Claims: nach dem Refresh enthält `verified_methods` zwar `'age'`, `age_group`/`age_verified`/`age_verification_method` sind jedoch weg.
**Auswirkung:** Nach einer EUDI-Altersverifikation verliert die Identität dauerhaft ihr Pseudonym (auch für OAuth `preferred_username`) und die Methodenflags; nach spätestens 1 h ist die verifizierte Altersangabe wieder weg, während `verified_methods` weiter „age“ meldet — inkonsistenter Token-Zustand. Die Tests decken nur den 403-Pfad (acceptance.test.mjs L540–551), nicht den Erfolgspfad ab.
**Empfehlung:** `...tokenSurface(session, v)` verwenden (wie eid/upgrade), `pseudonym: session.pseudonym` an `issueRefreshToken` geben und die Age-Claims in den Refresh-Token aufnehmen (und in `/hhttps/token/refresh` übernehmen); Integrationstest für den 200-Pfad ergänzen (Token-Claims prüfen).

### [S3] [Korrektheit] server/server.js:L3678-3707 — `/hhttps/revoke` widerruft nur das übergebene Token; der zugehörige Refresh-Token bleibt gültig und die Antwort behauptet vollständige Abmeldung
**Begründung:** Access- und Refresh-Token haben verschiedene `jti` ohne Verknüpfung. Bei Übergabe des Access-Tokens greifen `db.tokens.delete(decoded.jti)` und `db.refreshTokens.delete(decoded.jti)` (L3685–3686) nur auf dessen jti; der bei `role/declare` parallel ausgestellte Refresh-Token (7 Tage) bleibt in `refresh_tokens` aktiv und wird von `/hhttps/token/refresh` (L2611–2616) weiterhin akzeptiert. Trotzdem antwortet der Handler `status:'revoked'` und löscht das Identity-Cookie.
**Auswirkung:** Ein Nutzer, der „revoke“ auslöst (oder ein Betreiber, der ein kompromittiertes Access-Token zurückzieht), erhält mit dem noch gültigen Refresh-Token sofort ein neues Access-Token — der Widerruf ist praktisch wirkungslos, obwohl Status/Response Erfolg melden.
**Empfehlung:** Bei Revoke eines Access-Tokens alle Refresh-Tokens desselben `userId` (bzw. der Session) mit-löschen/-sperren, oder die Paar-Beziehung (`refresh_jti` im Access-Token bzw. `access_jti` in `refresh_tokens`) persistieren und beide widerrufen; API-Doku entsprechend präzisieren.

### [S3] [Korrektheit] server/server.js:L3683-3705 — `/hhttps/revoke`: Fehlerpfad mit Nebenwirkungen und irreführender Antwort bei Tokens ohne `jti` / mit ungültiger Signatur
**Begründung:** (a) `decoded.jti.slice(0, 8)` (L3689) wirft `TypeError`, wenn ein signaturgültiges Token kein `jti` trägt (z. B. ID-Token L1858, Signatur-Token L975). Der `catch` läuft dann in den „expired“-Fallback und antwortet 401 mit `Cannot read properties of undefined` — obwohl `db.revokedTokens.add(undefined, …)` zuvor bereits versucht wurde (NOT-NULL-Fehler, ebenfalls gefangen). (b) Der Fallback (L3696–3704) reagiert auf *jeden* Verifikationsfehler — auch „invalid signature“ — und schreibt `raw.jti` unverifiziert nach `revoked_tokens`, antwortet aber 401 `error: e.message`. Ein Client kann so nicht unterscheiden, ob widerrufen wurde oder nicht.
**Auswirkung:** Inkonsistente Semantik (401 mit erfolgtem Widerruf; 401 statt 400 bei falschem Token-Typ), und ein Token ohne jti wird als „ungültig“ statt „nicht widerrufbar“ gemeldet.
**Empfehlung:** Fehler von `verifyToken` differenzieren (`TokenExpiredError` → Fallback mit 200 `{revoked:true, note:'expired'}`; alle anderen → 400/401 ohne DB-Schreibzugriff); vor dem Widerruf `if (!decoded.jti) return 400`.

### [S3] [Korrektheit] server/server.js:L3097-3230 — `/hhttps/role/declare` und L3709-3715 `/hhttps/revoke/status` ohne try/catch: DB-Fehler oder Array-Query lassen die Anfrage ohne Antwort hängen
**Begründung:** Beide Handler sind `async` ohne `try/catch`; Express 4 fängt abgewiesene Promises nicht. `process.on('unhandledRejection')` (L4824) loggt nur. Konkrete Auslöser: `?jti=a&jti=b` macht `req.query.jti` zu einem Array → `pg` wirft bei `$1` („invalid input syntax“/Serialisierung) in `db.revokedTokens.has` (L3712); in `role/declare` jede pg-Störung in `db.sessions.get`/`issueAccessToken`/`db.sessions.update` (L3099, L3168, L3179, L3188). Alle anderen Handler des AP (age/eid/card/revoke/validate) haben ein try/catch.
**Auswirkung:** Der Client bekommt keine Antwort (Timeout statt 5xx), der Rate-Limiter zählt den Request, Verbindungen bleiben offen.
**Empfehlung:** try/catch mit `res.status(500).json(...)` ergänzen (bzw. ein globaler `express-async`-Wrapper/Error-Middleware) und `jti` per `String()`/Typ-Check normalisieren.

### [S3] [Korrektheit] server/server.js:L3598-3607 — `/hhttps/role/card` umgeht die E-Mail-Pflicht (AK-13) und dokumentiert das mit einem falschen Verweis auf `role/declare`
**Begründung:** Der Kommentar sagt „consistent with /hhttps/role/declare“, aber `role/declare` erzwingt `requireEmailVerified` (L3102), `role/card` nur
```js
const hasMethod = !!(session.emailVerified || session.hasPasskey || session.credentialId
                     || session.githubVerified || session.eudiVerified);
```
`session.hasPasskey` und `session.eudiVerified` existieren in `sessions._normalize` (db.js L211–232) nicht (immer `undefined`); eine Session mit nur `credentialId` oder nur `githubVerified` reicht aus. Alle anderen Ausstellungspfade (declare, age/upgrade, eid/upgrade, webauthn/register) verlangen die bestätigte E-Mail.
**Auswirkung:** Eine iamhmn-Card (mit `userId` und `issuer: hhttps://…`) wird für Sessions ausgestellt, die laut Sicherheitsmodell noch keine Identität haben; das Gate-Modell ist über die Routen inkonsistent.
**Empfehlung:** `if (!requireEmailVerified(session, res)) return;` wie in `role/declare` einsetzen und die toten Felder `hasPasskey`/`eudiVerified` entfernen (oder in `_normalize` einführen).

### [S3] [Korrektheit] server/server.js:L3600,L3635-3637 — `documentProvided` wird nur auf Truthiness geprüft; `human`-Claim der Karte widerspricht dem Zugangs-Gate
**Begründung:** `documentProvided` kommt roh aus `req.body`; `"false"`, `"0"`, `{}` sind truthy → `method:'document-checked'`, `verificationStatus:'verified'` → RAL 1. Gleichzeitig wird `humanVerified = !!(session.hasPasskey || session.credentialId)` nur aus dem Passkey abgeleitet: eine E-Mail-verifizierte Session ohne Passkey bekommt eine Karte mit `human:'false'` (stringifiziert in backend-client L463–470), obwohl der Handler sie als „verified method“ zugelassen hat und `role/declare` E-Mail als vollwertige Human-Methode zählt.
**Auswirkung:** RAL 1 durch beliebige Nicht-Booleans; Kartenclaim `human` ist für den Normalfall (E-Mail-first) systematisch falsch.
**Empfehlung:** `documentProvided === true` prüfen; `humanVerified` aus `computeVerification(flags).methods.length > 0` (oder aus `session.emailVerified`) ableiten.

### [S3] [Korrektheit] server/eudi-verifier/index.js:L232-267,L327-364,L408-431 — Status-Polling ohne In-Flight-Sperre: parallele Polls lösen den Upgrade mehrfach aus
**Begründung:** Das Frontend pollt alle ~2 s. `tx.status` wird erst *nach* dem `await callAgeUpgrade(...)`/`callEidUpgrade(...)` auf `'verified'` gesetzt (L261–262, L355–359, L425–426). Dauert der Round-Trip (EUDIPLO-Poll + interner Upgrade inkl. zweier DB-Inserts) länger als das Poll-Intervall, sehen zwei Requests `status:'pending'`, beide erhalten vom Backend `done` und rufen den Upgrade auf; es werden zwei Access- und zwei Refresh-Tokens ausgestellt, `stats.age_verifications`/`eudi_verifications` doppelt gezählt, `fireEvent` doppelt gefeuert; der Browser bekommt zwei verschiedene Tokens/Cookies.
**Auswirkung:** Doppelte Token-Ausstellung und Ereignisse pro Verifikation; welches Token im Cookie landet, hängt von der Antwortreihenfolge ab.
**Empfehlung:** Vor dem Backend-Poll `tx.status = 'upgrading'` (oder ein `tx.inflight`-Promise) setzen und Nachfolger daran hängen bzw. mit `pending` antworten; bei Fehler zurücksetzen.

### [S3] [Korrektheit] server/eudi-verifier/backend-client.js:L352-360,L388-395 — Nur Erfolgs-Status werden als terminal erkannt; Fehl-/Ablaufzustände und 404 bleiben bis zum 10-Minuten-TTL „pending“
**Begründung:** `TERMINAL = ['verified','completed','success','valid','done','submitted']`; jeder andere Status (z. B. `failed`, `rejected`, `expired`, `error`, `cancelled`) fällt in `return { status: 'pending' }` (L395). Ein 404 der Session (L388) wird ebenfalls als `pending` gewertet, obwohl die Transaktion bei EUDIPLO nicht (mehr) existiert. `index.js` gibt den Zustand 1:1 an den Browser weiter.
**Auswirkung:** Bei einem vom Wallet abgebrochenen oder vom Verifier abgelehnten Präsentationsversuch dreht die UI bis `TX_TTL_MS` (10 min) leer, statt `failed` zu melden; ein Neustart ist für den Nutzer nicht erkennbar.
**Empfehlung:** Bekannte Fehlstatus als terminal-negativ behandeln (`{ status:'failed', reason }`), 404 nach dem ersten erfolgreichen Poll als `failed` werten, und den Status-String im Debug-Log/Response sichtbar machen.

### [S3] [Korrektheit] server/eudi-verifier/backend-client.js:L61-83 — Token-Cache ohne Invalidierung bei 401: nach Token-Verlust auf EUDIPLO-Seite scheitern alle Aufrufe bis zu 24 h
**Begründung:** `getToken` erneuert nur zeitgesteuert (`expiresAt - 60_000`, Default 86 400 s). `authed()` (L85–92) reicht 401/403 einfach als `!r.ok` an die Aufrufer weiter, die daraus `Error('… offer failed (401)')` machen; der ungültige Token bleibt gecacht. Auslöser: Neustart/Secret-Rotation von EUDIPLO, kürzere serverseitige Gültigkeit als `expires_in`.
**Auswirkung:** Age-/eID-/Card-Flows sind bis zum Node-Neustart oder Cache-Ablauf komplett gestört (502 „EU verifier backend unavailable“).
**Empfehlung:** In `authed()` bei 401 den Cache leeren (`tokenCache = {value:null, expiresAt:0}`) und den Request einmal wiederholen.

### [S3] [Korrektheit] server/external-verify.js:L102-116,L211-232 — Anchor-Kollision: der GitHub-Anker wird auf den neuen Nutzer umgebunden, *bevor* der Aufrufer „entscheiden“ kann
**Begründung:** `handleGithubCallback` liest `alreadyOwnedBy` (L213–218) und ruft dann `recordAnchor`, dessen `ON CONFLICT … DO UPDATE SET user_id = EXCLUDED.user_id` (L110–111) den Anker unbedingt dem aktuellen `session.userId` zuweist. Die Doku (L151–153) verspricht „caller decides how strict to be“, der Aufrufer (server.js L3035) hängt jedoch nur „(warning: anchor collision)“ an die Seite; die Umbindung ist zu diesem Zeitpunkt bereits geschehen. Die Session wird ebenfalls unbedingt `githubVerified` markiert (L229–232).
**Auswirkung:** Ein GitHub-Konto kann beliebig viele HHTTPS-Identitäten nacheinander „verifizieren“ (Sybil über einen Account); der vorherige Besitzer verliert seinen Anker still. `getUserGithubAnchor` (L264–276, „re-login persistence“) wird zudem nirgends aufgerufen — die dokumentierte Wiederherstellung bei Re-Login ist nicht implementiert.
**Empfehlung:** Bei bestehendem Anker mit anderem `user_id` die Verifikation ablehnen (kein UPDATE, Session nicht markieren) oder eine explizite Re-Bind-Policy implementieren; `getUserGithubAnchor` entweder in `session/start` verdrahten oder entfernen.

### [S3] [Korrektheit] server/test/** — Keine Tests für `/hhttps/revoke`, `/hhttps/revoke/status`, `/hhttps/validate`, `/hhttps/protected`, `/hhttps/role/card` und den 200-Pfad von `/hhttps/age/upgrade`
**Begründung:** `grep` über server/test findet für diese Routen keinen Aufruf (nur `role/declare`, `eid/upgrade`, `age/direct`, `age/upgrade`-403 in acceptance/gate.test.mjs; errors.js in eudi-verifier-errors.test.mjs). Die oben beschriebenen Fehlerpfade (Maschinen-Token als human, Pseudonym-Verlust nach Age-Upgrade, Refresh-Token überlebt Revoke, RAL 1 durch `"false"`) wären mit je einem Integrationstest sichtbar.
**Auswirkung:** Regressionen in den Kern-Endpunkten Validate/Revoke bleiben unentdeckt; CI führt zudem gar keine Tests aus (siehe 01-automatische-checks.md).
**Empfehlung:** Integrationstests: validate mit Maschinen-/Refresh-Token → 401; revoke(access) → refresh muss scheitern; age/upgrade 200 → Claims `pseudonym`, `email_verified`, `age_group`; role/card mit `documentProvided:"false"` → RAL 0.

### [S4] [Korrektheit] server/server.js:L3328-3330 — `/hhttps/age/upgrade` stellt bei ausschließlich `false`-Claims ein `age_verified:true` für `minor_under_14` aus
**Begründung:** `ageGroupFromEudiClaims` liefert für `{}`/alle `false` `'minor_under_14'`; der Handler prüft nicht, dass mindestens ein `age_over_*` wahr ist, sondern verlässt sich auf den Guard im Verifier (index.js L254–258). Mit gültigem HMAC über `{false,false,false}` entsteht ein kryptografisch „verifiziertes“ Kind-Alter aus Nicht-Offenlegung.
**Auswirkung:** Nur über den internen Verifier erreichbar; bei künftigen Aufrufern (AV-App, andere Verifier) semantisch falsches Ergebnis.
**Empfehlung:** Im Handler `Object.values(ageOver).some(v => v === true)` verlangen, sonst 400 `no_age_claim_disclosed`.

### [S4] [Korrektheit] server/eudi-verifier/index.js:L238-258 — Zustand `failed` wird beim nächsten Poll nicht kurzgeschlossen
**Begründung:** Nur `tx.status === 'verified'` wird gecacht; nach `tx.status = 'failed'` (L256, L349) pollt jeder weitere Request erneut EUDIPLO und wiederholt die Extraktion. Ebenso wird `pollWalletResponse(…, req.query.response_code)` mit einem Parameter aufgerufen, den `backend-client.js` ignoriert (`_responseCode`, L370).
**Auswirkung:** Unnötige Backend-Aufrufe; der `failed`-Status ist nicht stabil (könnte beim Re-Poll theoretisch kippen).
**Empfehlung:** `if (tx.status === 'failed') return res.json({ status:'failed', reason: tx.reason })` vor dem Backend-Poll; toten Parameter entfernen.

### [S4] [Korrektheit] server/eudi-verifier/backend-client.js:L118-142 — PID-Age-Config wird bei Konflikt nicht aktualisiert (im Gegensatz zur AV-Config)
**Begründung:** `ensureVerifierConfig` behandelt 409/„exists“ als Erfolg ohne PATCH; `ensureAvVerifierConfig` (L218–250) wurde genau wegen dieses Problems („stale DCQL forever“) auf PATCH umgestellt. Änderungen an `EUDI_AV_DOCTYPE` oder am DCQL-Format wirken für `age-over-NN` nur nach manuellem Löschen der Config in EUDIPLO.
**Auswirkung:** Konfigurationsdrift zwischen Code und EUDIPLO-Instanz bei Doctype-/Claim-Änderungen.
**Empfehlung:** Dieselbe PATCH-Strategie wie in `ensureAvVerifierConfig` verwenden (gemeinsame Hilfsfunktion).

### [S4] [Korrektheit] server/eudi-verifier/docker/docker-compose.yaml:L1-17,L23 — Compose-Datei beschreibt den abgelösten EU-Verifier-Endpoint (:8080), der Code spricht EUDIPLO (:3002)
**Begründung:** `backend-client.js` L3–6 und L29 dokumentieren den Wechsel zu EUDIPLO unter `http://127.0.0.1:3002/api`; die Compose-Datei startet weiterhin `eudi-srv-verifier-endpoint` auf 8080 mit `VERIFIER_PUBLICURL https://hhttps.org/eudi-backend`. `/eudi/age/health` meldet `backend: BACKEND` (EUDIPLO). Nichts im Code referenziert :8080.
**Auswirkung:** Wer nach dem Kopf-Kommentar („Start: docker compose up -d“) deployt, startet einen Dienst, den der Server nie anspricht; Runbook/Deploy-Skript (deploy-phase8.sh L107) hängen an dieser Datei.
**Empfehlung:** Compose durch die EUDIPLO-Definition ersetzen oder die Datei als „legacy, unused“ markieren und aus dem Deploy-Skript nehmen.

### [S4] [Korrektheit] server/public/iamhmn-card-issuer.js:L130,L133-143 — Suggest-Race und pro `_render()` registrierter globaler Click-Listener
**Begründung:** `_suggest` setzt `this._sug` mit dem Ergebnis jedes Fetches, ohne die Anfrage-Reihenfolge zu prüfen; bei schneller Eingabe kann eine ältere Antwort eine neuere überschreiben (kein `AbortController`/Sequenznummer). `document.addEventListener('click', …)` (L130) wird in `connectedCallback` → `_render()` bei jedem (Re-)Connect erneut registriert und nie entfernt.
**Auswirkung:** Vereinzelt falsche Vorschlagsliste; Listener-Leak bei mehrfachem Ein-/Aushängen des Elements.
**Empfehlung:** Anfragen mit laufender Nummer/`AbortController` verwerfen; Listener in `disconnectedCallback` entfernen.

## Zusammenfassung

S1: 0 · S2: 2 · S3: 9 · S4: 5 (gesamt 16).

Die HMAC-Assertionen (age/eid/direct) und der Email-First-Gate sind sauber und konsistent umgesetzt und durch Tests abgedeckt. Die gravierenden Korrektheitsprobleme liegen daneben: `/hhttps/validate`/`/hhttps/protected` bestätigen Maschinen- und Refresh-Tokens als „human“, und `/hhttps/age/upgrade` baut die Token-Claims per Hand statt über `tokenSurface`, wodurch Pseudonym und Methodenflags verloren gehen und das Alter den Refresh nicht überlebt. Revoke/Validate/Card sind ungetestet; im EUDI-Verifier fehlen In-Flight-Sperre und negative Terminalzustände, und `docker-compose.yaml` beschreibt einen nicht mehr genutzten Backend-Dienst.

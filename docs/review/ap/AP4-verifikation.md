# AP4 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b (Arbeitsstand 485c740; `git diff bf0a82b..HEAD -- server/` ist leer, alle Zeilennummern gelten unverändert)

Vorgehen: Jede Datei:Zeile per `awk`/`sed` gegen den Code geprüft; ESLint über die AP4-Dateien gelaufen; Repro-Tests im Scratchpad (`ap4-repro.test.mjs`, 8 Fälle, Harness `server/test/helpers`, lokales Postgres `TEST_PG_HOST=/var/lib/pgtest`, `EMAIL_DEV_MODE=1`) ausgeführt. Repro-Ergebnisse sind unten als „Repro:“ zitiert. Secrets aus `docker-compose.yaml` werden nur als Zeile referenziert (Issue #32).

Rohbefund-Zählung: K meldet in der Zusammenfassung 16, enthält aber 17 Findings (S3 = 10, nicht 9). IDs: K = AP4-01…17, S = AP4-18…36, P = AP4-37…45, W = AP4-46…59.

## Bestätigte Findings

### AP4-01 [S2] [Korrektheit] server/server.js:L3719-3741, L3744-3763 — `/hhttps/validate` und `/hhttps/protected` bestätigen Maschinen- und Refresh-Tokens als `human:true · actorType:'human'`
**Urteil:** BESTÄTIGT (Severity unverändert; AP4-19 [S2 Sicherheit] und AP4-26 [S3 Sicherheit] hierher zusammengeführt — gleiche Ursache in `checkTokenValid`)
**Beleg:** `checkTokenValid` (L702–711) prüft Signatur, `revoked_tokens` und Existenz in `tokens` (bzw. `refresh_tokens` für `sub==='refresh'`), nie `sub`/`human`. Maschinen-Tokens (`sub:'machine', human:false, actorType:'bot'`, L3852–3853) landen in derselben `tokens`-Tabelle (L3868–3870). Beide Handler kodieren die Antwort hart (`human: true, actorType: 'human'`, L3725/L3729, L3754). Repro: `VALIDATE(refresh): 200 … "human": true, "actorType": "human"`; `PROTECTED(refresh): 200 "Human-verified access granted."`; Maschinen-Token (`{"sub":"machine","human":false,"actorType":"bot"}`) → `VALIDATE(machine): 200 … "human": true`, Response-Header `HHTTPS-Human: true`.
**Auswirkung:** Die zentrale Zusicherung der Validierungs-API („human-verified“) ist über registrierte Bot-Operatoren und über 7-Tage-Refresh-Tokens fälschbar; SDKs (`server/sdk/client.js` L191, `client.py` L214) und die Spec (`sites/spec.html` L758) verweisen genau auf diesen Endpunkt.
**Empfehlung:** In beiden Handlern `d.sub === 'human-verified'` verlangen (sonst 401 bzw. `human:false, actorType:d.actorType` aus dem Token spiegeln); `checkTokenValid` um `{ allowRefresh:false }` ergänzen; `human`/`actorType` nie hart setzen.

### AP4-02 [S2] [Korrektheit] server/server.js:L3341-3362 — `/hhttps/age/upgrade` reissued Tokens ohne `pseudonym` und ohne `*_verified`-Flags; Alter überlebt den Refresh nicht
**Urteil:** BESTÄTIGT (Severity unverändert; AP4-46 [S2 Wartbarkeit] hierher zusammengeführt — dieselbe Handkopie statt `tokenSurface`)
**Beleg:** L3349–3352 setzt nur `verified_methods`, `verification_status`, `domain_name`, `eudi_verified`; `tokenSurface` (L2400–2409) liefert zusätzlich `methodFlags()` und `pseudonym`. `issueRefreshToken` (L3360–3362) bekommt kein `pseudonym`; `issueRefreshToken` (L680–700) kennt keine Age-Claims. Repro (Session-Pseudonym `iamhmn_cdvdsej0w4`): Access-Claims nach Upgrade `{"age_group":"adult_18_plus","age_verified":true,"verified_methods":["email","domain","age"]}` — `pseudonym`, `email_verified`, `passkey_verified` fehlen; Refresh-Claims `{"verified_methods":[…]}` ohne `pseudonym`; nach `/hhttps/token/refresh`: `{"verified_methods":["email","domain","age"]}` — `age_group`/`age_verified` weg, `verified_methods` meldet weiter „age“.
**Auswirkung:** Nach EUDI-Altersverifikation verliert die Identität Pseudonym und Methodenflags (OAuth `preferred_username`, Consent), nach ≤1 h ist das verifizierte Alter weg bei inkonsistentem `verified_methods`.
**Empfehlung:** `...tokenSurface(session, v)` wie in `/hhttps/eid/upgrade` (L3555); `pseudonym: session.pseudonym || null` an `issueRefreshToken`; Age-Claims in Refresh-Token und `/hhttps/token/refresh` übernehmen; Integrationstest für den 200-Pfad (Vorlage: gate.test.mjs L108–125).

### AP4-03 [S2] [Korrektheit] server/server.js:L3678-3707 — `/hhttps/revoke` widerruft nur das übergebene Access-Token; der Refresh-Token bleibt gültig, Antwort meldet vollständigen Widerruf
**Urteil:** BESTÄTIGT (heraufgestuft von S3 auf S2, entsprechend AP4-22 [S2 Sicherheit], das hierher zusammengeführt wird: Widerruf ist nachweislich wirkungslos, Spec bewirbt „Revocable“)
**Beleg:** `issueRefreshToken` vergibt eine eigene `jti` (L681); Access-Token kennt sie nicht. L3685–3686 löschen `tokens`/`refresh_tokens` nur mit der Access-`jti` (No-op für den Refresh). Repro: `REVOKE: 200 {"status":"revoked","revoked":true}` → anschließend `/hhttps/token/refresh` mit dem zugehörigen Refresh-Token: `200 "status": "refreshed"`. Einziger Client (`extension/background.js` L233–237) sendet das Access-Token.
**Auswirkung:** Ein Angreifer mit Refresh-Token (gleicher Speicherort) holt sich bis zu 7 Tage neue Access-Tokens, obwohl der Nutzer widerrufen hat.
**Empfehlung:** Beim Revoke alle `refresh_tokens` des `userId` löschen und deren `jti` in `revoked_tokens` eintragen (Index `refresh_tokens_user_id_idx` existiert, schema.sql L92), oder Refresh-`jti` als Claim ins Access-Token schreiben und paarweise widerrufen.

### AP4-04 [S3] [Korrektheit] server/server.js:L3683-3705 — `/hhttps/revoke`: Fehlerpfad mit Nebenwirkungen und irreführender Antwort (Token ohne `jti`, ungültige Signatur)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** (a) `decoded.jti.slice(0, 8)` (L3689) wirft bei signaturgültigen Tokens ohne `jti` — ID-Token (L1858, `idTokenClaims` ohne `jti`) und Signatur-Token (L975–978, trägt `tokenJti`, nicht `jti`) — nachdem `db.revokedTokens.add(undefined, …)` bereits versucht wurde. (b) Der `catch` (L3695–3705) reagiert auf jeden `verifyToken`-Fehler. Repro mit unsigniertem Token: `REVOKE(garbage): 401 {"error":"\"ES256\" signatures must be \"64\" bytes, saw \"3\""}` und zugleich `revoked_tokens`-Zeile `{"jti":"fake-…","reason":"user-requested-expired"}` — 401 mit erfolgtem Schreibzugriff. Sicherheitsaspekt (unverifizierter Payload) siehe AP4-25.
**Auswirkung:** Client kann nicht unterscheiden, ob widerrufen wurde; falsche Statuscodes.
**Empfehlung:** Fehler differenzieren (`TokenExpiredError` → 200 `{revoked:true, expired:true}`, sonst 400/401 ohne DB-Schreibzugriff); `if (!decoded.jti) return 400`.

### AP4-05 [S3] [Korrektheit] server/server.js:L3097-3230, L3709-3715 — `/hhttps/role/declare` ohne try/catch: Fehler lassen die Anfrage ohne Antwort hängen
**Urteil:** BESTÄTIGT mit Korrektur (Severity unverändert). Der genannte Auslöser `?jti=a&jti=b` in `/hhttps/revoke/status` trifft NICHT zu: pg serialisiert das Array als Text-Literal, Repro `REVOKE/STATUS(array): HTTP 200 {"jti":["a","b"], …}` — kein Hänger, nur ein unsauberes Echo. Für `/hhttps/role/declare` ist das Hängen dagegen reproduzierbar (siehe AP4-31): `DECLARE(constructor): NO RESPONSE (AbortError) | tokens issued for user: 1`.
**Beleg:** L3097 `async` ohne try/catch; kein Error-Middleware; `process.on('unhandledRejection')` (L4824) loggt nur. Alle anderen AP4-Handler haben try/catch.
**Auswirkung:** Timeout statt 5xx, offene Verbindungen, Tokens werden ausgestellt ohne Antwort.
**Empfehlung:** try/catch mit 500 bzw. `asyncHandler`-Wrapper; in `/revoke/status` `jti` per `typeof === 'string'` normalisieren.

### AP4-06 [S3] [Korrektheit] server/server.js:L3598-3607 — `/hhttps/role/card` umgeht die E-Mail-Pflicht (AK-13); Kommentar verweist falsch auf `role/declare`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `role/declare` L3102 `requireEmailVerified`; `role/card` L3605–3606 nur `||`-Kette. `session.hasPasskey`/`session.eudiVerified` fehlen in `sessions._normalize` (db.js L211–232; `hasPasskey` wird in L2585 an `sessions.create` übergeben, das es nicht persistiert) → immer `undefined`. `credentialId` oder `githubVerified` allein reichen; beide sind seit AK-10/AK-11 nur nach E-Mail erreichbar, aber Alt-Sessions/Direktpfade sind nicht ausgeschlossen, und das Gate ist objektiv inkonsistent.
**Auswirkung:** Karte mit `issuer: hhttps://…` für Sessions ohne bestätigte E-Mail; Gate-Modell uneinheitlich.
**Empfehlung:** `requireEmailVerified(session, res)` wie in `role/declare`; tote Felder entfernen.

### AP4-07 [S3] [Korrektheit] server/server.js:L3600, L3635-3637 — `documentProvided` nur auf Truthiness geprüft; `human`-Claim der Karte widerspricht dem Zugangs-Gate
**Urteil:** BESTÄTIGT (Severity unverändert; ergänzend zu AP4-21, das die fehlende Nachweisprüfung selbst adressiert)
**Beleg:** L3600 destrukturiert roh aus `req.body`; L3623 `!documentProvided`, L3635–3636 ternär → `"false"`, `"0"`, `{}` sind truthy → `method:'document-checked'`, `verificationStatus:'verified'` → `deriveRAL` = 1 (roles.taxonomy.js L226). L3637 `humanVerified = !!(session.hasPasskey || session.credentialId)` — E-Mail-Session ohne Passkey → `human:'false'` (stringifiziert, backend-client L463–470), obwohl L3605 E-Mail als Methode zulässt.
**Auswirkung:** RAL 1 durch Nicht-Booleans; `human`-Claim im E-Mail-first-Normalfall systematisch falsch.
**Empfehlung:** `documentProvided === true`; `humanVerified` aus `computeVerification(flags).methods.length > 0` ableiten.

### AP4-08 [S3] [Korrektheit] server/eudi-verifier/index.js:L232-267, L327-364, L408-431 — Status-Polling ohne In-Flight-Sperre: parallele Polls lösen den Upgrade mehrfach aus
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `tx.status = 'verified'` wird erst nach `await callAgeUpgrade(...)` gesetzt (L261–262, L355–359, L425–426); Cache-Kurzschluss L238 greift nur bei `'verified'`. Frontend pollt alle 2,5 s (`server/public/index.html` L642, L667, L688); ein zweiter Tab/Poller sieht `pending` und ruft den Upgrade erneut (zwei Access-/Refresh-Tokens, doppelte `stats`/`fireEvent`).
**Auswirkung:** Doppelte Token-Ausstellung und Events; Cookie-Inhalt hängt von der Antwortreihenfolge ab.
**Empfehlung:** `tx.inflight`-Promise bzw. `tx.status='upgrading'` vor dem Backend-Poll setzen; Nachfolger mit `pending` beantworten.

### AP4-09 [S3] [Korrektheit] server/eudi-verifier/backend-client.js:L352-360, L388-395 — Nur Erfolgs-Status sind terminal; Fehl-/Ablaufzustände und 404 bleiben bis zum 10-min-TTL „pending“
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `TERMINAL` (L352) enthält nur positive Werte; L388 `404 → pending`; L395 Fallback `pending`. `index.js` reicht `pending` 1:1 durch (L244–246, L338–340, L419–421). Kein `failed`/`rejected`/`expired` wird erkannt. Komplementär zu AP4-24 (falsch-positive Terminal-Erkennung).
**Auswirkung:** UI dreht bis `TX_TTL_MS` (10 min) leer nach Abbruch/Ablehnung.
**Empfehlung:** Negative Terminalzustände als `{ status:'failed', reason }`; 404 nach erstem erfolgreichen Poll als `failed`.

### AP4-10 [S3] [Korrektheit] server/eudi-verifier/backend-client.js:L61-92 — Token-Cache ohne Invalidierung bei 401
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `getToken` (L63–83) erneuert nur zeitgesteuert (`expiresAt - 60_000`, Default 86 400 s); `authed()` (L85–92) gibt die Response unverändert zurück; alle Aufrufer werfen bei `!r.ok` (z. B. L156–159) ohne Cache-Reset.
**Auswirkung:** Nach EUDIPLO-Neustart/Secret-Rotation alle EUDI-Flows bis 24 h bzw. Node-Neustart gestört (502).
**Empfehlung:** Bei 401/403 in `authed()` `tokenCache` leeren und einmal wiederholen.

### AP4-11 [S3] [Korrektheit] server/external-verify.js:L102-116, L211-232 — GitHub-Anker wird bei Kollision unbedingt auf den neuen Nutzer umgebunden; `getUserGithubAnchor` ist tot
**Urteil:** BESTÄTIGT (Severity unverändert; AP4-30 [S3 Sicherheit] hierher zusammengeführt — Sybil/Anker-Übernahme ist dieselbe Ursache)
**Beleg:** L110–113 `ON CONFLICT … DO UPDATE SET user_id = EXCLUDED.user_id`; L213–218 liest `alreadyOwnedBy`, L221–226 überschreibt trotzdem, L229–232 markiert Session `githubVerified`. Aufrufer server.js L3035 hängt nur `' (warning: anchor collision)'` an. `getUserGithubAnchor` (L264): einzige Fundstelle ist die Definition (`grep -rn getUserGithubAnchor` → nur external-verify.js:264).
**Auswirkung:** Ein GitHub-Konto kann nacheinander beliebig viele HHTTPS-Identitäten mit GitHub-Trust (60–85) versorgen; Vorbesitzer verliert den Anker still; dokumentierte Re-Login-Persistenz nicht implementiert.
**Empfehlung:** Bei `alreadyOwnedBy !== session.userId` mit 409 ablehnen (kein UPDATE, Session nicht markieren) oder explizite Umzugsbestätigung; `getUserGithubAnchor` verdrahten oder entfernen.

### AP4-12 [S3] [Korrektheit] server/test/** — Keine Tests für `/hhttps/revoke`, `/revoke/status`, `/validate`, `/protected`, `/role/card`, den 200-Pfad von `/age/upgrade`, den `/eudi/*`-Router, backend-client.js und external-verify.js
**Urteil:** BESTÄTIGT (Severity unverändert; AP4-55 [S3 Wartbarkeit] hierher zusammengeführt)
**Beleg:** `grep -rn "hhttps/revoke|hhttps/validate|hhttps/protected|role/card|/eudi/|extractAgeClaims|computeGithubTrust" server/test/` → keine Treffer; AP4-Abdeckung nur `eid/upgrade` (gate.test.mjs L98–125, acceptance L389–401), `age/direct` (acceptance L527–559), `age/upgrade`-403 (acceptance L540) und errors.js (unit). Alle Repros dieser Verifikation (AP4-01/02/03/20/25/31) wären mit je einem Integrationstest sichtbar gewesen.
**Auswirkung:** Regressionen in Validate/Revoke/Card unentdeckt; CI führt zudem keine Tests aus (01-automatische-checks.md).
**Empfehlung:** Die Repro-Fälle aus `scratchpad/ap4-repro.test.mjs` als Integrationstests übernehmen; Unit-Tests für `extractAgeClaims`, `sessionLooksDone`, `computeGithubTrust`, `buildDcqlQuery`.

### AP4-13 [S4] [Korrektheit] server/server.js:L3328-3330 — `/hhttps/age/upgrade` stellt bei ausschließlich `false`-Claims `age_verified:true` für `minor_under_14` aus
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `ageGroupFromEudiClaims` (roles.js L373–380) liefert für `{}`/alle `false` `'minor_under_14'`; der Handler prüft nur `typeof ageOver === 'object'` (L3255); der Guard liegt allein im Verifier (index.js L254–258). Mit gültigem HMAC erreichbar.
**Auswirkung:** Nur über HMAC-Inhaber erreichbar; semantisch falsches „verifiziertes“ Kind-Alter.
**Empfehlung:** `Object.values(ageOver).some(v => v === true)` im Handler, sonst 400.

### AP4-14 [S4] [Korrektheit] server/eudi-verifier/index.js:L238-258 — Zustand `failed` wird beim nächsten Poll nicht kurzgeschlossen; toter `response_code`-Parameter
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L238 prüft nur `'verified'`; `tx.status='failed'` (L256, L349) führt beim nächsten Poll erneut zu `pollWalletResponse`. `_responseCode` (backend-client L370) ungenutzt (ESLint bestätigt), Aufrufer L243, L337, L418.
**Auswirkung:** Unnötige Backend-Aufrufe; `failed` nicht stabil.
**Empfehlung:** `failed` cachen; Parameter entfernen.

### AP4-15 [S4] [Korrektheit] server/eudi-verifier/backend-client.js:L118-142, L291-306 — PID-Age- und eID-Config werden bei Konflikt nicht per PATCH aktualisiert (im Gegensatz zur AV-Config)
**Urteil:** BESTÄTIGT (Severity unverändert; Wartbarkeitsseite in AP4-51)
**Beleg:** L137–140 und L304 behandeln 409/„exists“ als Erfolg ohne PATCH; `ensureAvVerifierConfig` L234–247 PATCHt und begründet dies in L213–217 mit einem realen Vorfall („silently went missing from live requests“). Direkt relevant für die Behebung von AP4-18: ein `trusted_authorities`-Fix in `buildDcqlQuery` käme bei bestehenden Configs nie an.
**Auswirkung:** Konfigurationsdrift; blockiert die Wirksamkeit des S1-Fixes.
**Empfehlung:** Gemeinsame `ensureConfig({ patchIfExists:true })`.

### AP4-16 [S4] [Korrektheit] server/eudi-verifier/docker/docker-compose.yaml:L1-17, L23 — Compose beschreibt das abgelöste EU-Verifier-Endpoint (:8080), Code spricht EUDIPLO (:3002)
**Urteil:** BESTÄTIGT (Severity unverändert; AP4-53 [S3 Wartbarkeit] hierher zusammengeführt)
**Beleg:** backend-client.js L3–6 („REPLACES the old EU Verifier Endpoint backend (Docker, :8080)“), L29 Default `http://127.0.0.1:3002/api`; Compose L13 `eudi-srv-verifier-endpoint:latest`, L17 Port 8080, L23 `VERIFIER_PUBLICURL … /eudi-backend`; `grep -rn 8080 server/*.js server/eudi-verifier/*.js` → keine Referenz. deploy-phase8.sh L107–111 und Runbook L18/L98/L128 behandeln die Datei weiterhin gesondert.
**Auswirkung:** Toter Dienst mit Deploy-Sonderlogik; trägt zudem das Secret aus AP4-23.
**Empfehlung:** Datei entfernen/als Legacy markieren, Sonderbehandlung im Deploy-Skript und Runbook streichen.

### AP4-17 [S4] [Korrektheit] server/public/iamhmn-card-issuer.js:L130, L133-143 — Suggest-Race und pro `_render()` registrierter globaler Click-Listener
**Urteil:** BESTÄTIGT (Severity unverändert; AP4-44 [S4 Performance] hierher zusammengeführt)
**Beleg:** L95 `connectedCallback() { this._render(); }`, L130 `document.addEventListener('click', …)` in `_render()`, kein `disconnectedCallback` (grep). `_suggest` L136–139 ohne `AbortController`/Sequenznummer.
**Auswirkung:** Listener-Leak bei Re-Mount; veraltete Vorschlagsliste.
**Empfehlung:** Listener in `disconnectedCallback` entfernen; laufenden Fetch abbrechen.

### AP4-18 [S1] [Sicherheit] server/eudi-verifier/backend-client.js:L98-109, L278-289 — PID-DCQL-Queries (Alter via PID, eID-Identität) ohne `trusted_authorities`; laut Backend-Vertrag im Code prüft EUDIPLO dann keine Aussteller-Vertrauenskette
**Urteil:** BESTÄTIGT (Severity S1 unverändert, mit Vorbehalt „Live-Nachweis gegen EUDIPLO steht aus“)
**Beleg:** Der Backend-Vertrag ist im Repo ausschließlich im Code selbst dokumentiert, und zwar eindeutig: L186–192 „EUDIPLO validates issuer trust ONLY when the DCQL credential query carries `trusted_authorities` … WITHOUT it, trust validation is SKIPPED (confirmed in EUDIPLO docs/source)“; L213–217 beschreibt einen realen Vorfall, bei dem genau diese Bindung im AV-Pfad fehlte. Konsequent hängt nur `buildAvDcqlQuery` (L205–209) die Trust-List an; `buildDcqlQuery` (L98–109) und `buildPidDcqlQuery` (L278–289) nicht. Gegenprüfung auf serverseitige Trust-Konfiguration: `grep -rni "trusted_authorit|trust list|etsi_tl|lote"` über docs/, scripts/, Runbook, .env.example, Compose → einzige Treffer sind die genannten Kommentare; das referenzierte `scripts/install-av-trustlist.sh` (L191) existiert weder im Arbeitsbaum noch in der Git-History (`git log --all -- '*install-av-trustlist*'` leer); eine EUDIPLO-Compose/-Konfiguration ist nicht eingecheckt (die vorhandene Compose ist das Alt-Backend, AP4-16); die Commits, die `trusted_authorities` einführten (`0118603 authorize fix`, `764acfe fix for eudi-flow`), enthalten keine gegenteilige Begründung. Es gibt also keinerlei Hinweis auf eine serverseitige Vertrauensprüfung in EUDIPLO; das Repo selbst behauptet das Gegenteil. Verstärkend: Der eID-Pfad wertet keine Claims aus — jede terminale Session gilt als „valid PID presentation“ (index.js L423–425, backend-client L308–310), und `sessionLooksDone` akzeptiert bereits `submitted` (AP4-24).
**Auswirkung:** `age_verified:true` (Methode `eudi-wallet`) und `eudi_verified:true` (+40 Trust) mit einem selbst signierten mdoc `eu.europa.ec.eudi.pid.1` aus einem Test-Issuer. Die Ausnutzung setzt ein Wallet voraus, das ein fremd signiertes PID-mdoc präsentiert (Sandbox-/Referenz-Wallets erlauben das). Ob EUDIPLO in der Live-Konfiguration nicht doch einen globalen Trust-Anchor besitzt, ist aus dem Repo nicht belegbar — im Zweifel gilt der eigene, ausdrücklich als bestätigt markierte Vertrag.
**Empfehlung:** (1) Einmalige Live-Prüfung: `GET /api/verifier/config/age-over-18` und `eid-identity` auf `trusted_authorities` prüfen; Test-Präsentation mit nicht gelisteter Issuer-CA. (2) `trusted_authorities` (etsi_tl, PID-Trust-List/LoTE) in `buildDcqlQuery`/`buildPidDcqlQuery` setzen, Configs per PATCH aktualisieren (AP4-15), fail-closed ohne Trust-List. (3) Fehlendes `install-av-trustlist.sh` einchecken oder Kommentar korrigieren.

### AP4-20 [S2] [Sicherheit] server/server.js:L3314-3322, L3520-3530 — `currentToken` in `/hhttps/age/upgrade` und `/hhttps/eid/upgrade` wird nicht an `session.userId` gebunden
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Beide Handler rufen nur `verifyToken` (keys.js L164–173: Signatur/Exp, keine Revocation) und lesen `eudi_verified` bzw. `age_*` ohne `prev.userId`-Vergleich. `currentToken` kommt aus dem Browser-Body (index.js L194, L378) und wird durchgereicht (L96, L158). Repro: Nutzer A macht Age-Upgrade (`adult_18_plus`); Nutzer B ruft eid/upgrade mit A's Access-Token als `currentToken` → `EID-UPGRADE(B) with A-token: {"userId_is_B":true,"age_group":"adult_18_plus","age_verified":true,"eudi_verified":true}`.
**Auswirkung:** Claim-Transplantation über Nutzergrenzen; mit einem geleakten (auch widerrufenen, noch nicht abgelaufenen) Fremdtoken.
**Empfehlung:** `prev.userId === session.userId` und `checkTokenValid` statt `verifyToken`; sonst `currentToken` ignorieren und warnen.

### AP4-21 [S2] [Sicherheit] server/server.js:L3598-3667 — Client-Flag `documentProvided:true` erzeugt ohne Nachweis eine Karte mit `verificationStatus:'verified'`, `method:'document-checked'`, RAL 1 — auch für geschützte Berufe
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L3623 `if (g.reserved && !documentProvided)` ist das einzige Gate; L3635–3636 setzen `document-checked`/`verified`; `buildRoleClaim` → `deriveRAL` = 1 mit `evidence_type:'document'`, `assurance_level:'substantial'` (roles.taxonomy.js L249–254); L3651 `reserved:'true'`; L3654 mintet via EUDIPLO. Frontend: Checkbox (`iamhmn-card-issuer.js` L108, L198) bzw. `documentProvided: … : true` für qualifizierte Rollen (index.html L916). Kein Upload, keine Prüfung, keine Persistenz.
**Auswirkung:** Jede Session erhält eine signierte Berufsattestation „Arzt · RAL1 · verified · document-checked“; Relying Parties können Pilot- von Echtbetrieb nicht unterscheiden.
**Empfehlung:** Bis zum realen Dokumenten-Review: `documentProvided` serverseitig ignorieren (reserved → 400) oder ehrlich labeln (`self-asserted-document`, RAL0); geschützte Berufe nur per externer (Q)EAA.

### AP4-23 [S2] [Sicherheit] server/eudi-verifier/docker/docker-compose.yaml:L34, L36 — Keystore-Passwörter des RP-Signaturschlüssels im Klartext im Repository (bekanntes Issue #32)
**Urteil:** BESTÄTIGT (Severity unverändert; bekanntes Issue #32 — Werte hier nicht zitiert)
**Beleg:** L34 (`VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD`) und L36 (`VERIFIER_ACCESS_CERTIFICATE_PASSWORD`) tragen Literalwerte; Keystore-Mount L20. Die Datei ist zugleich das tote Alt-Backend (AP4-16), das Secret bleibt aber in der Git-History.
**Auswirkung:** Mit Keystore-Zugriff Impersonation des Verifiers (`x509_san_dns:hhttps.org`) gegenüber Wallets.
**Empfehlung:** Wie in #32: `${VAR}` aus gitignored `.env`, Passwort rotieren, History bereinigen; Datei entfernen.

### AP4-24 [S3] [Sicherheit] server/eudi-verifier/backend-client.js:L352-360 — „Präsentation gültig“ heuristisch aus Status-Strings (`submitted`, …) oder bloßem Vorkommen eines `age_over_*`-Schlüssels abgeleitet
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L352 `TERMINAL` enthält `submitted`; L355–360 `sessionLooksDone` → `true`, sobald `extractAgeClaims` (rekursiver Scan L403–417) irgendwo einen `age_over_\d+`-Key findet; kein `error`/`rejected`-Feld wird geprüft; eID: „Terminal session → valid PID presentation“ (index.js L423–425). Beide Stellen tragen `**CONFIRM**` (L18, L24, L342). Verschärft AP4-18.
**Auswirkung:** Abhängig vom EUDIPLO-Format kann eine nicht/negativ validierte Präsentation als Erfolg gelten.
**Empfehlung:** `EUDIPLO_SESSION_PATH` verpflichtend, nur dokumentierten positiven Status akzeptieren, Claims nur aus dem verifizierten Disclosure-Feld, `submitted` entfernen.

### AP4-25 [S3] [Sicherheit] server/server.js:L3697-3703 — Fallback in `/hhttps/revoke` vertraut dem unsignierten JWT-Payload
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Repro: Token mit Müll-Signatur und Payload `{jti:'fake-…'}` → `401`, aber `revoked_tokens` enthält `{"jti":"fake-…","reason":"user-requested-expired"}`; L3701–3702 löschen zudem `tokens`/`refresh_tokens` mit der fremden `jti`. `revoked_tokens` ohne Cleanup (schema.sql L94–102, `cleanup_expired` L192–205 räumt sie nicht), `jti TEXT` ohne Limit, Body-Limit 2 MB (L371). Korrektur zum Rohbefund: `limit.revoke` ist `rl(30)` = 30/min (L429, Default-Fenster 60 s), nicht 30/15 min — der Storage-DoS ist damit ~15× größer als angegeben. `/hhttps/revoke/status` (L3709) ist als Orakel unauthentifiziert.
**Auswirkung:** (a) unbegrenztes Wachstum von `revoked_tokens` durch Unbefugte; (b) wer eine fremde `jti` kennt, invalidiert fremde Access-/Refresh-Tokens ohne Tokenbesitz.
**Empfehlung:** Fallback nur mit `jwt.verify(..., { ignoreExpiration:true })`; `jti` UUID-Format prüfen; Cleanup (siehe AP4-40).

### AP4-27 [S3] [Sicherheit] server/server.js:L3254, L3409, L3477 — „INTERNAL / 127.0.0.1 only“-Endpunkte ohne Loopback-Prüfung; nginx proxied `location /` vollständig
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Kommentare L3243–3244 („nginx MUST NOT expose“), L3467; Runbook `docs/deploy/RUNBOOK-srv1421412-phase8.md` L16: `location /` vollständig an `localhost:3000`, Ausnahmen nur `/spec`, ACME, EUDIPLO-`.well-known`; `docs/specs/email-anchored-identity/abnahme.md` L92: „heute schützt allein `EUDI_VERIFIER_SECRET`, keine 127.0.0.1-Prüfung“. Replay-Fenster L3290–3295/L3445–3450/L3501–3506 ohne Nonce-Set, `iat` optional (`if (iat)`).
**Auswirkung:** Gesamte Integrität der Alters-/eID-Claims hängt an einem statischen HMAC-Secret; Replay innerhalb 5 min möglich.
**Empfehlung:** Loopback-Check (fail-closed) oder separater interner Port/Unix-Socket; Nonce-Set mit TTL; `iat` verpflichtend.

### AP4-28 [S3] [Sicherheit] server/eudi-verifier/index.js:L251-252, L344-345; server/eudi-verifier/backend-client.js:L385 — `EUDI_DEBUG=1` schreibt die Wallet-Antwort (bis 1500 Zeichen) ins Server-Log
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L251 `JSON.stringify(poll.walletResponse).slice(0, 1500)`, L344 analog; backend-client L385 500 Zeichen je Poll. eID-Pfad fordert `issuing_country` an (L55); kein `NODE_ENV`-Gate.
**Auswirkung:** PID-bezogene Daten in pm2-/Journal-Logs; Widerspruch zum Zero-PII-Versprechen (L423–424).
**Empfehlung:** Nur `Object.keys`/Status loggen; `EUDI_DEBUG` in Produktion ignorieren.

### AP4-29 [S3] [Sicherheit] server/server.js:L3641-3643 — Ausgestellte iamhmn-Karte enthält die stabile `userId` als Klartext-Claim
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L3642 `userId: session.userId` → `stringifyClaims` (backend-client L463–470) → inline mdoc-Claims (L486). `userId` ist der Account-Schlüssel (sessions, tokens, refresh_tokens, anchors).
**Auswirkung:** RP-übergreifende Verkettbarkeit; direkt gegen `/hhttps/*` korrelierbar.
**Empfehlung:** `userId` entfernen oder kartenspezifischen gesalzenen Hash verwenden.

### AP4-31 [S3] [Sicherheit] server/server.js:L3124-3127, L3224 — `ageGroup` per Property-Lookup gegen Plain-Object validiert; Prototype-Schlüssel passieren, Tokens werden ausgestellt, Handler stürzt ohne Antwort ab
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `AGE_GROUPS` ist ein Plain-Object (roles.js L304); `AGE_GROUPS['constructor']` ist truthy → `ag.id === undefined` → L3224 `AGE_GROUPS[undefined].label` TypeError nach Token-Ausstellung. Repro: `POST /hhttps/role/declare {ageGroup:'constructor'}` → `NO RESPONSE (AbortError)` nach 3 s; `tokens`-Tabelle enthält danach 1 Zeile für den Nutzer.
**Auswirkung:** Verwaiste Tokens/Refresh-Tokens und Stats-Zähler, hängende Verbindung; kein Auth-Bypass.
**Empfehlung:** `Object.hasOwn(AGE_GROUPS, ageGroup)` + `typeof === 'string'`; try/catch (AP4-05).

### AP4-32 [S3] [Sicherheit] server/eudi-verifier/index.js:L192-211, L232-267 — Cross-Device-Flow ohne Bindung zwischen Session-Inhaber und Wallet-Inhaber
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `/eudi/age/request` nimmt `hhttpsSession` unauthentifiziert an (L194–197), speichert es in `txStore` (L204–211); Status-Handler ruft `callAgeUpgrade(ageOver, tx.hhttpsSession, …)` (L261) unabhängig davon, wessen Wallet gescannt hat; `/eid/*` analog (L376–431). Kein Transaktionscode, keine Same-Device-Rückbindung (`response_code` wird ignoriert, AP4-14).
**Auswirkung:** Relay-/Phishing: fremder Erwachsener/PID-Inhaber verschafft dem Angreifer `age_verified`/`eudi_verified` (+40).
**Empfehlung:** Transaktionscode im Wallet-Request + Bestätigung im Browser, oder Same-Device-Pflicht mit `response_code`-Bindung.

### AP4-33 [S4] [Sicherheit] server/server.js:L3386, L3461, L3581; server/eudi-verifier/index.js:L227, L322, L403; server/eudi-verifier/errors.js:L34 — Rohe Fehlermeldungen an den Client
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `res.status(500).json({ error: e.message })` an den drei Stellen; `detail: e.message` in den Request-Handlern; errors.js L34 `body.detail = err.body.detail || message`; backend-client baut Messages aus `text.slice(0, 200)` der EUDIPLO-Antwort (L75, L141, L158, L244, L263, L305, L319, L389, L459, L491).
**Auswirkung:** Information Disclosure (Backend-Pfade, Config-IDs, DB-Fehlertexte).
**Empfehlung:** Generische Fehlercodes nach außen, Details ins Log.

### AP4-34 [S4] [Sicherheit] server/eudi-verifier/index.js:L178-188 — `/eudi/age/health` gibt Backend-URL und Konfiguration unauthentifiziert preis
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L182 `backend: backendConfig.BACKEND`, L183–186 Doctypes, Scheme, `secretConfigured`.
**Auswirkung:** Interne Topologie öffentlich; geringe Ausnutzbarkeit.
**Empfehlung:** Auf `{ status:'ok' }` reduzieren oder Admin-Auth.

### AP4-35 [S4] [Sicherheit] server/eudi-verifier/backend-client.js:L193-196, L205 — Fail-open-Schalter `EUDI_AV_TRUST_LIST=off` ohne Kopplung an `NODE_ENV`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L195–196 liest die Variable, L205 `if (AV_TRUST_LIST_URL !== 'off')`; der Wert wird per PATCH persistiert (L235–241). Kein Prod-Gate, keine Startwarnung; Variable in `.env.example` undokumentiert (AP4-52).
**Auswirkung:** Konfigurationsfehler schaltet AV-Trust-Prüfung dauerhaft ab.
**Empfehlung:** `off` nur bei `NODE_ENV !== 'production'`; laut warnen.

### AP4-36 [S4] [Sicherheit] server/eudi-verifier/docker/docker-compose.yaml:L13 — Verifier-Image ungepinnt (`:latest`) mit `restart: unless-stopped`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L13 `…eudi-srv-verifier-endpoint:latest`, L15 `restart: unless-stopped`. Datei ist Legacy (AP4-16) — Fix ist das Entfernen der Datei.
**Auswirkung:** Unkontrollierte Updates, falls die Datei doch genutzt wird.
**Empfehlung:** Digest-Pin oder Datei entfernen.

### AP4-37 [S3] [Performance] server/eudi-verifier/index.js:L192-211, L287-311, L376-393 — Unauthentifizierte `/eudi/*/request`-Routen erzeugen pro Aufruf eine EUDIPLO-Session und einen `txStore`-Eintrag ohne Session-Prüfung und Route-Limit
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L195/L379 nur `!hhttpsSession`; `/av/request` (L289) prüft nichts; `initTransaction`/`initAvTransaction`/`initEidTransaction` → `POST /verifier/offer` (backend-client L152, L257, L313) vor jeder Antwort; `putTx` ohne Obergrenze (L43–48); nur `limit.global` 300/min (server.js L420, L434–437).
**Auswirkung:** Amplifikation gegen EUDIPLO (~3000 Sessions/10 min/IP) und ungebremstes Map-Wachstum.
**Empfehlung:** `db.sessions.get` vor dem Upstream-Call; Route-Limiter; `txStore`-Obergrenze.

### AP4-38 [S3] [Performance] server/eudi-verifier/backend-client.js:L374-381, L388 — Pfad-Autodiscovery wird bei jedem Poll wiederholt, solange kein Kandidat 2xx liefert; 404 im Pending-Zustand verhindert die Auflösung
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L378 setzt `resolvedSessionPath` nur bei `res.ok`; L380 `return pending`; L388 behandelt 404 nach Auflösung als `pending` — im nicht aufgelösten Zustand bleibt es bei drei sequentiellen GETs (L375–376) pro Poll alle 2,5 s (index.html L642/L667/L688, bis 80×).
**Auswirkung:** Faktor 3 auf EUDIPLO und Status-Latenz ohne `EUDIPLO_SESSION_PATH`.
**Empfehlung:** Pfad beim Boot auflösen oder Env verpflichtend; 404 auf erstem Kandidaten als „resolved + pending“.

### AP4-39 [S3] [Performance] server/eudi-verifier/index.js:L93, L129, L154, L243; server/eudi-verifier/backend-client.js:L68, L91; server/external-verify.js:L169, L191 — `fetch` ohne Timeout auf gepollten und Login-kritischen Pfaden
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -n "AbortSignal|signal:" eudi-verifier/*.js external-verify.js` → 0 Treffer; alle Upstream-Calls laufen ohne Abbruch (undici-Default ~300 s Header-Timeout).
**Auswirkung:** Hängendes EUDIPLO/GitHub blockiert Handler, Sockets und Nutzer bis zu 5 min; Poller stapeln offene Verbindungen.
**Empfehlung:** `signal: AbortSignal.timeout(5000–10000)` in `authed()`, den drei internen Calls und den GitHub-Calls; Timeout via `mapBackendError` als 502.

### AP4-40 [S3] [Performance] server/server.js:L3684-3687, L3700 — `revoked_tokens` wächst unbegrenzt (kein Cleanup, auch abgelaufene Tokens) und wird auf jedem `/hhttps/validate`/`/protected`-Aufruf abgefragt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** schema.sql L94 „permanent ban list“, `cleanup_expired` L199–203 ohne `revoked_tokens`; `grep "DELETE FROM revoked"` → kein Treffer; `checkTokenValid` L704 → db.js L309 `SELECT 1 FROM revoked_tokens` bei jedem Validate. Zusammen mit AP4-25 (unauthentifizierte Inserts, 30/min) wird das Wachstum steuerbar von außen.
**Auswirkung:** Vacuum/Backup/Index-Last auf dem heißesten Read-Pfad; nach REFRESH_TTL sind Einträge funktional wertlos.
**Empfehlung:** `DELETE FROM revoked_tokens WHERE revoked_at < NOW() - INTERVAL '8 days'` in `cleanup_expired`; keine Inserts für bereits abgelaufene Tokens.

### AP4-41 [S4] [Performance] server/server.js:L3723, L3753, L3712-3713 — Zwei sequentielle, unabhängige DB-Roundtrips pro Validate-/Status-Aufruf
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `checkTokenValid` L704 → L706/L708 sequentiell; `/revoke/status` L3712–3713 `has` dann `exists`.
**Auswirkung:** Doppelte DB-Latenz auf dem Integrations-Hotpath.
**Empfehlung:** `Promise.all` oder eine kombinierte `SELECT EXISTS(...), EXISTS(...)`.

### AP4-42 [S4] [Performance] server/server.js:L3168-3186, L3341-3371, L3547-3571, L3684-3687 — Token-Ausgabe mit vier bis fünf sequentiellen, teils unabhängigen DB-Schreibvorgängen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `issueAccessToken` (2 Queries L656–666) → `issueRefreshToken` (L696) → `sessions.update` (L3186) strikt nacheinander; Muster wiederholt in age/eid-Upgrade und Revoke.
**Auswirkung:** Mikro-Optimierung; spürbar nur bei Remote-DB.
**Empfehlung:** Unabhängige Schreibvorgänge bündeln.

### AP4-43 [S4] [Performance] server/eudi-verifier/backend-client.js:L63-83, L118-142 — Client-Credentials-Token-Cache und `ensureVerifierConfig` ohne In-Flight-Deduplizierung
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L65 Cache-Check, danach ungeschützter `fetch`; `ensuredConfigs.add` erst nach Antwort (L132, L138).
**Auswirkung:** Kurze Request-Spitze bei Kaltstart/Ablauf.
**Empfehlung:** In-Flight-Promise in Modulvariable.

### AP4-45 [S4] [Performance] server/eudi-verifier/index.js:L43-61 — `txStore` ist prozesslokal; Betrieb nur mit einer Node-Instanz korrekt; Tokens verbleiben bis 10 min im Speicher
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Modul-Map L43; Deploy pm2 fork mit einer Instanz (deploy-phase8.sh L219 `pm2 start server.js --name …` ohne `-i`); `tx.hhttps` (L264, L361, L428) enthält Access- und Refresh-Token bis TTL.
**Auswirkung:** Skalierungsgrenze; keine akute Störung.
**Empfehlung:** Als Betriebs-Constraint dokumentieren oder DB-Tabelle; Token-Felder nach Auslieferung löschen.

### AP4-47 [S3] [Wartbarkeit] server/server.js:L3262-3295, L3417-3450, L3484-3506; server/eudi-verifier/index.js:L65-77, L109-124, L142-149 — HMAC-Assertion-Prüfung dreifach kopiert, Signierseite ebenfalls dreifach
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Secret-Lookup, `JSON.stringify(canonical)`, `createHmac`, `timingSafeEqual` mit Längenvergleich und Fenster `-60_000/300_000` an allen sechs Stellen identisch (verifiziert L3266–3295, L3423–3450, L3490–3506).
**Auswirkung:** Sechs synchron zu haltende Stellen in zwei Dateien; Tippfehler → 401 für alle Verifikationen.
**Empfehlung:** `eudi-verifier/assertion.js` mit `signAssertion`/`verifyAssertion` und benannten Konstanten.

### AP4-48 [S3] [Wartbarkeit] server/server.js:L3142-3151, L3329-3338, L3535-3544 (+L2822-2830), L3605-3606 — Flag-Bag aus der Session vierfach kopiert; `hasMethod`-Kette in `/role/card` als fünfte Variante
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Vier wortgleiche Blöcke (nur `eudi`/`age` variieren); L3605–3606 eigene `||`-Kette mit toten Feldern (AP4-06).
**Auswirkung:** Neue Methode muss an fünf Stellen ergänzt werden; Divergenz bereits eingetreten.
**Empfehlung:** `sessionFlags(session, overrides)`; `hasMethod` aus `computeVerification`.

### AP4-49 [S3] [Wartbarkeit] server/server.js:L3100/L3602 vs. L3300/L3510, L3386/L3461/L3581 vs. L3672 vs. L3738/L3763, L3695-3706 — Fehlerformate und Statuscodes zwischen den AP4-Routen uneinheitlich
**Urteil:** BESTÄTIGT (Severity unverändert; der try/catch-Anteil dieses Rohbefunds ist in AP4-05 abgedeckt, hier bleibt die Format-Inkonsistenz)
**Beleg:** Unbekannte Session → 401 (L3100, L3602) vs. 404 (L3300, L3510); interne Fehler → `500 {error:e.message}` vs. `502 {error, detail}` (L3672) vs. `401 {hhttps:{status:'invalid'}, error}` (L3738, L3763); `/revoke` L3704 `catch {}` verschluckt DB-Fehler stumm (Repro AP4-25 zeigt 401 trotz Schreibzugriff).
**Auswirkung:** Clients (SDK, Extension, `mapBackendError`) können Fehlerklassen nicht einheitlich unterscheiden.
**Empfehlung:** Einheitliches `{ error:<code>, detail? }` mit festen Codes und festen Statuscodes je Fehlerklasse.

### AP4-50 [S3] [Wartbarkeit] server/eudi-verifier/index.js:L232-273 vs. L327-370 vs. L408-437; L80-164 — Status-Handler bis auf den Direct-Fallback identisch; drei `call*`-Funktionen mit gleichem Rumpf
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Unterschied der Age-/AV-Status-Handler nur L355–357 und Log-Präfix; `callAgeUpgrade`/`callAgeDirect`/`callEidUpgrade` wiederholen Secret-Check, Nonce/Iat, HMAC, URL-Bau (`HHTTPS_INTERNAL_URL` 3×), `BackendError`; `EUDI_VERIFIER_SECRET` 4× gelesen (L81, L110, L143, L186). Der Cookie-Fix ist tatsächlich sechsfach angebracht (L239, L266, L333, L363, L414, L430).
**Auswirkung:** Jede Korrektur am Poll-Ablauf sechsfach (siehe AP4-08, AP4-14).
**Empfehlung:** `postInternal(path, payload)` und `statusHandler(kind)`.

### AP4-51 [S3] [Wartbarkeit] server/eudi-verifier/backend-client.js:L149-167, L255-272, L311-328; L118-142, L218-250, L291-306 — Drei identische Offer-Aufrufe; drei `ensure*Config`-Varianten mit inkonsistentem Konfliktverhalten
**Urteil:** BESTÄTIGT (Severity unverändert; Korrektheitsseite in AP4-15)
**Beleg:** Offer-Funktionen zeilengleich bis auf Fehlertext; Duplikat-Erkennung `r.status === 409 || /exist|duplicate|already/i` viermal (L137, L234, L304, L455).
**Auswirkung:** Änderungen an `buildDcqlQuery`/`buildPidDcqlQuery` erreichen bestehende Configs nicht.
**Empfehlung:** `ensureConfig({ id, description, dcql_query, patchIfExists:true })`, `createOffer(requestId, label)`.

### AP4-52 [S3] [Wartbarkeit] server/eudi-verifier/backend-client.js:L29-57, L183-196, L347-350, L437; server/.env.example:L62-65 — 16 EUDI-/EUDIPLO-Umgebungsvariablen, nur eine dokumentiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -o "process.env.EUDI[A-Z_]*" backend-client.js | sort -u | wc -l` → 14; index.js zusätzlich `EUDI_VERIFIER_SECRET`, `HHTTPS_INTERNAL_URL`. `.env.example` L62–65 nennt nur `EUDI_VERIFIER_SECRET`; `EUDIPLO_CLIENT_SECRET` (Pflicht, L66) und `EUDI_AV_TRUST_LIST` (Fail-open, AP4-35) fehlen.
**Auswirkung:** Pflichtvariablen nur aus dem Quellcode erkennbar.
**Empfehlung:** `eudi-verifier/config.js` + vollständige `.env.example`; `EUDIPLO_CLIENT_SECRET` beim Mount (server.js L529) prüfen.

### AP4-54 [S3] [Wartbarkeit] server/eudi-verifier/index.js:L3-14, L34-37; server/server.js:L3119-3121, L3236, L3603-3604; server/eudi-verifier/backend-client.js:L18, L24, L52, L115, L179, L342 — Veraltete und widersprüchliche Kommentare; offene CONFIRM-Punkte im Code
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** index.js L5–6 „official EU Verifier Endpoint backend (Docker, :8080)“ vs. backend-client L3–6; server.js L3236 „Called only by the eudi-verifier service (port 3002)“ — der Verifier ist In-Process (L529), 3002 ist EUDIPLO; L3119–3121 „Phase 3 will set this“ neben der Phase-3-Implementierung; L3603–3604 „consistent with /hhttps/role/declare“ falsch (AP4-06); sechs `**CONFIRM**`-Marker, davon zwei sicherheitsrelevant (AP4-24).
**Auswirkung:** Leser werden zur falschen Architektur geführt; offene Verifikationspunkte gehen unter.
**Empfehlung:** Header/Kommentare an EUDIPLO anpassen; CONFIRM-Punkte als Issues.

### AP4-56 [S4] [Wartbarkeit] server/server.js:L3208, L3230, L3375, L3575, L3659, L3729, L3748-3750 — Magic Strings/Numbers und Rollen-Ära-Relikte
**Urteil:** BESTÄTIGT (Severity unverändert; Korrektur: `'0.5.0'` steht 25× in server.js, nicht 22×)
**Beleg:** `grep -c "'0.5.0'" server.js` → 25; L3230 „Access (1h) + Refresh (7d)“ trotz `ACCESS_TTL`/`REFRESH_TTL` (L93–94); `/validate` L3724 `ROLES[d.role] || ROLES.citizen` bei `role:null` (L3170) → immer „Citizen/🧑“ (Repro bestätigt `"roleLabel":"Citizen"`); L3748–3750 Challenge-Endpoint `/hhttps/webauthn/auth/start` trotz E-Mail-first.
**Auswirkung:** Versionssprung = 25 Edits; Antwortfelder suggerieren ein Rollenmodell, das es nicht mehr gibt.
**Empfehlung:** `HHTTPS_VERSION`-Konstante; Rollenfelder deprecaten; Challenge-Endpoint aktualisieren.

### AP4-57 [S4] [Wartbarkeit] server/public/iamhmn-card-issuer.js:L21-23 — `RESERVED_STEMS` und `fold()` duplizieren server/roles.taxonomy.js L92-104
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L21 Stem-Liste und L22 Umlaut-Normalisierung im Browser-Modul; Server-Quelle roles.taxonomy.js L92 `export const RESERVED_STEMS`; Server erzwingt ohnehin (L3611, L3621).
**Auswirkung:** Registry-Änderungen erreichen die UI-Vorabwarnung nicht.
**Empfehlung:** Über `/hhttps/esco/suggest` (liefert bereits `reserved`) oder gemeinsam ausgelieferte Datei beziehen.

### AP4-58 [S4] [Wartbarkeit] server/external-verify.js:L127, L157, L162, L183, L199, L204 — Gemischt deutsch/englische Fehlermeldungen als API-Antwort
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L127/L157/L199/L204 deutsch, L162/L183/L187 englisch; server.js L3024, L3046–3050 reichen `e.message` nach außen.
**Auswirkung:** Nicht maschinenlesbare, uneinheitliche Fehlerstrings.
**Empfehlung:** Fehlercodes werfen, Texte im Aufrufer.

### AP4-59 [S4] [Wartbarkeit] ESLint-Warnungen (gesammelt) — server/server.js:L3098, L3320, L3531; server/eudi-verifier/index.js:L213; server/eudi-verifier/backend-client.js:L370
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `npx eslint` über die AP4-Dateien: server.js 3098:22 `role`, 3098:28 `verificationMethod`, 3320:16 `_`, 3531:16 `_`; index.js 213:13 `qrDataUrl`; backend-client.js 370:57 `_responseCode` (alle `no-unused-vars`). `response_code` wird an drei Stellen durchgereicht (L243, L337, L418) und nie verwendet.
**Auswirkung:** Irreführende Signaturen (suggeriertes `response_code`-Handling).
**Empfehlung:** Unbenutzte Destrukturierungen/Variablen entfernen; `pollWalletResponse(transactionId)`; `catch {}` ohne Binding.

## Verworfen
— keine. (AP4-05 wurde in einem Teilaspekt korrigiert — `?jti=a&jti=b` führt zu keinem Hänger —, das Kernfinding bleibt bestätigt.)

## Zusammengeführt
- AP4-19 [S2] [Sicherheit] server/server.js:L3719-3741, L3744-3760 — Machine-Tokens als `human:true` → in AP4-01 (gleiche Ursache: `checkTokenValid` prüft `sub` nicht).
- AP4-22 [S2] [Sicherheit] server/server.js:L3683-3686 — Refresh-Token überlebt Revoke → in AP4-03 (identisch; AP4-03 auf S2 angehoben).
- AP4-26 [S3] [Sicherheit] server/server.js:L3719-3741, L3744-3760 — Refresh-Tokens von validate/protected akzeptiert → in AP4-01 (gleiche Ursache).
- AP4-30 [S3] [Sicherheit] server/external-verify.js:L106-115, L221-226, L239 — GitHub-Anker-Umhängung → in AP4-11 (identisch).
- AP4-44 [S4] [Performance] server/public/iamhmn-card-issuer.js:L130 — Click-Listener/Typeahead → in AP4-17 (identisch).
- AP4-46 [S2] [Wartbarkeit] server/server.js:L3341-3357 — Token-Surface von Hand in age/upgrade → in AP4-02 (identisch).
- AP4-53 [S3] [Wartbarkeit] server/eudi-verifier/docker/docker-compose.yaml:L1-49 — tote Compose-Konfiguration → in AP4-16 (identisch).
- AP4-55 [S3] [Wartbarkeit] server/test/** — fehlende Tests → in AP4-12 (identisch, Umfang dort übernommen).

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit | 17 | 17 | 0 | 0 |
| Sicherheit | 19 | 15 | 0 | 4 |
| Performance | 9 | 8 | 0 | 1 |
| Wartbarkeit | 14 | 11 | 0 | 3 |
| **Gesamt** | **59** | **51** | **0** | **8** |

Je Severity bestätigt: S1 1 (AP4-18), S2 6 (AP4-01, -02, -03, -20, -21, -23), S3 27, S4 17.

Severity-Änderungen: AP4-03 S3 → S2 (Repro: Widerruf wirkungslos, Spec bewirbt „Revocable“). Korrekturen an Rohbefunden: AP4-05 (Array-`jti` hängt nicht), AP4-25 (`limit.revoke` = 30/min, nicht 30/15 min), AP4-56 (25 statt 22 Literale), K-Zusammenfassung (17 statt 16 Findings).

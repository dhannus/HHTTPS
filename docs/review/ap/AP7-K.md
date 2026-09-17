# AP7 — Korrektheit

Geprüfte Dateien: server/privacy-pass/index.js, issuer.js, issuance.js, verifier.js, verifier-internal.js, verifications.js, verifications-api.js, role-requirements.js, keys.js, well-known.js, demo.js (migrations.js nur gelesen, AP6); server/privacy-pass/public/wallet.html; server/sdk/client.js; server/sdk/client.py; server/test/e2e/wallet.e2e.test.mjs. Zum Verständnis gelesen (keine Findings): server/server.js (role/declare, register/start|finish, email/status, check), server/db.js (sessions), server/roles.js, server/email.js, node_modules/@cloudflare/voprf-ts.

Stand: `main` @ `bf0a82b`, Zeilennummern per `awk`/`sed -n` geprüft.

---

### [S2] [Korrektheit] server/privacy-pass/issuance.js:L77-82 — `/privacy-pass/issue` verlangt `session.role === role`, aber kein Server-Pfad setzt `sessions.role` mehr → Token-Ausgabe über die Wallet ist vollständig blockiert
**Begründung:** Der Handler lehnt ab, wenn `session.role !== role`. Die Wallet „attestiert“ die Rolle vorher über `POST /hhttps/role/declare` (wallet.html L1185-1191, `verificationMethod: 'self_declared'`). Seit v0.5 nimmt `/hhttps/role/declare` jedoch keine Rolle mehr aus dem Request („we do not take a role from the request“, server.js L3112-3114) und schreibt nur `db.sessions.update(sessionId, { trustScore })`. Es gibt im gesamten Server keinen `sessions.update(..., { role })`-Aufruf mehr (grep über `server/`; `db.js:595` betrifft `roles_declared`, nicht `sessions`). `session.role` ist damit immer `null`:
```js
if (session.role !== role) {
  return res.status(403).json({ error: 'role_mismatch',
    detail: `session role is ${session.role || 'unset'}, requested ${role}` });
```
**Auswirkung:** Jeder Aufruf von `/privacy-pass/issue` endet mit 403 `role_mismatch` („session role is unset“); die Wallet-Schritte 4/5 (Tokens holen, einlösen) sind für alle Nutzer funktionsunfähig. `/eligibility` und `/email/start` (L75: toleriert `null`) melden hingegen „alles erfüllt“, sodass der Nutzer erst am Ende scheitert.
**Empfehlung:** Rollenbindung neu definieren: entweder die Rolle aus einem gültigen HHTTPS-Access-Token (Claim `role`, via `verifyToken`) bzw. der EUDI-(Q)EAA ableiten, oder — wenn Rollen für Privacy Pass weiterhin selbst gewählt werden dürfen — den Vergleich in eine reine Eligibility-Prüfung (`eligibilityFor(credentialId, role)`) umwandeln und den `session.role`-Check entfernen. Dazu einen Integrationstest `role/declare → /privacy-pass/issue → 200` ergänzen (siehe Test-Finding unten).

### [S2] [Korrektheit] server/privacy-pass/issuance.js:L98-110,L145 — Rate-Limit ist Check-then-Act ohne Transaktion/Lock; parallele Requests umgehen die 10-Tokens/24h-Grenze
**Begründung:** `getRecentIssuanceCount` (L98) liest die Summe aus `pp_issuance_log`, danach werden alle Blind-Evaluationen durchgeführt (L117-142, mehrere ms pro Request) und erst am Ende `logIssuance` (L145) geschrieben. Zwei oder mehr gleichzeitig eintreffende `/issue`-Requests derselben Credential sehen alle `usage = 0` und werden alle bedient. Es gibt keinen `SELECT … FOR UPDATE`, keine Advisory-Lock und keinen Unique-Constraint, der das verhindert.
**Auswirkung:** Die Sybil-Schranke („a single authenticator can only mint a bounded number of anonymous tokens per day“, Kopfkommentar L13-15) ist mit N parallelen Requests auf N×10 Tokens dehnbar; genau die Eigenschaft, auf der die Anonymitäts-/Missbrauchsargumentation des Moduls beruht.
**Empfehlung:** Zählen und Loggen in einer Transaktion mit `pg_advisory_xact_lock(hashtext(credential_id))` (oder `SELECT … FOR UPDATE` auf einer Quota-Zeile pro Credential) kapseln; das Log vor der Evaluation schreiben und bei Fehler zurückrollen.

### [S2] [Korrektheit] server/privacy-pass/public/wallet.html:L1025-1067 — Recovery-Flow verbrennt den Einmal-Code, registriert aber keinen Schlüssel am wiederhergestellten Account
**Begründung:** `useRecoveryCode` (L1025-1049) ruft `/privacy-pass/recovery/use` auf; der Server markiert den Code sofort als verbraucht (verifications.js L167-174) und liefert nur `userId` zurück — es entsteht keine Session für diesen Account. Die Wallet setzt `userId = d.userId` (L1041) und ruft `registerNewCredential()` (L1051-1067): `ensureHhttpsSession()` erzeugt eine frische Session, `registerStart()` schickt nur `{ sessionId }`, der Server ignoriert den Body-`userId` und nutzt `session.userId` der E-Mail-Verankerung (server.js register/start: „with sessionId the body userId is ignored“). `register/finish` wird dann mit dem *wiederhergestellten* `userId` gesendet (L1059-1062):
```js
body: JSON.stringify({ userId, response: att, sessionId }),
```
Der Server prüft `session.userId !== userId → 401 session_user_mismatch`. Nur wenn die bestätigte E-Mail zufällig zu genau diesem Account gehört, klappt es — dann hätte man aber keinen Recovery-Code gebraucht.
**Auswirkung:** Der Nutzer verliert pro Versuch einen seiner 10 Codes, bekommt „Registrierung fehlgeschlagen“ und keinen neuen Schlüssel; nach 10 Versuchen ist die Wiederherstellung endgültig unmöglich.
**Empfehlung:** `/recovery/use` muss eine (kurzlebige, E-Mail-verifizierte) Session mit `userId` des wiederhergestellten Accounts anlegen und deren `sessionId` zurückgeben; die Wallet nutzt diese Session für `register/start|finish`. Alternativ den Code erst nach erfolgreichem `register/finish` als verbraucht markieren.

### [S2] [Korrektheit] server/privacy-pass/verifications-api.js:L61,L70,L95-101,L156 — Client-gelieferter `method` wird ungeprüft als erfüllte Verifikationsmethode gespeichert
**Begründung:** `/email/start` übernimmt `method` aus dem Body (`const verificationMethod = method || 'email-verified'`, L70) ohne Whitelist-Prüfung, schreibt ihn in `pp_email_pending` (L95-101) und `/email/verify` trägt ihn nach dem Link-Klick 1:1 als `method` in `pp_attribute_verifications` ein (L156). `eligibilityFor` (verifications.js L72-77) zählt jede Zeile dort als „completed“. Damit erfüllt ein E-Mail-Link mit `method: 'approbation-id'`, `'bar-association-id'`, `'notary-chamber-id'` usw. die Pflicht-Anforderungen strikter Rollen (role-requirements.js L59, L73, L81); `recordVerification` vergibt zudem den vollen Trust-Score des behaupteten Verfahrens (verifications.js L43).
**Auswirkung:** Zustand in `pp_attribute_verifications` ist falsch (Methode ≠ tatsächlich durchgeführte Prüfung); die Rollen-Gates aus role-requirements.js sind wirkungslos. (Überschneidet sich mit Sicherheit; hier als Logikfehler/fehlende Validierung geführt.)
**Empfehlung:** `method` in `/email/start` auf E-Mail-basierte Methoden beschränken (z. B. `['email-verified','school-email','medical-email','lawyer-email','official-email']`) und alles andere mit 400 ablehnen; `recordVerification` nur für die Methode aufrufen, die tatsächlich geprüft wurde.

### [S2] [Korrektheit] server/privacy-pass/role-requirements.js:L61,L69,L75,L89 — Domain-Regexe sind nicht am Ende verankert; beliebige Fremddomains erfüllen die „strikte“ Domain-Bedingung
**Begründung:** `emailDomainMatchesRole` (L151-158) testet die Regex gegen die komplette Domain. Bei `medical_professional` (L61), `caregiver` (L69), `lawyer` (L75) und der zweiten Alternative von `civil_servant` (L89: `|(polizei|finanzamt|zoll|verwaltung|kommune)/i`) fehlt `$`, bei L61/L75/L89 auch ein Anfangs-/Punkt-Anker. Beispiele, die matchen: `zoll-freunde.example.com` (civil_servant, strict, nur `email-verified` erforderlich), `klinik.attacker.io` (medical), `anwalt.beispiel.org` (lawyer), `medi-xyz.net` (medical).
**Auswirkung:** Die als Gate gedachte Bedingung „Public-authority identity requires an official government email“ (L92) ist für `civil_servant` durch jede Domain mit dem Teilstring `zoll`, `polizei` … erfüllbar; `/email/start` lässt die Verifikation zu und das Token wird für die strikte Rolle ausgestellt.
**Empfehlung:** Alle Alternativen mit `(^|\.)…$` verankern und die generischen Wortlisten (`polizei|finanzamt|…`, `klinik…`, `anwalt…`) entweder streichen oder als explizite Domain-Allowlist (z. B. `polizei\.[a-z-]+\.de$`) formulieren; Unit-Tests mit Positiv-/Negativ-Domains je Rolle ergänzen.

---

### [S3] [Korrektheit] server/privacy-pass/keys.js:L80,L143-150 — Kollisionen des `truncated_token_key_id` (1 Byte) über 16 Issuer werden weder erkannt noch behandelt
**Begründung:** Der Key-Identifier ist das letzte Byte von SHA-256(pub) (L80, L128). Mit 16 Issuern (default + 15 Rollen) liegt die Kollisionswahrscheinlichkeit bei der Erstgenerierung bei ≈38 % (1−∏(1−i/256), i=0..15). `findIssuerByTruncatedKeyId` (L143-150) gibt bei Kollision den *ersten* Treffer in Map-Reihenfolge zurück; `loadOrCreateKeys` prüft nichts. (Die aktuell im Repo-Verzeichnis liegenden 16 `meta.json` sind zufällig kollisionsfrei — geprüft; für andere Deployments gilt das nicht.)
**Auswirkung:** Am öffentlichen RFC-Endpunkt `POST /privacy-pass/token-request` (issuer.js L82-105) wird bei Kollision der falsche Schlüssel verwendet; der Client scheitert beim DLEQ-Proof bzw. erhält ein Token, das später `authenticator mismatch` liefert. Nicht deterministisch reproduzierbar, daher schwer zu diagnostizieren.
**Empfehlung:** Beim Laden/Generieren Eindeutigkeit der Truncated-IDs prüfen und bei Kollision den Schlüssel neu generieren (RFC 9578 §6.1 verlangt vom Issuer eindeutige truncated IDs pro Directory), oder `token-request` zusätzlich mit einem Rollen-Pfad (`/r/:role/token-request`) anbieten.

### [S3] [Korrektheit] server/privacy-pass/keys.js:L61-75,L77-95 — Fehlt eine der drei Key-Dateien (z. B. `meta.json`), wird stillschweigend ein neues Schlüsselpaar erzeugt und der alte Private Key überschrieben
**Begründung:** Die Bedingung `existsSync(privFile) && existsSync(pubFile) && existsSync(metaFile)` (L61) fällt bei einer fehlenden Datei in den Generierungszweig, der `voprf-private.bin` mit `writeFileSync` (L83) ersetzt — ohne Warnung, ohne Backup.
**Auswirkung:** Unbeabsichtigte Key-Rotation: alle in Wallets gespeicherten Tokens dieser Rolle werden ungültig (`token_key_id matches no known issuer`), obwohl kein Rotationsereignis geplant war; der alte Private Key ist verloren.
**Empfehlung:** Bei teilweise vorhandenen Dateien mit Fehler abbrechen (oder `meta.json` aus `pub` rekonstruieren) statt zu regenerieren; nie einen existierenden `voprf-private.bin` überschreiben.

### [S3] [Korrektheit] server/privacy-pass/demo.js:L20,L49 — Import eines nicht existierenden Exports `parseTokenAndVerify`; das Modul ist beim Laden kaputt
**Begründung:** `verifier-internal.js` exportiert `parseToken`, `findIssuerForToken`, `parseAndVerify` — nicht `parseTokenAndVerify`. Ein `import` von demo.js wirft `SyntaxError: The requested module './verifier-internal.js' does not provide an export named 'parseTokenAndVerify'`. Zusätzlich verweist L29 auf `public/demo.html`, das nicht existiert (`ls privacy-pass/public` → `lib`, `wallet.html`). demo.js wird derzeit nirgends importiert (grep), ist also toter, aber falscher Code.
**Auswirkung:** Sobald jemand `demoRouter` mountet (wie der Kopfkommentar L4-7 nahelegt), startet der Server nicht.
**Empfehlung:** Datei entfernen oder auf `parseAndVerify` umstellen (`const { valid } = await parseAndVerify(buf)`) und `demo.html` liefern; in CI zumindest `node --check`/Import aller Module unter `privacy-pass/` erzwingen.

### [S3] [Korrektheit] server/privacy-pass/verifications-api.js:L72-74,L95-101 — `/email/start` mit E-Mail-only-Session (ohne Passkey) endet in 500 statt 401/403
**Begründung:** Eine Session aus `POST /hhttps/session/start` existiert und ist gültig, hat aber `credentialId = null`. Der Handler prüft nur `!session` (L74) und ruft `createEmailPending({ credentialId: session.credentialId, … })` auf; `pp_email_pending.credential_id` ist `NOT NULL` (migrations.js L68) → `INSERT` wirft → Catch L128-131 antwortet 500 `email_start_failed` mit der PG-Fehlermeldung als `detail`.
**Auswirkung:** Falscher Statuscode und Leak der DB-Fehlermeldung; die Wallet zeigt „✗ null value in column …“. Gleicher Pfad in `/recovery/generate` (L257: erzeugt Codes für `session.userId` ohne Credential-Prüfung).
**Empfehlung:** Wie in issuance.js L74-76 explizit `if (!session.credentialId) return 401 unauthenticated` vor dem DB-Zugriff.

### [S3] [Korrektheit] server/privacy-pass/public/wallet.html:L1320-1352 — `submitAttribute` meldet „im Pilot-Modus akzeptiert“, obwohl nichts gespeichert wird, und feuert einen unsinnigen `/email/start`-Fallback
**Begründung:** Der Nachweis wird an `/hhttps/role/declare` gesendet (L1330-1337), das seit v0.5 weder Rolle noch `verificationData` verarbeitet und nichts in `pp_attribute_verifications` schreibt (grep: keine Schreiber außerhalb von privacy-pass/). Bei `!r.ok` folgt ein Fallback-POST `/privacy-pass/email/start` mit `email: 'attribute@self-declared'` (L1340-1343) — der Server-Check `email.includes('@')` (verifications-api.js L65) lässt das durch, es wird eine Pending-Zeile angelegt und ein Mailversand an eine ungültige Adresse versucht; das Ergebnis `r2` wird nie ausgewertet (Kommentar L1344-1345 gibt das zu). Unabhängig vom Ausgang wird `tr('js.pilotAccepted')` geloggt (L1347).
**Auswirkung:** Für strikte Rollen (`approbation-id`, `bar-association-id`, `notary-chamber-id`) kann die Anforderung aus der Wallet nie erfüllt werden; der Nutzer sieht eine Erfolgsmeldung und anschließend weiterhin „Noch fehlend“. Zusätzlich Fehlversuche im Mail-Transport.
**Empfehlung:** Fallback entfernen; entweder einen echten Backend-Endpunkt (`POST /privacy-pass/attribute` mit Whitelist der Methoden) bereitstellen oder den Nachweis-Schritt in der Wallet als „noch nicht verfügbar“ deaktivieren. Erfolg nur bei `r.ok` melden.

### [S3] [Korrektheit] server/sdk/client.js:L337-344 (und server/sdk/client.py:L192-197) — Unbekannter `kid` löst keinen JWKS-Refresh aus, sondern fällt auf `keys[0]` des gecachten JWKS zurück
**Begründung:** `_resolveKey` sucht den `kid` nur im (bis zu 1 h alten) Cache und nimmt bei Nichttreffer `keys[0]`:
```js
const jwk = (kid ? keys.find(k => k.kid === kid) : keys[0]) || keys[0];
```
Nach einer Schlüsselrotation auf dem Issuer tragen neue Tokens einen neuen `kid`; der SDK-Client verifiziert sie bis zu `jwksMaxAgeMs` lang mit dem alten Schlüssel und meldet `bad signature`. Der Fehlertext „unknown kid“ (L117) ist nie erreichbar, solange das JWKS mindestens einen Key hat. Python L195 identisch.
**Auswirkung:** Bis zu eine Stunde lang werden alle frisch ausgestellten Tokens von Relying Parties als ungültig abgelehnt (Dokumentation L61-63 verspricht „keeps working across a key rotation“).
**Empfehlung:** Bei `kid`-Miss einmalig `getJwks()` mit erzwungenem Refetch aufrufen (Cache invalidieren) und erst danach `unknown kid` zurückgeben; keinen stillen Fallback auf `keys[0]`, wenn ein `kid` angegeben ist.

### [S3] [Korrektheit] server/sdk/client.js:L152-159,L376-390 — `check()` wirft bei ungültigem Token (401) statt ein `status:'invalid'`-Ergebnis zu liefern; `res.json()` vor `res.ok`-Prüfung
**Begründung:** `/hhttps/check` antwortet auf ungültige Tokens mit `401 { hhttps:{status:'invalid'}, error }` (server.js L937-938). `_fetchAbsolute` ruft `await res.json()` (L386) und wirft dann `new Error(data.error)` (L387). `check(token)` (L152-159) fängt das nicht → Promise-Rejection; die Doku L12-15/L148-151 und der Python-Client (`check()` fängt alles und liefert `HHTPPSResult()`) beschreiben ein Ergebnisobjekt. Bei Nicht-JSON-Antworten (nginx-502-HTML, 429-Text von express-rate-limit) wirft L386 zusätzlich einen `SyntaxError` statt „HTTP 502/429“.
**Auswirkung:** Aufrufer, die `check()` direkt nutzen (nicht über `middleware()`), müssen jede ungültige Nutzereingabe als Exception behandeln; Fehlermeldungen bei Infrastrukturfehlern sind irreführend („Unexpected token <“).
**Empfehlung:** In `_fetchAbsolute` erst `res.ok`/Content-Type prüfen, Body tolerant parsen; in `check()` 401 in `{ ...this._unverified(), status: 'invalid' }` übersetzen (Parität zu `verifyLocal` und zum Python-SDK).

### [S3] [Tests] server/test/e2e/wallet.e2e.test.mjs:L80-131 — Einziger Privacy-Pass-Test deckt nur den Login ab; Issuance/Verify/Redeem/Eligibility/E-Mail-Verify/Recovery sind komplett ungetestet
**Begründung:** Unter `server/test/{unit,integration}` gibt es keine Datei, die `/privacy-pass/*` anspricht (grep `privacy-pass` → nur `legacy-pages.test.mjs`, das den Wallet-Script-Text regex-prüft, und der e2e-Test). Der e2e-Test endet bei „Angemeldet“ (L118-129). Konkret ungetestet: `POST /privacy-pass/issue` (hätte Finding 1, den dauerhaften 403 `role_mismatch`, sofort gezeigt), `parseAndVerify`/`/redeem` inkl. Double-Spend (`ON CONFLICT`), `checkEligibility` mit strikten Rollen, `emailDomainMatchesRole` (Finding 5), `/email/start`→`/email/verify`-Kette, `consumeRecoveryCode`, Wire-Format-Annahmen in issuer.js L49-64 / wallet.html L1424-1430 gegenüber `@cloudflare/voprf-ts`.
**Auswirkung:** Regressionen im Kernpfad (Blind-Evaluate → Finalize → Verify) und in den Gates bleiben unentdeckt; der aktuelle Bruch der Ausgabe ist ein Beispiel.
**Empfehlung:** Integrationstest, der mit `VOPRFClient` aus `@cloudflare/voprf-ts` 2 Tokens über `/issue` holt, finalisiert, `/verify` → valid, `/redeem` → redeemed, zweites `/redeem` → `already_redeemed`; Unit-Tests für `checkEligibility`/`emailDomainMatchesRole`; e2e um Schritt 2-5 erweitern.

---

### [S4] [Korrektheit] server/privacy-pass/issuance.js:L118,L140 — Nicht-String-Elemente in `requests` und ungültige Gruppenelemente führen zu 500 statt 400
**Begründung:** `Buffer.from(requests[i], 'base64')` wirft `TypeError` bei Zahlen/Objekten im Array; `EvaluationRequest.deserialize` (issuer.js L49-52) wirft bei einem Byte-String korrekter Länge, der kein gültiger P-384-Punkt ist. Beides landet im Catch L156-159 → 500 `issuance_failed` mit interner Fehlermeldung.
**Auswirkung:** Falsche Statusklasse (Client-Fehler als Serverfehler), Monitoring-Rauschen.
**Empfehlung:** `typeof requests[i] === 'string'` prüfen; Deserialisierung in try/catch mit 400 `malformed_request`.

### [S4] [Korrektheit] server/privacy-pass/issuance.js:L101-102,L108 — `Retry-After`/`window_seconds` melden immer das volle 24-h-Fenster
**Begründung:** `reset = Math.ceil(RATE_WINDOW_MS / 1000)` ignoriert, wann der älteste Eintrag im Fenster fällt.
**Auswirkung:** Clients warten bis zu 24 h länger als nötig bzw. Wallet zeigt falsche Restzeit.
**Empfehlung:** `MIN(issued_at)` im Fenster mit abfragen und `Retry-After = issued_at + 24h − now` berechnen.

### [S4] [Korrektheit] server/privacy-pass/public/wallet.html:L1363,L1383 — Wallet fordert immer 10 Tokens an, Button ist nur bei `remaining === 0` gesperrt
**Begründung:** `N = 10` fest; bei `0 < remaining < 10` (z. B. anderer Client hat Tokens geholt) antwortet der Server 429 `rate_limited`.
**Auswirkung:** Nutzer sieht „Verbleibend: 3“, klickt und erhält eine Fehlermeldung.
**Empfehlung:** `N = Math.min(10, q.remaining)` aus `refreshQuota` übernehmen.

### [S4] [Korrektheit] server/privacy-pass/verifications.js:L147-159 — Recovery-Codes: `DELETE` + 10 `INSERT`s ohne Transaktion
**Begründung:** Bricht ein `INSERT` (z. B. Pool-/Verbindungsfehler) ab, sind alte Codes bereits gelöscht und nur ein Teil der neuen gespeichert; der Client bekommt 500 und keine Codes.
**Auswirkung:** Nutzer ohne funktionierende Recovery-Codes, ohne es zu wissen (Status zeigt ggf. „3 Codes verfügbar“).
**Empfehlung:** In einer Transaktion (`BEGIN … COMMIT`) mit einem Multi-Row-`INSERT` ausführen.

### [S4] [Korrektheit] server/sdk/client.js:L393-394, server/sdk/client.py:L222 — Toter CommonJS-Shim bzw. fehlendes URL-Encoding
**Begründung:** client.js ist ein ES-Modul (`export class`); `require()` scheitert bereits am Parser, der `module.exports`-Zweig ist unerreichbar bzw. wirft in Bundlern `module is not defined`-Warnungen. client.py `is_revoked` interpoliert `jti` unkodiert in die Query (JS-Pendant L201 nutzt `encodeURIComponent`).
**Auswirkung:** Irreführende Kompatibilitätszusage; Sonderzeichen in `jti` brechen den Aufruf (bei UUID-JTIs praktisch nicht).
**Empfehlung:** Shim entfernen oder echte Dual-Package-Auslieferung; `urllib.parse.quote(jti)` verwenden.

### [S4] [Wartbarkeit/Lint] server/privacy-pass/issuer.js:L9 (`Oprf`, `Ns`), server/privacy-pass/verifications.js:L12 (`ROLES`), server/privacy-pass/verifier.js:L11 (`findIssuerForToken`) — ungenutzte Importe
**Begründung:** ESLint `no-unused-vars` (siehe 01-automatische-checks.md); `ROLES` aus `roles.js` ist zudem ein Objekt, während `ROLES` aus `keys.js` ein Array ist — Verwechslungsgefahr.
**Auswirkung:** Keine funktionale; Lint-Rauschen.
**Empfehlung:** Importe entfernen.

## Zusammenfassung

S1: 0 · S2: 5 · S3: 8 · S4: 6 (gesamt 19)

Die Krypto-Kernlogik (VOPRF-Blind-Evaluate, Token-Parsing, constant-time-Vergleich, atomare Double-Spend-Sperre via `ON CONFLICT`) ist sauber umgesetzt und stimmt mit dem Wire-Format von `@cloudflare/voprf-ts` überein. Der Ausgabe-Pfad ist jedoch durch die v0.5-Umstellung von `/hhttps/role/declare` funktional gebrochen (`session.role` wird nie gesetzt → dauerhaft 403), und die Gates darum herum (Client-gesteuerter `method`, unverankerte Domain-Regexe, Check-then-Act-Rate-Limit) halten ihre eigenen Zusagen nicht ein; der Recovery-Flow verbrennt Codes ohne Ergebnis. Dass all das unbemerkt blieb, liegt an fehlenden Tests: außer dem Login gibt es für das gesamte Privacy-Pass-Modul keinen einzigen automatisierten Test.

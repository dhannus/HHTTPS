# AP7 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b (Arbeitsbaum `claude/kind-pasteur-kweqf1`@0ecc431 ist unter `server/` diff-identisch zu bf0a82b)

Methodik: Jedes Finding an Datei:Zeile geprüft (`cat -n`/`grep -n`), Zeilennummern korrigiert wo nötig. Zusätzlich Live-Repro gegen den Test-Server (`TEST_PG_HOST=/var/lib/pgtest EMAIL_DEV_MODE=1`, Skript `scratchpad/ap7-repro.mjs`, Client-Seite mit `@cloudflare/voprf-ts`): Session per E-Mail-Flow angelegt, Credential per SQL angehängt, dann `/issue`, `/email/start|verify`, `/token-request`, `/verify`, `/redeem`, `/recovery/*` angesprochen. Ergebnisse sind unten als „Repro:“ zitiert.

IDs in Reihenfolge K (01–19), S (20–37), P (38–46), W (47–66).

## Bestätigte Findings

### AP7-01 [S2] [Korrektheit] server/privacy-pass/issuance.js:L77-82 — `/privacy-pass/issue` verlangt `session.role === role`, aber kein Server-Pfad setzt `sessions.role` → Token-Ausgabe über die Wallet dauerhaft 403
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rn "sessions.update" server --include=*.js` liefert genau drei Aufrufer: `server.js:2812` (`bindSessionToEmailAnchor`: userId/pseudonym/email*-Felder), `server.js:3186` (`/hhttps/role/declare`: nur `{ trustScore }`), `external-verify.js:229` (`githubVerified`, `githubTrustBonus`). `sessions.create` (db.js L148-160) schreibt keine `role`-Spalte; `eudi-verifier/` enthält keinen Sessions-Schreibzugriff; das einzige rohe `UPDATE sessions` ist die generische `update()` in db.js L195. `/hhttps/role/declare` (server.js L3112-3114) nimmt ausdrücklich keine Rolle mehr aus dem Request. Damit bleibt `sessions.role` (schema.sql L40, Default NULL) immer `null`. Repro: `POST /privacy-pass/issue` mit gültiger Session + Credential + korrekten TokenRequests → `403 {"error":"role_mismatch","detail":"session role is unset, requested citizen"}`; erst nach `UPDATE sessions SET role='citizen'` per SQL kommt der Handler zur Eligibility-Prüfung (`403 not_eligible`). Die Wallet ruft vorher `/hhttps/role/declare` (wallet.html L1185-1191) auf, das die Rolle ignoriert.
**Auswirkung:** Schritte 4/5 der Wallet (Tokens holen/einlösen) sind für alle Nutzer funktionsunfähig; `/eligibility` und `/email/start` (L75 toleriert `null`) melden vorher „alles erfüllt“. Sicherheitsseitig fail-closed — daher kein S1.
**Empfehlung:** Rollenbindung neu definieren (Rolle aus verifiziertem Access-Token/EUDI-EAA ableiten oder `session.role`-Vergleich durch reine `eligibilityFor`-Prüfung ersetzen). Vor dem Entfernen des Checks zwingend AP7-04/05/20 beheben, sonst wird die dort beschriebene Gate-Umgehung sofort scharf. Integrationstest `role → /issue → 200` ergänzen (AP7-13).

### AP7-02 [S2] [Korrektheit/Sicherheit] server/privacy-pass/issuance.js:L98-110,L145,L164-183 — Quota-Prüfung ist Check-then-Act ohne Transaktion/Lock; parallele Requests umgehen 10 Tokens/24h
**Urteil:** BESTÄTIGT (Severity unverändert; S-Duplikat AP7-23 zusammengeführt)
**Beleg:** `getRecentIssuanceCount` (L98 → L164-174, `SELECT SUM(token_count)`), danach Blind-Evaluation (L117-142), erst dann `logIssuance` (L145 → L176-183, `INSERT`). Kein `FOR UPDATE`, kein Advisory-Lock, kein Constraint (migrations.js L17-27). Repro: 5 parallele `/issue`-Aufrufe mit je 10 Requests auf dieselbe Credential → Status `[200,200,200,200,200]`, `SUM(token_count)` in `pp_issuance_log` = **50** bei Limit 10. Alle ausgegebenen Tokens waren anschließend über `/verify` gültig (`{"valid":true,"role":"citizen"}`).
**Auswirkung:** Die Sybil-Schranke (Kopfkommentar L13-15) ist mit N parallelen Requests auf N×10 dehnbar; die Tokens sind unlinkbar und nicht widerrufbar.
**Empfehlung:** Zählen und Loggen in einer Transaktion mit `pg_advisory_xact_lock(hashtext(credential_id))` (oder `SELECT … FOR UPDATE` auf einer Quota-Zeile) kapseln; Log vor der Evaluation schreiben und bei Fehler zurückrollen.

### AP7-03 [S2] [Korrektheit] server/privacy-pass/public/wallet.html:L1025-1067 — Recovery-Flow verbrennt den Einmal-Code, registriert aber keinen Schlüssel am wiederhergestellten Account
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `/recovery/use` (verifications-api.js L293-314) markiert den Code sofort als verbraucht (`consumeRecoveryCode`, verifications.js L167-174) und liefert nur `userId`; keine Session entsteht. Wallet L1041 setzt `userId = d.userId`, `registerNewCredential()` (L1051-1067) ruft `ensureHhttpsSession()` (L819-829: frische Session via `/hhttps/session/start`) und `ensureEmailVerified()` (L838-849: E-Mail-Code-Dialog); `registerStart()` (L907-920) sendet nur `{ sessionId }`, der Server nimmt `session.userId` (server.js L2413-2427 „with sessionId the body userId is ignored“). `register/finish` wird mit dem wiederhergestellten `userId` gesendet (L1059-1062); der Server prüft `session.userId !== userId → 401 session_user_mismatch` (server.js L2466-2469). Nur wenn die bestätigte E-Mail zum selben Anchor gehört, gelingt es — dann war kein Code nötig.
**Auswirkung:** Pro Versuch ein Code weniger, Meldung „Registrierung fehlgeschlagen“, kein neuer Schlüssel; nach 10 Versuchen ist Recovery endgültig unmöglich. Siehe auch AP7-30 (Endpunkt-Seite).
**Empfehlung:** `/recovery/use` muss eine kurzlebige Session mit dem wiederhergestellten `userId` und Registrierungserlaubnis anlegen und deren `sessionId` zurückgeben; alternativ Code erst nach erfolgreichem `register/finish` verbrauchen.

### AP7-04 [S1] [Sicherheit/Korrektheit] server/privacy-pass/verifications-api.js:L61,L70,L95-101,L156-159 — Frei wählbares `method` in `/email/start` wird per E-Mail-Klick als erfüllte Registerprüfung (`approbation-id`, `bar-association-id`, `notary-chamber-id`) gespeichert
**Urteil:** BESTÄTIGT (hochgestuft von S2 auf S1 wegen vollständiger Umgehung der „strict“-Anforderungen mit vollem Trust-Score; S-Duplikat AP7-22 zusammengeführt)
**Beleg:** L70 `const verificationMethod = method || 'email-verified'` ohne Whitelist; L95-101 speichert es in `pp_email_pending`; L156 `recordVerification(pending.credential_id, pending.role, pending.method, …)`; verifications.js L43 vergibt `VERIFICATION_LEVELS[method].trustScore` (roles.js L88-90: 92/95/93). `resolveVerification`/`VERIFICATION_CHECKS` aus roles.js (L225-290, dort `approbation-id: implemented:false → self-declared 30`) werden nicht benutzt. `checkEligibility` (role-requirements.js L135) prüft nur Namensgleichheit. Repro: `POST /email/start {role:'citizen', email:'a@example.org', method:'approbation-id'}` → 200; Link-Klick → 200; DB: `pp_attribute_verifications` = `{method:'approbation-id', trust_score:93}`; `/eligibility` → `completed:["webauthn","approbation-id","email-verified"], trustScore:93`. Für `notary` (kein Domain-Muster) ist damit jede Adresse ausreichend; für `medical_professional`/`lawyer` genügt eine Domain nach AP7-05. Die Wallet nutzt diesen Pfad selbst als Fallback (L1340-1343, AP7-10).
**Auswirkung:** Die Register-Gates der höchsten Vertrauensstufe sind wirkungslos; der gespeicherte Zustand ist falsch (Methode ≠ durchgeführte Prüfung). Aktuell nur deshalb nicht in Rollen-Tokens umsetzbar, weil `/issue` an AP7-01 scheitert — `/token-request` (AP7-20) liefert die Tokens ohnehin.
**Empfehlung:** `method` serverseitig auf E-Mail-basierte Methoden (`email-verified`, ggf. `school-email`, `medical-email`, `lawyer-email`, `official-email`) beschränken, Fremdwerte 400; `recordVerification` den Score über `resolveVerification()` ermitteln lassen.

### AP7-05 [S1] [Sicherheit/Korrektheit] server/privacy-pass/role-requirements.js:L61,L69,L75,L89,L97,L151-158 — Domain-Regexe sind unverankerte Substring-Muster; Fremddomains erfüllen strikte Rollen
**Urteil:** BESTÄTIGT (hochgestuft von S2 auf S1: für `civil_servant`/`politician` ist die Domain die *einzige* strikte Anforderung; S-Duplikat AP7-21 zusammengeführt)
**Beleg:** `emailDomainMatchesRole` (L151-158) testet `regex.test(domain)`. Repro mit dem Modul direkt (`node --input-type=module`): `zoll-freunde.example.com`, `meine-verwaltung.example`, `zoll-shop.com` → civil_servant ✔; `klinik.attacker.io`, `klinik-x.evil.com`, `medi-xyz.net` → medical ✔; `anwalt.beispiel.org`, `anwalt-fan.example` → lawyer ✔; `abgeordnete.evil.com`, `landtag.evil.de` → politician ✔; `drkx.com` → caregiver ✔; `uni-evil.de` → student ✔ (Muster ist verankert, aber `uni-[\w-]+\.de` matcht jede registrierbare Domain); `notary` hat kein Muster (L80-85). Kontrolle: `gmail.com` → civil_servant ✘, `bund.de` ✔. Ursache: fehlende `$`-/`(^|\.)`-Anker in L61, L69, L75 und der zweiten Alternative von L89; L97 `abgeordnete[\w.-]*$` und `landtag\.[\w-]+\.de$` erlauben beliebige Subdomain-/Suffix-Konstruktionen.
**Auswirkung:** Für `civil_servant`/`politician` (required nur `email-verified`, L86-101) erhält jeder Inhaber einer Domain mit passendem Teilstring nach Klick auf seinen eigenen Link die strikte Rolle; mit AP7-04 gilt das auch für `medical_professional`/`lawyer`.
**Empfehlung:** Alle Alternativen mit `(^|\.)…$` verankern, generische Wortlisten (`verwaltung`, `zoll`, `drk`, `anwalt`, `klinik…`, `medi-`) streichen oder als explizite Allowlist offizieller Domains führen; strikte Rollen nur über Registerprüfung/EUDI-Attestierung; Unit-Tests mit Positiv-/Negativ-Domains je Rolle.

### AP7-06 [S3] [Korrektheit/Sicherheit] server/privacy-pass/keys.js:L80,L143-150 — 1-Byte-`truncated_token_key_id` über 16 Issuer: Kollisionen werden weder erkannt noch behandelt; keine Rotation/kein Ablauf
**Urteil:** BESTÄTIGT (Severity unverändert; S-Duplikat AP7-28 zusammengeführt)
**Beleg:** Key-ID = SHA-256(pub) (L80), Vergleich nur des letzten Bytes (L145), erster Treffer in Map-Reihenfolge; `loadOrCreateOne` prüft keine Eindeutigkeit. Kollisionswahrscheinlichkeit bei 16 unabhängigen Schlüsseln ≈ 38 % (Geburtstagsproblem über 256). Die 16 `meta.json` im Repo sind kollisionsfrei (geprüft: 0 doppelte letzte Bytes) — für andere Deployments gilt das nicht. `meta.json` kennt kein `not-after`, es gibt keinen Rotationsmechanismus.
**Auswirkung:** Am öffentlichen `/token-request` (issuer.js L91) wird bei Kollision der falsche Rollenschlüssel benutzt (Client scheitert an DLEQ bzw. `authenticator mismatch`); kompromittierte Schlüssel sind nicht geordnet austauschbar, `pp_redeemed` muss Nonces ewig halten (AP7-42).
**Empfehlung:** Beim Generieren Eindeutigkeit der Truncated-IDs sicherstellen (neu würfeln), `not-after` in meta.json/Directory führen, Rotation mit Übergangsfenster vorsehen.

### AP7-07 [S3] [Korrektheit] server/privacy-pass/keys.js:L61,L77-95 — Fehlt eine der drei Key-Dateien, wird stillschweigend ein neues Schlüsselpaar erzeugt und `voprf-private.bin` überschrieben
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L61 `existsSync(privFile) && existsSync(pubFile) && existsSync(metaFile)`; sonst L77-83 `generateKeyPair` + `writeFileSync(privFile, …)` ohne Prüfung/Backup.
**Auswirkung:** Unbeabsichtigte Rotation; alle Wallet-Tokens der Rolle werden ungültig (`token_key_id matches no known issuer`), alter Private Key verloren.
**Empfehlung:** Bei inkonsistentem Dateisatz mit Fehler abbrechen; nie existierende `voprf-private.bin` überschreiben.

### AP7-08 [S3] [Korrektheit/Wartbarkeit] server/privacy-pass/demo.js:L20,L29,L49 — Import eines nicht existierenden Exports `parseTokenAndVerify`; Modul bricht beim Laden
**Urteil:** BESTÄTIGT (Severity unverändert; W-Duplikat AP7-47 zusammengeführt)
**Beleg:** `node --input-type=module -e "import './privacy-pass/demo.js'"` → `SyntaxError: The requested module './verifier-internal.js' does not provide an export named 'parseTokenAndVerify'`. verifier-internal.js exportiert `parseToken` (L25), `findIssuerForToken` (L44), `parseAndVerify` (L52). `public/demo.html` existiert nicht (`ls public` → `lib`, `wallet.html`). `demoRouter` wird nirgends importiert.
**Auswirkung:** Toter, falscher Code; sobald gemountet, startet der Server nicht.
**Empfehlung:** Entfernen oder auf `parseAndVerify` umstellen und `demo.html` liefern; Import aller Module unter `privacy-pass/` in CI erzwingen.

### AP7-09 [S3] [Korrektheit] server/privacy-pass/verifications-api.js:L72-74,L95-101,L128-131,L248-257 — `/email/start` und `/recovery/generate` mit Session ohne Credential: 500 mit PG-Fehlermeldung bzw. Codes ohne Passkey
**Urteil:** BESTÄTIGT (Severity unverändert; S-Duplikat AP7-36 zusammengeführt)
**Beleg:** Nur `!session` wird geprüft (L74); `pp_email_pending.credential_id NOT NULL` (migrations.js L67). Repro mit E-Mail-only-Session: `POST /email/start` → `500 {"error":"email_start_failed","detail":"null value in column \"credential_id\" of relation \"pp_email_pending\" violates not-null constraint"}`; `POST /recovery/generate` → 200 mit 10 Codes. `if (session.role && …)` (L75) lässt rollenlose Sessions durch — konsistent mit AP7-01, aber inkonsistent zu `/issue` L74-82.
**Auswirkung:** Falscher Statuscode, Schema-Leak (siehe AP7-35), Recovery-Codes für Accounts ohne Passkey.
**Empfehlung:** Wie in issuance.js L74-76 `if (!session.credentialId) return 401` vor jedem DB-Zugriff; Rollen-/Credential-Prüfung in `/email/start` angleichen.

### AP7-10 [S3] [Korrektheit/Wartbarkeit] server/privacy-pass/public/wallet.html:L1320-1352 — `submitAttribute` meldet „im Pilot-Modus akzeptiert“, speichert nichts und feuert einen unsinnigen `/email/start`-Fallback
**Urteil:** BESTÄTIGT (Severity unverändert; W-Duplikat AP7-55 zusammengeführt)
**Beleg:** L1330-1337 POST `/hhttps/role/declare` (verarbeitet seit v0.5 weder Rolle noch `verificationData`, schreibt nicht in `pp_attribute_verifications`); bei `!r.ok` Fallback L1340-1343 `/privacy-pass/email/start` mit `email:'attribute@self-declared'` und `method` (Server: `includes('@')` L65 lässt es durch, für Rollen ohne Domain-Muster wird eine Pending-Zeile angelegt und ein Mailversand versucht); `r2` nie ausgewertet (Kommentar L1344-1345 gibt es zu); L1347 loggt unabhängig `js.pilotAccepted`.
**Auswirkung:** Strikte Anforderungen sind aus der Wallet nie erfüllbar, Nutzer sieht Erfolg + weiterhin „Noch fehlend“; Log-/Mail-Rauschen. Zusammen mit AP7-04: der Fallback ist genau der Missbrauchspfad.
**Empfehlung:** Fallback entfernen; Nachweis-Schritt als „nicht verfügbar“ deaktivieren oder echten Endpunkt mit Whitelist bauen; Erfolg nur bei `r.ok`.

### AP7-11 [S3] [Korrektheit] server/sdk/client.js:L337-344, server/sdk/client.py:L192-197 — Unbekannter `kid` löst keinen JWKS-Refresh aus, sondern fällt auf `keys[0]` zurück
**Urteil:** BESTÄTIGT (Severity unverändert; kid-Teil von AP7-37 zusammengeführt)
**Beleg:** client.js L343 `const jwk = (kid ? keys.find(k => k.kid === kid) : keys[0]) || keys[0];` — bei `kid`-Miss wird `keys[0]` genommen; `getJwks()` (L65-83) refetcht nur nach `jwksMaxAgeMs`. `'unknown kid'` (L117) ist unerreichbar, solange das JWKS ≥ 1 Key hat. client.py L195 identisch.
**Auswirkung:** Nach Rotation bis zu 1 h `bad signature` für alle frischen Tokens, entgegen Doku L61-63.
**Empfehlung:** Bei `kid`-Miss einmalig Cache invalidieren und neu laden; bei angegebenem `kid` kein stiller Fallback.

### AP7-12 [S3] [Korrektheit] server/sdk/client.js:L152-159,L376-390 — `check()` wirft bei ungültigem Token (401) statt `status:'invalid'`; `res.json()` vor `res.ok`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `/hhttps/check` antwortet `401 { hhttps:{status:'invalid'}, error }` (server.js L937-938); `_fetchAbsolute` L386 `await res.json()`, L387 `throw new Error(data.error)`; `check()` L152-159 fängt nichts. Repro: `new HHTPPSClient(base).check('garbage.token.x')` → **wirft** `Error: invalid token`. Python-`check()` (client.py L120-123) liefert dagegen ein Ergebnisobjekt. Nicht-JSON-Antworten (429-Text, 502-HTML) erzeugen `SyntaxError`.
**Auswirkung:** Direktnutzer von `check()` müssen jede ungültige Eingabe als Exception behandeln; irreführende Fehlertexte bei Infrastrukturfehlern.
**Empfehlung:** Erst `res.ok`/Content-Type prüfen, tolerant parsen; 401 in `{ ...this._unverified(), status:'invalid' }` übersetzen.

### AP7-13 [S3] [Tests] server/test/e2e/wallet.e2e.test.mjs:L80-131 — Einziger Privacy-Pass-Test deckt nur den Login ab; Issuance/Verify/Redeem/Eligibility/E-Mail-Verify/Recovery ungetestet
**Urteil:** BESTÄTIGT (Severity unverändert; W-Duplikat AP7-54 zusammengeführt)
**Beleg:** `grep -rln "privacy-pass|pp_redeemed|pp_issuance|sdk/" server/test` → nur `unit/legacy-pages.test.mjs` (Regex auf Wallet-HTML) und `e2e/wallet.e2e.test.mjs`, das bei „Angemeldet“ (L118) endet. README.md L21 behauptet „End-to-end roundtrip test … ✅ Passing“ — ein solcher Test existiert nicht. Mein Repro-Skript zeigt, dass ein solcher Test AP7-01 (403 role_mismatch) sofort aufgedeckt hätte; die Krypto-Kernschleife (blind → `/issue` → finalize → `/verify` → `/redeem` → `already_redeemed`) funktioniert im Repro korrekt.
**Auswirkung:** Regressionen in Kernpfad und Gates bleiben unentdeckt; AP7-01 ist der Beleg.
**Empfehlung:** Integrationstest wie im Repro (mit `@cloudflare/voprf-ts` als Client), Unit-Tests für `checkEligibility`/`emailDomainMatchesRole`/`parseTokenRequest`; README-Aussage korrigieren.

### AP7-14 [S4] [Korrektheit] server/privacy-pass/issuance.js:L118,L140,L156-159 — Nicht-String-Elemente in `requests` und ungültige Gruppenelemente führen zu 500 statt 400
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L118 `Buffer.from(requests[i], 'base64')` wirft `TypeError` bei Zahl/Objekt; `EvaluationRequest.deserialize` (issuer.js L51) wirft bei ungültigem Punkt; beides landet in L156-159 → `500 issuance_failed`. (Repro mit `requests:[123]` war wegen erschöpfter Quota nur bis 429 prüfbar; Codepfad eindeutig.)
**Auswirkung:** Falsche Statusklasse, Monitoring-Rauschen.
**Empfehlung:** `typeof === 'string'` prüfen, Deserialisierung in try/catch → 400.

### AP7-15 [S4] [Korrektheit] server/privacy-pass/issuance.js:L101-102,L108 — `Retry-After`/`window_seconds` melden immer das volle 24-h-Fenster
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L101 `const reset = Math.ceil(RATE_WINDOW_MS / 1000)` ohne Bezug auf `MIN(issued_at)`. Repro-Antwort: `"window_seconds":86400`.
**Auswirkung:** Clients warten bis zu 24 h zu lang; Wallet zeigt falsche Restzeit.
**Empfehlung:** `MIN(issued_at)` im Fenster abfragen und `issued_at + 24h − now` berechnen.

### AP7-16 [S4] [Korrektheit] server/privacy-pass/public/wallet.html:L1363,L1383 — Wallet fordert immer 10 Tokens an, Button nur bei `remaining === 0` gesperrt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L1363 `disabled = q.remaining === 0`; L1383 `const N = 10`; Server L100 `usage + wanted > RATE_MAX_TOKENS → 429`.
**Auswirkung:** Bei `0 < remaining < 10` Fehlermeldung statt Teilbatch.
**Empfehlung:** `N = Math.min(10, q.remaining)`.

### AP7-17 [S4] [Korrektheit/Performance] server/privacy-pass/verifications.js:L147-159 — Recovery-Codes: `DELETE` + 10 sequentielle `INSERT`s ohne Transaktion
**Urteil:** BESTÄTIGT (Severity unverändert; P-Duplikat AP7-43 zusammengeführt)
**Beleg:** L147-150 `DELETE … WHERE used_at IS NULL`, L152-159 Schleife mit je einem `await db.pool().query(INSERT …)`; kein `BEGIN/COMMIT`.
**Auswirkung:** Bei Abbruch alte Codes weg, neue unvollständig, Client bekommt 500; 11 Roundtrips statt 1-2.
**Empfehlung:** Transaktion mit Multi-Row-`INSERT`.

### AP7-18 [S4] [Korrektheit/Wartbarkeit] server/sdk/client.js:L393-394, server/sdk/client.py:L222,L398 — Toter CommonJS-Shim; fehlendes URL-Encoding von `jti`; nacktes `except:`; fehlende Feature-Parität
**Urteil:** BESTÄTIGT (Severity unverändert; AP7-65 und Encoding-Teil von AP7-37 zusammengeführt)
**Beleg:** client.js L30 `export class` (ESM) → `require()` scheitert am Parser, L393-394 unerreichbar. client.py L222 `f"/hhttps/revoke/status?jti={jti}"` ohne `quote`; L398 `except:`. client.py hat Webhook-Methoden (L251-279), client.js nicht; kein Test referenziert `sdk/`.
**Auswirkung:** Irreführende CJS-Zusage; SDKs driften; `jti` mit `&`/`#` verändert die Anfrage (bei UUID-JTIs praktisch nicht).
**Empfehlung:** Shim entfernen oder echtes Dual-Package; `urllib.parse.quote(jti, safe='')`; Webhook-Parität; Smoke-Tests für beide SDKs.

### AP7-19 [S4] [Wartbarkeit/Lint] server/privacy-pass/issuer.js:L9,L16; verifications.js:L11-12; verifier.js:L11; role-requirements.js:L20; verifications-api.js:L25; issuance.js:L24; demo.js:L18 — ungenutzte Importe/Konstanten (ESLint `no-unused-vars`, gesammelt)
**Urteil:** BESTÄTIGT (Severity unverändert; W-Sammelfinding AP7-66 zusammengeführt)
**Beleg:** docs/review/ap/eslint-output.txt L30-52 listet genau diese neun Warnungen. Zusätzlich exportiert, aber nirgends importiert: keys.js L126-133 `truncatedKeyId`/`getPublicKeyB64Url`, L33 `MODE`; `emailDomain` doppelt (verifications.js L21-24 vs. role-requirements.js L154-156). `ROLES` aus roles.js ist ein Objekt mit nur `citizen` (per `node -e` geprüft), `ROLES` aus keys.js ein Array mit 15 Rollen — Verwechslungsgefahr.
**Auswirkung:** Lint-Rauschen; unbenutzte Exporte täuschen eine API vor.
**Empfehlung:** Entfernen bzw. verwenden (`truncatedKeyId` in issuance.js L133); `emailDomain` einmal definieren; ESLint `--max-warnings 0` für das Verzeichnis.

### AP7-20 [S1] [Sicherheit] server/privacy-pass/issuer.js:L82-98, index.js:L61-65 — Öffentlicher `/privacy-pass/token-request` stellt Rollen-Tokens ohne Session, Eligibility oder Quota aus
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Route ohne Middleware (index.js L61-65); Issuer wird allein aus dem Client-Byte `truncated_token_key_id` gewählt (`findIssuerByTruncatedKeyId`, keys.js L143-150), alle 15 Rollenschlüssel sind erreichbar. Repro: TokenRequest für `notary` (strict, „highest trust level“) ohne jede Session → `200`, 145 Byte `application/private-token-response`; finalisiertes Token → `/verify` `{"valid":true,"role":"notary"}`; 20 weitere Anfragen hintereinander → 20× 200. Einzige Schranke: `limit.global` 300/min/IP (server.js L420, L436).
**Auswirkung:** Jeder kann unbegrenzt gültige, unlinkbare Tokens für jede Rolle minten; die gesamte Gate-Logik in issuance.js/verifications*.js ist umgehbar; `/verify`/`/redeem` bestätigen die Tokens.
**Empfehlung:** Anonymen Endpunkt auf den `default`-Issuer beschränken (oder entfernen) und auch dort Autorisierung verlangen; Rollenschlüssel nur über `/issue` nach Eligibility-/Quota-Prüfung evaluieren.

### AP7-24 [S2] [Sicherheit] server/privacy-pass/verifications-api.js:L59-67,L136-167; server/email.js:L845 — Bestätigungslink schließt die Verifikation für den *Anfragenden* ab, ohne Bindung an die klickende Person
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `/email/start` akzeptiert jede Adresse (L65-67) für die eigene Session; Token ist an `session.credentialId` gebunden (L95-101); `GET /email/verify` konsumiert es ohne Login/Session der klickenden Person und ruft `recordVerification` (L147-159). Mailtext email.js L845 „You requested email verification …“, keine „nicht angefordert → ignorieren“-Warnung.
**Auswirkung:** Klickt der Inhaber von `x@bund.de`/`x@bundestag.de` den legitimen Link, ist das Angreifer-Credential für `civil_servant`/`politician` freigeschaltet (nur `email-verified` erforderlich).
**Empfehlung:** Abschluss an die anfragende Session binden (Code-Eingabe in der Wallet wie `/hhttps/email/confirm-code`) und Mailtext anpassen.

### AP7-25 [S2] [Sicherheit] server/privacy-pass/verifications-api.js:L164,L172,L199; verifications.js:L21-24 — HTML-Injection in `renderEmailResult` (E-Mail-Domain und `err.message` unescaped)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `emailDomain()` nimmt alles nach dem letzten `@`; Validierung nur `includes('@')` (L65). Repro: `email:"a@example.org, x@<svg onload=alert(1)>"` → `200 {"domain":"<svg onload=alert(1)>"}`; Link-Klick → 200, Antwort-Body enthält wörtlich `<svg onload=alert(1)>` (L199 `· ${domain}`). CSP (server.js L392-400) erlaubt `scriptSrcAttr 'unsafe-inline'`, der Handler läuft. nodemailer akzeptiert kommaseparierte `to`-Listen, die Mail geht an `a@example.org`.
**Auswirkung:** Stored XSS auf der Wallet-Origin (IndexedDB-Tokens, `hhttps_uid`, Identity-Cookie-Requests).
**Empfehlung:** `esc()` für alle interpolierten Werte, `err.message` nie ins HTML, Adresse strikt als Einzeladresse validieren.

### AP7-26 [S2] [Sicherheit/Performance] server/privacy-pass/verifications-api.js:L59-132 — `/email/start` ohne eigenes Rate-Limit: Mailversand an beliebige Dritte, DB-Insert pro Aufruf
**Urteil:** BESTÄTIGT (Severity unverändert; P-Duplikat AP7-40 zusammengeführt, dessen Zeilenangaben L262-335 falsch waren)
**Beleg:** Kein Limiter an der Route; `limit.email` (server.js L428) hängt nur an `/hhttps/email/*`, `/hhttps/session/*` (L2676, L2720, L2847, L2940); für `/privacy-pass` greift nur `limit.global` (300/min). `pp_email_pending` wächst pro Aufruf (L95-101, keine Bereinigung, AP7-39). Mailversand synchron im Request (L109).
**Auswirkung:** Bis zu ~18.000 Mails/h pro IP mit hhttps.org-Absender; SMTP-/Event-Loop-Last; Reputationsschaden.
**Empfehlung:** `limit.email`-äquivalenten Limiter vor die Route; zusätzlich pro Session/Credential und Empfänger-Hash begrenzen; alte Pending-Zeilen desselben Credentials löschen.

### AP7-27 [S3] [Sicherheit] server/privacy-pass/verifications-api.js:L104-105 — Verifikationslink aus `req.protocol`/`Host` (Host-Header-Poisoning)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L104 `` `${req.protocol}://${req.get('host')}` ``; nginx reicht `Host $host` durch (scripts/deploy-all.sh L287 ff.). `BASE_URL` existiert (server.js L78) und wird hier nicht genutzt.
**Auswirkung:** Phishing-Link mit legitimem Absender; das Token selbst verrät dem Angreifer nichts Neues.
**Empfehlung:** Basis-URL aus `BASE_URL`/`RP_ID` bilden.

### AP7-29 [S3] [Sicherheit] server/privacy-pass/verifier-internal.js:L52-71, verifier.js:L13-39, wallet.html:L1391-1392 — `challenge_digest` wird nie geprüft: keine Origin-/Challenge-Bindung, Replay über `/verify`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `parseAndVerify` verifiziert nur den Authenticator über `token_input` (L63-70); `challengeDigest` wird nirgends verglichen; Wallet wählt ihn selbst zufällig (L1391-1392); `/verify` speichert nichts. Repro: dasselbe Token wurde mehrfach über `/verify` bestätigt, erst `/redeem` liefert beim zweiten Mal `already_redeemed`.
**Auswirkung:** Token bei anderen Relying Parties wiederverwendbar; RFC-9578-Bindung fehlt.
**Empfehlung:** `challenge`/`origin` in `/verify`/`/redeem` entgegennehmen und `SHA-256(challenge)` gegen `challengeDigest` prüfen; `/verify` als reine Signaturprüfung dokumentieren.

### AP7-30 [S3] [Sicherheit] server/privacy-pass/verifications-api.js:L293-314 — `/recovery/use` als unauthentifiziertes Code-Orakel mit spoofbarer IP im Audit-Log, ohne wirksame Recovery-Funktion
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Kein Session-Erfordernis, nur `limit.global`; L300 nimmt den *ersten* `X-Forwarded-For`-Eintrag statt `req.ip` (trust proxy 1, server.js L102). Repro: `X-Forwarded-For: 203.0.113.99, 10.0.0.1` → `pp_recovery_codes.used_from_ip = '203.0.113.99'`; Antwort enthält die `userId`. Serverseitig verleiht der Code nichts (`register/finish` verlangt `session.userId === userId`, server.js L2466-2469) — Wallet-Seite in AP7-03.
**Auswirkung:** Codes werden bei Fehlbedienung verbraucht, interne IDs geleakt, Audit-Log fälschbar; ~50 Bit Entropie ist bei 18.000/h nicht brute-forcebar.
**Empfehlung:** Code an eine echte kurzlebige Recovery-Session koppeln (AP7-03); `req.ip` verwenden; dedizierter Limiter.

### AP7-31 [S3] [Sicherheit] server/privacy-pass/verifications-api.js:L42,L209,L273; issuance.js:L192; wallet.html:L1072,L1117,L1213,L1358 — Session-ID als Bearer-Geheimnis in GET-Query-Strings
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `/eligibility`, `/credentials`, `/recovery/status`, `/issuance/quota` lesen `req.query.sessionId`; Wallet sendet sie in der URL (Zeilen geprüft).
**Auswirkung:** Session-ID (einziger Auth-Faktor aller PP-Endpunkte) in nginx-Logs, Browser-History.
**Empfehlung:** Header oder POST-Body.

### AP7-32 [S3] [Sicherheit] server/privacy-pass/migrations.js:L17-27,L106-112; verifier.js:L74-78 — Rolle und Zeitstempel in `pp_issuance_log`/`pp_redeemed` ermöglichen Korrelation bei kleinen Anonymitätsmengen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `pp_issuance_log(credential_id, role, issued_at)`; `pp_redeemed(nonce, role, redeemed_at)`; `role` in `pp_redeemed` (verifier.js L75-77) ist für die Double-Spend-Prüfung unnötig (Kommentar L49-50 verspricht „no identity link“).
**Auswirkung:** Für Rollen mit wenigen Nutzern Zuordnung über Zeitfenster möglich.
**Empfehlung:** `role` in `pp_redeemed` streichen, Zeitstempel runden/kurze Retention, Issuance-Log auf Zähler reduzieren.

### AP7-33 [S3] [Sicherheit] server/privacy-pass/verifications.js:L14-19 — E-Mail-Pseudonymisierung mit öffentlich bekanntem Fallback-Salt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L14 `process.env.HHTTPS_EMAIL_HASH_SALT || 'hhttps-pp-v1-email-hash-salt'`; kein Start-Check.
**Auswirkung:** Bei DB-Leak sind `email_hash`-Spalten per Wörterbuch rückrechenbar.
**Empfehlung:** In Produktion ohne ENV abbrechen; HMAC-SHA-256.

### AP7-34 [S3] [Sicherheit/Performance] server/privacy-pass/public/wallet.html:L9; server.js:L396 — WebAuthn-Bibliothek von unpkg.com ohne SRI, synchron im `<head>`
**Urteil:** BESTÄTIGT (Severity unverändert; P-Duplikat AP7-44 zusammengeführt)
**Beleg:** L9 `<script src="https://unpkg.com/@simplewebauthn/browser@9.0.1/…">` ohne `integrity`/`defer`; CSP `scriptSrc` enthält `unpkg.com`. Der e2e-Test muss die URL stubben (wallet.e2e.test.mjs L38-41).
**Auswirkung:** CDN-Kompromittierung = Fremd-JS auf der Wallet-Origin; CDN-Ausfall = weiße Seite.
**Empfehlung:** Bundle lokal unter `/privacy-pass/lib/` ausliefern (wie `voprf.js`), `defer`, `unpkg.com` aus CSP entfernen.

### AP7-35 [S4] [Sicherheit] server/privacy-pass/issuance.js:L158,L207; verifications-api.js:L53,L130,L242,L265,L287,L316 — `err.message` interner Fehler geht an Clients
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Alle 500-Antworten hängen `detail: err.message` an. Repro (AP7-09): PG-NOT-NULL-Meldung inkl. Spalten-/Tabellenname in der Antwort.
**Auswirkung:** Schema-/Implementierungsdetails.
**Empfehlung:** Generische Meldung, Details ins Server-Log.

### AP7-38 [S3] [Performance] server/privacy-pass/migrations.js:L17-27; issuance.js:L164-183 — `pp_issuance_log` wird nie bereinigt
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilenangaben des Reviewers (migrations L473-484, issuance L378-397) korrigiert)
**Beleg:** Insert L176-183, Lesen nur im 24-h-Fenster L164-174; `cleanup_expired()` (schema.sql L192-206) und der 5-Minuten-Intervall (server.js L714-724) kennen keine `pp_*`-Tabelle; `grep pp_issuance_log server/` → nur Insert/Select/Migration.
**Auswirkung:** Lineares Wachstum von Tabelle und Indizes; pseudonymes Nutzungsprotokoll ohne Retention (siehe AP7-32).
**Empfehlung:** `DELETE … WHERE issued_at < NOW() - INTERVAL '2 days'` in den Cleanup.

### AP7-39 [S3] [Performance] server/privacy-pass/verifications.js:L90-119; migrations.js:L75-76 — `pp_email_pending`: abgelaufene Links werden nie gelöscht, Ablaufindex ungenutzt
**Urteil:** BESTÄTIGT (Severity unverändert; Indexzeile korrigiert: L75-76 statt L531-532)
**Beleg:** Löschung nur bei Konsum (L110-113); `pp_email_pending_expires_idx` wird von keiner Query benutzt.
**Auswirkung:** Unbegrenztes Wachstum inkl. `credential_id`, `email_hash`, `email_domain`; Verstärker für AP7-26.
**Empfehlung:** `DELETE FROM pp_email_pending WHERE expires_at < NOW()` in den Cleanup.

### AP7-41 [S3] [Performance/Wartbarkeit] server/server.js:L371; privacy-pass/issuance.js:L30; verifications-api.js:L36; index.js:L77-78 — Router-eigene Body-Limits (32/8/4 kB) sind wirkungslos, es gilt das globale 2-MB-Limit
**Urteil:** BESTÄTIGT (Severity unverändert; W-Duplikat AP7-48 zusammengeführt — dessen Aussage „effektiv 32 kB“ ist falsch, effektiv gelten 2 MB; Zeilenangaben des P-Reviewers (issuance L244/L274/L332, verifier L442/L484) korrigiert)
**Beleg:** `app.use(express.json({ limit:'2mb' }))` läuft vor allen Routern; body-parser überspringt weitere Parser bei `req._body` (node_modules/body-parser/lib/types/json.js L106-110). Repro: 100-kB-JSON an `/privacy-pass/issue` → Handler erreicht (429 `rate_limited`, nicht 413); 100-kB-Body an `/verify` → 400 `invalid_token` (nicht 413). `Buffer.from(requests[i],'base64')` (L118) dekodiert vollständig, bevor L119 die Länge prüft.
**Auswirkung:** ~500× mehr Parse-/Decode-Arbeit pro Request als vorgesehen; Limits sind Dokumentation ohne Wirkung.
**Empfehlung:** Globales Limit senken bzw. PP-Router vor dem globalen Parser mounten; in `/issue` `requests[i].length` vor dem Decode prüfen; redundante Parser-Deklarationen entfernen.

### AP7-42 [S4] [Performance] server/privacy-pass/verifier.js:L74-78; migrations.js:L106-112 — `pp_redeemed` wächst dauerhaft ohne Rotations-/Zeitgrenze
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilen korrigiert)
**Beleg:** Ein Insert pro Einlösung; Tokens ohne Ablauf, keine Rotation (AP7-06); `pp_redeemed_at_idx` ungenutzt.
**Auswirkung:** Proportionales Wachstum; kein Betriebsplan.
**Empfehlung:** Nonces an `token_key_id` binden und bei Rotation löschen, oder dokumentierte Retention.

### AP7-45 [S4] [Performance] server/sdk/client.js:L65-83; client.py:L127-155 — JWKS-Refresh ohne In-Flight-Deduplizierung
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `getJwks()` teilt laufende Fetches nicht; jeder Abschluss `_keyCache.clear()` (L81). Middleware (L253-279) ruft `verifyLocal` pro Request.
**Auswirkung:** Lastspitzen auf `/.well-known/*` bei Kaltstart/TTL-Ablauf; funktional harmlos.
**Empfehlung:** Laufendes Promise in `_jwksPromise` wiederverwenden.

### AP7-46 [S4] [Performance] server/privacy-pass/issuer.js:L82-98; verifier-internal.js:L64; server.js:L420,L436 — Öffentliche VOPRF-Endpunkte nur durch das globale IP-Limit geschützt
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilen korrigiert)
**Beleg:** `/token-request`, `/verify`, `/redeem` unauthentifiziert, P-384-Operationen in reinem JS auf dem Event-Loop; nur `limit.global` 300/min. Sicherheitsaspekt in AP7-20.
**Auswirkung:** ~1-2 s CPU/min pro IP; verteilt spürbar.
**Empfehlung:** Engere Limiter, perspektivisch Worker-Thread.

### AP7-49 [S3] [Wartbarkeit] server/privacy-pass/keys.js:L40-44; role-requirements.js:L23-110; wallet.html:L614-630; roles.js:L56 — Rollenliste an vier Stellen ohne gemeinsame Quelle
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Drei Kopien der 15 Rollen (inkl. `strict`-Flag in Wallet und Server); `ROLES` aus roles.js enthält nur `citizen` (per `node -e` geprüft) und wird in verifications.js L12/role-requirements.js L20 importiert, nicht benutzt. Kommentar keys.js L37-39 („just add it here“) ist falsch: `checkEligibility` liefert sonst `Unknown role` (L131-134).
**Auswirkung:** Drift zwischen Keys, Eligibility und UI.
**Empfehlung:** `ROLES = Object.keys(ROLE_REQUIREMENTS)`; Labels/`strict` per Endpunkt an die Wallet.

### AP7-50 [S3] [Wartbarkeit] server/privacy-pass/issuance.js:L118-139; issuer.js:L33-47; keys.js:L126-129,L145 — TokenRequest-Parsing und Truncated-Key-ID dreifach implementiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Identische drei Schritte (Länge, `readUInt16BE(0)`, `readUInt8(2)`, `subarray(3)`) mit unterschiedlichen Fehlercodes; `truncatedKeyId()` (keys.js L126) wird nirgends aufgerufen.
**Auswirkung:** Wire-Format-Änderungen müssen doppelt nachgezogen werden; Fehlerformate divergieren bereits.
**Empfehlung:** `parseTokenRequest` exportieren und in `/issue` verwenden; `truncatedKeyId(role)` nutzen.

### AP7-51 [S4] [Wartbarkeit] server/privacy-pass/verifier-internal.js:L18-23; issuer.js:L22-31 — VOPRFServer-Cache pro Rolle doppelt
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: zwei kleine Maps, funktional folgenlos; Rotation existiert ohnehin nicht)
**Beleg:** Beide Module halten eine eigene `Map` von `VOPRFServer(SUITE, issuer.privateKey)`.
**Auswirkung:** Doppelte Materialisierung; bei künftiger Rotation zwei Caches.
**Empfehlung:** `getVoprfServer(role)` in keys.js.

### AP7-52 [S4] [Wartbarkeit] server/privacy-pass/well-known.js:L28-36; issuer.js:L115-123 — `token-keys`-Liste zweimal erzeugt
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: 8 Zeilen Duplikat)
**Beleg:** Identisches Mapping `{ role, 'token-type', 'token-key', 'not-before' }`.
**Auswirkung:** Künftige Felder (`not-after`) doppelt zu pflegen.
**Empfehlung:** Gemeinsame `issuerKeyList()`.

### AP7-53 [S4] [Wartbarkeit] server/privacy-pass/verifications.js:L88,L98,L102; verifications-api.js:L125 — E-Mail-Token-TTL dreimal festverdrahtet
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: lokal begrenzt)
**Beleg:** `EMAIL_VERIFY_TTL_MS` (L88) nur als Rückgabe (L102); SQL-Literal `INTERVAL '15 minutes'` (L98); API-Literal `15 * 60` (L125); `expiresInMs` wird vom Aufrufer nicht genutzt (L95 destrukturiert nur `rawToken`).
**Auswirkung:** TTL-Änderung lässt zwei Stellen falsch.
**Empfehlung:** TTL als Parameter ins SQL; `expires_in_seconds` ableiten.

### AP7-56 [S3] [Wartbarkeit] server/privacy-pass/public/wallet.html:L938-943,L1059-1063,L1104-1108 — `register/finish`-Aufruf dreimal kopiert mit divergierender Fehlerbehandlung
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `registerPasskey` zeigt `d2.detail || d2.error`; `registerNewCredential` feste Meldung „Registrierung fehlgeschlagen“ (L1063) trotz Kommentar L1052-1054 (409 „as is“ anzeigen); `addCredential` „Fehler beim Registrieren“ (L1108). Verschärft AP7-03 (Nutzer sieht nicht `session_user_mismatch`).
**Auswirkung:** Dokumentierte Absicht in zwei von drei Pfaden nicht umgesetzt.
**Empfehlung:** `registerPasskey()` parametrisieren, Kopien entfernen.

### AP7-57 [S3] [Wartbarkeit] server/privacy-pass/README.md:L21-22; INSTALL.md:L61,L71,L75-76; verifications-api.js:L4-11 — Modul-Doku beschreibt einen veralteten Stand und widerspricht dem Code
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** INSTALL.md L61/L71/L75 „returns 501 … `TODO` in issuer.js/verifier.js“ — Evaluation ist implementiert (issuer.js L71-75), kein `TODO`. README L21 „roundtrip test ✅ Passing“ (existiert nicht, AP7-13), L22 „Replay protection … Pending“ (existiert: `/redeem`, verifier.js L55-97). Header verifications-api.js L11 nennt `{ code, userId }`, Handler nutzt kein `userId` (L295); `/recovery/status` fehlt im Header.
**Auswirkung:** Betreiber/Integratoren werden in die Irre geführt.
**Empfehlung:** README/INSTALL auf Ist-Stand (Endpunkt-Tabelle, Rate-Limits, Rollen-Requirements).

### AP7-58 [S4] [Wartbarkeit] server/privacy-pass/issuance.js:L68,L165,L177,L195; verifications.js:L29,L42,L91,L106,L143,L164,L181; verifications-api.js:L46,L72,L212,L253,L276; verifier.js:L73 — `await import('../db.js')` 17-mal statt statischer Import
**Urteil:** BESTÄTIGT (Severity unverändert; Zahl korrigiert: 17 in den vier genannten Dateien, 18 inkl. migrations.js)
**Beleg:** `grep -c "await import('../db.js')"`: issuance 4, verifications 7, verifications-api 5, verifier 1 (+ migrations 1). db.js importiert nichts aus `privacy-pass/`, kein Zirkel. Aufrufmuster inkonsistent (`pool().query` vs. `q`).
**Auswirkung:** Rauschen, suggeriertes Zirkularitätsproblem.
**Empfehlung:** Statischer Import, einheitlich `q()`.

### AP7-59 [S4] [Wartbarkeit] server/privacy-pass/verifications-api.js:L84 — Lokale Konstante `req` verschattet das Express-Request-Objekt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L84 `const req = ROLE_REQUIREMENTS[role];` im if-Block L83-90; L104 `req.protocol` trifft nur wegen der Blockgrenze das Express-Objekt.
**Auswirkung:** Refactoring-Falle.
**Empfehlung:** `reqs` umbenennen.

### AP7-60 [S4] [Wartbarkeit] server/privacy-pass/issuance.js:L13,L23-27; wallet.html:L1383 — Kommentar „tune via env“ ohne Konfigurierbarkeit; `DEFAULT_BATCH_SIZE` ungenutzt; Batchgröße doppelt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Harte Konstanten ohne `process.env`; `DEFAULT_BATCH_SIZE` L24 unreferenziert (ESLint); Wallet `N = 10` (L1383) implizit gekoppelt (AP7-16).
**Auswirkung:** Irreführende Kommentare.
**Empfehlung:** `max_per_window` aus `/issuance/quota` in der Wallet nutzen; Kommentar bereinigen oder ENV lesen.

### AP7-61 [S4] [Wartbarkeit] server/privacy-pass/verifications-api.js:L177-203; wallet.html:L1140-1150 — HTML-Seite inkl. CSS/Google-Fonts als Template-String im API-Modul; DE/EN hart codiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `renderEmailResult` L180-202 mit Inline-CSS, Fonts-Link L182, gemischte Texte L141-142, L151-152, L163-164; Recovery-Markup L1140-1150 ohne `tr()`.
**Auswirkung:** UI-Änderungen im Server-Router; kein Test fürs Markup; Escaping-Lücke (AP7-25) ebendort.
**Empfehlung:** Template auslagern, Texte über `T`/`roles.i18n.js`.

### AP7-62 [S4] [Wartbarkeit] server/privacy-pass/public/wallet.html:L951,L998,L1027,L1228,L1370 u. a. — Mischung aus `tr()` und hart codierten deutschen Strings
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Stichprobe L951 „Versuche Login …“, L998 „✓ Angemeldet“, L1228 „Noch fehlend:“, L1370 „Discovery: lade Issuer-Verzeichnis …“; e2e-Test hängt an „Angemeldet“ (wallet.e2e.test.mjs L118).
**Auswirkung:** Gemischte Sprachen; Übersetzung erfordert Durchsuchen des Inline-Skripts.
**Empfehlung:** Alle Strings in `T`; Test auf `#btn-login.done` o. ä.

### AP7-63 [S4] [Wartbarkeit] server/privacy-pass/public/wallet.html:L602-1550 — ~950 Zeilen Anwendungslogik als Inline-`<script type="module">`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Datei 1552 Zeilen / 83 kB; Skriptblock ab L602; ESLint erfasst Inline-Skripte nicht; `index.js` L57-58 liefert bereits statische Assets.
**Auswirkung:** Kein Linting, keine Unit-Testbarkeit der Token-Konstruktion.
**Empfehlung:** Nach `public/wallet.js` (ESM) auslagern und aufteilen.

### AP7-64 [S4] [Wartbarkeit] server/sdk/client.js:L30; client.py:L39,L58 — Klassenname `HHTPPSClient`/`HHTPPSResult` ist ein Tippfehler des Produktnamens
**Urteil:** BESTÄTIGT (Severity unverändert; Korrektur: öffentlich dokumentiert nur in `sites/iamhmn.html`, nicht in `developers/index.html`)
**Beleg:** `export class HHTPPSClient` (L30), `class HHTPPSClient` (py L58), `HHTPPSResult` (py L39); `grep -rl HHTPPSClient sites developers` → nur `sites/iamhmn.html`.
**Auswirkung:** Verwirrung für Integratoren; spätere Korrektur ist Breaking Change.
**Empfehlung:** `HHTTPSClient` als Primärname, alten Namen als Deprecated-Alias.

## Verworfen
- keine. Alle Findings hatten Datei:Zeile und waren am Code bzw. per Repro nachvollziehbar; Zeilenangaben wurden bei AP7-38, -39, -41, -42, -46, -58, -64 korrigiert.

## Zusammengeführt
- AP7-21 (S: unverankerte Domain-Regexe, S1) → in AP7-05 (gleiche Ursache; Severity dort auf S1 gehoben).
- AP7-22 (S: frei wählbares `method`, S1) → in AP7-04 (gleiche Ursache; Severity dort auf S1 gehoben).
- AP7-23 (S: Quota-TOCTOU, S2) → in AP7-02 (gleiche Ursache).
- AP7-28 (S: Key-ID-Kollision/keine Rotation/Überschreiben, S3) → in AP7-06 (Kollision/Rotation) und AP7-07 (Überschreiben).
- AP7-36 (S: Session ohne Rolle/Credential in `/email/start`, S4) → in AP7-09 (gleiche Ursache).
- AP7-37 (S: `kid`-Fallback + unkodiertes `jti`, S4) → in AP7-11 (kid) und AP7-18 (jti).
- AP7-40 (P: `/email/start` ohne Limiter, S3) → in AP7-26 (gleiche Ursache; P-Zeilenangaben L262-335 waren falsch, korrekt L59-132).
- AP7-43 (P: Recovery-Codes 10 Einzel-INSERTs, S4) → in AP7-17 (gleiche Ursache).
- AP7-44 (P: unpkg render-blockierend, S4) → in AP7-34 (gleiche Datei:Zeile, gleiche Abhilfe).
- AP7-47 (W: demo.js tot/nicht ladbar, S3) → in AP7-08 (gleiche Ursache).
- AP7-48 (W: 4-kB-Limits wirkungslos wegen 32-kB-Router-Parser, S3) → in AP7-41 (gleiche Ursache; Aussage „effektiv 32 kB“ korrigiert auf 2 MB).
- AP7-54 (W: keine Tests für Issuer/Verifier/…, S3) → in AP7-13 (gleiche Ursache; README-Behauptung dort und in AP7-57 aufgenommen).
- AP7-55 (W: `submitAttribute`-Fallback, S3) → in AP7-10 (gleiche Ursache).
- AP7-65 (W: CJS-Shim/Parität/`quote`/`except:`, S4) → in AP7-18 (gleiche Ursache).
- AP7-66 (W: ESLint `no-unused-vars` gesammelt, S4) → in AP7-19 (gleiche Ursache).

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit (K) | 19 | 19 | 0 | 0 |
| Sicherheit (S) | 18 | 12 | 0 | 6 |
| Performance (P) | 9 | 6 | 0 | 3 |
| Wartbarkeit (W) | 20 | 14 | 0 | 6 |
| **Gesamt** | **66** | **51** | **0** | **15** |

Bestätigt je Severity: S1 3 (AP7-04, -05, -20), S2 6 (AP7-01, -02, -03, -24, -25, -26), S3 22, S4 20. Hochgestuft: AP7-04, AP7-05 (S2→S1). Herabgestuft: AP7-51, -52, -53 (S3→S4).

# AP3 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b

Methodik: Jede Datei:Zeile per `sed -n`/`grep -n` nachgelesen; drei Repro-Skripte im Scratchpad gegen die Test-DB (`TEST_PG_HOST=/var/lib/pgtest`) ausgeführt:
`repro-k1-db.mjs` (db.js direkt), `repro-k1-e2e.mjs` (Playwright/Chromium mit virtuellem Authenticator, kompletter Sign-in-Flow bis `#issueBtn`), `repro-k3.mjs` (Integrations-Harness: hängende Requests, Cookie, Kommentar-Adresse), `repro-s1-email.mjs` (Regex + `classifyDomain` + nodemailer 6.10.1 `streamTransport`). Der vorhandene E2E-Test `signin.e2e.test.mjs` wurde zusätzlich ausgeführt (6/6 grün).

Zählung: AP3-K enthält 12 Findings (die Zusammenfassung dort sagt 11 — Zählfehler), AP3-S 11, AP3-P 6, AP3-W 18 → 47 Rohbefunde. IDs in Reihenfolge K (AP3-01…12), S (AP3-13…23), P (AP3-24…29), W (AP3-30…47).

## Bestätigte Findings

### AP3-01 [S1] [Korrektheit] server/server.js:L2571-2592 — Passkey-Login verwirft die gemergte E-Mail-/GitHub-Verifikation: `db.sessions.create` persistiert `priorMerge` nicht
**Urteil:** BESTÄTIGT (Severity unverändert S1; Sachverhalt in einem Punkt korrigiert: die Vorgänger-Session wird NICHT gelöscht, siehe AP3-26)
**Beleg:**
- `db.sessions.create` (db.js L148-161) schreibt nur `session_id, user_id, credential_id, device_type, backed_up, verified, trust_score, pseudonym, expires_at`. Die Felder `emailVerified/emailDomain/emailLevel/emailTrustBonus/githubVerified` aus `priorMerge` (identity.js L118-129) landen nicht in der DB.
- DB-Repro (`repro-k1-db.mjs`): `priorMerge = {emailVerified:true, emailDomain:'example.org', emailLevel:'email-verified', emailTrustBonus:0, pseudonym:'Pia'}` → `sessions.create(sid, {…, ...priorMerge})` → `sessions.get(sid)` = `{emailVerified:false, emailDomain:null, emailLevel:null, pseudonym:'Pia', trustScore:50}`. Nur `pseudonym` überlebt.
- Browser-Repro (`repro-k1-e2e.mjs`, exakt der Ablauf der Sign-in-Seite): E-Mail-Code bestätigen (200, `methods:["email","domain"]`) → `#m-passkey` → `#passkeyGo` (register/finish 200, auth/finish 200 `merged:true`) → `sessionId` der Seite wechselt auf die neue Passkey-Session (index.html L621) → Klick `#issueBtn` → **`POST /hhttps/role/declare` → 403 `{"error":"email_verification_required"}`** (L3102 via `requireEmailVerified`, L670-676). DB-Zustand danach: alte Session `email_verified:true`, neue Session `email_verified:false, credential_id gesetzt`.
- Warum `signin.e2e.test.mjs` trotzdem grün ist: der Test (L205-250) asserted nur `auth/finish 200` und `#st-passkey .check` und klickt `#issueBtn` nie; `gate.test.mjs` L154-166 ruft `role/declare` nur mit einer reinen E-Mail-Session (`verifiedSession()`) auf. Der Fehler tritt also genau im Schritt NACH dem Passkey auf (Token-Bezug), nicht beim Passkey selbst.
- Korrektur zum Rohbefund: `db.sessions.delete` existiert nicht (AP3-26), der Aufruf in L2573 wirft `TypeError` in einen leeren `catch`. Die alte E-Mail-Session bleibt daher bestehen und `role/declare` mit der ALTEN sessionId liefert 200 (`["email","domain"]`) — die Seite kennt diese ID aber nicht mehr (`sessionId=d.sessionId`, L621). Für den Nutzer ist die Auswirkung identisch: nach Passkey-Login kein Token, E-Mail-Verifikation muss neu begonnen werden (neue Session).
**Auswirkung:** Der Standard-Sign-in-Flow der Seite (E-Mail → Passkey → Token) endet in 403. Passkey ist für Nutzer der Sign-in-Seite faktisch unbenutzbar; dieselbe Lücke gilt für eine vorher abgeschlossene GitHub-Verifikation (`githubVerified` geht ebenfalls verloren). `merged:true` in der Antwort (L2598) ist falsch.
**Empfehlung:** Nach dem INSERT `await db.sessions.update(sid, priorMerge)` (die `allowedColumns` in `sessions.update` L171-195 decken alle Merge-Felder ab) oder `sessions.create` um die E-Mail-/GitHub-Spalten erweitern; `sessions.delete` implementieren (AP3-26) und die Vorgänger-Session erst NACH erfolgreichem Anlegen löschen. Test: E-Mail-verifizierte Session → Passkey → `role/declare` 200 mit `email_verified:true` und `passkey_verified:true` (E2E: `#issueBtn` klicken, siehe AP3-10).

### AP3-02 [S2] [Korrektheit/Sicherheit] server/email.js:L99-115 — `classifyDomain` prüft Domain-Suffixe ohne Label-Grenze; Fremddomains erhalten `official-email`/`school-email` und bis zu +40 Trust
**Urteil:** BESTÄTIGT (Severity unverändert S2; AP3-14 zusammengeführt)
**Beleg:** `DOMAIN_RULES.official/press/creative` werden mit `domain.endsWith(d)` ohne führenden Punkt geprüft (L102, L108, L111), `university` mit `domain.includes(d)` (L105); `'.uni-'` steht doppelt in L70/L74. Repro (`repro-s1-email.mjs`): `x@notbundestag.de` → `official-email +40`; `x@umwelt.de` → press +15; `x@a.uni-b.evil.com` und `x@hochschule-x.evil.com` → `school-email +15`. Über `bindSessionToEmailAnchor` (L2812-2818) landet `level/trustBonus/domain` in der Session, über `computeVerification` (roles.js L182ff., `domainTrust` dynamisch) im Trust: `computeVerification({email:true, domain:true, domainTrust:40})` → `trust 60, band 'human', isHuman true` — d. h. die Stufe „Verified human“ (Schwelle 50) wird OHNE Passkey erreicht.
**Auswirkung:** Mit einer frei registrierbaren Lookalike-Domain (`notbundestag.de`) oder einer eigenen Subdomain (`*.uni-*.`) erhält man dauerhaft Behörden-/Hochschul-Assurance, den Header `HHTTPS-Domain-Verified: true` und die Human-Schwelle ohne zweiten Faktor.
**Empfehlung:** `domain === d || domain.endsWith('.' + d)`; Präfixregeln auf Label-Anfang (`/(^|\.)(uni|tu|hs|fh|hochschule)-[a-z0-9-]+\.(de|edu)$/` o. ä.) beschränken, Liste deduplizieren; Unit-Tests für die Grenzfälle (siehe AP3-41).

### AP3-03 [S3] [Korrektheit] server/server.js:L2534-2538 — `auth/finish` liest `response.id` vor dem `try`; fehlendes `response` → unbehandelte Rejection, Request hängt
**Urteil:** BESTÄTIGT (Severity unverändert; AP3-21 und AP3-38 zusammengeführt)
**Beleg:** L2534 `const { sessionId, response, … } = req.body;`, L2538 `db.credentials.get(response.id)` vor `try` (L2540). Repro (`repro-k3.mjs`): `POST /hhttps/webauthn/auth/finish {sessionId:<gültige Challenge>}` ohne `response` → **keine Antwort innerhalb 4 s (TIMEOUT)**; Express 4 fängt die Rejection nicht, `process.on('unhandledRejection')` (L4824) loggt nur. Auch die Vor-`try`-Awaits in `register/finish` (L2465-2470), `/email/send` (L2849-2856), `/email/confirm-code` (L2947-2957), `/email/status` (L2967), `/verify/github/status` (L3092) sind nur bei DB-Fehlern betroffen. Hinweis zu W-Befund: Express liefert hier keine 500-HTML-Seite (das gilt nur für synchrone Throws wie AP3-07), sondern gar keine Antwort.
**Auswirkung:** Offene Verbindung bis Client-/nginx-Timeout statt 400; unkontrollierter Fehlerpfad.
**Empfehlung:** `if (!sessionId || typeof response?.id !== 'string') return res.status(400)…`; Vor-`try`-Awaits in den `try` ziehen bzw. einen `asyncHandler`-Wrapper + Error-Middleware einführen (gilt für alle AP3-Routen).

### AP3-04 [S3] [Korrektheit] server/server.js:L2896-2925 — `/hhttps/email/verify` ohne try/catch; Array-/Objekt-Query-Parameter wirft in `verifyEmailToken`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2897 `const { token, session } = req.query;` unvalidiert → email.js L746 `createHash('sha256').update(rawToken)`. Repro: `GET /hhttps/email/verify?token=a&token=b&session=<sid>` und `?token[x]=a&session=<sid>` → **beide TIMEOUT (keine Antwort, kein Redirect)**. Kein `try/catch` um L2900, L2905, L2908.
**Auswirkung:** Magic-Link-Klick bleibt bei manipulierten Parametern oder DB-Fehlern ohne Fehlerseite hängen.
**Empfehlung:** `typeof token !== 'string' || typeof sessionId !== 'string'` → Redirect `reason=missing_params`; Handler-Body in `try/catch` mit Redirect `reason=internal`.

### AP3-05 [S3] [Korrektheit] server/server.js:L2695,L2736,L2761 — Session-TTL (15 min ab Session-Start) und Code-/Kontext-TTL (15 min ab Versand) sind nicht aufeinander abgestimmt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Sessions werden mit `900_000` ms angelegt (L2695, L2736); `/hhttps/email/send` erlaubt bis zu 3 Sends (L2857) und verlängert nichts — `sessions.update` (db.js L171-195) kennt keine `expires_at`-Spalte; Code-Row (email.js L399 `EMAIL_VERIFICATION_TTL_MS`) und Kontext (L2761 `EMAIL_CONTEXT_TTL_MS`, L2872-2876) gelten 15 min ab Versand. `confirm-code` antwortet dann 404 (L2948), Magic-Link `reason=session_expired` (L2906).
**Auswirkung:** Wer die Mail spät anfordert, hat laut Mail einen gültigen Code, die Session ist aber weg; Neustart nötig.
**Empfehlung:** In `/email/send` die Session auf `NOW() + EMAIL_VERIFICATION_TTL_MS` verlängern (neue db-Methode) oder Code-TTL auf Restlaufzeit begrenzen und Mailtext anpassen.

### AP3-06 [S4] [Korrektheit] server/server.js:L2687-2695,L2728-2736 — `trustScore: 0` wird von `db.sessions.create` zu 60 hochgesetzt
**Urteil:** BESTÄTIGT (herabgestuft von S3 wegen fehlender Laufzeitwirkung: `grep session.trustScore server.js` liefert keinen Leser; `role/declare` rechnet über `computeVerification` neu)
**Beleg:** db.js L157 `data.trustScore || 60`. Repro: `sessions.create(sid, {trustScore:0})` → `sessions.get` → `trustScore: 60`; im E2E-Repro trägt die E-Mail-Session in der DB `trust_score: 60`. Antwort der Routen sagt `trustScore: 0` (L2702, L2743).
**Auswirkung:** DB-Zustand widerspricht API und Kommentar (L2693); falsche Basis für Statistik/künftige Leser.
**Empfehlung:** `data.trustScore ?? 60` in db.js (AP6) und Testerwartung in db-phase8.test ergänzen.

### AP3-07 [S4] [Korrektheit] server/server.js:L468-478 — `readIdentityCookie` ruft `decodeURIComponent` ungeschützt auf; fehlerhaft kodierter Cookie → 500 auf jeder Route
**Urteil:** BESTÄTIGT (herabgestuft von S3 wegen fehlender Fremdauslösbarkeit; AP3-22 zusammengeführt)
**Beleg:** L475 `decodeURIComponent(part.slice(i+1).trim())`, Middleware L485-516, `try` (L490) umschließt nur `verifyToken`. Repro: `GET /hhttps/info` mit `Cookie: hhttps_identity=%E0%A4%A` → **HTTP 500** (Express-Default-HTML „Error“), Cookie wird nicht gelöscht. Einschränkung: Der Cookie wird nur serverseitig per `res.cookie` (korrekt kodiert, JWT ohne `%`) gesetzt, ist `HttpOnly` — ein solcher Wert entsteht nur durch manuelle Manipulation/Fremdskript auf der Origin. Hinweis: der Cookie-Name im S-Rohbefund (`hhttps_id`) ist falsch, korrekt `hhttps_identity` (L453); mit falschem Namen bleibt alles 200.
**Auswirkung:** Selbst-DoS des betroffenen Browsers bis Cookie-Ablauf (1 h); keine Cross-User-Wirkung.
**Empfehlung:** `decodeURIComponent` in `try/catch`, bei Fehler `null` + `clearIdentityCookie(res)`; oder ohne Decoding lesen.

### AP3-08 [S3] [Korrektheit/Sicherheit] server/server.js:L485-516 — Identity-Cookie-Middleware prüft nur die Signatur, nicht die Revocation
**Urteil:** BESTÄTIGT (Severity unverändert; AP3-17 zusammengeführt)
**Beleg:** L491 `verifyToken(cookieToken)` — kein `db.revokedTokens.has`/`db.tokens.exists` wie in `checkTokenValid` (L702-711). `/hhttps/revoke` (L3678-3697) löscht den Cookie nur in der eigenen Antwort (L3693); ein anderer Browser/Kopie desselben Cookies liefert bis `ACCESS_TTL` (3600 s, L93) weiter `HHTTPS-Status: verified` plus Rolle/Alter/Methoden.
**Auswirkung:** Widersprüchlicher Zustand `/hhttps/check` (revoked) vs. Landing-Page-Header (verified); die Revoke-Zusage gilt für den Cookie-Kanal nicht.
**Empfehlung:** In der Middleware mindestens `db.revokedTokens.has(jti)` (ggf. kurz gecacht) und bei Treffer `clearIdentityCookie`; Doku der Header entsprechend präzisieren.

### AP3-09 [S3] [Korrektheit] server/server.js:L3028-3050 — GitHub-Callback ignoriert `alreadyOwnedBy`: Anchor wird auf zweiten User umgehängt, Session trotzdem verifiziert
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilen korrigiert: Route L3028-3050, Warnung L3035)
**Beleg:** external-verify.js L104-115 `recordAnchor` mit `ON CONFLICT … SET user_id = EXCLUDED.user_id` (läuft VOR der Rückgabe), L225-229 `sessions.update({githubVerified:true})` bedingungslos, L233-237 `alreadyOwnedBy` nur als Rückgabewert. server.js L3035 `const warn = result.alreadyOwnedBy ? ' (warning: anchor collision)' : ''` → `ok:true`-Seite (L3040-3044), `getGithubStatus` (external-verify.js L247-254) meldet `verified:true`. Kein Test referenziert `alreadyOwnedBy` (grep test/).
**Auswirkung:** Ein GitHub-Konto verifiziert beliebig viele HHTTPS-Identitäten nacheinander; `external_verification_anchors` zeigt nur den letzten User — Widerspruch zur E-Mail-Anker-Semantik (409 `identity_conflict`).
**Empfehlung:** Bei `alreadyOwnedBy !== null` Fehlerseite `github_already_bound`, `recordAnchor`/`sessions.update` unterlassen (Reihenfolge in `handleGithubCallback` ändern, AP4); Test analog F-6.

### AP3-10 [S3] [Korrektheit] server/test/integration/gate.test.mjs:L154-166, server/test/e2e/signin.e2e.test.mjs:L205-250 — Kein Test deckt die Kette Passkey-Session → `role/declare` ab
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `signin.e2e.test.mjs` läuft 6/6 grün und endet nach `auth/finish 200` + `#st-passkey .check` (L221-223); `#issueBtn` wird nie geklickt. `gate.test.mjs` nutzt nur `verifiedSession()` (E-Mail). Das Scratchpad-Skript `repro-k1-e2e.mjs` (gleicher Ablauf + `#issueBtn`) zeigt sofort das 403 aus AP3-01. Ebenfalls fehlend (grep): Negativtests `token/refresh` (revoked/expired → 401), `email/verify` mit Array-Parametern, `classifyDomain` (kein Import in test/unit).
**Auswirkung:** Regressionen im zentralen Sign-in-Pfad bleiben in `npm test`/`test:e2e` unsichtbar — AP3-01 ist der Beweis.
**Empfehlung:** E2E um `#issueBtn` + Assertion `role/declare 200`, `email_verified:true`, `passkey_verified:true` ergänzen; Integrationstest mit per SQL angelegter Credential-Row; Negativtests für Refresh/Magic-Link; Unit-Tests für `classifyDomain` (siehe AP3-41).

### AP3-11 [S4] [Korrektheit] server/identity.js:L118-129, server/server.js:L2809,L2829 — `eudiVerified`/`hasPasskey` werden nie persistiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `sessions` hat keine Spalte `eudi_verified`/`has_passkey` (schema.sql L27-45; grep sql/ leer), `_normalize` (db.js L210-231) liefert die Felder nicht, `allowedColumns` kennt sie nicht. Repro: `sessions.get` → `hasPasskey: undefined`. `prior.eudiVerified` (identity.js L127), `session.eudiVerified` (L2829, L3149), `hasPasskey: true` (L2585) sind wirkungslos; nur `credentialId` trägt Passkey-Information (`session.hasPasskey || session.credentialId`, L2824/L3144).
**Auswirkung:** Kein Laufzeitfehler, aber irreführende Merge-/Konfliktlogik; EUDI vor E-Mail-Bind fließt nie in `hasOtherMethod`/claims cache.
**Empfehlung:** Spalte einführen (Migration + `_normalize` + `allowedColumns`) und im EUDI-Flow schreiben, oder tote Flags und Kommentare entfernen.

### AP3-12 [S4] [Korrektheit/Wartbarkeit] server/server.js:L2658-2674, server/email.js:L86-97 — Kommentare zu `/session/email/start` und zum Trust-Modell widersprechen dem Code
**Urteil:** BESTÄTIGT (Severity unverändert S4; AP3-31 zusammengeführt — dessen S3 auf S4 gesetzt, da reine Doku-Wirkung)
**Beleg:** L2666 „trust_score: 30“, L2674 „trustScore: 30“ vs. Code `trustScore: 0` (L2693, L2702); L2670 „5 Req / 60 min“ vs. `limit.email = rl(30, 60*60_000)` (L428). email.js L86-97 „baseline (30)“, „base 30 + domainBonus + (passkey ? 30 : 0)“, „.edu“ (nicht in `DOMAIN_RULES`) vs. roles.js L28-29 (email 20, passkey +30) und `computeVerification`. L2882 `expiresIn: '15 Minuten'` bezieht sich auf Code, nicht Session (AP3-05).
**Auswirkung:** Irreführende Doku; keine Laufzeitwirkung.
**Empfehlung:** Kommentare auf `trustScore: 0`, `limit.email` (30/h) und das `computeVerification`-Modell korrigieren; Zahlen aus roles.js referenzieren statt wiederholen.

### AP3-13 [S1] [Sicherheit] server/server.js:L2852-2854 — E-Mail-Regex und nodemailer-Adressparser interpretieren die Adresse unterschiedlich: `x@evil.com(bundestag.de` wird an evil.com zugestellt, aber als `official-email` (+40) klassifiziert
**Urteil:** BESTÄTIGT (Severity unverändert S1)
**Beleg:** Regex L2853 `^[^\s@]+@[^\s@]+\.[^\s@]+$` lässt `(`, `)` und Nicht-ASCII zu. Repro (`repro-s1-email.mjs`, nodemailer 6.10.1, `streamTransport:true`, `info.envelope.to`):
```
x@evil.com(bundestag.de   regexOk:true  classifyDomain: official-email +40  addressparser/Envelope: ["x@evil.com"]
x@evil.com(.uni-          regexOk:true  classifyDomain: school-email  +15  Envelope: ["x@evil.com"]
x@evil.com＠bundestag.de  regexOk:true  classifyDomain: official-email +40  Envelope: ["x@evil.xn--combundestag-k050e.de"]
```
Ende-zu-Ende gegen den Harness (`repro-k3.mjs`): `POST /hhttps/email/send {email:'x@evil.com(bundestag.de'}` → **200 `{domain:"evil.com(bundestag.de", expectedLevel:"official-email", expectedTrustScore:40}`**; mit SMTP ginge der Code an `x@evil.com`. Nach `confirm-code` schreibt `bindSessionToEmailAnchor` (L2812-2818) `emailLevel/emailTrustBonus/emailDomain` in die Session; `computeVerification({email, domain, domainTrust:40})` → `trust 60, isHuman true` (Human-Schwelle 50 ohne Passkey), `domain_name` im Token (`tokenSurface` L2406) und Header `HHTTPS-Domain: evil.com(bundestag.de`. Ein Relying Party mit `endsWith('bundestag.de')` wird getäuscht. Anmerkung zum Rohbefund: `roles.js L92` (`official-email: trustScore 90`) ist die Legacy-Level-Tabelle; die live wirksame Größe ist der +40-Bonus in `computeVerification` — die Bewertung S1 bleibt, weil die Umgehung kostenlos ist und die Human-Schwelle betrifft.
**Auswirkung:** Kostenlose Erlangung der höchsten E-Mail-Assurance-Stufe (Behörde) und des „Verified human“-Bands ohne Passkey; Assurance-Modell für Behörden/Hochschulen/Presse ist nicht belastbar.
**Empfehlung:** Strikte ASCII-Validierung (`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`, max. 254 Zeichen) VOR `classifyDomain` und `sendMail`; zusätzlich `addressparser(email)[0].address === email` erzwingen (sonst 400); nodemailer ≥ 9.1.0 (GHSA-cc9r-2j5m-2m83, GHSA-mm7p-fcc7-pg87, GHSA-wmmp-3585-3rmp); Label-Grenzen-Fix aus AP3-02 zusätzlich nötig.

### AP3-15 [S2] [Sicherheit] server/email.js:L445-448 — `setupUrl` wird unescaped in ein `href`-Attribut der Registrierungsmail eingesetzt → HTML-Injection in Mails von noreply@hhttps.org an frei wählbare Empfänger
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** email.js L445/L448 `<a href="${setupUrl}" …>` ohne `escapeHtml`. `setupUrl` = `String(homepage_url).replace(/\/+$/, '') + '/wp-admin/…'` (wp-plugin-registration.js L163-164); `homepage_url` wird nur über `apexDomainFromUrl` (L38-51, `new URL(...).hostname`) geprüft — Pfad/Query/Fragment bleiben roh, `https://evil.com/"><img src=x onerror=…>` liefert hostname `evil.com` und passiert. `/hhttps/plugin/register` (L102) ist ohne Authentifizierung, nur IP-Rate-Limit (L103-107); `contact_email` frei wählbar (L115-118). Zusätzlich: `emailShell` setzt `ctaUrl` (L263/L266) und `subject` `platformName` ungeprüft ein (Header-CRLF wird von mime-node neutralisiert).
**Auswirkung:** Phishing-Relay mit vertrauenswürdigem Absender und SPF-Domain hhttps.org.
**Empfehlung:** `escapeHtml` für jede interpolierte URL (auch `ctaUrl`); `setupUrl` serverseitig aus `https://<apex>` + festem Pfad bilden statt aus der Roh-URL; `homepage_url` auf `new URL(u).origin === u` (ohne Pfad) prüfen.

### AP3-16 [S3] [Sicherheit/Wartbarkeit] server/email.js:L498-502, L553-557, L602-606, L725-730, L871-875 — Fünf Versandfunktionen fallen ohne Transport still in „Dev-Mode“ und loggen Bestätigungs-Links/Tokens
**Urteil:** BESTÄTIGT (Severity unverändert; AP3-32 zusammengeführt)
**Beleg:** Nur `sendVerificationEmail` prüft `emailDevModeAllowed()` (L404-409). Die fünf anderen Blöcke (`createTransport()` L498, L553, L602, L725, L871) geben bei `null` `{sent:false, devMode:true}` zurück und `devLog` (L797-808) schreibt Empfänger und Link (mit `email_token` bzw. Privacy-Pass-`rawToken`) auf stdout — unabhängig von `NODE_ENV`. Aufrufer privacy-pass/verifications-api.js L109-112 quittiert das nur mit `console.warn`. Sechsfach kopierter Block = Wartbarkeitsbefund AP3-32 (gleiche Ursache).
**Auswirkung:** Bei SMTP-Ausfall in Produktion landen Einmal-Tokens in pm2-/Journal-Logs; Nutzer erhalten nichts, Aufrufer melden Erfolg.
**Empfehlung:** Gemeinsamer `sendMail({…, failClosed})`-Helfer, der Transport, Dev-Fallback und `buildMailOptions` kapselt und ohne `emailDevModeAllowed()` wirft; `devLog` ohne Tokens außerhalb von `EMAIL_DEV_MODE=1`.

### AP3-18 [S3] [Sicherheit] server/server.js:L2606-2656 — Refresh-Token: 7-Tage-Bearer ohne Rotation, ohne Reuse-Erkennung, ohne Bindung
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2611-2616 prüfen Signatur/Revocation/Existenz, L2628 stellt nur ein neues Access-Token aus; kein neuer Refresh-Token, keine Invalidierung der jti (Antwort L2644-2651 enthält keinen `refreshToken`). `issueRefreshToken` (L680-700): `REFRESH_TTL = 7 d` (L94), keine Client-/Gerätebindung; Route ohne eigenen Limiter (nur `limit.global`).
**Auswirkung:** Abgeflossener Refresh-Token ist 7 Tage unbemerkt nutzbar.
**Empfehlung:** Rotation + Familien-Revocation bei Reuse (RFC 6819 §5.2.2.3); moderates Rate-Limit (siehe AP3-28).

### AP3-19 [S3] [Sicherheit] server/server.js:L2940-2951 — 6-stelliger Code ohne Fehlversuchszähler pro Session
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `verifyEmailCode` → `getAndConsumeByCode` (db.js L357-365) `WHERE code = $1 AND session_id = $2 AND used = FALSE`; ein Fehlversuch verändert nichts. Einzige Bremse `limit.email` (30/60 min pro IP, L428, IP-basiert). `sessionId` steht im Magic-Link (email.js L400) und in Antworten.
**Auswirkung:** Kein direkter Exploit (10^6 Codes, 15 min), aber der Standardschutz für OTPs (≤ 5-10 Versuche) fehlt.
**Empfehlung:** Spalte `attempts`, ab N Fehlversuchen Zeile auf `used = TRUE` und Kontext löschen.

### AP3-20 [S4] [Sicherheit] server/server.js:L2453, L2526, L2709, L2750, L2892, L3024 — Interne Fehlermeldungen (`e.message`) gehen 1:1 an den Client
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Alle sechs Zeilen verifiziert (`res.status(500).json({ error: e.message })`, L2892 `'E-Mail-Fehler: ' + err.message`); zusätzlich L2502, L2601 (400), L2654 (401), L3049 (GitHub-Fehlerseite `message: e.message`).
**Auswirkung:** Information Disclosure (pg-/SMTP-Fehlertexte).
**Empfehlung:** Generische Fehlercodes, `e.message` nur ins Log (Helfer aus AP3-37).

### AP3-23 [S4] [Sicherheit] server/email.js:L842-848, L879 — `roleDisplay(role)` in der Privacy-Pass-Mail nicht HTML-escaped; `roleLabel` fällt auf die rohe `roleId` zurück
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** email.js L842 `const label = roleDisplay(role)`, L848 `${label}` roh im HTML; roles.i18n.js L369-372 `?? roleId`. Einziger Aufrufer privacy-pass/verifications-api.js L44/L64 prüft `ROLES.includes(role)` — heute nicht ausnutzbar, Absicherung fehlt im Modul (anders als `renderVerificationEmail` L308-310).
**Auswirkung:** Latente HTML-Injection.
**Empfehlung:** Whitelist + `escapeHtml(label)` in der Funktion selbst.

### AP3-24 [S3] [Performance] server/email.js:L388-398, server/sql/schema.sql:L203 — Verbrauchte `email_verifications`-Zeilen werden nie gelöscht; Lookups auf `session_id`/`code` ohne Index
**Urteil:** BESTÄTIGT (herabgestuft von S2: lineares Wachstum um eine Zeile pro Login, keine Hot-Loop; schleichender Latenzanstieg, kein Ausfallszenario; Fix trivial)
**Beleg:** `cleanup_expired()` schema.sql L203 `DELETE FROM email_verifications WHERE expires_at < NOW() AND used = FALSE`; alle Konsumpfade setzen `used = TRUE` (db.js L335-365); kein weiteres `DELETE` im Repo (grep sql/, db.js; einzige Migration-Referenz: keine). Indizes nur `expires_at`, `email` (schema.sql L118-119); `code` per `ALTER TABLE` (db.js L376) ohne Index; `getAndConsumeByCode` filtert `code, session_id`, `invalidateForSession` `session_id`.
**Auswirkung:** Tabelle wächst mit jedem Sign-in; `email/send`/`confirm-code` machen Seq-Scans über Altzeilen; `sha256(email)`-Hashes bleiben unbegrenzt liegen.
**Empfehlung:** `AND used = FALSE` aus `cleanup_expired()` entfernen (AP6); Index auf `(session_id)` bzw. `(code, session_id)`.

### AP3-25 [S3] [Performance] server/email.js:L145-162 — Pro Mail ein neuer SMTP-Transport ohne Timeouts; `/hhttps/email/send` blockiert bis zur SMTP-Antwort
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `createTransport()` an sechs Stellen pro Versand (L403, L498, L553, L602, L725, L871), kein `pool`, keine Timeouts (L147-153). nodemailer-Defaults geprüft (smtp-connection/index.js L14-16): `CONNECTION_TIMEOUT` 2 min, `GREETING_TIMEOUT` 30 s, `SOCKET_TIMEOUT` 10 min. `await transporter.sendMail` (L414) im Request-Pfad (server.js L2869), Kontext-Parken erst danach (L2871-2876); `fs.existsSync` ×2 pro Send im Fallback (L158).
**Auswirkung:** Hängendes Relay hält Send-Requests minutenlang offen; Session-TTL (15 min) läuft weiter; TLS+AUTH-Handshake pro Mail.
**Empfehlung:** Transporter einmal lazy erzeugen (`pool:true`, `connectionTimeout/greetingTimeout/socketTimeout` 10 s/10 s/30 s); `existsSync` einmalig.

### AP3-26 [S4] [Performance/Korrektheit] server/server.js:L2573 — `db.sessions.delete` existiert nicht; die vorherige Session wird beim Passkey-Merge nie gelöscht
**Urteil:** BESTÄTIGT (Severity unverändert S4; Ursache verknüpft mit AP3-01)
**Beleg:** db.js exportiert unter `sessions` nur `create/get/update/incrementEmailsSent/count/_normalize` (L147-237); `grep "async delete" db.js` → nur challenges (L140), tokens (L259), refreshTokens (L287), webhooks (L680). Repro: `typeof db.sessions.delete === 'undefined'`, Aufruf wirft `TypeError: db.sessions.delete is not a function` in den leeren `catch (e) {}` (ESLint L2573:57). Nach dem E2E-Repro existieren beide Sessions in der DB.
**Auswirkung:** Kommentar L2558-2566 („exactly ONE active session“) trifft nicht zu; doppelte Zählung in `sessions.count()`; die alte Session bleibt bis 15/30 min nutzbar (heute paradoxerweise der einzige Weg, mit der E-Mail-Verifikation noch ein Token zu bekommen, vgl. AP3-01).
**Empfehlung:** `sessions.delete(sessionId)` implementieren, `catch` loggen; zusammen mit AP3-01 fixen.

### AP3-27 [S4] [Performance] server/server.js:L656-666 — `issueAccessToken` und alle Session-/Verifikations-Pfade schreiben sequentiell auf eine einzige `stats`-Zeile
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L656 `db.tokens.create` → L666 `db.stats.increment('tokens_issued')` sequentiell; `stats.increment` = `INSERT … ON CONFLICT DO UPDATE` (db.js L1321-1327, Row-Lock); `verifications` inkrementiert in L2497, L2593, L2697, L2738.
**Auswirkung:** Serialisierung auf zwei Zeilen unter Last; heute irrelevant.
**Empfehlung:** Zähler nicht awaiten oder batchen; mindestens `Promise.all`.

### AP3-28 [S4] [Performance] server/server.js:L2606-2656 — `/hhttps/token/refresh`: fünf sequentielle DB-Roundtrips ohne eigenes Rate-Limit; `credentials.get` nur für `deviceType`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2613 `revokedTokens.has` → L2615 `refreshTokens.get` → L2618 `credentials.get` (nur `cred?.deviceType`, L2635) → `tokens.create` + `stats.increment` (L2628). Kein Limiter außer `limit.global` (300/min, L420).
**Auswirkung:** Unnötige Latenz; bis 300 Token-Zeilen/min pro IP bis zum Cleanup.
**Empfehlung:** `Promise.all` für die unabhängigen Reads, `deviceType` in den Refresh-Claims mitführen, moderates Limit.

### AP3-29 [S4] [Performance] server/server.js:L485-516 — Identity-Cookie-Middleware verifiziert das ES256-JWT bei jedem Request, auch für statische Assets
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Middleware L485 vor `express.static` (L519); `verifyToken` (L491) = `jwt.decode` + `jwt.verify` (keys.js L164-173) pro Request mit Cookie.
**Auswirkung:** ~0,1-0,3 ms CPU pro Asset-Request; kein Engpass.
**Empfehlung:** Auf Dokument-/API-Requests beschränken oder Ergebnis pro Token-Hash cachen.

### AP3-30 [S3] [Wartbarkeit] server/server.js:L2676-2752 — Zwei fast identische Session-Bootstrap-Routen; Frontend nutzt nur `/session/start`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2676-2711 und L2720-2752 unterscheiden sich nur in `deviceType` (`'email-only'`/`'pending'`) und `method`-String. grep über public/, sites/, extension/, privacy-pass/public/, test/, sdk/: einziger Treffer `sites/spec.html:783` (Doku). Kommentarblock veraltet (AP3-12).
**Auswirkung:** Doppelte Pflege; ungenutzte Route mit eigener Angriffsfläche.
**Empfehlung:** Alias auf gemeinsamen Handler oder deprecaten/entfernen; spec.html anpassen.

### AP3-33 [S3] [Wartbarkeit] server/server.js:L2896-2928 vs L2940-2987 — Bestätigungspfad (Token vs. Code) doppelt implementiert, zwei Fehlerformate, Reihenfolge driftet
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `/email/verify` konsumiert den Token (L2900) VOR dem Session-Lookup (L2905); `/email/confirm-code` lädt die Session zuerst (L2947) — der #22-Fix ist nur im Code-Pfad. Fehler als Redirect-`reason` (L2898-2909) vs. JSON 400/404/409/500 (L2942-2973).
**Auswirkung:** Fixes müssen doppelt eingebaut werden und driften nachweislich schon; zwei Fehlerkataloge für Clients.
**Empfehlung:** Gemeinsame `confirmEmailVerification()`; Routen mappen nur noch auf Redirect/JSON.

### AP3-34 [S3] [Wartbarkeit] server/server.js:L2611-2616 — `/token/refresh` reimplementiert den Refresh-Zweig von `checkTokenValid`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2611-2616 = `verifyToken` → `sub !== 'refresh'` → `revokedTokens.has` → `refreshTokens.get`; identisch zu `checkTokenValid` L702-711 inkl. wörtlich kopierter Meldung `'Refresh-Token nicht aktiv'` (L707/L2616).
**Auswirkung:** Ergänzungen in `checkTokenValid` (z. B. weitere Revocation-Quelle) gelten nicht für Refresh.
**Empfehlung:** `checkTokenValid(refreshToken)` verwenden, `refreshTokens.get` nur noch für `user_id/credential_id`.

### AP3-35 [S3] [Wartbarkeit] server/server.js:L2775 vs server/email.js:L391 — Hash-Vertrag „sha256(normalisierte E-Mail)“ zweimal unabhängig definiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** email.js L391 `sha256(email.toLowerCase())`, server.js L2775 `sha256(normalizeEmail(ctx.email))` (identity.js L9-12: trim+lowercase); Übereinstimmung nur, weil `/email/send` L2852 vorher normalisiert; email.js importiert `normalizeEmail` nicht (L36 nur `normalizeCode, isValidCode`).
**Auswirkung:** Änderung an einer Stelle → jede Verifikation scheitert still mit `email_context_mismatch`.
**Empfehlung:** `emailVerificationHash()` in identity.js exportieren und an beiden Stellen nutzen.

### AP3-36 [S3] [Wartbarkeit] server/email.js:L53 vs server/server.js:L78 — `BASE_URL` zweimal mit unterschiedlichem Default aus der Umgebung gelesen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** server.js L76-78 `BASE_URL = process.env.BASE_URL || ORIGIN` (ORIGIN aus `RP_ID`); email.js L53 `|| 'https://hhttps.org'`. Nur `sendVerificationEmail` erhält `baseUrl` (L2869); Verified/Rejected/Admin-Mails nutzen den email.js-Default (L539, L590, L651).
**Auswirkung:** Instanz mit `RP_ID`, aber ohne `BASE_URL`, verschickt Dashboard-Links auf hhttps.org.
**Empfehlung:** Zentrales `config.js`.

### AP3-37 [S3] [Wartbarkeit] server/server.js:L2413-3093 — Uneinheitliche Fehlerformate, Sprachen und Body-Handling
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Deutsch (L2480, L2539, L2553, L2612, L2858, L2892, L2705) neben Englisch (L2424, L2746); Text-Antworten `res.status(401).send('Invalid session.')` (L3007, L3010) neben JSON (L3014); `req.body || {}` in L2421, L2463, L2678, L2722, L2941 vs. nacktes `req.body` in L2509, L2534, L2607, L2848, L3090 — alle Zeilen verifiziert.
**Auswirkung:** Clients können Fehler nicht programmatisch unterscheiden.
**Empfehlung:** `sendError(res, status, code, detail)`-Helfer, Body-Normalisierung in Middleware.

### AP3-39 [S4] [Wartbarkeit] server/server.js:L2692,L2733,L2850,L3010 — `session.verified` ist bei jeder Session `true`; die Gates darauf sind wirkungslos
**Urteil:** BESTÄTIGT (herabgestuft von S3: tote Spalte/irreführender Name ohne Laufzeitwirkung)
**Beleg:** Alle drei `sessions.create`-Aufrufe setzen `verified: true` (L2584, L2692, L2733), db.js L157 `data.verified !== false`, Schema-Default `TRUE` (schema.sql L33). Prüfungen `!session?.verified` in L2850, L3010, L3100, L3299, L3509, L3602 sind äquivalent zu `!session`.
**Auswirkung:** Leser nehmen ein Gate an, das nichts filtert.
**Empfehlung:** Feld entfernen oder bedeutungsvoll belegen.

### AP3-40 [S4] [Wartbarkeit] server/email.js:L1-7 vs L62,L280,L743,L827 — Widersprüchliche „LEGACY“-Marker für den obligatorischen ersten Anmeldeschritt
**Urteil:** BESTÄTIGT (herabgestuft von S3: reine Kommentar-/Doku-Wirkung)
**Beleg:** L4-7 „MANDATORY first step“; L62 „legacy flow“, L280 „LEGACY: User email verification“, L743 „legacy user flow“, L827 „legacy HHTTPS role declaration flow“ — alle verifiziert.
**Auswirkung:** Fehlinterpretation als entfernbar.
**Empfehlung:** Marker ersetzen, Phase-Nummern durch Spec-Verweise.

### AP3-41 [S3] [Wartbarkeit] server/email.js:L435-741, server/server.js:L3056-3087 — Module ohne Tests: Plattform-/Admin-Mails, `classifyDomain`, GitHub-Return-Seite, `/session/email/start`
**Urteil:** BESTÄTIGT (Severity unverändert; überschneidet sich bei `classifyDomain` mit AP3-10)
**Beleg:** grep test/: keine Referenz auf `sendPlatformRegistrationEmail`, `sendPlatformVerifiedEmail`, `sendPlatformRejectedEmail`, `sendAdminPlatformNotification`, `sendPrivacyPassVerification`, `classifyDomain`, `renderGithubReturnPage`, `/session/email/start`; `email-template.test.mjs` importiert nur `renderVerificationEmail` (L5).
**Auswirkung:** AP3-02/AP3-13/AP3-15 wären mit Unit-Tests für `classifyDomain` bzw. die Mail-Renderer billig zu fangen gewesen.
**Empfehlung:** Render/Send trennen, Unit-Tests je Kategorie + Negativfall + Escaping.

### AP3-42 [S4] [Wartbarkeit] server/server.js:L2451,L2522,L2524,L2590,L2592,L2624,L2695,L2736,L2857,L2880 — Magic Numbers für TTLs, Trust-Seeds und Limits
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `120_000` (L2451), `60_000`/`90_000` (L2522/L2524), `1800_000` (L2592), `900_000` (L2695, L2736), `50` (L2590; `HUMAN_CONFIRMED_THRESHOLD` importiert L41, laut ESLint L41:34 ungenutzt), `20` (L2624), `> 3` (L2857), `'15 Minuten'` (L2882); in email.js „15 min“ hartkodiert an L323, L349-350, L363-364, L751, L781, L851, L854, L867-868 trotz `EMAIL_VERIFICATION_TTL_MS` (L45); `'0.5.0'` 25× in server.js.
**Auswirkung:** TTL-Änderungen erfordern Volltextsuche.
**Empfehlung:** Benannte Konstanten; Minutenangabe aus der TTL ableiten.

### AP3-43 [S4] [Wartbarkeit] server/server.js:L2636 — `tokenSurface` wird mit einem Pseudo-Session-Objekt aufgerufen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2400 Signatur `tokenSurface(session, v, pseudonym = session?.pseudonym || null)`; L2636 `tokenSurface({ emailDomain: domainVal }, { methods }, pseudonym)`; echte Sessions in L3176, L3555.
**Auswirkung:** Erweiterung um Session-Felder bricht Refresh still.
**Empfehlung:** Explizite Eingabe `{ methods, emailDomain, pseudonym }`.

### AP3-44 [S4] [Wartbarkeit] server/server.js:L2697,L2738 — `stats.increment('verifications')` beim reinen Session-Bootstrap
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2697, L2738 (Trust 0, keine Methode) sowie L2497 (Registrierung), L2593 (Login) erhöhen denselben Zähler.
**Auswirkung:** Kennzahl nicht als „Verifikationen“ interpretierbar.
**Empfehlung:** `sessions_started` separat; Inkrement erst nach bestätigter Methode.

### AP3-45 [S4] [Wartbarkeit] server/server.js:L2779-2790 — JSDoc von `bindSessionToEmailAnchor` hängt an `anchorConflict`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L2779-2784 `@returns {{ userId, pseudonym, created, methods, trust }}` direkt über `function anchorConflict(code)` (L2785); `bindSessionToEmailAnchor` beginnt L2792.
**Auswirkung:** Falsche IDE-Doku.
**Empfehlung:** Block verschieben.

### AP3-46 [S4] [Wartbarkeit] server/email.js:L810-818 vs server/server.js:L2370-2374 — `escapeHtml` doppelt implementiert
**Urteil:** BESTÄTIGT (Severity unverändert; Sachverhalt korrigiert: die Kopien sind NICHT byte-identisch)
**Beleg:** email.js L810-818 ersetzt `& < > " '` (5 Replaces); server.js L2370-2374 ersetzt nur `& < > "` — das `'`-Escaping fehlt dort. Die Kopien sind also bereits auseinandergedriftet (`renderGithubReturnPage` L3077 nutzt die schwächere Variante; heute unkritisch, da `message` nur in Element-Content steht).
**Auswirkung:** Härtungen müssen zweimal erfolgen; Drift bereits eingetreten.
**Empfehlung:** Eine exportierte Variante (identity.js/html.js), beide Dateien importieren.

### AP3-47 [S4] [Wartbarkeit] server/server.js:L535,L612,L2573; server/email.js:L159,L249,L511,L573 — ESLint-Warnungen im AP3-Bereich (Sammelfinding)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** docs/review/ap/eslint-output.txt: server.js 535:58 `token` unused, 612:18 `\-`, 2573:57 `e` unused; email.js 159:74 `e`, 249:23 `title` unused (`emailShell` rendert kein `<title>` — grep `<title>` in email.js leer), 511:69 `homepageUrl` unused (Aufrufer L4577 übergibt ihn), 573:9 `reasonDe` unused (deutscher Block L579-580 ohne Grund).
**Auswirkung:** Lint-Rauschen; Mails ohne `<title>`.
**Empfehlung:** Wie im Rohbefund.

## Verworfen
(keine — alle Rohbefunde haben Datei:Zeile und einen erreichbaren Codepfad)

## Zusammengeführt
- AP3-14 [S2] [Sicherheit] server/email.js:L99-115 — Domain-Klassifikation ohne Label-Grenze → in AP3-02 (gleiche Ursache; Security-Impact dort übernommen).
- AP3-17 [S3] [Sicherheit] server/server.js:L485-516 — Cookie-Middleware ohne Revocation → in AP3-08 (gleiche Ursache).
- AP3-21 [S4] [Sicherheit] server/server.js:L2896-2901, L2534-2538 — ungeprüfte Eingabetypen → unbehandelte Rejections → in AP3-03 (auth/finish) und AP3-04 (email/verify); gleiche Ursache.
- AP3-22 [S4] [Sicherheit] server/server.js:L468-479 — `readIdentityCookie` URIError → in AP3-07 (gleiche Ursache).
- AP3-31 [S3] [Wartbarkeit] server/server.js:L2658-2674 — Kommentarblock widerspricht Code → in AP3-12 (gleiche Ursache).
- AP3-32 [S3] [Wartbarkeit] server/email.js:L403-412 u. a. — sechsfacher Transport-Fallback-Block → in AP3-16 (gleiche Ursache, dort inkl. Helfer-Empfehlung).
- AP3-38 [S3] [Wartbarkeit] server/server.js:L2534-2539 — `auth/finish` liest `response.id` außerhalb des try → in AP3-03 (gleiche Ursache).

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit | 12 | 12 | 0 | 0 |
| Sicherheit | 11 | 7 | 0 | 4 |
| Performance | 6 | 6 | 0 | 0 |
| Wartbarkeit | 18 | 15 | 0 | 3 |
| **Summe** | **47** | **40** | **0** | **7** |

Bestätigt je Severity: S1 2, S2 2, S3 18, S4 18.
Umstufungen: AP3-06 S3→S4, AP3-07 S3→S4, AP3-24 S2→S3, AP3-39 S3→S4, AP3-40 S3→S4; AP3-31 (S3) in AP3-12 (S4) aufgegangen.

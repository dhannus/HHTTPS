# AP8 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b (Arbeitsstand 0386105)

Umfang: Frontend `server/public/*`, `sites/*`, `extension/*`. Rohbefunde: AP8-K (14), AP8-S (8), AP8-P (11), AP8-W (21) = 54 Findings. IDs in Reihenfolge K → S → P → W.

Methodik: Jede Datei:Zeile per `sed -n`/`grep -n` geöffnet; Gegenmaßnahmen in `server/server.js` (CSP L392–410, Static-Mount L519, Routen), `server/email.js`, `server/eudi-verifier/index.js` geprüft. Zusätzlich: Testserver aus `test/helpers/server.mjs` gebootet (Repro-Skript `scratchpad/ap8-repro.mjs`) und die Legacy-Seiten/CSP/404 real abgefragt; Unit-Tests `signin-page.test.mjs` + `legacy-pages.test.mjs` ausgeführt (29/29 pass); Logik-Repros für K-Findings in `node -e`.

## Bestätigte Findings

### AP8-01 [S2] [Korrektheit] sites/hhttps.html:L1839-1896 — Nach erfolgreichem `/hhttps/role/declare` wirft die aktive `doDeclarRole`-Implementierung immer einen TypeError (`d.role` ist seit v0.5 `null`)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `window.doDeclarRole` (L1839) liest `d.role.emailVerified` (L1879) sowie `d.role.level` (L1884, L1885) ohne Optional Chaining. Der Server antwortet in `/hhttps/role/declare` fest mit `role: null, // no self-declared role (EUDI EAA only)` (server.js L3221). Repro: `const d={role:null}; d.role.emailVerified` → `TypeError: Cannot read properties of null (reading 'emailVerified')`. Der `catch` (L1891) zeigt `msg('Fehler: '+e.message,'e')`; `setStep(4)` (L1890) ist unerreichbar. `publishIdentity()` (L1863–1871) wurde vorher bereits ausgeführt (Token in localStorage + postMessage an Extension).
**Auswirkung:** Interaktiver Demo-Flow der Landing-Page endet immer mit „Fehler: Cannot read properties of null“, obwohl Access+Refresh-Token ausgestellt wurden; jeder Retry stellt weitere Tokens aus. (Einschränkung: die Seite wird laut AP8-40 nicht deployt — der Fehler ist aber im Repo-Stand reproduzierbar und die Seite wird aktiv getestet/gepflegt.)
**Empfehlung:** `d.role?.…` bzw. auf `d.verification.emailVerified` / `d.hhttps.verifiedMethods` umstellen; tote Original-Implementierung (AP8-41) entfernen.

### AP8-02 [S2] [Korrektheit] extension/popup.js:L176-184 — `buildSnippet()` erzeugt für Maschinen-Identitäten und für v0.5-Menschen „… human · Trust 60/100 …“
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** popup.js L179 `const role = ident.role || 'human'`, L180 `const trust = ident.trustScore || 60`; `actorType` wird in popup.js nirgends gelesen. index.html L758–766 schreibt die Bot-Identität mit `role:null, trustScore:0, actorType:'bot'` nach `localStorage['hhttps_identity']`; content-issuer.js L36–42 leitet jedes Objekt mit `token` an den Background weiter (`IDENTITY_CAPTURED`, background.js L36–45). Repro: `{role:null,trustScore:0}` → `role='human'`, `trust=60`.
**Auswirkung:** Die Extension produziert einen menschenlesbaren Identitätsclaim „human · Trust 60/100“ für ein Bot-Token (Server: `human:false, trustScore:0`) — Verstoß gegen die Kernregel „nie als Mensch ausgewiesen“. Für v0.5-Menschen-Tokens (`role:null`) wird ebenfalls ein Default statt der echten Werte ausgegeben. Zusammen mit AP8-16 (Snippet enthält das Bearer-Token) besonders unschön.
**Empfehlung:** `??` statt `||`, `actorType==='bot'` explizit rendern, keinen 60er-Default; besser das Snippet-Feature ganz entfernen (AP8-16).

### AP8-03 [S3] [Korrektheit] server/public/workload.html:L117, L180, L233, L254 — Seite ruft `/hhttps/machine/workload/{list,bind,unbind}` (und bewirbt `/hhttps/machine/exchange`), die auf dem Server nicht existieren
**Urteil:** BESTÄTIGT (Severity unverändert; AP8-38 hier zusammengeführt)
**Beleg:** `grep -n "workload\|machine/exchange" server/server.js` → leer; `workload-identity.js` wird nicht importiert. Live-Repro gegen Testserver: `POST /hhttps/machine/workload/list` → **404, `content-type: text/html`**; damit wirft `await r.json()` (L184) einen `SyntaxError` („Unexpected token <“), den der `catch` als Fehlertext anzeigt. Die Seite ist über `express.static` (server.js L519) unter `/workload.html` erreichbar und nirgends verlinkt (kein Treffer außerhalb der Datei und der Review-Dokumente).
**Auswirkung:** Öffentlich ausgelieferte, vollständig funktionslose Seite mit irreführender Fehlermeldung; Integratoren finden eine „Workload-Identity“-UI, die nichts tut. Server-Seite (fehlende Routen) ist in AP5 dokumentiert.
**Empfehlung:** Seite entfernen bzw. erst ausliefern, wenn die Routen aus `workload-identity.js` gemountet sind; `r.json()` gegen Nicht-JSON absichern.

### AP8-04 [S3] [Korrektheit] extension/background.js:L36-45 + L128-141 + L168-182 — Auto-Refresh wird für frisch eingefangene Identitäten nie geplant (`identity.id` ist `undefined`)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L37–39 `storeIdentity(msg.identity).then(() => { scheduleRefreshFor(msg.identity); …})` übergibt das rohe Seiten-Objekt. `storeIdentity` setzt `id` nur auf der Kopie `enriched` (L131) und gibt nichts zurück. In `scheduleRefreshFor` entsteht `alarmName = 'refresh_undefined'` (L175) bzw. bei knapp ablaufendem Token `refreshIdentity(undefined)` (L177). Der Alarm-Listener (L184–189) ruft `refreshIdentity('undefined')` → `findIndex` < 0 → `throw new Error('identity not found')` (L194), vom `.catch(() => {})` geschluckt. Repro: `'refresh_'+raw.id` → `refresh_undefined`. Weder `publishIdentity()` (index.html L786–810, hhttps.html L1573–1590) noch der Maschinen-Pfad setzen ein `id`-Feld.
**Auswirkung:** Die im Header (L6) versprochene Funktion „auto-refresh 5 min before expiry“ läuft im Normalpfad nicht; erst `rebuildSchedules` (L290–294, nur bei `onStartup`/`onInstalled`) plant mit gespeicherten IDs. Popup zeigt nach 1 h „abgelaufen – wird erneuert“ (popup.js L127–129), ohne dass etwas passiert.
**Empfehlung:** `storeIdentity()` das `enriched`-Objekt zurückgeben lassen und dieses an `scheduleRefreshFor` übergeben.

### AP8-05 [S3] [Korrektheit] extension/background.js:L159-165 — Identitäts-ID `issuer#role` kollidiert für alle v0.5-Identitäten; Mensch und Maschine überschreiben sich gegenseitig
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `computeIdentityId` (L163) `identity.role || 'unknown'`. index.html publiziert Menschen mit `role: (d.role&&…)||h.role||null` (L792; Server liefert `role:null`, s. AP8-01) und Maschinen mit `role:null` (L761). Repro: beide → `hhttps://hhttps.org#unknown`. `storeIdentity` (L133–134) ersetzt den Eintrag mit gleicher ID und setzt ihn als aktiv (L139).
**Auswirkung:** Bot-Registrierung nach Menschen-Login (oder umgekehrt) überschreibt die andere Identität samt Refresh-Token ohne Rückfrage; Rollen-Umschalter (popup.js L143–164, nur ab 2 Identitäten) bleibt wirkungslos.
**Empfehlung:** ID aus `issuer` + `actorType` + `sub`/`jti` aus dem JWT-Payload (`decodeJwtPayload`, L276) bilden.

### AP8-06 [S3] [Korrektheit] server/public/index.html:L722-727 + L782 — Maschinen-Flow bleibt nach verbrauchtem Code hängen, wenn `machine/register` oder `machine/token` fehlschlagen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Schritt B ruft `confirm-code` (L724) auf; `verifyEmailCode` verbraucht den Code (`emailVerifications.getAndConsumeByCode`, email.js L777). Danach `machine/register` (L743) mit `if(!r.ok)throw 0` → generischer `catch` (L782) `tr('err')`; `MACHINE_STEP` bleibt `'code'` (nur in Schritt A auf `'code'` gesetzt, L711, nie weiter). Reale Fehlerpfade: 400 `invalid_role`/reservierter Beruf (server.js L3797–3800 `guardReservedRole`), `operator_email_unconfirmed` (L3788–3789), 429 `limit.machine`. Beim nächsten Klick liefert `confirm-code` 400 (Code verbraucht) → `machine.codeErr` (L725); E-Mail-Feld ist `readOnly` (L712), Schritt A unerreichbar. Das Server-`detail` wird verworfen.
**Auswirkung:** Nutzer sieht „Code ungültig“, obwohl der Code korrekt war; einziger Ausweg ist Reload + neuer Mailversand. Der eigentliche Grund (z. B. geschützter Beruf) wird nie angezeigt.
**Empfehlung:** Nach erfolgreichem `confirm-code` `MACHINE_STEP='confirmed'` setzen und `confirm-code` überspringen; `d.detail` anzeigen.

### AP8-07 [S3] [Korrektheit] server/public/index.html:L641-646 (pollEudi), L666-671 (pollAge), L687-691 (pollGithub) — Terminale Zustände (`failed`, `expired`/404, HTTP≥400) werden ignoriert; feste Kadenz 80×2,5 s ohne Backoff/Abbruch/Doppelstart-Schutz
**Urteil:** BESTÄTIGT (Severity unverändert; AP8-28 [Performance] hier zusammengeführt)
**Beleg:** Alle drei Schleifen: `for(let i=0;i<80;i++){await …2500; try{… if(d.status==='verified'){…return} if(d.status==='error'&&d.error==='email_verification_required'){…return}}catch(e){}}` — kein anderer Ausstieg. `eudi-verifier/index.js` liefert `404 {status:'expired'}` (L235 age, L330 av, L411 eid) und `{status:'failed', reason:'no_age_claim_disclosed'}` (L257, L350). `pollGithub` kennt nur `d.verified` (L690). Keine Cancel-Referenz: erneuter Klick startet einen zweiten Poller; `document.hidden` unberücksichtigt. (Korrektur zu K: `failed` liegt in L257/L350, nicht L241–244.)
**Auswirkung:** Nutzer sieht bis zu 200 s „Warte auf Bestätigung …“ nach endgültigem Scheitern; bis zu 80 unnötige Backend-Aufrufe je Versuch (GitHub-Status ist ein POST unter `limit.global`), vervielfacht bei Mehrfachklick.
**Empfehlung:** Bei `failed`/`expired`/HTTP≥400 abbrechen und Meldung zeigen; Generation-Counter/AbortController gegen Doppelstart; progressives Intervall; nach 80 Iterationen Meldung.

### AP8-08 [S3] [Korrektheit] sites/hhttps.html:L923 + L1904-1907 + L1468-1479 — Gecachte `hhttps_uid` springt direkt zum Passkey-Login; die entstehende Session ist nicht E-Mail-verifiziert → `role/declare` 403 ohne Rückweg
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L923 `let userId = localStorage.getItem('hhttps_uid') || null;` (gesetzt in L1430, L1765). Init L1904–1907: `if (userId) { … setTimeout(() => setStep(2), 300); }`. `doAuth` (L1476–1479) sendet `priorSessionId: sessionId` mit `sessionId === null`. Server `auth/finish` (L2567–2569): `priorId = priorSessionId || emailSessionId` → `null` → `prior = null` → kein Merge; neue Session ohne `emailVerified`. `/hhttps/role/declare` → `requireEmailVerified` (server.js L3102, L672–678) → 403 `email_verification_required`. Der Override zeigt nur `Fehler: email_verification_required` (L1891); `setStep(0)` bei 403 existiert nur in `doRegister` (L1425–1427).
**Auswirkung:** Jeder Zweitbesuch am selben Gerät endet in einer Sackgasse (Reload → wieder Schritt 2); nur localStorage-Löschen hilft.
**Empfehlung:** Auto-Sprung entfernen bzw. an `checkEmailStatus()` koppeln; 403-Behandlung wie in `doRegister`.

### AP8-09 [S3] [Korrektheit] sites/hhttps.html:L930-946 + L1849-1871 — Seite sendet einen frei gewählten v0.4-Rollenkatalog und publiziert ihn an die Extension, obwohl der Server die Rolle ignoriert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `ROLES_LOCAL` L930–946 (journalist, lawyer, medical_professional, politician …); Request L1849–1852 `role: selRole, verificationMethod, verificationData`. Server (L3114–3119, Kommentar „we do not take a role from the request“; Antwort `role: null` L3221). `publishIdentity({ role: selRole, roleLabel: rl?.label, roleIcon: rl?.icon, … })` L1863–1871 läuft vor dem TypeError aus AP8-01 und ist damit wirksam (localStorage + postMessage).
**Auswirkung:** Extension-Badge (background.js L260–261), Popup und Snippet zeigen z. B. „⚖️ Anwalt / Anwältin“, obwohl das Token keine Rolle trägt und `/hhttps/check`/Signaturen sie nie bestätigen.
**Empfehlung:** Rollenauswahl entfernen oder auf `/hhttps/role/card` (ESCO) umstellen; `publishIdentity` nur mit Server-Antwortwerten füllen.

### AP8-10 [S4] [Korrektheit] server/public/email-verify.html:L77-115 — Verwaiste Legacy-Seite mit veraltetem URL-Vertrag; Doku behauptet einen Redirect, den es nicht gibt
**Urteil:** BESTÄTIGT (Severity unverändert; AP8-39 hier zusammengeführt; Sicherheitsaspekt separat in AP8-15)
**Beleg:** email.js L400 `verifyUrl = ${base}/hhttps/email/verify?token=…&session=…`; server.js L2896–2927 leitet ausschließlich auf `/?email_verify=…` um. Einzige Referenzen: `EMAIL_SETUP.md:109` und `server/EMAIL_SETUP.md:114` („redirect zu /email-verify.html“ — falsch). Die Seite baut `/?verified_session=…&score=…&level=…` (L93); index.html `handleEmailVerifyReturn` (L1000–1025) kennt nur `email_verify/session/pseudonym`; `verified_session` wird nur in sites/hhttps.html L1803–1816 verarbeitet (nicht deployt, AP8-40). Live-Repro: `GET /email-verify.html` → 200.
**Auswirkung:** Toter, öffentlich ausgelieferter Code; drei Seiten mit drei Parameter-Sets für denselben Vorgang; Doku falsch.
**Empfehlung:** Datei löschen (schließt zugleich AP8-15), EMAIL_SETUP.md korrigieren.

### AP8-11 [S4] [Korrektheit] server/public/email-patch.js:L1-2 — Datei besteht nur aus einem Kommentar und verweist auf ein nicht existierendes Build-Skript
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Inhalt exakt zwei Kommentarzeilen; `grep -rn email-patch` trifft nur die Datei selbst und Review-Dokumente. Live-Repro: `GET /email-patch.js` → 200.
**Auswirkung:** Irreführend, öffentlich ausgeliefert.
**Empfehlung:** Löschen.

### AP8-12 [S4] [Korrektheit] sites/spec.html:L577, L650, L684, L783, L1495-1515 (+ sites/iamhmn.html L1728, L2904, L2923, L3138) — Öffentliche Spezifikation dokumentiert v0.4.1, falschen `issuer`-Wert und eine unvollständige Endpunkt-Tabelle
**Urteil:** BESTÄTIGT (Severity unverändert; AP8-43 hier zusammengeführt, mit Korrektur)
**Beleg:** spec.html L1503–1504 `"issuer": "hhttps://hhttps.org"`, `"protocol_version": "0.4.1"`, `supported_roles: ["citizen","journalist",…]`; Server L728–753: `issuer: https://hhttps.org`, `hhttps_issuer`, `protocol_version: '0.5.0'`, `supported_roles: 'esco-dynamic (no fixed catalogue)'`, zusätzliche Felder (`token_refresh_endpoint`, `roles_model`, …). Versionsstrings „v0.4.1“ spec.html L577/L650/L684, iamhmn.html 4×; Server sendet `HHTTPS-Protocol-Version: 0.5.0` (L486, L551). Tabelle nennt `/hhttps/session/email/start` (L783, Server: „legacy name“ L835), nicht aber `/hhttps/session/start`, `/hhttps/email/confirm-code`, `/hhttps/esco/suggest`, `/hhttps/role/card` u. a.
**Korrektur zu W10:** `/hhttps/s/{slug}` (spec L893) ist **kein** 404-Pfad — server.js L1164 registriert `app.get('/hhttps/s/:slug')`; `/s/:slug` (L1357) ist nur die Kurz-Redirect-Variante. Dieser Teilbefund ist nicht zutreffend.
**Auswirkung:** Integratoren prüfen falsche Feldwerte/Versionen und kennen den E-Mail-first-Flow nicht.
**Empfehlung:** Discovery-Beispiel aus der Live-Antwort generieren, Tabelle aus `/hhttps/info` (server.js L808–856) ableiten, Versionsstring zentral pflegen.

### AP8-13 [S4] [Korrektheit] server/public/index.html:L554-566 — Im `EMAIL_DEV_MODE` liefert `/hhttps/email/send` `devCode`, die Seite zeigt ihn nicht an
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** server.js L2880–2884 `resp.devCode = result.code`; `emailStart()` L562–564 wertet nur `r.ok` aus und setzt `tr('codeSent')`. sites/hhttps.html L1737–1740 füllt `d.devCode` ein; die e2e-Tests lesen ihn aus der Netzwerkantwort (signin.e2e.test.mjs L69–74).
**Auswirkung:** Lokale Entwicklung/Demo ohne SMTP nur mit DevTools; Hinweistext falsch.
**Empfehlung:** Wie in sites/hhttps.html `if(d.devCode){…}`.

### AP8-14 [S4] [Korrektheit] server/public/index.html:L681-694 — GitHub-Popup ohne Fehlerbehandlung; 503 `github_not_configured` endet als rohes JSON im Popup, Hauptseite pollt 200 s stumm
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `githubRun()` L682–686 `window.open(…github/start?session=…)` + `pollGithub()`; `catch(e){}`. Server L3010–3018: 401 Text `Invalid session.`, 403 JSON (`requireEmailVerified`), 503 JSON `github_not_configured`. Schleife L688–692 kennt nur `d.verified`.
**Auswirkung:** Popup mit JSON, kein Hinweis, Button scheinbar „in Arbeit“. Überschneidet sich mit AP8-07 (Polling), bleibt aber als eigener UX-Defekt (Popup-Inhalt) bestehen.
**Empfehlung:** Status vorab per fetch prüfen oder 503-Fall serverseitig als HTML rendern; nach Schleifenende Meldung.

### AP8-15 [S1] [Sicherheit] server/public/email-verify.html:L69, L96-97, L111 — DOM-XSS auf der IdP-Origin: URL-Parameter `domain`, `level`, `reason` landen ungeprüft in `innerHTML`
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilennummern korrigiert: innerHTML L69, `domain` L96, `level` L97, `reason` L111)
**Beleg (Erreichbarkeit):** `app.use(express.static(join(__dirname,'public')))` (server.js L519); Live-Repro gegen Testserver: `GET /email-verify.html?token=x&session=y&email_verify=error&reason=%3Csvg%20onload%3Dalert(1)%3E` → **200 text/html**, Seite enthält `body.innerHTML = extra`. Es gibt keine Route, die den Pfad vorher abfängt.
**Beleg (CSP):** Ausgelieferter Header: `script-src 'self' 'unsafe-inline' unpkg.com fonts.googleapis.com; script-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'` (helmet-Konfiguration server.js L392–403, gilt vor dem Static-Mount). Per `innerHTML` eingefügte `<script>`-Elemente werden vom Browser nicht ausgeführt — Inline-Event-Handler wie `<svg onload=…>` / `<img src=x onerror=…>` aber schon, und `script-src-attr 'unsafe-inline'` erlaubt sie explizit. `<img src=x>` ist same-origin (`img-src 'self'`), 404 → `onerror` feuert; `<svg onload>` braucht gar keinen Request.
**Beleg (Datenfluss):** `params.get('domain')` (L85) → Template L96; `levelLabels[level]||level` L97 (unbekanntes `level` wird roh ausgegeben); `decodeURIComponent(params.get('reason'))` L111 — alle ohne Escaping in `show(…, extra)` → `body.innerHTML = extra` (L69). `score` ist per `parseInt` (L84) unkritisch. Voraussetzung ist nur, dass `token` und `session` (beliebige Werte) gesetzt sind (L73).
**Auswirkung:** Skriptausführung auf `hhttps.org`. Dort liegen Access- **und Refresh-Token** in `localStorage['hhttps_identity']` (index.html L791, hhttps.html L1577) sowie `hhttps_uid`. `connect-src 'self'` blockiert `fetch` zu Fremd-Origins, nicht aber `location = 'https://evil/?'+localStorage…` (kein `navigate-to`). Mit dem Access-Token lassen sich Signaturen im Namen des Opfers erzeugen (`/hhttps/signatures` liest `hhttps-token`-Header, server.js L1077); mit dem Refresh-Token 7 Tage lang neue Access-Tokens (stateless `/hhttps/token/refresh`). Angriff = Link an ein angemeldetes Opfer, keine Interaktion außer Klick. S1 bleibt gerechtfertigt, weil es sich um reflektiertes XSS auf der Identitäts-Origin mit direktem Token-Diebstahl handelt; mildernd nur, dass die Seite ein Legacy-Artefakt ist.
**Empfehlung:** Datei löschen (der Server steuert sie nie an, AP8-10). Zusätzlich `unsafe-inline` in `script-src`/`script-src-attr` durch Nonces ersetzen — die `onclick=`-Handler in index.html sind der einzige Grund für `script-src-attr 'unsafe-inline'` (Kommentar server.js L390–391).

### AP8-16 [S2] [Sicherheit] extension/popup.js:L176-184, L275-292 — „Signatur-Snippet“ kopiert das vollständige Bearer-Token zum öffentlichen Einfügen in die Zwischenablage
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L183 `` return `[HHTTPS ✓ ${icon} ${label} · Trust ${trust}/100 · ${ident.token}]` ``; `doCopySnippet` L279 `navigator.clipboard.writeText(buildSnippet(ident))`; Kommentar L168–170 „pasted into any text field as a portable identity claim“. `ident.token` ist dasselbe Access-Token, das background.js L387 als `HHTTPS-Token` an `/hhttps/signatures` sendet; der Server akzeptiert es dort und in `/hhttps/check` per Header/Bearer (server.js L867, L950, L1077, L1328).
**Auswirkung:** Jeder Leser des Beitrags besitzt bis zum Ablauf (1 h) ein gültiges Bearer-Token und kann Signatur-Slugs im Namen des Nutzers erzeugen. Das Slug-Verfahren (`#hhttps:s:`) existiert genau, um das zu vermeiden.
**Empfehlung:** Snippet-Funktion entfernen oder nur serverseitig erzeugte, domain-gebundene Slugs einfügen.

### AP8-17 [S3] [Sicherheit] sites/hhttps.html:L1232-1250 (+ L1611-1625, server/public/index.html:L812-828) — Open Redirect: `?returnTo=<beliebige URL>` leitet eingeloggte Nutzer sofort weiter; in L1247 auch `javascript:`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `showOAuthReturnBanner()` L1235–1247: `new URL(returnTo)` nur als Parse-Check; bei Identität in localStorage sofort `window.location.href = returnTo` (L1247) ohne Protokoll-/Host-Prüfung. Repro: `new URL('javascript:alert(1)').protocol === 'javascript:'` → parst. Zweiter Pfad L1621 und index.html L819 erlauben jede `https:`-URL (Kommentar L1617 „Phase 3b will tighten this“).
**Auswirkung:** Phishing-Links `https://hhttps.org/?returnTo=https://evil.example` wirken vertrauenswürdig; auf sites/hhttps.html zusätzlich Skriptausführung — diese Seite wird derzeit aber nicht deployt (AP8-40), die deployte index.html hat „nur“ den https-Open-Redirect. Daher S3.
**Empfehlung:** `returnTo` gegen registrierte `oauth_clients`-Redirect-URIs bzw. same-origin prüfen; `javascript:`/`data:` ausschließen.

### AP8-18 [S3] [Sicherheit] server/public/index.html:L1034-1052 — `?login_hint=<E-Mail>` löst beim bloßen Öffnen des Links automatisch einen Code-Versand an die Adresse aus
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `handleLoginHint()` liest `login_hint`, füllt das Feld und ruft `emailStart()` (L1051) ohne Nutzeraktion → `POST /hhttps/email/send`. Einziger Schutz: `limit.email` = 30/h **pro IP** (server.js L428, Route L2847); keine per-Adresse-Drossel in email.js. Gewolltes Verhalten laut e2e-Test (signin.e2e.test.mjs L152 „auto-sends the code once“).
**Auswirkung:** Verteilte Klicks (Forum/Mail) → E-Mail-Bombing mit Absender hhttps.org gegen beliebige Adressen; Reputationsschaden.
**Empfehlung:** Versand nur nach explizitem Klick, oder `login_hint` nur akzeptieren, wenn `returnTo` ein registrierter OAuth-Client ist und ein kurzlebiger signierter Parameter mitkommt; zusätzlich per-Adresse-Drossel.

### AP8-19 [S3] [Sicherheit] extension/popup.js:L222-227 (+ content-universal.js L57-68, L761-770, L881-882) — Seitengesteuerte `<meta name="hhttps-*">`-Tags werden ungeprüft als „HHTTPS aktiv / verifiziert“ angezeigt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `readMetaTags()` (L57–68) liest `hhttps-status/human/role/…` aus dem DOM jeder Seite; `GET_PAGE_STATE`-Handler (L761–770) gibt `meta` bevorzugt zurück; Popup L222–227 zeigt bei `status==='verified'` Häkchen + `pageHhttpsActive(role)`. Keine kryptografische oder Server-Prüfung.
**Auswirkung:** Jede Website kann sich Extension-Nutzern gegenüber als „HHTTPS-verifiziert“ mit beliebiger Rolle ausgeben (Vertrauenssiegel-Spoofing).
**Empfehlung:** Seitenstatus nur mit serverseitig prüfbarem Artefakt anzeigen, sonst neutral „Seite behauptet Unterstützung“.

### AP8-20 [S3] [Sicherheit] server/public/index.html:L791 (analog sites/hhttps.html:L1577) — Refresh-Token im `localStorage` der IdP-Origin
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `publishIdentity()` L791 `refreshToken: h.refreshToken||null`, L806 `localStorage.setItem('hhttps_identity', …)`; `restoreIdentity()` L962–990 nutzt es stateless gegen `/hhttps/token/refresh` (L976). HttpOnly-Cookie-Pfad existiert bereits (server.js L455 ff. `setIdentityCookie`).
**Auswirkung:** Jede XSS (AP8-15) oder ein kompromittiertes Drittskript (`script-src unpkg.com`, L396; index.html L382–383) liefert 7-Tage-Sitzungsfortsetzung statt 1 h.
**Empfehlung:** Refresh-Token nur als HttpOnly-Cookie; Verlängerung serverseitig.

### AP8-21 [S4] [Sicherheit] extension/manifest.json:L54, L57 — Nicht genutzte Berechtigungen `activeTab` und `scripting`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -n "chrome.scripting\|activeTab" extension/*.js` → leer; alle Injektionen sind statische `content_scripts` (L28–51). INSTALL.md L48 begründet `activeTab` mit „liest den Status der aktiven Seite“ — das macht der Content-Script ohne diese Permission.
**Auswirkung:** Unnötige Angriffsfläche und Store-Review-Aufwand.
**Empfehlung:** Beide entfernen.

### AP8-22 [S4] [Sicherheit] extension/content-universal.js:L113, L177-183, L484 — Debug-`console.log` auf jeder besuchten Seite inkl. iframe-`src`, Body-Länge und Slug-Listen
**Urteil:** BESTÄTIGT (Severity unverändert; AP8-31 [Performance] hier zusammengeführt — gleiche Zeilen, gleiche Empfehlung)
**Beleg:** `grep -n console.log` → genau L113, L177, L484. Läuft mit `<all_urls>`, `all_frames`, `match_about_blank` (manifest L40–50). L175–176 serialisieren `doc.body.innerHTML` zweimal nur für die Log-Werte.
**Auswirkung:** Informationsabfluss in Konsolen/Error-Reporter fremder Seiten (Webmail-iframe-URLs), Fingerprinting; kleiner CPU-Overhead pro Frame.
**Empfehlung:** Hinter Debug-Flag legen oder entfernen.

### AP8-23 [S2] [Performance] extension/content-universal.js:L165-267 — Pro same-origin-iframe 30 s lang alle 1,5 s Body-Serialisierung + Voll-Scan, ohne Backoff, zusätzlich zu drei weiteren Hooks
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `tryHookIframe` (L165): zwei `innerHTML`-Serialisierungen für Logs (L175–176), `scanForSignatures(doc.body)` (L189), `load`-Listener (L198), Attribut-Observer (L211), Body-Observer via `watchDocument` (L229) **und** `setInterval` (L240–266, `IFRAME_POLL_INTERVAL_MS=1500`, `IFRAME_POLL_MAX_ATTEMPTS=20`), der je Tick `d.body.innerHTML` serialisiert (L252) und `scanForSignatures` (L256) ausführt; stoppt nur bei Seals > 0 oder nach 20 Versuchen (L259–261). `scanIframesIn` wird bei Boot und bei jedem MutationObserver-Treffer aufgerufen (L707–712). Kein „Body unverändert“-Check.
**Auswirkung:** 30 s CPU-Last pro Frame auf jeder Seite mit erreichbaren iframes (Werbe-iframes sind meist `about:blank` = same-origin).
**Empfehlung:** Poller nur bei leerem Body und mit Backoff; abbrechen, sobald der Body-Observer aktiv ist; `innerHTML.length` durch `childNodes.length` ersetzen.

### AP8-24 [S2] [Performance] extension/manifest.json:L40-50 + content-universal.js:L80-121, L165-267 — Same-origin-iframes werden doppelt verarbeitet (eigene Instanz im Frame + Eltern-Instanz); Verifikations-Requests dupliziert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `all_frames: true` + `match_about_blank: true` (L48–49) → eigene Instanz je Frame mit eigenem `boot()` (L881–886), `watchMutations()` (L693) und eigenem `slugCache` (L41, IIFE-lokal). Zusätzlich hookt die Eltern-Instanz denselben `contentDocument` (L165 ff.). `iframesHooked`/`watchedDocs` sind Instanz-lokale WeakSets (L151, L699). Beide Instanzen senden für dieselben Slugs `POST /hhttps/signatures/batch` (L115–116, L473–477).
**Auswirkung:** Doppelte DOM-Arbeit und doppelte Server-Requests je Frame; multipliziert mit Verschachtelungstiefe.
**Empfehlung:** Entweder Eltern-Scanning auf Frames ohne eigene Instanz beschränken oder `all_frames` abschalten; Slug-Cache in den Background verlagern.

### AP8-25 [S3] [Performance] extension/content-universal.js:L128-139 — TreeWalker-Filter ruft für jeden Textknoten zwei `closest()` auf, bevor der billige Textcheck greift
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `acceptNode` L130–137: `SKIP_TAGS` (L131), `closest('.__hhttps-wrapped__')` (L132), `closest('[contenteditable="true"]')` (L133), erst dann `t.includes('#hhttps:s:')` (L135–137). Läuft bei jedem Boot-Scan und bei jeder Mutation (L708).
**Auswirkung:** O(Knoten × Tiefe) auf jeder Seite, obwohl fast nie Marker vorhanden sind.
**Empfehlung:** Reihenfolge tauschen (`includes` zuerst).

### AP8-26 [S3] [Performance] extension/content-universal.js:L700-720 — MutationObserver scannt jeden hinzugefügten Element-Knoten sofort und ungedrosselt inkl. `querySelectorAll('iframe')`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L703–719: je `addedNodes`-Element `scanForSignatures(node)` → `scanIframesIn(node)` (L87 → `querySelectorAll('iframe')` L158) + TreeWalker; kein Debounce/`requestIdleCallback`. Eigene Wrapper (`textNode.replaceWith(wrapper)` L324, `innerHTML` L334/L370) lösen den Observer erneut aus (der Walker lehnt Knoten unter `SEAL_WRAPPER` zwar ab, der Aufruf findet aber statt).
**Auswirkung:** Scan-Last skaliert linear mit der Mutationsrate der Host-Seite.
**Empfehlung:** Mutationen bündeln und im Idle-Slot verarbeiten; eigene Seal-Knoten vor dem Scan filtern.

### AP8-27 [S3] [Performance] extension/content-universal.js:L98-117, L462-481 — Batch-Verify ohne Chunking; Server lehnt >100 Slugs mit 400 ab; Fehler werden nicht gecacht → Seals dauerhaft „pending“
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `slugsToFetch` unbegrenzt (L105–110); ein `POST` (L473–477). Server: `if (slugs.length > 100) return res.status(400)…` (server.js L1271–1273). `if (!r.ok) { console.warn(…); return; }` (L478–481) — kein `slugCache`-Eintrag, Seals behalten `data-state="pending"` (L311–317).
**Auswirkung:** Auf Seiten mit >100 Markern funktioniert die Verifikation nicht; jeder Scan wiederholt den 400-Request.
**Empfehlung:** Chunks à 100, negative TTL für Fehler.

### AP8-29 [S3] [Performance] sites/hhttps.html:L1825-1835 + L1777-1790 — E-Mail-Status-Polling (5 s) wird bei jedem `setStep(3)` neu gestartet ohne das alte Intervall zu löschen und läuft nach erfolgreicher Verifikation endlos weiter
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `window.setStep` L1828–1835: bei `n === 3` `pollInterval = setInterval(…)` (L1831) ohne vorheriges `clearInterval` — ein bereits laufendes Intervall wird unerreichbar. `setStep(3)` wird in L1489 (doAuth) und L1814 (verified_session-Rückkehr) ausgelöst. `checkEmailStatus` (L1777–1790) beendet das Intervall bei `emailVerified` nicht; `setStep(4)` wird wegen AP8-01 nie erreicht.
**Auswirkung:** 12 POSTs/min (bzw. 24 bei Doppelstart) auf `/hhttps/email/status` pro offenem Tab, bis zum Schließen; verbraucht `limit.global`. Seite nicht deployt (AP8-40), im Repo aber reproduzierbar.
**Empfehlung:** `clearInterval` vor dem Anlegen; bei `emailVerified` stoppen.

### AP8-30 [S4] [Performance] extension/background.js:L245-253, L297, L21-29 — `updateAllBadges` liest für jeden Tab einzeln `chrome.storage.local`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L245–250 iteriert alle Tabs → `updateBadge(tabId)` → `getActiveIdentity()` (L253, Storage-Read) je Tab. Ausgelöst bei Worker-Start (L297), `IDENTITY_CAPTURED` (L40, bei jedem Seitenaufruf auf hhttps.org via content-issuer.js L35–43) und `tabs.onUpdated` `loading` (L21–29, ein Tab).
**Auswirkung:** Gering; N Storage-Reads für dieselbe Information.
**Empfehlung:** Identität einmal lesen und durchreichen bzw. Badge global ohne `tabId` setzen.

### AP8-33 [S4] [Performance] server/public/index.html:L8, L382-383; sites/hhttps.html:L9 — Render-blockende Drittressourcen (Google Fonts ohne `preconnect` in index.html; zwei unpkg-Skripte synchron)
**Urteil:** BESTÄTIGT (Severity unverändert, mit Korrekturen)
**Beleg:** index.html L8 Fonts-CSS ohne `preconnect` (`grep preconnect` trifft nur sites/hhttps.html L7); L382–383 `<script src="https://unpkg.com/qrcode-generator@1.4.4/…">` und `@simplewebauthn/browser@9.0.1` synchron ohne `defer`; sites/hhttps.html L9 WebAuthn-Bundle synchron im `<head>`.
**Korrekturen:** Die unpkg-Pfade sind **versioniert** (kein Redirect-Auflösen unversionierter Pfade); sites/hhttps.html hat `preconnect` für Fonts. Kern (Abhängigkeit von Dritt-CDN im Renderpfad der Sign-in-Seite, kein `defer`) bleibt.
**Auswirkung:** Höhere First-Paint-Latenz; Ausfall von unpkg blockiert die Sign-in-Seite.
**Empfehlung:** Bundles lokal unter `public/vendor/` ausliefern, `defer`, `preconnect`.

### AP8-34 [S3] [Wartbarkeit] server/public/index.html:L384-1058 — Sign-in-Seite ist ein 675-zeiliges Inline-Skript-Monolith, der nur per Regex getestet werden kann
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Ein `<script>`-Block L384–1058 (i18n L398–485, Flows L546–778, Identity L786–843, Rolle L851–934, Restore/Magic-Link/login_hint L941–1052). `signin-page.test.mjs` L20–41 schneidet per Regex (`html.match(/<script>([\s\S]*?)<\/script>/)`, `js.match(/function pick\(m\)\{([\s\S]*?)\n\}/)`) und prüft per String-Matching. Tests laufen (29/29), sind aber formatierungsabhängig.
**Auswirkung:** Blind-Edits in 1.060 Zeilen; Tests geben falsche Sicherheit/Alarme.
**Empfehlung:** ES-Module unter `public/js/signin/`, Tests gegen Importe.

### AP8-35 [S3] [Wartbarkeit] server/public/index.html:L546-624 — E-Mail-zuerst-Passkey-Flow dreifach implementiert (index.html, sites/hhttps.html, wallet.html) und bereits gedriftet
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `ensureSession` index.html L546–551 / hhttps.html L1402–1412 / wallet.html L818 ff.; E-Mail send+confirm L554–583 / L1718–1775 / L855–896; Passkey inkl. `InvalidStateError`-Sonderfall L591–624 / L1414–1493 / L907–950. `legacy-pages.test.mjs` L3–23 lädt alle drei Seiten als Fixture. Drift: index.html `throw 0` **13×** (`grep -c`), immer `tr('err')`; hhttps.html/wallet.html werfen `d.detail || d.error` und behandeln 403 (hhttps.html L1425–1427).
**Auswirkung:** Jede Protokolländerung dreifach; Server-`detail` geht auf der Hauptseite verloren (siehe AP8-06).
**Empfehlung:** Gemeinsamer Client `public/js/hhttps-signin.js`; einheitliche Fehlerklasse.

### AP8-36 [S3] [Wartbarkeit] server/public/index.html:L786-827 — `hhttps_identity`-Format an vier Stellen ohne gemeinsames Schema, mit abweichender Semantik
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Producer: index.html L786–810 (Mensch, `method` = Kommaliste + `verified_methods`), L759–766 (Maschine, `actorType`, `operatorEmail`), hhttps.html L1573–1590 (`method: 'webauthn-passkey'`). Consumer: content-issuer.js L36–42/L99–100, server.js Consent-Page L2209/L2225/L2360, popup.js, background.js (`issuer` `hhttps://` wird dreimal per `.replace(/^hhttps:\/\//,'https://')` zurückgerechnet, L198, L231, L381–382).
**Auswirkung:** Neue Felder müssen in Producer, Consent-Page und Extension synchron ergänzt werden (siehe AP8-02/05: `actorType` wird von der Extension nicht ausgewertet).
**Empfehlung:** `buildIdentity()` in gemeinsamem Modul + versionierte Doku; `issuer` als echte URL.

### AP8-37 [S3] [Wartbarkeit] server/public/iamhmn-card-issuer.js:L1-236 — Web-Component ist tot; index.html dupliziert sie inline; Reserved-Liste dreifach mit abweichendem Inhalt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rn iamhmn-card-issuer --include=*.html --include=*.js` trifft nur die Datei selbst (L2, L236); `FINALIZE-NOTE.md` L5–8 und `ROLE-SYSTEM-v0.5-INTEGRATION.md` L31/L48–51 behaupten die Einbindung. index.html implementiert `escoSuggest` (L873–886) und `roleIssue` (L910–934) inline. Reserved-Listen: index.html `RESERVED` L851–858 (6), card-issuer `RESERVED_STEMS` L21 (Wortstämme), Server `RESERVED_REGISTRY` roles.taxonomy.js L77 (maßgeblich).
**Auswirkung:** 236 Zeilen toter Code, falsche Doku, divergierende Reserved-Listen.
**Empfehlung:** Modul + Notizen löschen oder index.html darauf umstellen; Reserved-Liste nur vom Server.

### AP8-40 [S3] [Wartbarkeit] sites/hhttps.html:L919-1925 — Landing-Page wird von keinem Deploy-Skript ausgeliefert, aber mit Tests und Protokoll-Migrationen aktiv gepflegt; Inhalt veraltet
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `scripts/deploy-all.sh` kopiert nur `sites/iamhmn.html` (L166) und `sites/spec.html` (L174); `grep -rn hhttps.html scripts docs/deploy README.md` → nur ein Runbook-Satz. `legacy-pages.test.mjs` lädt die Seite (L23) und testet sie (L177, L195). Veraltet: `ROLES_LOCAL` L930–946, `VMETHOD_LABELS` L948–972 mit clientseitigen Scores, `setTrust(60)` L1378, `Math.max(60, …)` L1386/L1714/L1788/L1812, `getDomainHint` L1695–1707 als Kopie von email.js `DOMAIN_RULES` L62 ff.; Server: „roles are no longer a fixed catalogue“ (L2382). Magic-Link-Rückkehr L1818–1821 ist No-op (`checkEmailStatus` bricht bei `sessionId === null` ab, L1778).
**Auswirkung:** ~1.000 Zeilen JS + Tests für eine nicht ausgelieferte Seite; bei Deploy würden falsche Trust-Scores/Rollen gezeigt (AP8-01, -08, -09, -17, -29 betreffen genau diese Seite).
**Empfehlung:** Entscheiden: deployen + modernisieren oder archivieren (inkl. Landing-Tests).

### AP8-41 [S3] [Wartbarkeit] sites/hhttps.html:L1498-1571 + L1838-1895 — `doDeclarRole()` wird 270 Zeilen später komplett überschrieben; Original ist toter Code
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L1498 `async function doDeclarRole()`; L1838 `const origDeclare = doDeclarRole;` (nie verwendet); L1839 `window.doDeclarRole = async function(){…}` nahezu identisch (Unterschiede: Badge-Text L1879, Feld-Key L1845–1848). Button L684 `onclick="doDeclarRole()"` → Override. Gleiches Muster `window.setStep` L1828. Token-Anzeige doppelt L1544–1547 / L1874–1877.
**Auswirkung:** Änderungen landen leicht in der toten Kopie (beide Kopien haben den Bug aus AP8-01).
**Empfehlung:** Original + `origDeclare` löschen; Polling als expliziten Aufruf.

### AP8-42 [S3] [Wartbarkeit] sites/iamhmn.html:L3346-3392 — Drei divergierende Rollen-Kataloge im Frontend gegenüber dynamischem Rollenmodell im Server
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** iamhmn.html `ROLES` L3346 ff. (mit „Trust 30–60“-Spannen), hhttps.html `ROLES_LOCAL` L930–946, wallet.html `ROLE_DEFS` L615; Server `/hhttps/roles` L2378–2385 `model: 'esco-dynamic'`, „no longer a fixed catalogue“.
**Auswirkung:** Marketing verspricht Rollen/Trust-Werte, die das Backend nicht vergibt; dreifache Pflege.
**Empfehlung:** Eine Quelle (`/hhttps/roles` bzw. `roles.json`); Trust-Spannen entfernen.

### AP8-44 [S3] [Wartbarkeit] extension/background.js:L405-420 + L323-343 — Signatur-Modus-Einstellung wird gespeichert, aber nie gelesen; Popup-Schalter wirkungslos, Kommentar behauptet das Gegenteil
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilenkorrektur: Popup-Schalter in popup.js L60–72 `initSignModeSwitch`, nicht L256–268)
**Beleg:** L405 „popup writes here, context menu reads“; `getSignMode()` (L406–409) nur vom `GET_SIGN_MODE`-Handler (L411–414) aufgerufen. Kontextmenü-Handler L328 `mode = info.menuItemId === 'hhttps-sign-beta' ? 'beta' : 'alpha'` — zwei getrennte Einträge L310–319. popup.js L60–72 schreibt `SET_SIGN_MODE`, das kein Codepfad auswertet.
**Auswirkung:** Nutzer wählt „beta“, bekommt je nach Menüeintrag „alpha“; falscher Kommentar.
**Empfehlung:** Einen Menüeintrag + `getSignMode()` in `onClicked`, oder Schalter entfernen.

### AP8-45 [S3] [Wartbarkeit] extension/content-universal.js:L843-876 — Fetch/XHR-Sniffer läuft in der isolierten Content-Script-Welt und sieht keine Seitenrequests; zugehöriges Background-Plumbing ist tot
**Urteil:** BESTÄTIGT (Severity unverändert; AP8-32 [Performance] hier zusammengeführt)
**Beleg:** L855–876 patchen `window.fetch`/`XMLHttpRequest.prototype.send` des Content-Scripts (MV3 isolated world; ohne `world: 'MAIN'` unwirksam für die Seite); sichtbar nur der eigene `fetch` L473. `r.clone()` (L859) wird nie konsumiert. `PAGE_STATE` → `tabState` (background.js L19–31, L48–53) → nur `GET_TAB_STATE` (L88–91) liest es; popup.js fragt stattdessen den Tab per `GET_PAGE_STATE` (L214). Ebenfalls tot: `REMOVE_IDENTITY` (L80–85; Popup sendet `REVOKE_IDENTITY` L299), `collectContextForSlug` (L509–531, kein Aufrufer), Permission `scripting` (AP8-21).
**Auswirkung:** ~80 Zeilen wirkungsloser Code; Header (background.js L8) beschreibt etwas, das nicht funktioniert; `clone()` würde bei Verlagerung in die Main-World Streaming-Antworten puffern.
**Empfehlung:** Sniffer, `tabState`, `GET_TAB_STATE`, `REMOVE_IDENTITY`, `collectContextForSlug` entfernen; Page-State nur über Meta-Tags (und AP8-19 beachten).

### AP8-46 [S3] [Wartbarkeit] extension/INSTALL.md:L1, L43-58 — Nutzer-Doku zu Version, Datenabflüssen und Berechtigungen ist veraltet/falsch
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L1 „v1.2.0“ (Manifest L4 `1.4.3`). L53–55 „sendet KEINE Daten … außer token/refresh und revoke“ — tatsächlich: background.js L383–395 POSTet den zu signierenden Text + Domain an `/hhttps/signatures`; content-universal.js L473–477 POSTet alle gefundenen Slugs + Hostname jeder besuchten Seite an `/hhttps/signatures/batch`. Berechtigungstabelle L45–51 nennt `contextMenus`/`scripting` nicht; `activeTab` mit falscher Begründung.
**Auswirkung:** Datenschutz-Versprechen stimmt nicht mit dem Code überein; Store-Review-Risiko.
**Empfehlung:** Aus Manifest generieren; Abschnitt „Datenabflüsse“ um Signatur-Endpunkte ergänzen.

### AP8-47 [S3] [Wartbarkeit] extension/background.js:L1-420 (+ content-universal.js, popup.js) — Browser-Extension hat keinerlei Tests und kein Lint-Gate
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rln extension server/test/` → leer; `.github/workflows/ci.yml` L32–46 prüft nur `json.load(manifest)` und `node --check`; `server/eslint.config.js` L11 ignoriert `public/**`, `sites/`/`extension/` liegen außerhalb des Pakets. Testbare Logik: `decodeJwtPayload` L276, `computeIdentityId` L159, `scheduleRefreshFor` L168 — genau dort liegen AP8-04/05. Marker-Regexe: `gi` (L27) vs. `g` (L29–30).
**Auswirkung:** Regressionen fallen erst beim Nutzer auf.
**Empfehlung:** Logik in `extension/lib/*.js` extrahieren, `node:test` + Chrome-API-Stubs; ESLint mit `globals.webextensions`.

### AP8-48 [S4] [Wartbarkeit] extension/manifest.json:L4 — Versionskennung in sechs Dateien, fünf davon veraltet
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** manifest L4 `1.4.3`; popup.html L446 „v1.2.0“ (UI); popup.js L2, background.js L2 „v1.2.0“; content-universal.js L2 „v1.4.0“; INSTALL.md L1 „v1.2.0“.
**Auswirkung:** Support nennt falsche Version.
**Empfehlung:** `chrome.runtime.getManifest().version` im Popup; Header-Versionen streichen.

### AP8-49 [S4] [Wartbarkeit] extension/content-universal.js:L341-383, L544 — i18n inkonsistent: hart kodiertes Deutsch neben `chrome.i18n`, Datumsformat fest `de-DE`
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilenkorrektur: popup.js „HHTTPS Identity Provider“ steht in L204, nicht L398)
**Beleg:** L341 „Unbekannte Signatur“, L346 „Widerrufen“, L352 „Falsche Domain“, L383 „Legacy ${subtype}“ als Literale; Nachbarzeilen L334, L359, L366 nutzen `chrome.i18n.getMessage`. `formatDate` L544 `toLocaleDateString('de-DE', …)`. background.js L261 Badge-Titel „Trust …/100“ nicht lokalisiert.
**Auswirkung:** Englische Nutzer sehen gemischte Sprachen genau in den Fehlerzuständen.
**Empfehlung:** Keys ergänzen; `chrome.i18n.getUILanguage()`.

### AP8-50 [S4] [Wartbarkeit] server/public/index.html:L423, L466 (+ L756, L771, L821, L837, L950, L953) — i18n-Wörterbuch mit ungenutzten Schlüsseln und zweisprachigen Inline-Ternaries; analog sites/hhttps.html
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `'eudi.age'`/`'eudi.ageDone'` in L423/L466 definiert; `grep` nach Verwendung außerhalb der Definition → leer. `LANG==='de'?…:…`-Literale L756, L771, L821, L837, L950, L953 (L771 und L953 identischer String). sites/hhttps.html: Keys `msg.doWebauthn`, `msg.emailSent1/2` (L1003, L1006, L1038, L1041) ungenutzt; Literale trotz Key: L1456 „Passkey anlegen →“ (`btn.reg` L986), L1688 „/hhttps/check aufrufen — Live-Test →“ (`btn.check` L994), `'Fehler: '` L1455/L1492/L1561/L1685/L1891 (`err.prefix` vorhanden, in L1745/L1771 genutzt).
**Auswirkung:** Sprachumschaltung unvollständig; tote Keys.
**Empfehlung:** Keys bereinigen, Literale in `T`; Konsistenztest anfügen.

### AP8-51 [S4] [Wartbarkeit] server/public/index.html:L642-692 — Dreifach kopierte Polling-Schleife mit Magic Numbers; Token-Kürzung und HTML-Escaping mehrfach implementiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `for(let i=0;i<80;i++){await new Promise(r=>setTimeout(r,2500));…}` identisch L642, L667, L688. Token-Kürzung `p[0]+'.'+p[1]+'.'+(p[2]||'').slice(0,16)+'…'` L773, L839, L958. Escape-Helfer: index.html `escHtml` L872 (mit `'`), workload.html `esc` L161 (ohne `'`), content-universal.js `escapeHtml` L534–539 (ohne `'`). Abbruchlogik bereits auseinandergelaufen (siehe AP8-07).
**Auswirkung:** Änderungen dreifach; Divergenz bereits eingetreten.
**Empfehlung:** `pollUntil()`, `shortToken()`, Konstanten.

### AP8-52 [S4] [Wartbarkeit] server/public/index.html:L391 (+ sites/hhttps.html L1081, L1617; extension/popup.js L169; content-issuer.js L71-78; email-patch.js) — Veraltete/irreführende Kommentare und Phase-Marker
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilenkorrektur: popup.js-„Phase 2“-Kommentar steht in L169, nicht L363)
**Beleg:** L391 „Endpoints marked //VERIFY …“ — `grep -n "//VERIFY"` trifft nur diesen Kommentar. hhttps.html L1081 `document.getElementById('ldot').textContent;` (wirkungslos), L1617 „Phase 3b will tighten this“. iamhmn.html „Phase 3a“ L844, L2218, L3101, L3316. popup.js L169 „Phase 2 will turn this into invisible markers“ (Phase 2.5 laut content-universal.js L27 umgesetzt). content-issuer.js L72–77: Kommentar will den Toast beim localStorage-Pickup unterdrücken; Bedingung L74 `!__hhttpsToastShown && readyState === 'complete'` ist beim `document_start`-Pickup (`readyState === 'loading'`) falsch → Toast erscheint gerade dann.
**Auswirkung:** Kommentare beschreiben das Gegenteil des Codes.
**Empfehlung:** Marker durch Issue-Links ersetzen; Toast-Guard auf Pickup-Quelle umstellen.

### AP8-53 [S4] [Wartbarkeit] extension/background.js:L34-108, L347-367, L410-420 — Drei getrennte `onMessage`-Listener und sechsfach hart kodierter Issuer
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Listener L34, L347, L410. Issuer-Literale: background.js L15 `ISSUER_BASE`, L162, L332; content-universal.js L38 `DEFAULT_ISSUER_BASE`, L418 `issuerHost = 'hhttps.org'`; popup.js L202. Rewrite `.replace(/^hhttps:\/\//,'https://')` dreimal (L198, L231, L381–382).
**Auswirkung:** Multi-Issuer/Staging (Kommentar L37) erfordert Änderungen an sechs Stellen.
**Empfehlung:** Gemeinsame `config.js`, ein Router.

### AP8-54 [S4] [Wartbarkeit] server/public/.well-known/hhttps-role-assurance.json:L1-107 — Statische Kopie der berechneten Discovery-Antwort
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Route server.js L767–770 liefert `roleAssuranceDiscovery(RP_ID)`; die statische Datei wird per `express.static` unter `/.well-known/hhttps-role-assurance.json` ausgeliefert (Live-Repro: 200). Vergleich per Node: `JSON.stringify(roleAssuranceDiscovery('hhttps.org')) === JSON.stringify(datei)` → **true** (1632 Bytes); kein Generator, keine Referenz.
**Auswirkung:** Nächste Änderung an `RESERVED_REGISTRY`/RAL-Texten lässt beide Pfade divergieren.
**Empfehlung:** Datei löschen oder per Script generieren + CI-Gleichheitscheck.

## Verworfen
— keine. Alle 54 Findings hatten Datei:Zeile und ließen sich am Code belegen; Teilaussagen wurden korrigiert (AP8-12: `/hhttps/s/{slug}` existiert; AP8-33: unpkg-Pfade sind versioniert, hhttps.html hat `preconnect`; mehrere Zeilennummern in S1/W11/W16/W19).

## Zusammengeführt
- AP8-28 [P] (Polling ohne Backoff/Abbruch, index.html L641–691) → in AP8-07 (gleiche Schleifen, gleiche Ursache: nur `verified` beendet die Schleife).
- AP8-31 [P] (console.log auf jeder Seite) → in AP8-22 (identische Zeilen L113/L177/L484, identische Empfehlung).
- AP8-32 [P] (Fetch/XHR-Patch in isolierter Welt, `r.clone()`) → in AP8-45 (gleicher Code L855–876, gleiche Schlussfolgerung „wirkungslos“).
- AP8-38 [W] (workload.html ruft nicht existierende Endpunkte) → in AP8-03.
- AP8-39 [W] (email-verify.html tote Ergebnisseite, falsche EMAIL_SETUP.md) → in AP8-10.
- AP8-43 [W] (spec.html veraltete Version/Pfade) → in AP8-12 (mit Korrektur: `/hhttps/s/{slug}` ist registriert).

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit (K) | 14 | 14 | 0 | 0 |
| Sicherheit (S) | 8 | 8 | 0 | 0 |
| Performance (P) | 11 | 8 | 0 | 3 |
| Wartbarkeit (W) | 21 | 18 | 0 | 3 |
| **Gesamt** | **54** | **48** | **0** | **6** |

Bestätigt je Severity: S1 1 · S2 5 · S3 26 · S4 16.

Schwerpunkt-Hinweis: Fünf der bestätigten Findings (AP8-01, -08, -09, -17 [Teil], -29) betreffen `sites/hhttps.html`, die laut AP8-40 aktuell nicht deployt wird — im Repo reproduzierbar, in Produktion nur nach einer Deploy-Entscheidung relevant. Der S1-Befund (AP8-15) betrifft dagegen eine Datei, die `express.static` **produktiv** ausliefert; Löschen von `email-verify.html` (mit AP8-10) ist der kleinste wirksame Fix; `unsafe-inline` in der CSP bleibt als strukturelle Schwäche (AP8-20).

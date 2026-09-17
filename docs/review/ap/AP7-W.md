# AP7 — Wartbarkeit

Geprüfte Dateien: server/privacy-pass/index.js, issuer.js, issuance.js, verifier.js, verifier-internal.js, verifications.js, verifications-api.js, role-requirements.js, keys.js, well-known.js, demo.js; server/privacy-pass/public/wallet.html; server/privacy-pass/README.md, INSTALL.md (Doku zu den Endpunkten); server/sdk/client.js; server/sdk/client.py; server/test/e2e/wallet.e2e.test.mjs. Zum Verständnis gelesen (keine Findings): server/server.js (Mounts L62, L521-523), server/db.js (`pool()`, `q()`, `sessions.get`), server/roles.js, server/email.js (`sendPrivacyPassVerification`), docs/review/ap/eslint-output.txt.

Stand: `main` @ `bf0a82b`. Zeilennummern per `cat -n`/`grep -n` im aktuellen Stand geprüft.

---

### [S3] [Wartbarkeit] server/privacy-pass/demo.js:L20-49 — Totes, nicht lauffähiges Modul: importiert einen nicht existierenden Export und verweist auf eine nicht vorhandene Datei
**Begründung:** `demo.js` importiert `parseTokenAndVerify` aus `./verifier-internal.js` (L20) und ruft es in L49 auf; `verifier-internal.js` exportiert aber nur `parseToken`, `findIssuerForToken` und `parseAndVerify` (L27, L46, L54). Zusätzlich liefert L29 `public/demo.html` aus, das nicht existiert (`public/` enthält nur `wallet.html` und `lib/`). `demoRouter` wird nirgends importiert (grep über `server/`: nur Definition in demo.js).
**Auswirkung:** Sobald jemand das Modul mountet, schlägt der ESM-Import mit `SyntaxError: does not provide an export named 'parseTokenAndVerify'` fehl und der Server startet nicht. Bis dahin ist die Datei irreführender Ballast, der ein vermeintlich funktionierendes „Demo“-Feature suggeriert und beim Refactoring von `verifier-internal.js` nicht mitgezogen wird.
**Empfehlung:** Datei löschen oder auf `parseAndVerify` umstellen, `demo.html` ergänzen und in `index.js` mounten; in jedem Fall `demo.js` in einen Test einbeziehen, damit Import-Brüche auffallen.

### [S3] [Wartbarkeit] server/privacy-pass/index.js:L68-78 — Body-Limits `4kb` für `/verify` und `/redeem` sind wirkungslos, weil `issuanceRouter` bereits einen globalen 32-kB-JSON-Parser einhängt
**Begründung:** `issuanceRouter` wird in L68 mit Pfad `/` gemountet und hängt in `issuance.js:L30` `express.json({ limit: '32kb' })` als Router-weite Middleware ein; dasselbe tut `verificationsRouter` (L71 → `verifications-api.js:L36`, `8kb`). Da beide Router ohne Pfadfilter für *alle* Requests durch `privacyPassRouter` laufen, ist der Body bei `/verify`/`/redeem` (L77-78) bereits geparst (`req._body = true`), und das dort deklarierte `express.json({ limit: '4kb' })` wird von body-parser übersprungen (`node_modules/body-parser/lib/types/json.js:L106`).
**Auswirkung:** Die pro Route deklarierten Limits sind Dokumentation ohne Wirkung; effektiv gilt für alle JSON-Routen des Moduls 32 kB. Wer später ein Limit „anpasst“, ändert nichts, was schwer zu debuggen ist.
**Empfehlung:** `express.json` nur pro Route (`issuanceRouter.post('/issue', express.json({limit}), …)`) oder einmal zentral in `index.js` mit einem Wert einhängen und die redundanten Deklarationen in L77-78 entfernen.

### [S3] [Wartbarkeit] server/privacy-pass/keys.js:L40-44 — Rollenliste an vier Stellen dupliziert (keys.js, role-requirements.js, wallet.html, roles.js) ohne gemeinsame Quelle
**Begründung:** `keys.js:L40-44` definiert `ROLES` (15 Einträge) hart; `role-requirements.js:L23-110` wiederholt dieselben 15 Schlüssel als Objektschlüssel von `ROLE_REQUIREMENTS`; `wallet.html:L614-630` (`ROLE_DEFS`) wiederholt sie ein drittes Mal inkl. `strict`-Flag, das serverseitig in `role-requirements.js` (z. B. L63, L77, L83) ebenfalls steht. `roles.js` exportiert ein eigenes `ROLES`-Objekt, das aktuell nur `citizen` enthält (per `node -e` geprüft) und in `verifications.js:L12` und `role-requirements.js:L20` importiert, aber nicht benutzt wird. Der Kommentar in `keys.js:L37-39` („To add a new role, just add it here“) ist damit falsch: eine neue Rolle braucht Änderungen in mindestens drei Dateien, sonst schlägt `checkEligibility` mit `Unknown role` fehl (`role-requirements.js:L131-134`).
**Auswirkung:** Drift zwischen Issuer-Keys, Eligibility-Regeln und Wallet-UI (z. B. eine Rolle mit Key, aber ohne Requirements → `/issue` 403 `not_eligible` mit `Unknown role`). `strict` kann im Wallet und Server auseinanderlaufen.
**Empfehlung:** `ROLES` aus `Object.keys(ROLE_REQUIREMENTS)` ableiten (oder umgekehrt) und dem Wallet Labels/`strict` über `/privacy-pass/eligibility` bzw. einen kleinen `/privacy-pass/roles`-Endpunkt liefern; unbenutzte `roles.js`-Importe entfernen.

### [S3] [Wartbarkeit] server/privacy-pass/issuance.js:L118-139 — TokenRequest-Parsing dupliziert `parseTokenRequest` aus issuer.js inkl. eigener Fehlerpfade
**Begründung:** `issuer.js:L33-47` (`parseTokenRequest`) prüft Länge `2 + 1 + Ne`, `token_type` und extrahiert `truncatedKeyIdVal`/`blindedMsg`. `issuance.js:L118-139` implementiert exakt dieselben drei Schritte erneut (`reqBuf.length !== 2 + 1 + Ne`, `readUInt16BE(0)`, `readUInt8(2)`, `subarray(3)`) mit anderen Fehlercodes. Die Ableitung des truncated key id (`tokenKeyId[tokenKeyId.length - 1]`) steht zusätzlich dreimal: `issuance.js:L133`, `keys.js:L128` (`truncatedKeyId()`, nirgends aufgerufen) und `keys.js:L145`.
**Auswirkung:** Änderungen am Wire-Format (z. B. anderer Token-Typ, Ne-Wechsel) müssen an zwei Parsern nachgezogen werden; die Fehlerformate divergieren bereits (`invalid_token_request` vs. `malformed_request`/`unsupported_token_type`).
**Empfehlung:** `parseTokenRequest` aus `issuer.js` exportieren und in `/issue` je Element aufrufen; `truncatedKeyId(role)` aus `keys.js` in L133 und L145 verwenden.

### [S3] [Wartbarkeit] server/privacy-pass/verifier-internal.js:L18-23 — VOPRFServer-Cache pro Rolle ist ein Duplikat von issuer.js L22-31
**Begründung:** `issuer.js:L22-31` (`_servers`/`getServer`) und `verifier-internal.js:L18-23` (`_servers`/`srv`) bauen je eine eigene `Map` von `VOPRFServer(SUITE, issuer.privateKey)` pro Rolle auf; identische Logik, zwei Instanzen pro Rolle im Prozess.
**Auswirkung:** Doppelte Schlüssel-Materialisierung; bei einer späteren Key-Rotation müssen zwei Caches invalidiert werden, und es gibt keinen Ort, an dem das zentral passiert.
**Empfehlung:** Cache in `keys.js` ansiedeln (`getVoprfServer(role)`), beide Module darauf umstellen; bei Rotation dort invalidieren.

### [S3] [Wartbarkeit] server/privacy-pass/well-known.js:L23-38 — Aggregat-Directory und `handleKeysList` (issuer.js L114-125) erzeugen dieselbe `token-keys`-Liste zweimal
**Begründung:** `well-known.js:L28-36` und `issuer.js:L115-123` mappen `listIssuers()` identisch auf `{ role, 'token-type', 'token-key', 'not-before' }`. `INSTALL.md` beschreibt `/privacy-pass/keys` als „same key information in JSON“ — also bewusst gleicher Inhalt, aber nicht als gemeinsame Funktion.
**Auswirkung:** Felder (z. B. ein künftiges `not-after` für Rotation) müssen doppelt ergänzt werden; die zwei Endpunkte können unbemerkt auseinanderlaufen.
**Empfehlung:** Eine Funktion `issuerKeyList()` in `keys.js` oder `well-known.js`, die beide Handler verwenden.

### [S3] [Wartbarkeit] server/privacy-pass/verifications.js:L88-98 — E-Mail-Token-TTL an drei Stellen festverdrahtet (JS-Konstante, SQL-Literal, Response-Feld)
**Begründung:** `EMAIL_VERIFY_TTL_MS = 15 * 60 * 1000` (L88) wird nur als Rückgabewert `expiresInMs` (L102) verwendet; die tatsächliche Ablaufzeit setzt das SQL-Literal `NOW() + INTERVAL '15 minutes'` (L98). `verifications-api.js:L125` gibt zusätzlich `expires_in_seconds: 15 * 60` als eigenes Literal zurück, statt den Rückgabewert von `createEmailPending` zu nutzen (der Aufruf in L95 destrukturiert nur `rawToken`).
**Auswirkung:** Eine Änderung der TTL an einer Stelle lässt die anderen zwei falsch — die API meldet dann eine Gültigkeit, die die DB nicht einhält.
**Empfehlung:** TTL einmal definieren und als Parameter ins SQL geben (`NOW() + ($7 || ' milliseconds')::interval`, wie in `issuance.js:L170` bereits gemacht); `expires_in_seconds` aus `expiresInMs` ableiten.

### [S3] [Wartbarkeit] server/privacy-pass/issuer.js:L1-125 — Kein einziger Unit-/Integrationstest für Issuer, Verifier, Redeem, Issuance-Quota, Eligibility und Recovery-Codes
**Begründung:** `grep -rln "privacy-pass/issue|privacy-pass/verify|privacy-pass/redeem|pp_redeemed|pp_issuance" server/test` liefert keinen Treffer. Die einzigen Tests, die das Modul berühren, sind `test/unit/legacy-pages.test.mjs` (prüft nur Strings in `wallet.html`) und `test/e2e/wallet.e2e.test.mjs`, das ausschließlich den Login-Pfad bis „Angemeldet“ abdeckt (L80-131) — keine Token-Ausgabe, kein Redeem, keine Double-Spend-Prüfung. `README.md` behauptet dagegen „End-to-end roundtrip test (client blind → issue → finalize → verify) ✅ Passing“; ein solcher Test existiert im Repo nicht.
**Auswirkung:** Die kryptografische Kernschleife (blind → evaluate → finalize → verify, Wire-Format-Konvertierung in `issuer.js:L49-64` und `verifier-internal.js:L54-71`), die Rate-Limit-Arithmetik (`issuance.js:L98-110`) und das `ON CONFLICT`-Double-Spend (`verifier.js:L73-78`) sind ungetestet; ein Fehler in `blindedToEvalRequest`/`evaluationToTokenResponse` würde erst in Produktion auffallen.
**Empfehlung:** Integrationstest mit `@cloudflare/voprf-ts` als Client (blind → `/issue` → finalize → `/verify` → `/redeem` zweimal, zweites Mal `already_redeemed`), plus Unit-Tests für `checkEligibility` und `parseTokenRequest`. README-Aussage korrigieren oder Test nachliefern.

### [S3] [Wartbarkeit] server/privacy-pass/public/wallet.html:L1320-1352 — `submitAttribute` enthält einen wissentlich wirkungslosen Fallback-Pfad mit irreführenden Kommentaren
**Begründung:** Wenn `/hhttps/role/declare` fehlschlägt (L1337), wird `/privacy-pass/email/start` mit `email: 'attribute@self-declared'` aufgerufen (L1340-1343), und die Kommentare sagen selbst: „This will fail email validation; the real path requires a backend route. For now, we manually record via a one-off route.“ (L1344-1345). Das Ergebnis `r2` wird nie ausgewertet, danach wird in L1347 unabhängig vom Erfolg `js.pilotAccepted` geloggt und `refreshEligibility` per `setTimeout(…, 500)` aufgerufen.
**Auswirkung:** Toter Request, der serverseitig einen 400 `domain_does_not_match`/`invalid_email` erzeugt (Log-Rauschen), und eine UI, die „akzeptiert“ meldet, obwohl nichts gespeichert wurde. Wer den Code liest, muss erst herausfinden, dass die Attribut-Verifikation (approbation-id, bar-association-id …) serverseitig gar keinen Endpunkt hat.
**Empfehlung:** Fallback entfernen; entweder einen echten `/privacy-pass/attribute/declare`-Endpunkt bauen oder im UI klar als „noch nicht verfügbar“ deaktivieren.

### [S3] [Wartbarkeit] server/privacy-pass/public/wallet.html:L938-943 — `register/finish`-Aufruf dreimal kopiert (L938-943, L1059-1063, L1104-1108) mit jeweils anderer Fehlerbehandlung
**Begründung:** Identischer `fetch('/hhttps/webauthn/register/finish', { userId, response: att, sessionId })` in `registerPasskey` (L938-943, Fehlermeldung aus `d2.detail || d2.error`), `registerNewCredential` (L1059-1063, feste Meldung „Registrierung fehlgeschlagen“) und `addCredential` (L1104-1108, „Fehler beim Registrieren“). Die beiden letzten verwerfen die Server-Fehlermeldung (z. B. `identity_conflict`), obwohl der Kommentar in L1052-1054 ausdrücklich sagt, die 409-Meldung solle „as is“ angezeigt werden.
**Auswirkung:** Fehlerbehandlung driftet; die dokumentierte Absicht (409-Detail anzeigen) ist in zwei von drei Pfaden nicht umgesetzt.
**Empfehlung:** `registerPasskey()` so erweitern, dass es auch für Recovery/Add-Credential genutzt wird (Parameter `allowExisting`), und die zwei Kopien entfernen.

### [S3] [Wartbarkeit] server/privacy-pass/README.md:L1-60 — Modul-Doku (README/INSTALL) beschreibt einen veralteten Stand und widerspricht dem Code
**Begründung:** `INSTALL.md` (Abschnitt „3. Verify it's running“ und „What this module does NOT do yet“) sagt, `/privacy-pass/token-request` liefere „HTTP 501 not_implemented“ und „Real VOPRF blind evaluation … returns 501“, ein `TODO` sei in `issuer.js`/`verifier.js` markiert — tatsächlich ist die Evaluation implementiert (`issuer.js:L71-75`, `verifier-internal.js:L54-71`), ein `TODO` existiert nicht. `README.md` führt „Replay protection … Pending“, obwohl `/redeem` mit `pp_redeemed` existiert (`verifier.js:L55-97`). Beide Dokumente beschreiben nur Issuer/Verifier; die Endpunkte `/issue`, `/issuance/quota`, `/eligibility`, `/email/start|verify`, `/credentials`, `/recovery/*` und das Wallet fehlen komplett. Der Header von `verifications-api.js:L4-11` listet `/recovery/use { code, userId }` (Handler nutzt kein `userId`, L295) und lässt `/recovery/status` (L271) aus.
**Auswirkung:** Wer das Modul betreibt oder integriert, wird von der Doku aktiv in die Irre geführt (501-Erwartung, fehlende Replay-Schutz-Annahme).
**Empfehlung:** README/INSTALL auf den Ist-Stand bringen (Endpunkt-Tabelle inkl. Request/Response, Rate-Limit, Rollen-Requirements) und den Modul-Header von `verifications-api.js` synchronisieren.

### [S4] [Wartbarkeit] server/privacy-pass/verifications.js:L28-30 — `await import('../db.js')` 18-mal statt eines statischen Imports
**Begründung:** `issuance.js` (4×: L68, L165, L177, L195), `verifications.js` (7×: L29, L42, L91, L106, L143, L164, L181), `verifications-api.js` (5×: L46, L72, L212, L253, L276), `verifier.js` (1×: L73) laden `db.js` per dynamischem Import in jeder Funktion. `db.js` importiert nichts aus `privacy-pass/` (geprüft: nur `fs`, `path`, `url`, `pg`), `server.js` importiert `db.js` statisch (L49) — es gibt keinen Zirkel, der das rechtfertigt. Der Kommentar in `demo.js:L62` („Lazy-load to avoid circular import“) betrifft `../keys.js`, nicht `db.js`.
**Auswirkung:** Unnötig verrauschter Code, der ohne Grund ein Zirkularitäts-Problem suggeriert; Aufrufmuster inkonsistent (`db.pool().query` in `issuance.js:L166`/`verifications.js` vs. `db.q` in `verifier.js:L73`).
**Empfehlung:** `import { pool, q, sessions } from '../db.js'` am Dateianfang; einheitlich `q()` verwenden.

### [S4] [Wartbarkeit] server/privacy-pass/verifications-api.js:L84 — Lokale Konstante `req` verschattet das Express-Request-Objekt `req`
**Begründung:** Innerhalb des Handlers `(req, res)` wird in L84 `const req = ROLE_REQUIREMENTS[role];` deklariert und in L87-88 als Requirements-Objekt verwendet. Der Block endet in L90, sodass `req.protocol`/`req.get('host')` in L104 noch das Express-Objekt treffen — aber nur wegen der Blockgrenze.
**Auswirkung:** Klassische Falle beim nächsten Refactoring (Verschieben von L104 in den if-Block liefert `undefined://undefined`).
**Empfehlung:** In `const reqs = ROLE_REQUIREMENTS[role]` umbenennen.

### [S4] [Wartbarkeit] server/privacy-pass/issuance.js:L23-27 — Kommentar „tune via env or per-request later“ und „by default“ (L13) ohne jede Konfigurierbarkeit; `DEFAULT_BATCH_SIZE` ungenutzt
**Begründung:** `RATE_MAX_TOKENS`, `RATE_WINDOW_MS`, `MAX_BATCH_SIZE` sind harte Konstanten, kein `process.env`-Zugriff. `DEFAULT_BATCH_SIZE` (L24) wird nirgends referenziert (ESLint). Die Wallet-Seite hat ihr eigenes `const N = 10` (`wallet.html:L1383`), das implizit mit `MAX_BATCH_SIZE`/`RATE_MAX_TOKENS` übereinstimmen muss.
**Auswirkung:** Irreführende Kommentare; Batchgröße an zwei Stellen gekoppelt.
**Empfehlung:** Konstanten über `/issuance/quota` (bereits `max_per_window`) an das Wallet geben und `N = Math.min(remaining, max)` daraus ableiten; Kommentar bereinigen oder tatsächlich `process.env` lesen.

### [S4] [Wartbarkeit] server/privacy-pass/verifications-api.js:L177-203 — HTML-Seite inkl. CSS als Template-String im API-Modul; Sprachen/Farben hart codiert
**Begründung:** `renderEmailResult` erzeugt eine komplette zweisprachige HTML-Seite mit Inline-CSS (L180-194), Google-Fonts-Link (L182) und Hex-Farben; Texte in L141-142, L151-152, L163-164 sind DE/EN gemischt im Code. Analog `wallet.html:L1140-1150` (Recovery-Codes-Markup als String inkl. deutschem Text ohne `tr()`).
**Auswirkung:** UI-Änderungen (Design-Tokens, Übersetzung) erfordern Eingriffe im Server-Router; kein Test für das Markup.
**Empfehlung:** Template in `public/` (oder ein Template-Modul) auslagern und Texte über die vorhandene `T`-Tabelle bzw. `roles.i18n.js` ziehen.

### [S4] [Wartbarkeit] server/privacy-pass/public/wallet.html:L951-1370 — Mischung aus i18n (`tr()`) und hart codierten deutschen Strings in derselben Datei
**Begründung:** Trotz `T.de/T.en`-Tabelle (L660-712) und `tr()` (L714) bleiben feste deutsche Log-/UI-Strings: L951 („Versuche Login …“), L965, L975, L998 („✓ Angemeldet“), L1027, L1147, L1149, L1228 („Noch fehlend:“), L1275, L1305, L1324, L1326, L1370, L1412, L1419; Fehlermeldungen teils via `alert()` (L1111, L1153), sonst via `L.*`. Der e2e-Test hängt an dem festen String „Angemeldet“ (`wallet.e2e.test.mjs:L118`).
**Auswirkung:** Englische Nutzer sehen gemischte Sprachen; jede Übersetzungsrunde muss den 950-Zeilen-Inline-Skriptblock durchsuchen.
**Empfehlung:** Alle Strings in `T` ziehen; für den Test einen sprachunabhängigen Zustand (`#btn-login.done`) prüfen.

### [S4] [Wartbarkeit] server/privacy-pass/public/wallet.html:L602-1550 — 950 Zeilen Anwendungslogik als Inline-`<script type="module">` in der HTML-Datei
**Begründung:** Wallet-State, IndexedDB-Layer (L767-815), WebAuthn-Flows (L819-1066), Credentials/Recovery (L1070-1156), Eligibility (L1210-1352), Token-Ausgabe/-Einlösung (L1355-1525), i18n und Helper (L1528-1546) liegen in einem Skriptblock ohne Modulgrenzen; `base64urlDecode`/`b64encode`/`concat` (L1528-1546) werden nicht mit dem Server geteilt. Die Datei ist 83 kB, `legacy-pages.test.mjs` prüft sie per Regex auf Strings.
**Auswirkung:** Kein Linting (ESLint-Lauf deckt Inline-Skripte nicht ab), keine Unit-Testbarkeit der Token-Konstruktion (L1385-1447), hohe Änderungskosten.
**Empfehlung:** Skript nach `public/wallet.js` (ESM) auslagern und in mindestens `wallet-crypto.js` (blind/finalize/Wire-Format), `wallet-auth.js`, `wallet-ui.js` teilen; `index.js:L57-58` liefert bereits statische Assets aus.

### [S4] [Wartbarkeit] server/sdk/client.js:L30 — Klassenname `HHTPPSClient` ist ein Tippfehler des Produktnamens (HHTTPS) in beiden öffentlichen SDKs
**Begründung:** `client.js:L30` und `client.py:L58` exportieren `HHTPPSClient` (auch `HHTPPSResult`, `client.py:L39`); der Name ist in `sites/iamhmn.html:L2480-2496` und `developers/index.html` als öffentliche API dokumentiert.
**Auswirkung:** Verwirrend für Integratoren (Import-Fehler durch „richtige“ Schreibweise); eine spätere Korrektur ist ein Breaking Change.
**Empfehlung:** `HHTTPSClient` als primären Namen exportieren und `HHTPPSClient` als Alias (deprecated) behalten.

### [S4] [Wartbarkeit] server/sdk/client.js:L393-394 — CommonJS-Kompatibilitätszeile ist toter Code; Feature-Parität zu client.py fehlt
**Begründung:** Die Datei nutzt `export class` (L30) und ist damit ESM; `require()` dieser Datei scheitert bereits am `export`-Syntax, bevor L394 (`if (typeof module !== 'undefined') module.exports = …`) erreicht würde, und unter ESM ist `module` nie definiert. Zudem bietet `client.py` Webhook-Methoden (`register_webhook`, `list_webhooks`, `remove_webhook`, `verify_webhook_signature`, L251-279), die im JS-SDK fehlen; `client.py:L222` baut `jti` ohne URL-Encoding in die Query, `client.js:L201` mit `encodeURIComponent`. `client.py:L398` verwendet ein nacktes `except:`.
**Auswirkung:** Falsche Erwartung „CJS-kompatibel“; SDKs driften funktional auseinander; keine Tests für beide SDKs (kein `test/**` referenziert `sdk/`).
**Empfehlung:** L393-394 entfernen (oder ein `package.json`-`exports` mit CJS-Build), Webhook-Methoden im JS-SDK ergänzen, `urllib.parse.quote(jti)` in Python, Smoke-Tests gegen den Test-Server für beide SDKs.

### [S4] [Wartbarkeit] server/privacy-pass/verifier.js:L20-21 — Token wird in `handleVerify` doppelt geparst; Antwortformat weicht von `/redeem` ab
**Begründung:** `parseAndVerify(buf)` (L21) parst intern (`verifier-internal.js:L55`), anschließend wird `parseToken(buf)` (L22) erneut aufgerufen, nur um `nonce` zu erhalten; `parseAndVerify` gibt das Token nicht zurück. Ein ungültiger Token liefert bei `/verify` 200 `{valid:false, reason}` (L23-30), ein syntaktisch kaputter Token 400 `{valid:false, error, detail}` (L33-38); `/redeem` ergänzt `redeemed`. `handleTokenRequest` (`issuer.js:L100-105`) antwortet auf *alle* Fehler mit `400 invalid_token_request`, auch bei internem VOPRF-Fehler (L59-63 „Internal: …“).
**Auswirkung:** Kleiner Mehraufwand und drei leicht unterschiedliche Fehlerkontrakte für Verifier-Clients.
**Empfehlung:** `parseAndVerify` soll `{ valid, issuer, reason, token }` zurückgeben; „Internal:“-Fehler als 500 klassifizieren; ein gemeinsames Fehlerobjekt `{ valid, redeemed?, error, reason }` dokumentieren.

### [S4] [Wartbarkeit] server/privacy-pass/verifications.js:L11-12 — ESLint `no-unused-vars` im AP7-Umfang (gesammelt)
**Begründung:** Aus `docs/review/ap/eslint-output.txt`: `demo.js:L18` `jwt`; `issuance.js:L24` `DEFAULT_BATCH_SIZE`; `issuer.js:L9` `Oprf`, `L16` `Ns`; `role-requirements.js:L20` `ROLES`; `verifications-api.js:L25` `hashEmail`; `verifications.js:L11` `emailDomainMatchesRole`, `L12` `ROLES`; `verifier.js:L11` `findIssuerForToken`. Zusätzlich (nicht von ESLint gemeldet, da exportiert): `keys.js:L126-133` `truncatedKeyId`/`getPublicKeyB64Url` und `keys.js:L33` `MODE` werden nirgends importiert; `verifications.js:L21-24` `emailDomain` dupliziert `role-requirements.js:L154-156`.
**Auswirkung:** Rauschen, das echte Warnungen verdeckt; unbenutzte Exporte täuschen eine API vor.
**Empfehlung:** Importe/Exporte entfernen bzw. verwenden (`truncatedKeyId` in `issuance.js:L133`), `emailDomain` an einer Stelle definieren; ESLint in CI (AP6) mit `--max-warnings 0` für dieses Verzeichnis.

---

## Zusammenfassung

Findings: S1: 0 · S2: 0 · S3: 11 · S4: 9 (gesamt 20).

Das Privacy-Pass-Modul ist sauber in kleine Dateien geschnitten und die Kernlogik (VOPRF-Wire-Format, Redeem mit `ON CONFLICT`) ist gut lesbar — aber es ist praktisch ungetestet, und die Modul-Doku (README/INSTALL) beschreibt einen älteren „501“-Stand. Die auffälligsten Wartbarkeitsrisiken sind die vierfach duplizierte Rollenliste (inkl. `strict`-Flag im Wallet), die doppelt implementierten Parser/Caches/Key-Listen zwischen `issuer.js`, `issuance.js`, `verifier-internal.js` und `well-known.js`, die wirkungslosen Body-Limits durch Router-weite `express.json`-Middleware sowie das tote, nicht importierbare `demo.js`. Das Wallet trägt 950 Zeilen ungelintete Inline-Logik mit einem eingestandenen Dummy-Pfad (`submitAttribute`); die SDKs sind ohne Tests und mit einem Tippfehler im öffentlichen Klassennamen.

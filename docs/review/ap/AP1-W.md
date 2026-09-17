# AP1 — Wartbarkeit

Geprüfte Dateien: server/server.js (L1–1373), server/keys.js, server/roles.js, server/roles.eaa.js, server/roles.i18n.js, server/roles.taxonomy.js, server/roles.taxonomy.i18n.js, server/roles.taxonomy.test.mjs, server/webhooks.js (zum Verständnis gelesen: server/db.js, server/email.js, server/package.json, server/test/**, docs/review/ap/eslint-output.txt; Stand: Arbeitsbaum nach `bf0a82b`).

---

### [S3] [Wartbarkeit] server/server.js:L109-366 — `sendJson` ist ein 258-Zeilen-Handler, davon ~230 Zeilen eingebettetes HTML/CSS/JS-Template.
**Begründung:** Die Funktion vereint Content-Negotiation (L118-131), einen regex-basierten JSON-Syntax-Highlighter (L136-143) und ein komplettes HTML-Dokument inkl. CSS-Palette und Copy-Script als Template-Literal (L146-365). Jede Design-Änderung an der API-Ansicht erfordert Edits mitten in der Server-Datei; die Palette (`--cream`, `--terra`, …) existiert zusätzlich in `server/public/*.css`.
**Auswirkung:** Hoher Umfang von `server.js` (4.829 LOC) ohne funktionalen Grund; Highlighter-Regexe und HTML sind nicht isoliert testbar; Diff-Rauschen bei reinen Stil-Änderungen.
**Empfehlung:** Template + Highlighter nach `server/views/json-viewer.js` (Funktion `renderJsonPage(title, subtitle, path, json)`) auslagern; `sendJson` behält nur die Negotiation. CSS aus dem bestehenden Public-Stylesheet referenzieren statt duplizieren.

### [S3] [Wartbarkeit] server/server.js:L867-869, L950-952, L1077-1079, L1328-1330 — Token-Extraktion aus Header/Authorization/Body ist viermal identisch kopiert (weitere Kopien L3745, L3971 außerhalb des AP).
**Begründung:**
```js
const token = req.headers['hhttps-token'] ||
              req.headers['authorization']?.replace('Bearer ', '') ||
              req.body?.token;
```
Dazu kommt die Signer-ID-Kette `d.uid || d.userId || d.sub` doppelt (L1122, L1340; weitere L1580, L1956, L3976), obwohl `uid` in keinem ausgestellten Token gesetzt wird (grep `uid:` in server.js: nur Lesezugriffe) und `sub` bei Access-Tokens die Konstante `'human-verified'` ist (L654).
**Auswirkung:** Eine Änderung (z. B. Bearer-Parsing case-insensitiv, `Bearer` ohne Leerzeichen) muss an sechs Stellen nachgezogen werden; der `sub`-Fallback erzeugt eine nicht-eindeutige Signer-ID, was bei einer Refactoring-Lücke unbemerkt bleibt.
**Empfehlung:** Helfer `extractToken(req)` und `signerIdOf(decoded)` einführen (letzterer ohne `sub`-Fallback, stattdessen `null` → 401); an allen Stellen verwenden.

### [S3] [Wartbarkeit] server/server.js:L1166, L1275, L1334, L1359 — Slug-Regex `/^hp-[A-Z0-9\-]+$/i` viermal dupliziert und inkonsistent zum Generator.
**Begründung:** `generateSlug()` (L609-618) erzeugt `hp-XXX-XXXX-XXX` aus dem Crockford-Alphabet `SLUG_ALPHABET` (ohne 0/1/I/O/L), die vier Validierungs-Regexe akzeptieren jedoch beliebige `[A-Z0-9-]+`-Folgen beliebiger Länge. Die Regex enthält zudem den von ESLint gemeldeten überflüssigen Escape `\-`.
**Auswirkung:** Zwei Wahrheiten für „gültiger Slug“; ein Format-Wechsel muss an fünf Stellen erfolgen; Validierung lässt strukturell ungültige Slugs bis zur DB-Abfrage durch.
**Empfehlung:** `const SLUG_RE = /^hp-[23456789A-HJKMNP-Z]{3}-[…]{4}-[…]{3}$/i` neben `SLUG_ALPHABET` definieren (oder aus dem Alphabet ableiten) und überall verwenden.

### [S3] [Wartbarkeit] server/server.js:L1219-1257 vs. L1291-1312 — Status-Auswertung einer Signatur (revoked / wrong-domain / text-modified) ist in Einzel- und Batch-Endpunkt doppelt implementiert.
**Begründung:** `/hhttps/s/:slug` (L1219-1257) und `/hhttps/signatures/batch` (L1291-1312) prüfen dieselben drei Bedingungen mit denselben Feldern (`revoked_at`, `binding_type === 'web' && reqDomain && …`, `binding_type === 'document' && textPreview` + `hashTextStrict`). Bereits jetzt divergieren sie: der Einzelendpunkt liefert `revokeReason`, `expected/observed` unter `hhttps.*` und `warning`, der Batch liefert `expected/observed` flach und keine `revokeReason`; der Einzelendpunkt zählt Verify-Aufrufe und First-Seen (L1176-1183), der Batch nicht.
**Auswirkung:** Neue Prüfungen (z. B. Ablauf, loose-Hash) müssen zweimal geschrieben werden; Clients (Extension) erhalten zwei Antwortformate für dieselbe Aussage.
**Empfehlung:** `evaluateSignature(sig, { reqDomain, textPreview })` → `{ status, expected, observed, warning }` extrahieren und in beiden Routen verwenden; Antwortformat vereinheitlichen.

### [S3] [Wartbarkeit] server/server.js:L770-793 — ESCO-Suche dupliziert `resolveEsco`/`ESCO_API` aus roles.taxonomy.js; `resolveEsco` wird importiert, aber nie verwendet.
**Begründung:** `/hhttps/esco/suggest` baut die URL `https://ec.europa.eu/esco/api/search?type=occupation&language=…&text=…&full=false&limit=8` von Hand (L775-777) und parst `_embedded.results` (L780) — exakt die Logik von `resolveEsco()` in roles.taxonomy.js L156-168, wo auch die Konstante `ESCO_API` (L154) liegt. server.js L56 importiert `resolveEsco` trotzdem (ESLint: unused).
**Auswirkung:** Zwei Stellen für dieselbe externe API (Endpunkt-Änderung, Timeout, Fehlerbehandlung müssen doppelt gepflegt werden); der Handler hat keinen Timeout/AbortSignal, `resolveEsco` auch nicht — eine zentrale Stelle wäre der Ort dafür.
**Empfehlung:** `resolveEsco` um `limit`-Option erweitern (oder `searchEsco(text, {language, limit, fetchImpl})` in roles.taxonomy.js) und im Handler verwenden; ESCO_API nutzen.

### [S3] [Wartbarkeit] server/server.js:L4-22 — Datei-Header beschreibt v4.1 mit „14 roles (citizen, journalist, …)“ und widerspricht dem aktuellen Modell.
**Begründung:** Der Kopfkommentar listet 14 Rollen und „/hhttps/role/declare (no /v2 suffix)“ als Neuerungen von v4.1. roles.js L46-55 stellt klar, dass `ROLES` seit v0.5 genau einen Eintrag (`citizen`) hat und Professionen dynamisch über ESCO kommen. Ergänzend sind Phasen-Marker als Orientierung verstreut (L594 „Phase 2.5“, L826 „W-18 … Phase 8“, L1066 „Phase 2.5“, L1363 „Phase 3a“; L4809-4815 loggt beim Start weiterhin „HHTTPS v4.1 … All v4 live bugs fixed“).
**Auswirkung:** Neue Entwickler lesen zuerst eine falsche Architekturbeschreibung; Versionierung (v4.1 vs. Protokoll 0.5.0) ist nicht nachvollziehbar.
**Empfehlung:** Header auf den Ist-Zustand kürzen (Zweck, Modulstruktur, Verweis auf docs/), Phasen-Marker durch fachliche Überschriften ersetzen; Startlog auf eine Versionskonstante umstellen.

### [S3] [Wartbarkeit] server/server.js:L955, L1082 vs. L1333; L938, L1002, L1062 — Inkonsistente Statuscodes und Fehlerformate zwischen den Signatur-Endpunkten.
**Begründung:** Fehlendes Token liefert bei `/hhttps/sign-text` (L955) und `POST /hhttps/signatures` (L1082) `400 {error:'token required'}`, bei `/hhttps/signatures/:slug/revoke` (L1333) dagegen `401` mit gleichem Text. Ungültiges Token: `/hhttps/check` antwortet `401 { hhttps:{status:'invalid',human:false}, error }` (L938), `/hhttps/sign-text` `401 { error }` (L1002), `/hhttps/verify-text` `401 { hhttps:{status:'invalid'}, error }` (L1062). Die `error`-Texte stammen aus `checkTokenValid` (L735 `'Refresh-Token nicht aktiv'`, L737 `'Token nicht aktiv'`) und sind deutsch, alle übrigen Fehlertexte englisch; `e.message` von jsonwebtoken („jwt expired“) wird ungefiltert durchgereicht.
**Auswirkung:** Clients (Extension, SDK) müssen pro Endpunkt unterschiedliche Fehlerpfade parsen; Sprachmix in einer öffentlichen API.
**Empfehlung:** Einheitliche Fehlerhilfe `apiError(res, status, code, detail)` mit stabilen Codes (`token_required`, `token_invalid`, `token_revoked`) definieren; 401 für fehlendes/ungültiges Token durchgängig; Meldungen in `checkTokenValid` auf englische Codes umstellen.

### [S3] [Wartbarkeit] server/server.js:L324, L486, L551, L732, L808, L874, … — Protokollversion `'0.5.0'` als Literal 27-mal in server.js; weitere Versionsstrings verstreut.
**Begründung:** `grep -c "'0.5.0'\|v0.5.0" server/server.js` → 27 Treffer (Header L486/L551, Discovery L732, Info L808, alle `hhttps.version`-Felder). Daneben: roles.taxonomy.js L267 `version: '0.5'`, webhooks.js L73 `'User-Agent': 'HHTTPS-Webhook/4.1'`, server.js L5/L4809 „v4.1“, `server/package.json` eigene Version.
**Auswirkung:** Ein Versionssprung (0.6.0) erfordert eine fehleranfällige Massenersetzung; Discovery, Header und JSON-Body können auseinanderlaufen.
**Empfehlung:** `export const PROTOCOL_VERSION = '0.5.0'` (z. B. in einem `constants.js` neben `ACCESS_TTL` etc.) und überall referenzieren; Webhook-User-Agent daraus ableiten.

### [S3] [Wartbarkeit] server/roles.js:L208-288 — `VERIFICATION_CHECKS`/`resolveVerification` („honesty gate“) sind seit v0.5 toter Code; `VERIFICATION_LEVELS` (L72-98) enthält 25 Einträge, von denen nur noch `label` gelesen wird.
**Begründung:** `resolveVerification` und `VERIFICATION_CHECKS` werden in server.js L39 importiert, aber nirgends aufgerufen (ESLint, eigener grep); der einzige weitere Nutzer ist `verificationCheckNote` in roles.i18n.js L382-388, die ebenfalls keinen Aufrufer hat. server.js L3157 dokumentiert: „honesty gate lives in computeVerification“. `VERIFICATION_LEVELS` wird nur noch als `VERIFICATION_LEVELS[x]?.label` (L923, L1116, L1797) gelesen; Felder `level`, `trustScore` und der 80-Zeilen-Kommentar zu „BREAK/targetTrust“ sind ohne Wirkung. Ebenfalls unbenutzt: `ROLES.citizen.verificationMethods` (L60) und der Parameter `baseTrust` (L268).
**Auswirkung:** Rund 100 Zeilen Regel-Logik samt Kommentaren beschreiben ein Verhalten, das nicht mehr existiert; Reviewer und neue Entwickler müssen erst nachweisen, dass der Pfad tot ist.
**Empfehlung:** `VERIFICATION_CHECKS`, `resolveVerification`, `verificationCheckNote` entfernen (Git bewahrt sie); `VERIFICATION_LEVELS` auf die tatsächlich vergebenen `roleLevel`-Werte reduzieren oder als reine Label-Map dokumentieren; unbenutzte Importe in server.js L39-41 streichen.

### [S3] [Wartbarkeit] server/roles.js:L143 vs. server/server.js:L571 — Header `HHTTPS-Age-Verified` hat zwei Eigentümer mit unterschiedlicher Semantik.
**Begründung:** `setHHTPPS` setzt L571 `HHTTPS-Age-Verified` auf `String(ageVerified)` (kann `'false'` sein), und anschließend überschreibt die Schleife L568-575 denselben Header mit `'true'`, sobald `'age'` in `verifiedMethods` steht, weil `VERIFICATION_METHODS.age.header` (roles.js L143) denselben Namen trägt. Welcher Wert gewinnt, hängt von der Aufrufreihenfolge und den übergebenen Optionen ab.
**Auswirkung:** Zwei Quellen für einen Header; wer die Age-Logik ändert, muss beide Stellen kennen. Ein Token mit `age_group` selbstdeklariert (`age_verified:false`) und gleichzeitig `verified_methods` mit `age` würde `true` melden.
**Empfehlung:** Einen Eigentümer festlegen: entweder `age` in `VERIFICATION_METHODS` ohne `header` (nur Badge) oder die explizite `ageVerified`-Zeile entfernen und den Wert allein aus `verifiedMethods` ableiten.

### [S3] [Wartbarkeit] server/roles.i18n.js:L47-239 — 14 Rollen-Übersetzungen (journalist … craftsman) für Rollen-IDs, die in `ROLES` nicht mehr existieren.
**Begründung:** Der DE-Katalog enthält Übersetzungen für `journalist` (L47), `student` (L61), `teacher` (L75), `researcher` (L89), `creative` (L103), `developer` (L116), `medical_professional` (L129), `caregiver` (L143), `lawyer` (L157), `notary` (L171), `civil_servant` (L184), `politician` (L198), `business` (L212), `craftsman` (L226) inkl. `verificationHints`. `localizeRole` (L341-343) gibt für alle diese IDs `null` zurück, da `ROLES[roleId]` fehlt; `localizeRoles` (L361-365) iteriert nur über `ROLES` (= citizen). Einziger produktiver Nutzer des Moduls ist `roleLabel` in email.js L39.
**Auswirkung:** ~190 Zeilen nicht erreichbare Daten, die das entfernte 14-Rollen-Modell weiter suggerieren (siehe auch server.js-Header).
**Empfehlung:** Katalog auf `citizen` reduzieren; falls die Texte für ESCO-Rollen wiederverwendet werden sollen, in eine explizit benannte Datei (`esco-role-hints.de.js`) mit ISCO-Schlüsseln überführen.

### [S3] [Wartbarkeit] server/roles.taxonomy.i18n.js:L1-71 — Modul wird nirgends importiert (totes Modul); `kind`-Katalog übersetzt Werte, die `resolveRole` nie erzeugt.
**Begründung:** `grep -rn "roles.taxonomy.i18n"` findet nur Kommentare (roles.taxonomy.js L5, roles.i18n.js). Der `kind`-Katalog (L25-30: `status`, `legal_entity`, `sector`) bezieht sich auf ein Rollenmodell, das roles.taxonomy.js L196 mit `kind: 'occupation'` fest verdrahtet hat. `SUPPORTED_LOCALES`/`DEFAULT_LOCALE` (L13-14) duplizieren roles.i18n.js L28-29.
**Auswirkung:** Übersetzungen (u. a. das kritische RAL0-Wording „Selbst angegeben“, L18) werden nirgends ausgeliefert, obwohl der Datei-Header L7-8 einen „CRITICAL UI CONTRACT“ postuliert; Frontend-Strings müssen anderswo gepflegt werden.
**Empfehlung:** Entweder das Modul in den Rollen-/Karten-Endpunkten (z. B. `/hhttps/role/card`, `/.well-known/hhttps-role-assurance` mit `?lang=`) tatsächlich nutzen oder entfernen und den UI-Contract dort dokumentieren, wo die Strings wirklich liegen.

### [S3] [Wartbarkeit] server/roles.eaa.js:L17, L51-59 — Modul hat keinen Laufzeit-Aufrufer; `setRoleHeaders` verlangt ein `hdrSafe`, das server.js nicht exportiert.
**Begründung:** Einziger Import ist roles.taxonomy.test.mjs L10. `setRoleHeaders(res, {ral, role}, hdrSafe)` (L53) dokumentiert „pass server.js's hdrSafe“, aber `hdrSafe` ist eine lokale Closure innerhalb von `setHHTPPS` (server.js L541-547) und nicht erreichbar; der Default `(v) => String(v)` würde Umlaute ungefiltert in Header schreiben — genau der Crash (`ERR_INVALID_CHAR`), den server.js L537-540 beschreibt. `guardReservedRole` (L17) ist importiert, aber unbenutzt.
**Auswirkung:** Toter Pfad mit einer Schnittstelle, die im Ernstfall nicht wie dokumentiert nutzbar ist; die EAA-Read-Logik ist nicht mit dem echten Kartenendpunkt (server.js L3620ff.) verbunden.
**Empfehlung:** `hdrSafe` als exportierte Utility (z. B. `server/http-util.js`) herausziehen und in `setHHTPPS`, `setRoleHeaders` und roles.taxonomy.js `normalize` (L103-107, gleiche Transliteration) gemeinsam nutzen; roles.eaa.js entweder anbinden oder entfernen.

### [S3] [Wartbarkeit] server/roles.taxonomy.js:L84, L88, L120-126 — `RESERVED_REGISTRY`: ISCO-Präfix `'261'` (notary) überdeckt `2611` (lawyer) und `2612` (judge); Treffer hängen von der Objekt-Reihenfolge ab.
**Begründung:** `guardReservedRole` iteriert `Object.entries(RESERVED_REGISTRY)` und gibt beim ersten `startsWith`-Treffer zurück (L121-125). Mit `isco08 = '2612'` matcht `lawyer` (`2611`) nicht, danach `notary` über `'261'` → `key: 'notary'`, `sourceHint: 'Notarkammer'`; der Eintrag `judge` (L88) ist über ISCO nie erreichbar. Gleiches gilt für `medical` `'221'` vs. `'2212'`/`'2211'` (redundant, hier aber harmlos).
**Auswirkung:** Fachlich falscher `reservedKey`/`sourceHint` für Richter/Staatsanwälte; die Tabelle ist fragil gegenüber Umsortierung; Test L25-28 deckt nur den Medical-Fall ab.
**Empfehlung:** Präfixe disjunkt halten (`notary: ['2619']`) und einen Test ergänzen, der für jeden Registry-Eintrag prüft, dass sein erstes Präfix genau auf ihn selbst auflöst (bzw. „längster Präfix gewinnt“ implementieren).

### [S3] [Wartbarkeit] server/roles.taxonomy.test.mjs:L1-78 — Tests laufen weder in `npm test` noch in CI; Testdatei liegt im Modulverzeichnis mit eigenem Mini-Framework.
**Begründung:** `server/package.json` L11: `node --test "test/unit/**/*.test.mjs" "test/integration/**/*.test.mjs"` — die Datei `server/roles.taxonomy.test.mjs` passt auf keines der Globs; `.github/workflows/ci.yml` ruft ohnehin nur `node --check`. Die Datei nutzt `assert` + `console.log` statt `node:test` (L12) und importiert `guardReservedRole`, `CUSTOM_ROLE_ID` ungenutzt (L7-8). Manuell ausgeführt: 9 Checks bestehen.
**Auswirkung:** Regressionen in Rollen-Taxonomie/RAL (z. B. das Präfix-Problem oben) bleiben unbemerkt; das Projekt hat faktisch zwei Test-Konventionen.
**Empfehlung:** Nach `server/test/unit/roles.taxonomy.test.mjs` verschieben, auf `test()/describe()` aus `node:test` umstellen, unbenutzte Importe entfernen.

### [S3] [Wartbarkeit] server/webhooks.js:L14-25 — Event-Registry (`VALID_EVENTS`) und tatsächlich gefeuerte Events sind auseinandergelaufen.
**Begründung:** Registrierbar sind nur `token.issued`, `token.revoked`, `role.declared` (L14; `'*'` expandiert L23-25 auf dieselbe, doppelt gepflegte Liste). server.js feuert jedoch `identity.verified` (L3188), `age.verified` (L3372), `eudi.verified` (L3572), `card.issued` (L3656) — diese landen in `db.webhooks.findForEvent` (`$1 = ANY(events)`, db.js L670-672) nie bei einem Abonnenten, weil kein Webhook sie eintragen darf. `role.declared` wird umgekehrt nirgends gefeuert.
**Auswirkung:** Vier von sechs Events sind für Integratoren unerreichbar, ohne dass Registrierung oder Doku (`/hhttps/info` „Webhook management“) dies erkennen lassen; jedes neue Event muss an zwei Stellen + Liste eingetragen werden.
**Empfehlung:** `export const WEBHOOK_EVENTS = Object.freeze([...])` als einzige Quelle in webhooks.js, `fireEvent` validiert gegen diese Liste (Warnung bei unbekanntem Event), `'*'` expandiert aus derselben Konstante; Registry und Aufrufer in server.js abgleichen.

### [S3] [Wartbarkeit] server/keys.js:L109-150, L194-197 — Rotations-API (`rotateKeys`, `forgetRetiredKey`, `getRetiredKids`, …) hat keinen Aufrufer, und `forgetRetiredKey` wirkt nur bis zum nächsten Neustart.
**Begründung:** Kein Modul, Script (`server/scripts`, `scripts/`) oder Runbook (`docs/deploy`) ruft `rotateKeys`/`forgetRetiredKey` auf; ebenso sind `getPublicKey`, `getPrivateKey`, `getKid`, `getRetiredKids` unbenutzt. `forgetRetiredKey` (L142-150) entfernt den Kid nur aus der In-Memory-Map und lässt die Datei absichtlich stehen (L145), `loadRetiredKeys` (L57-69) lädt beim Start aber alle `retired/*.pem` wieder — der „Vergessen“-Zustand ist nicht persistent, was der Kommentar L139-141 nicht erwähnt. Nebenbei: Kommentar L46 „planabler“ (Tippfehler), `makeKid` nutzt `Math.random` für die Eindeutigkeit (L52).
**Auswirkung:** Der dokumentierte Rotationsprozess (Header L13-20) ist operativ nicht ausführbar (kein CLI, kein Endpunkt, kein Test) und `forgetRetiredKey` verhält sich anders als beschrieben.
**Empfehlung:** Script `server/scripts/rotate-keys.mjs` (+ `forget-retired-key`) ergänzen, das die Funktionen aufruft, und `forgetRetiredKey` entweder die Datei nach `retired/archived/` verschieben lassen oder den Kommentar auf „bis Neustart“ korrigieren; unbenutzte Getter entfernen.

### [S3] [Wartbarkeit] server/server.js:L728-1361 (Endpunkte) — Keine Tests für Discovery, JWKS, `/hhttps/check`, Sign-/Verify-Text, Signaturen, `/s/:slug`, `setHHTPPS`, `normalizeApexDomain`, keys.js und webhooks.js.
**Begründung:** `grep -rn "hhttps/check|well-known|jwks|sign-text|signatures|webhook|normalizeApex|HHTTPS-Protocol-Version" server/test` liefert einen einzigen Treffer (oauth-claims.test.mjs L241, `/.well-known/openid-configuration`, AP2); smoke.test.mjs prüft nur `/hhttps/info`. Die Slug-Logik (Kollisionsschleife L1107-1113, Domain-Binding L1229-1240, First-Seen-Lock L1180-1183), `normalizeApexDomain` (L601-616, heuristische PSL) und die Header-Sanitizer (L541-547) sind reine Funktionen, die sich trivial unit-testen ließen.
**Auswirkung:** Der von der Browser-Extension (extension/content-universal.js, background.js) genutzte Signatur-Pfad hat null automatisierte Absicherung; Refactorings aus diesem Review (Helfer extrahieren) sind ohne Netz.
**Empfehlung:** Unit-Tests für `normalizeApexDomain`, `hashTextLoose`, `generateSlug`/`SLUG_RE`, `setHHTPPS` (Umlaut-Header) und Integrationstests für `check`, `signatures` (create → verify → wrong-domain → revoke) und `verify-text` ergänzen; keys.js `verifyToken` mit retired kid testen.

### [S4] [Wartbarkeit] server/server.js:L828-855, L728-752 — Handgepflegter Endpunkt-Katalog in `/hhttps/info` und Discovery ist unvollständig.
**Begründung:** Beide Listen nennen weder `POST /hhttps/sign-text`, `POST /hhttps/verify-text`, `POST /hhttps/signatures`, `GET /hhttps/s/:slug`, `POST /hhttps/signatures/batch`, `POST /hhttps/signatures/:slug/revoke`, `GET /s/:slug`, `GET /hhttps/esco/suggest` noch `GET /.well-known/hhttps-role-assurance` (Discovery verweist unter `roles_model.discovery` immerhin darauf). `/hhttps/info` führt `session/email/start` als „legacy name“ (L835).
**Auswirkung:** Die öffentliche Selbstbeschreibung ist die einzige API-Doku im Server; Integratoren finden die Signatur-Endpunkte nur im Extension-Code.
**Empfehlung:** Katalog aus einer zentralen Routen-Tabelle generieren (oder zumindest die fehlenden neun Einträge ergänzen) und den Legacy-Alias mit Ablaufdatum markieren.

### [S4] [Wartbarkeit] server/server.js:L535, L1080 — Irreführender Funktionsname `setHHTPPS` (Tippfehler, HHTPPS ≠ HHTTPS) und still ignoriertes Request-Feld `mode`.
**Begründung:** `function setHHTPPS(res, opts)` (L535) wird ~30-mal im Projekt aufgerufen; der Parameter `token` (L536) wird angenommen, aber nie verwendet (Kommentar L558-565 erklärt warum — dann sollte er nicht mehr entgegengenommen werden; `/hhttps/check` übergibt ihn L880). `POST /hhttps/signatures` destrukturiert `mode` aus dem Body (L1080) und nutzt es nicht; ein Client, der `mode:'document'` schickt, bekommt kommentarlos `web`-Binding.
**Auswirkung:** Suchen/Ersetzen nach „HHTTPS“ übersieht die Funktion; API akzeptiert ein Feld ohne Wirkung.
**Empfehlung:** Umbenennen zu `setHhttpsHeaders`, `token`-Option entfernen; `mode` entweder verarbeiten (Alias für `bindingType`) oder mit 400 ablehnen und aus der Destrukturierung streichen.

### [S4] [Wartbarkeit] server/server.js:L482-509 vs. L879-886 — Mapping „dekodiertes Token → `setHHTPPS`-Optionen“ doppelt.
**Begründung:** Die Identity-Cookie-Middleware (L487-497) und `/hhttps/check` (L879-886) bauen dasselbe Optionsobjekt (`status:'verified', human:true, actorType:'human', role, roleLevel, trustScore, method, ageGroup, ageVerified, ageVerificationMethod`); nur `verifiedMethods`/`domainValue` fehlen in der Middleware, sodass die Cookie-Variante keine `HHTTPS-*-Verified`-Header liefert, obwohl der Kommentar L463-471 genau das als Zweck nennt.
**Auswirkung:** Die beiden Pfade driften bereits (Methoden-Header fehlen im Cookie-Pfad).
**Empfehlung:** `headerOptsFromToken(decoded)` extrahieren und in beiden Stellen verwenden.

### [S4] [Wartbarkeit] server/server.js:L959, L1086, L1111, L1119, L1272, L753 — Magic Numbers ohne benannte Konstante.
**Begründung:** Textlimit `100_000` doppelt (L959, L1086, jeweils mit eigenem Fehlertext), Preview `120`/`117` (L1119), Slug-Versuche `5` (L1111), Batchgröße `100` (L1272), Cleanup-Intervall `5 * 60 * 1000` (L753), Signatur-`exp`-Vergleich `* 1000` mehrfach.
**Auswirkung:** Limits sind nicht an einer Stelle einsehbar/änderbar; Fehlertexte müssen separat angepasst werden.
**Empfehlung:** `const SIGN_TEXT_MAX = 100_000, SIGN_PREVIEW_LEN = 120, SLUG_MAX_ATTEMPTS = 5, SIG_BATCH_MAX = 100, CLEANUP_INTERVAL_MS = …` neben den TTLs (L93-96) definieren.

### [S4] [Wartbarkeit] server/webhooks.js:L18, L21, L64, L73, L76, L89, L95 — Sprachmix in Fehlermeldungen und verstreute Konstanten im Delivery-Pfad.
**Begründung:** L18 `'Invalid webhook URL.'` (en) vs. L21 `'Unbekanntes Event: …'` (de); beide werden in server.js als `error` an den Client durchgereicht. `MAX = 3` liegt innerhalb der Funktion (L64), Timeout `8000` (L76), Backoff `1000 * 2^attempt` (L89), Deaktivierungsschwelle `10` (L95, zusätzlich Default in db.js L701) und `User-Agent: HHTTPS-Webhook/4.1` (L73) sind unbenannte Literale. `registerWebhook` validiert `events` nicht als Array (L20 `events.find` wirft TypeError bei String).
**Auswirkung:** Uneinheitliche API-Fehler; Retry-Policy nicht auf einen Blick nachvollziehbar.
**Empfehlung:** Konstanten-Block am Modulanfang (`MAX_ATTEMPTS`, `DELIVERY_TIMEOUT_MS`, `DISABLE_AFTER_FAILURES`), englische Fehlercodes, `Array.isArray(events)`-Prüfung.

### [S4] [Wartbarkeit] server/server.js:L39-57, L535, L612, L792, L1080, L1166, L1254, L1275, L1310, L1334, L1359; server/roles.js:L268; server/roles.eaa.js:L17; server/roles.taxonomy.test.mjs:L7-8 — Gesammelte ESLint-Warnungen (no-unused-vars, no-useless-escape) im AP1-Bereich.
**Begründung:** Laut docs/review/ap/eslint-output.txt: server.js unbenutzte Importe `VERIFICATION_CHECKS`, `resolveVerification` (L39), `TRUST_BANDS`, `trustBand`, `HUMAN_CONFIRMED_THRESHOLD` (L41), `resolveEsco` (L56), `CUSTOM_ROLE_ID` (L57); unbenutzte Variablen `token` (L535), `e` (L792, L1254, L1310), `mode` (L1080); überflüssige Escapes `\-` (L612, L1166, L1275, L1334, L1359). roles.js `baseTrust` (L268); roles.eaa.js `guardReservedRole` (L17); roles.taxonomy.test.mjs `guardReservedRole`, `CUSTOM_ROLE_ID` (L7-8). 20 der 59 Projektwarnungen liegen in AP1.
**Auswirkung:** Lint-Rauschen verdeckt neue, relevante Warnungen; ungenutzte Importe suggerieren Abhängigkeiten, die nicht existieren.
**Empfehlung:** Importe/Variablen entfernen (`catch {}` statt `catch (e) {}`), Escapes streichen; danach `--max-warnings 0` in CI.

## Zusammenfassung

**Findings: S1: 0 · S2: 0 · S3: 18 · S4: 6** (gesamt 24).

Der AP1-Kern ist funktional gut kommentiert, aber die Kommentare beschreiben an mehreren Stellen ein früheres Modell (v4.1/14 Rollen, Honesty-Gate, Phasen-Marker), und mit dem v0.5-Umbau sind mehrere Module (roles.eaa.js, roles.taxonomy.i18n.js, große Teile von roles.i18n.js und roles.js) ohne Aufrufer zurückgeblieben. In server.js dominieren Duplikate (Token-Extraktion, Slug-Regex, Signatur-Statusauswertung, ESCO-Fetch) und verstreute Literale (27× `'0.5.0'`), die sich mit wenigen Helfern und einem Konstanten-Modul beseitigen lassen. Größte strukturelle Lücke: der komplette Signatur-/Check-/Schlüssel-/Webhook-Pfad hat keine automatisierten Tests, und die vorhandene Taxonomie-Testdatei wird von `npm test` nicht ausgeführt — Refactorings sollten mit diesen Tests beginnen.

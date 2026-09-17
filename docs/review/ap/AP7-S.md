# AP7 — Sicherheit

Geprüfte Dateien: server/privacy-pass/index.js, issuer.js, issuance.js, keys.js, verifier.js, verifier-internal.js, verifications.js, verifications-api.js, role-requirements.js, well-known.js, demo.js (nicht gemountet), migrations.js (nur Schema-Kontext); server/privacy-pass/public/wallet.html; server/sdk/client.js; server/sdk/client.py; server/test/e2e/wallet.e2e.test.mjs. Zum Verständnis gelesen (keine Findings): server/server.js L371–520 (Middleware, Rate-Limits, CSP, Identity-Cookie), L2456–2470 (register/finish), server/db.js L147–210 (sessions), server/roles.js L70–290, server/email.js L164–171, L841–881.

Stand: main @ bf0a82b. Zeilennummern per `cat -n` geprüft.

---

### [S1] [Sicherheit] server/privacy-pass/issuer.js:L82-98 — Öffentlicher `/privacy-pass/token-request` stellt Rollen-Tokens ohne Session, Eligibility oder Quota aus
**Begründung:** `handleTokenRequest` ist als RFC-9578-Endpunkt ohne jede Authentisierung gemountet (index.js:L61-65). Der Issuer wird allein aus dem vom Client gewählten Byte `truncated_token_key_id` bestimmt (`findIssuerByTruncatedKeyId`, L91) — dabei sind alle 15 Rollen-Schlüssel (keys.js:L40-44) genauso erreichbar wie der `default`-Schlüssel. Sämtliche Kontrollen aus issuance.js (Session mit Credential L69-75, Rollenabgleich L77, `eligibilityFor` L85, 10-Token-Quota L98-110) werden dadurch umgangen; es greift nur der globale IP-Limiter (300/min).
**Auswirkung:** Jeder kann unbegrenzt gültige, unlinkbare Tokens für `medical_professional`, `notary`, `politician` usw. minten (~300/min pro IP). Die Sybil-Resistenz („eine Passkey = 10 Tokens/24h") und die gesamte Rollen-Attestierung über Privacy Pass sind wirkungslos; `/verify` und `/redeem` (verifier.js) bestätigen diese Tokens als echt.
**Empfehlung:** Den anonymen Endpunkt auf den `default`-Issuer beschränken (oder ganz entfernen) und auch dort eine Autorisierung (z. B. Session-Bindung oder Origin-Challenge) verlangen; Rollen-Schlüssel dürfen nur über `/issue` nach Eligibility- und Quota-Prüfung evaluiert werden.

### [S1] [Sicherheit] server/privacy-pass/role-requirements.js:L61-97 — E-Mail-Domain-Muster sind unverankerte Substring-Regexe; angreifer-eigene Domains erfüllen strikte Rollen
**Begründung:** Die `emailDomainPattern` für `medical_professional` (L61), `caregiver` (L69), `lawyer` (L75), `civil_servant` (L89) und `politician` (L97) enthalten nicht verankerte Alternativen wie `klinik[\w-]*\.`, `(polizei|finanzamt|zoll|verwaltung|kommune)`, `(rechtsanwalt|kanzlei|anwalt|…)`, `drk`, `abgeordnete[\w.-]*` und `landtag\.[\w-]+\.de`. `emailDomainMatchesRole` (L151-158) testet nur `regex.test(domain)`. Reproduziert: `x@meine-verwaltung.example`/`x@zoll-shop.com` → civil_servant ✔, `x@abgeordnete.evil.com`/`x@landtag.evil.de` → politician ✔, `x@anwalt-fan.example` → lawyer ✔, `x@klinik-x.evil.com` → medical ✔, `x@drkx.com` → caregiver ✔, `x@uni-evil.de` → student ✔. `notary` (L80-85) hat gar kein Domain-Muster.
**Auswirkung:** Für `civil_servant` und `politician` ist `email-verified` mit passender Domain die *einzige* strikte Anforderung (L86-101). Ein Angreifer mit einer beliebigen Domain, die das Substring-Muster enthält, erhält nach einem Klick auf seinen eigenen Bestätigungslink amtliche/parlamentarische Rollen-Tokens; der `strict`-Marker suggeriert gleichzeitig hohes Vertrauen.
**Empfehlung:** Muster auf ganze Domains verankern (`^(…)$` bzw. exakte Suffix-Liste) und Substring-Alternativen (`verwaltung`, `zoll`, `drk`, `anwalt`, `klinik…`) streichen; strikte Rollen ausschließlich über eine Allowlist offizieller Domains oder eine echte Registerprüfung/EUDI-Attestierung freigeben.

### [S1] [Sicherheit] server/privacy-pass/verifications-api.js:L61-70,L95-101,L156-159 — Frei wählbares `method` in `/email/start` erlaubt das Eintragen von `approbation-id`, `bar-association-id`, `notary-chamber-id` per E-Mail-Klick
**Begründung:** `method` kommt ungeprüft aus dem Body (`const verificationMethod = method || 'email-verified'`, L70) und wird in `pp_email_pending` gespeichert (L95-101). Beim Klick auf den Link ruft L156 `recordVerification(pending.credential_id, pending.role, pending.method, …)` auf. `checkEligibility` (role-requirements.js:L130-145) prüft nur, ob die Methodennamen in `completed` enthalten sind. Zwei Aufrufe (`method:'email-verified'`, `method:'approbation-id'`) mit einer Domain, die das Muster erfüllt (siehe voriges Finding), machen einen Angreifer für `medical_professional` eligible; für `notary` genügt jede Domain. Zusätzlich vergibt verifications.js:L43 den vollen `trustScore` aus `VERIFICATION_LEVELS` (z. B. 93/95) und ignoriert die „honesty gate" `VERIFICATION_CHECKS`/`resolveVerification` aus roles.js:L228-290, die diese Methoden auf self-declared (30) herunterstuft. Die Wallet selbst nutzt diesen Pfad als Fallback (wallet.html:L1340-1343).
**Auswirkung:** Vollständige Umgehung der Register-Anforderungen (Approbation, Anwalts-/Notarkammer) — genau der Rollen, die im Modul als „highest trust level" deklariert sind — inklusive aufgeblähtem Trust-Score.
**Empfehlung:** `method` serverseitig auf `email-verified` (bzw. eine explizite Allowlist E-Mail-basierter Methoden) beschränken und Fremdwerte mit 400 abweisen; `recordVerification` den Score über `resolveVerification()` ermitteln lassen, damit nicht implementierte Prüfungen nicht als erfüllt zählen.

### [S2] [Sicherheit] server/privacy-pass/issuance.js:L98-110,L145 — Quota-Prüfung und Protokollierung sind nicht atomar (TOCTOU) → Quota beliebig überschreitbar
**Begründung:** `getRecentIssuanceCount` (L98) liest die Summe, dann werden die Tokens evaluiert (L117-142) und erst danach `logIssuance` (L145) geschrieben. Es gibt keine Transaktion, kein Lock und keinen DB-Constraint; N parallele Requests mit je 10 Tokens sehen alle `usage = 0` und werden alle bedient.
**Auswirkung:** Die als „Sybil-resistance hinge" beschriebene Grenze von 10 Tokens/24h pro Credential ist mit einem einfachen Parallel-Request auf N·10 Tokens ausdehnbar; die Tokens sind danach unlinkbar und nicht widerrufbar.
**Empfehlung:** Prüfung und Insert in einer Transaktion mit `SELECT … FOR UPDATE` auf einer Zähler-Zeile pro Credential (oder `pg_advisory_xact_lock(hash(credential_id))`) kapseln bzw. den Insert nur ausführen, wenn die Summe im selben Statement unter dem Limit bleibt, und bei 0 betroffenen Zeilen 429 senden.

### [S2] [Sicherheit] server/privacy-pass/verifications-api.js:L136-167 — Bestätigungslink schließt die Verifikation für den *Anfragenden* ab, ohne Bindung an die klickende Person (Phishing institutioneller Adressen)
**Begründung:** `/email/start` akzeptiert jede Adresse (L65-67) für die eigene Session und versendet einen Link, dessen Token an `session.credentialId` gebunden ist (L95-101). `GET /email/verify` konsumiert das Token und ruft `recordVerification` auf (L147-159) — ohne Login, Session oder Bestätigungs-Interaktion der klickenden Person. Der Mailtext (email.js:L845-854) behauptet „You requested email verification", ein Empfänger, der nicht angefragt hat, wird nicht gewarnt.
**Auswirkung:** Ein Angreifer trägt `mitarbeiter@bund.de` oder `abgeordneter@bundestag.de` ein; klickt der Empfänger den legitimen HHTTPS-Link, ist das Credential des Angreifers für `civil_servant`/`politician` (nur `email-verified` erforderlich, role-requirements.js:L86-101) freigeschaltet und kann Rollen-Tokens beziehen.
**Empfehlung:** Den Abschluss an die anfragende Session binden (Link nur in der Wallet-Session einlösbar, oder Code-Eingabe in der Wallet statt Link-Klick wie beim bestehenden `/hhttps/email/confirm-code`) und in der Mail klar auf „nicht angefordert → ignorieren" hinweisen.

### [S2] [Sicherheit] server/privacy-pass/verifications-api.js:L164,L172,L199 — HTML-Injection in `renderEmailResult` (E-Mail-Domain und Fehlermeldungen unescaped)
**Begründung:** `pending.email_domain` wird in L199 (`· ${domain}`) und `err.message` in L172 unescaped in ein serverseitig gerendertes HTML-Dokument interpoliert. Die Domain stammt aus `emailDomain(email)` (verifications.js:L21-24: alles nach dem letzten `@`, nur `includes('@')` geprüft). Da nodemailer für `to` kommaseparierte Listen akzeptiert, liefert `email = "opfer@example.com, x@<svg onload=alert(1)>"` die Mail an `opfer@example.com` und speichert als Domain `<svg onload=alert(1)>`. Die CSP erlaubt `script-src 'unsafe-inline'` (server.js:L392-400), ein Inline-Handler wird also ausgeführt.
**Auswirkung:** Beim Klick des Empfängers läuft Angreifer-JavaScript auf der Origin hhttps.org (Zugriff auf IndexedDB-Wallet mit Tokens, localStorage `hhttps_uid`, same-origin Requests mit dem `hhttps_identity`-Cookie).
**Empfehlung:** Alle interpolierten Werte HTML-escapen (kleiner `esc()`-Helper), `err.message` nie in HTML ausgeben, und die E-Mail-Adresse strikt validieren (einzelne Adresse, RFC-konformer Domain-Teil) bevor sie an nodemailer geht.

### [S2] [Sicherheit] server/privacy-pass/verifications-api.js:L59-132 — `/email/start` ohne eigenes Rate-Limit: Mailversand an beliebige Dritte
**Begründung:** Der Endpunkt sendet an jede Adresse im Body (L65, L109); Voraussetzung ist nur eine gültige Session mit Credential. Anders als `/hhttps/email/send` (server.js: `limit.email` 30/h) ist hier keine Begrenzung pro Session, Credential oder Empfänger implementiert, nur der globale 300/min-IP-Limiter. `pp_email_pending` wird zudem pro Aufruf um eine Zeile erweitert (L95-101), ohne Bereinigung.
**Auswirkung:** Bis zu ~18.000 Mails/h pro IP mit hhttps.org-Absender an fremde Adressen (Spam/Belästigung, Reputationsschaden für die Domain, Wachstum von `pp_email_pending`).
**Empfehlung:** `limit.email`-äquivalenten Limiter vor die Route setzen, zusätzlich pro Session (`emails_sent`) und pro Empfänger-Hash begrenzen, und beim Erstellen einer neuen Pending-Zeile alte Zeilen desselben Credentials/Methods löschen.

### [S3] [Sicherheit] server/privacy-pass/verifications-api.js:L104-105 — Verifikationslink wird aus `req.protocol`/`Host` gebaut (Host-Header-Poisoning)
**Begründung:** `const baseUrl = \`${req.protocol}://${req.get('host')}\`` übernimmt den Client-Header `Host` in den Link. nginx setzt zwar `Host $host` (scripts/deploy-all.sh:L287), was den vom Client gesendeten Wert weiterreicht; ein Request mit `Host: attacker.example` erzeugt einen Link auf die Angreifer-Domain.
**Auswirkung:** In Kombination mit dem vorigen Finding (Mail an Dritte) lässt sich ein Empfänger auf eine fremde Domain leiten; das Token verrät dort dem Angreifer nichts Neues (es ist an sein eigenes Credential gebunden), aber die Mail wirkt legitim und dient als Phishing-Vektor mit hhttps.org-Absender.
**Empfehlung:** Basis-URL aus Konfiguration (`PUBLIC_BASE_URL`/`RP_ID`) ableiten statt aus dem Request.

### [S3] [Sicherheit] server/privacy-pass/keys.js:L143-150,L61-75 — 1-Byte-Key-ID für 16 Issuer (38 % Kollisionswahrscheinlichkeit) und keine Schlüsselrotation/-ablauf
**Begründung:** `findIssuerByTruncatedKeyId` vergleicht nur das letzte Byte der SHA-256-Key-ID und gibt den ersten Treffer zurück. Bei 16 unabhängig erzeugten Schlüsseln liegt die Wahrscheinlichkeit einer Kollision bei ≈ 0,38 (1 − ∏(1 − i/256), i = 0…15); bei Kollision beantwortet `handleTokenRequest` (issuer.js:L91) Anfragen mit dem falschen Rollen-Schlüssel. Außerdem gibt es weder `not-after`/Expiry noch einen Rotationsmechanismus: Schlüssel gelten unbegrenzt, `pp_redeemed` muss Nonces ewig halten, und wenn eine der drei Dateien fehlt (L61), wird der private Schlüssel stillschweigend neu erzeugt und überschrieben (L77-83).
**Auswirkung:** Kompromittierte oder überschriebene Schlüssel sind nicht geordnet austauschbar; ausgestellte Tokens sind unbegrenzt gültig; Key-ID-Kollision führt zu Fehlausstellung (vom Client durch DLEQ erkennbar, aber Verfügbarkeit des Endpunkts betroffen).
**Empfehlung:** Beim Generieren Kollisionen des letzten Bytes ausschließen (neu würfeln), `not-after` in meta.json und Directory führen, Rotation mit Übergangsfenster vorsehen und bei inkonsistentem Dateisatz mit Fehler abbrechen statt neu zu generieren.

### [S3] [Sicherheit] server/privacy-pass/verifier-internal.js:L149-167, server/privacy-pass/verifier.js:L13-39 — `challenge_digest` wird nie geprüft: keine Origin-/Challenge-Bindung, Replay über `/verify`
**Begründung:** `parseAndVerify` verifiziert nur den VOPRF-Authenticator über den gesamten `token_input`; der Inhalt von `challengeDigest` (vom Wallet selbst zufällig gewählt, wallet.html:L1391-1392) wird nirgends gegen eine vom Verifier gestellte Challenge verglichen. `/verify` (L13-39) speichert nichts und bestätigt dasselbe Token beliebig oft.
**Auswirkung:** Ein Relying Party, der ein Token sieht, kann es bei anderen Relying Parties (oder mehrfach über `/verify`) einsetzen; die im RFC vorgesehene Bindung an eine Origin-Challenge (Anti-Replay über Origin-Grenzen) fehlt. Dokumentation und SDK bieten keinen Hinweis, dass nur `/redeem` Einmaligkeit erzwingt.
**Empfehlung:** Verifier-Endpunkte um `challenge` (oder `origin`) erweitern und `SHA-256(challenge)` gegen `token.challengeDigest` prüfen; `/verify` als „nur Signaturprüfung, kein Schutz vor Wiederverwendung" kennzeichnen oder entfernen.

### [S3] [Sicherheit] server/privacy-pass/verifications-api.js:L293-314 — `/recovery/use` als unauthentifiziertes Code-Orakel mit Log-Spoofing, ohne wirksame Wiederherstellungs-Funktion
**Begründung:** Der Endpunkt nimmt Codes ohne Session entgegen, unterliegt nur dem globalen 300/min-Limiter und gibt bei Erfolg die `userId` zurück. `used_from_ip` wird aus dem *ersten* Eintrag von `X-Forwarded-For` (L300) übernommen, obwohl `trust proxy 1` gesetzt ist — der Wert ist frei vom Client wählbar. Serverseitig verleiht der Code keinerlei Berechtigung: `register/finish` (server.js:L2465-2469) verlangt ohnehin eine E-Mail-verifizierte Session mit `session.userId === userId`; der Code wird nur verbraucht.
**Auswirkung:** ~50 Bit Entropie sind bei 18.000 Versuchen/h praktisch nicht brute-forcebar, aber der Endpunkt bietet keinen Nutzen, verbraucht Codes bei Fehlbedienung, liefert interne IDs und schreibt spoofbare IPs ins Audit-Log; Nutzer erhalten ein falsches Sicherheitsgefühl („Recovery-Codes").
**Empfehlung:** Entweder den Code an eine echte Recovery-Fähigkeit koppeln (z. B. kurzlebige Session mit `userId` und Registrierungserlaubnis) oder Feature entfernen; `req.ip` verwenden; dedizierten Limiter (z. B. 10/15 min) setzen.

### [S3] [Sicherheit] server/privacy-pass/verifications-api.js:L42,L209,L273, server/privacy-pass/issuance.js:L192, server/privacy-pass/public/wallet.html:L1072,L1117,L1213,L1358 — Session-ID als Bearer-Geheimnis in GET-Query-Strings
**Begründung:** `/eligibility`, `/credentials`, `/recovery/status`, `/issuance/quota` lesen `sessionId` aus `req.query`; die Wallet sendet ihn entsprechend in der URL.
**Auswirkung:** Die Session-ID (einziger Auth-Faktor aller PP-Endpunkte inkl. `/issue`) landet in nginx-Access-Logs, Browser-History und ggf. Referer-Headern (CSP `connect-src 'self'`, aber History/Logs bleiben).
**Empfehlung:** Session-ID per Header (`HHTTPS-Session`) oder POST-Body übertragen; GET-Varianten mit Query-Session abschalten.

### [S3] [Sicherheit] server/privacy-pass/migrations.js:L17-23,L106-110, server/privacy-pass/verifier.js:L74-78 — Rollen- und Zeitstempel in `pp_issuance_log` und `pp_redeemed` ermöglichen Korrelation bei kleinen Anonymitätsmengen
**Begründung:** Die Ausstellung protokolliert `(credential_id, role, issued_at)`, die Einlösung `(nonce, role, redeemed_at)`. Die Rolle ist kryptografisch bereits im Token (eigener Schlüssel), das Speichern in `pp_redeemed` (verifier.js:L75-77) ist für die Double-Spend-Prüfung unnötig.
**Auswirkung:** Für Rollen mit wenigen Nutzern (z. B. `notary`, `politician`) lässt sich eine Einlösung über Zeitfenster mit hoher Wahrscheinlichkeit einem Credential zuordnen — entgegen der Zusicherung „no identity link" im Kommentar (verifier.js:L49-50).
**Empfehlung:** `role` in `pp_redeemed` weglassen, `redeemed_at` grob runden oder nach kurzer Retention löschen, Issuance-Log auf einen Zähler pro Credential/Fenster reduzieren (ohne Rolle) und Tokens mit Ablauf versehen, damit die Nonce-Tabelle nicht unbegrenzt wächst.

### [S3] [Sicherheit] server/privacy-pass/verifications.js:L14-19 — E-Mail-Pseudonymisierung mit öffentlich bekanntem Fallback-Salt
**Begründung:** `EMAIL_SALT` fällt ohne ENV auf die im Repo stehende Konstante `'hhttps-pp-v1-email-hash-salt'` zurück; `hashEmail` ist ein ungesalzenes-äquivalentes SHA-256 über `salt:email`. Es gibt keinen Start-Check, der die ENV erzwingt.
**Auswirkung:** Bei DB-Leak sind die `email_hash`-Spalten (pp_attribute_verifications, pp_email_pending) per Wörterbuch-/Listenangriff rückrechenbar; die Zusicherung „nie im Klartext" greift dann nicht.
**Empfehlung:** Beim Start ohne `HHTTPS_EMAIL_HASH_SALT` in Produktion abbrechen (wie bei anderen Secrets) und HMAC-SHA-256 mit dem Secret als Schlüssel verwenden.

### [S3] [Sicherheit] server/privacy-pass/public/wallet.html:L9 — WebAuthn-Bibliothek von unpkg.com ohne Subresource Integrity
**Begründung:** `<script src="https://unpkg.com/@simplewebauthn/browser@9.0.1/…">` ohne `integrity`-Attribut; die CSP lässt `unpkg.com` global zu (server.js:L396).
**Auswirkung:** Kompromittierung des CDN oder des Pakets führt zu Fremd-JavaScript auf der Wallet-Origin (Session-ID, Tokens in IndexedDB, Passkey-Ceremonies).
**Empfehlung:** Bundle lokal unter `/privacy-pass/lib/` ausliefern (wie voprf.js) oder `integrity`+`crossorigin` setzen und `unpkg.com` aus der CSP entfernen.

### [S4] [Sicherheit] server/privacy-pass/issuance.js:L158, server/privacy-pass/verifications-api.js:L53,L130,L242,L265,L287,L316 — `err.message` interner Fehler wird an Clients zurückgegeben
**Begründung:** Alle 500-Antworten hängen `detail: err.message` an; z. B. liefert `/email/start` mit einer Session ohne Credential die PostgreSQL-NOT-NULL-Meldung inkl. Spalten-/Tabellenname.
**Auswirkung:** Preisgabe von Schema-/Implementierungsdetails.
**Empfehlung:** Generische Fehlermeldung an den Client, Details nur ins Server-Log.

### [S4] [Sicherheit] server/privacy-pass/verifications-api.js:L73-80 — Session ohne deklarierte Rolle und ohne Credential-Prüfung darf `/email/start` für jede Rolle nutzen
**Begründung:** `if (session.role && session.role !== role)` lässt Sessions ohne Rolle durch; `session.credentialId` wird nicht geprüft (Fehler erst im INSERT).
**Auswirkung:** Kein direkter Bypass (die Verifikation hängt am Credential), aber inkonsistent zu `/issue` (L74-82) und Quelle des 500-Lecks.
**Empfehlung:** Wie in `/issue` `credentialId` und Rollenabgleich strikt prüfen.

### [S4] [Sicherheit] server/privacy-pass/public/wallet.html:L1077-1090,L1140-1152,L1247-1266 — `innerHTML` mit Server-Daten ohne Escaping
**Begründung:** Credential-IDs, `deviceType`, Recovery-Codes/`message` und Requirement-Namen werden per Template-String in `innerHTML` geschrieben. Die Werte sind heute serverseitig konstant bzw. base64url (kein ausnutzbarer Pfad gefunden), aber jede künftige Erweiterung der API (z. B. Gerätename) wird direkt zur XSS.
**Auswirkung:** Latentes XSS-Risiko in einer Seite, die Session-ID und Tokens hält.
**Empfehlung:** `textContent`/DOM-APIs verwenden oder einen `esc()`-Helper konsequent anwenden.

### [S4] [Sicherheit] server/sdk/client.py:L222, server/sdk/client.js:L343, server/sdk/client.py:L195 — Unkodierter Query-Parameter und `kid`-Fallback auf ersten JWKS-Schlüssel
**Begründung:** `is_revoked` baut `?jti={jti}` ohne `urllib.parse.quote`; ein `jti` mit `&`/`#` verändert die Anfrage. `_resolveKey`/`verify_local` fallen bei unbekanntem oder fehlendem `kid` auf `keys[0]` zurück.
**Auswirkung:** Gering — die Signatur wird weiterhin gegen einen Issuer-Schlüssel geprüft; Query-Injection betrifft nur den Revocation-Status-Aufruf.
**Empfehlung:** `quote(jti, safe='')` verwenden; bei unbekanntem `kid` `invalid` zurückgeben statt Fallback.

---

## Zusammenfassung

**S1: 3 · S2: 4 · S3: 7 · S4: 4** (18 Findings)

Die Privacy-Pass-Schicht erfüllt ihre eigene Sicherheitszusage derzeit nicht: Rollen-Tokens sind über den öffentlichen `/token-request`-Endpunkt ohne jede Prüfung mintbar, und selbst der „richtige" Pfad über `/issue` lässt sich durch unverankerte Domain-Regexe, ein frei wählbares `method`-Feld und ein nicht-atomares Quota trivial für strikte Rollen missbrauchen. Die Kryptografie selbst (VOPRF P-384, DLEQ, timing-safe Vergleich, atomarer Double-Spend-Insert in `/redeem`) ist sauber umgesetzt; die Schwächen liegen in Autorisierung, Eingabevalidierung, Rate-Limiting und der fehlenden Challenge-Bindung. `demo.js` ist nicht gemountet (index.js importiert es nicht) und `demo.html` liegt nicht im Repo — toter Code, nicht bewertet.

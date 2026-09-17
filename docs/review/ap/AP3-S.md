# AP3 — Sicherheit

Geprüfte Dateien: server/server.js L455-720 (Identity-Cookie-Middleware, issueAccessToken, requireEmailVerified, issueRefreshToken, checkTokenValid), server/server.js L2400-3096 (tokenSurface, /hhttps/webauthn/*, /hhttps/token/refresh, /hhttps/session/email/start, /hhttps/session/start, readEmailContext, emailContextMatches, bindSessionToEmailAnchor, /hhttps/email/*, /hhttps/verify/github/*, renderGithubReturnPage), server/identity.js, server/email.js; zum Verständnis gelesen: server/db.js (sessions, challenges, emailVerifications, identityAnchors), server/wp-plugin-registration.js, server/privacy-pass/verifications-api.js, server/roles.i18n.js, node_modules/nodemailer (addressparser, mime-node), Tests server/test/integration/email-*.test.mjs, gate.test.mjs, security-fixes.test.mjs, server/test/unit/identity.test.mjs, email-template.test.mjs.

Stand: `main` @ `bf0a82b`, Zeilennummern per `cat -n` geprüft am 2026-09-17.

---

### [S1] [Sicherheit] server/server.js:L2852-2854 — E-Mail-Validierung und nodemailer-Adressparser interpretieren die Adresse unterschiedlich: `x@evil.com(bundestag.de` wird an evil.com zugestellt, aber als `official-email` (+40 Trust) klassifiziert
**Begründung:** `/hhttps/email/send` akzeptiert jede Zeichenkette, die `^[^\s@]+@[^\s@]+\.[^\s@]+$` erfüllt — also auch RFC-5322-Kommentarzeichen `(`, `)`, `<`, `>`. `classifyDomain()` (email.js L100) nimmt naiv `email.split('@')[1]` und prüft mit `endsWith`; nodemailer (addressparser, 6.10.1) entfernt Kommentare und ermittelt die Envelope-Adresse anders. Reproduziert mit `nodemailer.createTransport({streamTransport:true})`:
```
"x@evil.com(bundestag.de"   → classifyDomain: official-email +40 | SMTP-Envelope to: ["x@evil.com"]
"x@evil.com(.uni-"          → classifyDomain: school-email  +15 | SMTP-Envelope to: ["x@evil.com"]
"x@evil.com＠bundestag.de"  → classifyDomain: official-email +40 | Envelope to: x@evil.xn--combundestag-k050e.de
```
Der Angreifer erhält den 6-stelligen Code an seiner eigenen Mailbox, bestätigt per `/hhttps/email/confirm-code` (L2950) und `bindSessionToEmailAnchor` (L2812-2820) schreibt `emailLevel = 'official-email'`, `emailTrustBonus = 40`, `emailDomain = 'evil.com(bundestag.de'` in die Session. Der Wert landet über `tokenSurface` (L2406) als `domain_name` im Access-Token und im Header `HHTTPS-Domain-Value` (L588), ein Relying Party, der `domain_name.endsWith('bundestag.de')` prüft, wird ebenfalls getäuscht. Genau diese Klasse deckt die nodemailer-Advisories GHSA-cc9r-2j5m-2m83 (Kommentar-Fehlparsing, fix ≥ 9.1.0), GHSA-mm7p-fcc7-pg87 und GHSA-wmmp-3585-3rmp (IDN/Punycode) ab — sie sind über `email.js:L414` (`to: email`) mit Nutzereingabe erreichbar.
**Auswirkung:** Ohne Kosten (kein Domain-Kauf) erlangt ein beliebiger Nutzer die höchste E-Mail-Assurance-Stufe (`official-email`, roles.js L92: trustScore 90) und +40 Trust-Bonus; das Assurance-Modell für Behörden-/Hochschul-/Presse-Domains ist umgehbar.
**Empfehlung:** Adresse strikt validieren, bevor sie an nodemailer und `classifyDomain` geht: Zeichenklasse auf `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}` (nur ASCII, keine `()<>",;:` und keine Nicht-ASCII-@-Varianten) einschränken, Länge begrenzen (z. B. 254) und zusätzlich die von nodemailer geparste Adresse (`addressparser(email)[0].address`) mit der klassifizierten Adresse vergleichen (ungleich → 400). nodemailer auf ≥ 9.1.0 anheben.

### [S2] [Sicherheit] server/email.js:L99-115 — Domain-Klassifikation ohne Label-Grenze: `endsWith('bundestag.de')` matcht `notbundestag.de`, `includes('.uni-')` matcht jede eigene Subdomain
**Begründung:** `DOMAIN_RULES.official`/`press`/`creative` werden mit `domain.endsWith(d)` ohne führenden Punkt geprüft, `university` mit `domain.includes(d)`:
```js
if (DOMAIN_RULES.official.some(d => domain.endsWith(d))) { return { level: 'official-email', trustBonus: 40, ... } }
if (DOMAIN_RULES.university.some(d => domain.includes(d))) { return { level: 'school-email', trustBonus: 15, ... } }
```
Reproduziert: `x@notbundestag.de` → `official-email +40`; `x@a.uni-b.evil.com` → `school-email +15`; `x@hochschule-x.evil.com` → `school-email`. Eine frei registrierbare Domain wie `notbundestag.de` oder eine beliebige Subdomain `*.uni-*.` der eigenen Domain genügt.
**Auswirkung:** Mit einer ~10-€-Domain lässt sich dauerhaft die Stufe `official-email` (Behörde) bzw. `school-email` erlangen; die Assurance-Aussage gegenüber Plattformen ist nicht belastbar.
**Empfehlung:** Exakten Host- oder Suffix-Vergleich mit Label-Grenze verwenden (`domain === d || domain.endsWith('.' + d)`), die `includes`-Regeln durch Label-basierte Regexe ersetzen (`/(^|\.)uni-[a-z0-9-]+\.de$/` o. ä.) und die Liste auf vollständige, geprüfte Domains beschränken.

### [S2] [Sicherheit] server/email.js:L445-448 — `setupUrl` wird unescaped in ein `href`-Attribut der Registrierungsmail eingesetzt → HTML-Injection in Mails von noreply@hhttps.org an frei wählbare Empfänger
**Begründung:** `sendPlatformRegistrationEmail` baut `<a href="${setupUrl}" ...>` ohne `escapeHtml`. `setupUrl` stammt aus `wp-plugin-registration.js:L165` (`String(homepage_url) + '/wp-admin/...'`); `homepage_url` wird dort nur per `new URL(...).hostname` auf Apex geprüft (L38-51), Pfad/Query bleiben roh — `https://evil.com/"><img src=x onerror=…>` passiert die Prüfung (`new URL` liefert hostname `evil.com`). Der unautorisierte Endpunkt `/hhttps/plugin/register` erlaubt zudem `contact_email` frei zu wählen, d. h. Empfänger und HTML-Inhalt sind angreifergesteuert.
**Auswirkung:** hhttps.org wird zum Phishing-Relay: Mails vom vertrauenswürdigen Absender `"HHTTPS Issuer" <noreply@hhttps.org>` mit angreiferkontrolliertem HTML (Links, Bilder, Formulare) an beliebige Opfer; Mail-Reputation/SPF-Domain wird missbraucht.
**Empfehlung:** In email.js jede interpolierte URL im HTML mit `escapeHtml` versehen (auch `ctaUrl` in `emailShell` L263/L266 als Defense in Depth) und in `sendPlatformRegistrationEmail` `setupUrl` nur akzeptieren, wenn `new URL(setupUrl).href === setupUrl` und Protokoll `https:` ist; besser: `setupUrl` serverseitig nur aus `origin` + festem Pfad bilden.

### [S3] [Sicherheit] server/email.js:L498-502, L553-557, L602-606, L725-730, L871-875 — Vier Versandfunktionen fallen ohne Transport still in „Dev-Mode“ und loggen Bestätigungs-Links/Tokens im Klartext
**Begründung:** Nur `sendVerificationEmail` prüft `emailDevModeAllowed()` (L405-409, F-3) und wirft `email_transport_unavailable`. `sendPlatformRegistrationEmail`, `sendPlatformVerifiedEmail`, `sendPlatformRejectedEmail`, `sendAdminPlatformNotification` und `sendPrivacyPassVerification` geben bei `transporter === null` `{ sent: false, devMode: true }` zurück und schreiben per `devLog` (L797-808) Empfänger, `confirmUrl` (enthält `email_token`) bzw. den Privacy-Pass-Verify-Link mit `rawToken` nach stdout — auch mit `NODE_ENV=production`.
**Auswirkung:** Bei SMTP-Ausfall/-Fehlkonfiguration in Produktion landen Einmal-Tokens und E-Mail-Adressen in pm2-/Journal-Logs (Datenschutz, Token-Leak an jeden mit Log-Zugriff); Aufrufer melden „versandt“ (privacy-pass/verifications-api.js L112 nur `console.warn`), die Nutzer erhalten nichts.
**Empfehlung:** Die F-3-Logik zentralisieren (`getTransportOrThrow()`), in allen fünf Funktionen ohne `emailDevModeAllowed()` fail-closed werfen, und `devLog` niemals Tokens/Links loggen, wenn nicht explizit `EMAIL_DEV_MODE=1` gesetzt ist.

### [S3] [Sicherheit] server/server.js:L485-516 — Identity-Cookie-Middleware prüft nur die Signatur, nicht die Revocation: widerrufene Tokens liefern bis zu 1 h weiter „verified“-Header
**Begründung:** `verifyToken(cookieToken)` (L492) prüft ES256-Signatur und `exp`; `db.revokedTokens`/`db.tokens.exists` (wie in `checkTokenValid`, L702-711) werden nicht konsultiert. `/hhttps/revoke` (L3678-3697) trägt die jti in `revoked_tokens` ein und löscht das Cookie nur in **dieser** Antwort; ein anderswo gespeichertes/kopiertes Cookie bleibt bis `ACCESS_TTL` (3600 s, L93) gültig.
**Auswirkung:** Nach Revoke (z. B. Gerät verloren, Token in Logs aufgetaucht) zeigt hhttps.org dem Cookie-Inhaber weiterhin `HHTTPS-Status: verified`, Rolle, Alter, Methoden; die Zusage „revoked“ des Revoke-Endpunkts gilt für diesen Kanal nicht.
**Empfehlung:** In der Middleware `checkTokenValid` (oder mindestens `db.revokedTokens.has(jti)`) verwenden, ggf. mit kurzem In-Memory-Cache der Revocation-Liste, und bei Treffer `clearIdentityCookie` aufrufen.

### [S3] [Sicherheit] server/server.js:L2606-2656 — Refresh-Token: 7-Tage-Bearer ohne Rotation, ohne Reuse-Erkennung, ohne Bindung
**Begründung:** `/hhttps/token/refresh` prüft Signatur, Revocation und Existenz in `refresh_tokens` (L2611-2616), stellt dann ein neues Access-Token aus (L2628) und gibt **denselben** Refresh-Token weiter (kein neuer Token, kein Löschen der jti). `issueRefreshToken` (L680-700) erzeugt reine Bearer-Token (`REFRESH_TTL = 7 d`, L94) ohne Client-/Gerätebindung; der Endpunkt hat keinen Rate-Limiter außer `limit.global`.
**Auswirkung:** Ein einmal abgeflossener Refresh-Token (Extension-Storage, Log, XSS auf einer RP) erlaubt 7 Tage lang unbemerkt die Ausstellung frischer Access-Tokens mit allen `verified_methods`; der legitime Nutzer bemerkt nichts, da kein Reuse-Alarm existiert.
**Empfehlung:** Rotation implementieren (neuen Refresh-Token ausgeben, alte jti sofort in `revoked_tokens`), Wiederverwendung einer rotierten jti als Kompromittierung werten und die gesamte Familie widerrufen (RFC 6819 §5.2.2.3); optional Bindung an `credentialId`/PoP.

### [S3] [Sicherheit] server/server.js:L2940-2951 — 6-stelliger Code ohne Fehlversuchszähler pro Session
**Begründung:** `verifyEmailCode` → `getAndConsumeByCode` (db.js L358-366) prüft nur `code = sha256 AND session_id = … AND used = FALSE`. Ein falscher Code hat keine Konsequenz für die Verification-Zeile; die einzige Bremse ist `limit.email` (30 Req / 60 min pro IP, L428) — der Zähler ist IP-basiert, nicht sessionbasiert. Bei 15 min Gültigkeit (email.js L45) und 10^6 Codes ist ein verteilter Angriff (viele IPs, ein `sessionId`) nicht ausgeschlossen; die `sessionId` steht im Magic-Link und in jeder Antwort.
**Auswirkung:** Kein direkter Exploit (hohe IP-Zahl nötig), aber der Standard-Schutz für kurze OTPs (≤ 5-10 Versuche pro Code, dann Invalidierung) fehlt.
**Empfehlung:** Spalte `attempts` in `email_verifications`; bei jedem Fehlversuch inkrementieren und ab z. B. 5 Versuchen die Zeile auf `used = TRUE` setzen (bzw. den Session-Kontext löschen), sodass ein neuer Code angefordert werden muss.

### [S4] [Sicherheit] server/server.js:L2453, L2526, L2709, L2750, L2892, L3024 — Interne Fehlermeldungen (`e.message`) werden 1:1 an den Client ausgegeben
**Begründung:** Die `catch`-Blöcke antworten mit `res.status(500).json({ error: e.message })` bzw. `'E-Mail-Fehler: ' + err.message`; bei DB-Fehlern (pg) oder SMTP-Fehlern (nodemailer: Host, Port, Auth-Antwort) gelangen Details zur Infrastruktur nach außen.
**Auswirkung:** Information Disclosure (Tabellennamen, SMTP-Host, Fehlercodes) als Vorbereitung weiterer Angriffe.
**Empfehlung:** Generische Fehlercodes an den Client, `e.message` nur ins Server-Log.

### [S4] [Sicherheit] server/server.js:L2896-2901, L2534-2538 — Ungeprüfte Eingabetypen führen zu unbehandelten Promise-Rejections (Request bleibt ohne Antwort hängen)
**Begründung:** `/hhttps/email/verify` übergibt `req.query.token` direkt an `verifyEmailToken` → `crypto.createHash().update(rawToken)`; mit `?token[]=a&session=x` (qs-Parser, Express-Default) ist `token` ein Array und `update()` wirft `ERR_INVALID_ARG_TYPE` außerhalb jedes `try`. Ebenso `/hhttps/webauthn/auth/finish`: `db.credentials.get(response.id)` (L2538) vor dem `try` mit fehlendem `response` → `TypeError`. Express 4 fängt asynchrone Fehler nicht; nur `process.on('unhandledRejection')` (L4824) loggt.
**Auswirkung:** Kein Crash, aber Verbindungen bleiben bis zum Client-/nginx-Timeout offen (Slot-Bindung), und die Fehlerpfade sind nicht kontrolliert.
**Empfehlung:** Typprüfung (`typeof token === 'string'`, `response?.id`) bzw. einen `asyncHandler`-Wrapper/`express-async-errors` einsetzen.

### [S4] [Sicherheit] server/server.js:L468-479 — `readIdentityCookie` wirft bei fehlerhaft kodiertem Cookie-Wert `URIError`
**Begründung:** `decodeURIComponent(part.slice(i + 1).trim())` ohne `try/catch`; ein Cookie `hhttps_id=%E0` lässt die globale Middleware (L485) synchron werfen → Express antwortet 500 auf **jede** Route für diesen Client, bis das Cookie entfernt ist.
**Auswirkung:** Selbst-DoS des Browsers (kein Cross-User-Effekt, da Cookies nicht fremdgesetzt werden können; `SameSite=Lax`, `Secure`, `HttpOnly` sind korrekt).
**Empfehlung:** `decodeURIComponent` in `try/catch` kapseln und bei Fehler `null` zurückgeben + Cookie löschen.

### [S4] [Sicherheit] server/email.js:L842-848, L879 — `roleDisplay(role)` in der Privacy-Pass-Mail nicht HTML-escaped; `roleLabel` fällt auf die rohe `roleId` zurück
**Begründung:** `roleLabel()` (roles.i18n.js L368-372) gibt für unbekannte IDs `roleId` unverändert zurück; `sendPrivacyPassVerification` setzt `${label}` roh ins HTML. Aktuell nicht ausnutzbar, weil der einzige Aufrufer (privacy-pass/verifications-api.js) `ROLES.includes(role)` prüft — im Gegensatz zu `renderVerificationEmail` (L308-310, F-5) fehlt hier die Absicherung im Modul selbst.
**Auswirkung:** Latente HTML-Injection, sobald ein Aufrufer die Whitelist-Prüfung nicht durchführt.
**Empfehlung:** Wie in `renderVerificationEmail`: `ROLES[role] ? role : 'citizen'` und `escapeHtml(label)`.

---

## Bewertung der nodemailer-Advisories (6.10.1) auf Erreichbarkeit über server/email.js

| Advisory | Pfad | Erreichbar? |
|---|---|---|
| GHSA-cc9r-2j5m-2m83 (Kommentar-Fehlparsing → fremde Domain), GHSA-mm7p-fcc7-pg87 (Interpretationskonflikt), GHSA-wmmp-3585-3rmp (IDN/Punycode) | `to: email` in `sendVerificationEmail` (L414), `email` aus `/hhttps/email/send` nur per lockerer Regex geprüft | **Ja** — siehe S1-Finding; die eigene Domain-Klassifikation vertraut einer anderen Parse-Logik als nodemailer |
| GHSA-c7w3-x93f-qmm8 (`envelope.size`), GHSA-vvjj-xcjg-gr5g (`name`-Option EHLO), GHSA-268h-hp4c-crq3 (`List-*`-Header), GHSA-wqvq-jvpq-h66f (jsonTransport), GHSA-p6gq-j5cr-w38f (`raw`), GHSA-8m3c-c648-2xjj (`resolveContent`), GHSA-r7g4-qg5f-qqm2 (OAuth2-TLS) | `createTransport` (L147-153) setzt nur host/port/secure/auth/tls; `sendMail` erhält nur `from/to/replyTo/subject/text/html` | Nein — keine der Optionen wird verwendet |
| CRLF-Header-Injection über `subject` (platformName/roleLabel) | mime-node `_encodeHeaderValue` ersetzt `\r?\n` durch Leerzeichen (node_modules/nodemailer/lib/mime-node/index.js L1099, L1141, L1147); `to` schließt Whitespace per Regex aus | Nein |
| GHSA-rcmh-qjqh-p98v / GHSA-2x7j-588g-ccc2 (addressparser-DoS) | `to: email`, Länge nur durch Body-Limit 2 MB begrenzt | Praktisch nein — gemessen: 100 000 `(`-Zeichen → 10 ms, 50 000 `<` → 2 ms; zusätzlich `limit.email` 30/h/IP. Dennoch Längenlimit empfohlen (siehe S1) |

Fazit: Der Upgrade-Bedarf (nodemailer ≥ 9.1.0) ist real, aber der eigentliche Fehler liegt in der zu laxen Adressvalidierung in server.js L2853 und der `endsWith`/`includes`-Klassifikation in email.js L99-115; ein Upgrade allein schließt die Lookalike-Domain-Lücke (S2) nicht.

## Positiv geprüft (keine Findings)

- Cookie-Flags (`httpOnly`, `secure`, `sameSite: 'lax'`, L455-462); Token-Signatur ES256 mit fixiertem `algorithms` (keys.js L172).
- WebAuthn: Registrierung nur auf E-Mail-verifizierter Session mit Session/userId-Bindung (L2464-2468), `attestationType: 'none'` (Advisory GHSA-6hxq-p678-4hr2 daher nicht relevant), Origin/RP-ID-Prüfung, Counter-Update, Challenge-Verbrauch; `resolvePasskeySession` (identity.js L112-132) verhindert Fremd-Merge und userId-Spoofing aus `auth/start`.
- E-Mail-Anker: Code/Token nur als SHA-256 gespeichert, Session-Bindung des Codes (db.js L358), Kontext-Hash-Abgleich `emailContextMatches` (L2773-2777), Invalidierung älterer Codes pro Session (L2866), Anchor-Konfliktprüfung (L2798-2810), 256-Bit-Magic-Link-Token, alle Redirects relativ (`/?email_verify=…`) — kein Open Redirect.
- identity.js: Pepper-Pflicht in Produktion (`assertPepperConfigured`, aufgerufen in server.js L4778; deploy-phase8.sh erzwingt `NODE_ENV=production`), `crypto.randomInt` für Pseudonyme, `sanitizePseudonym` mit Whitelist.
- Alle SQL-Zugriffe in den geprüften db.js-Helfern sind parametrisiert; `sessions.update` verwendet eine Spalten-Whitelist.
- `renderGithubReturnPage`: `message` escaped, `title` serverseitig konstant; GitHub-`error`-Query-Parameter URL-encodiert.

## Zusammenfassung

Findings: **S1: 1 · S2: 2 · S3: 4 · S4: 4** (gesamt 11).

Der Kern des E-Mail-Anker-Flows (Hashing, Session-Bindung, Kontext-Abgleich, Passkey-Merge) ist sorgfältig gehärtet und durch Tests abgedeckt. Die gravierende Schwäche liegt eine Ebene davor: Die Domain-Klassifikation, aus der Assurance-Stufen wie `official-email` und Trust-Boni abgeleitet werden, vertraut einer laxen Regex und `endsWith`/`includes`-Vergleichen — sie ist sowohl ohne Kosten (Kommentar-Trick, nodemailer-Parserdifferenz) als auch mit einer Lookalike-Domain umgehbar. Daneben fehlen im Token-Lebenszyklus Refresh-Rotation und Revocation-Check im Cookie-Pfad, und die nicht-user-facing Mailfunktionen fallen bei fehlendem Transport still in einen Log-Modus, der Einmal-Tokens preisgibt.

# AP3 — Wartbarkeit

Geprüfte Dateien: server/server.js L455–720 (Identity-Cookie, setHHTPPS, issueAccessToken, requireEmailVerified, issueRefreshToken, checkTokenValid) und L2400–3096 (tokenSurface, /hhttps/webauthn/*, /hhttps/token/refresh, /hhttps/session/email/start, /hhttps/session/start, readEmailContext, bindSessionToEmailAnchor, /hhttps/email/*, /hhttps/verify/github/*, renderGithubReturnPage); server/identity.js; server/email.js; Tests server/test/integration/email-*.test.mjs, gate.test.mjs, security-fixes.test.mjs, server/test/unit/identity.test.mjs, email-template.test.mjs. Zum Verständnis gelesen (ohne Findings): server/roles.js, server/db.js (sessions), server/external-verify.js, sites/hhttps.html, privacy-pass/public/wallet.html.

---

### [S3] [Wartbarkeit] server/server.js:L2676-2752 — Zwei fast identische Session-Bootstrap-Routen (`/session/email/start` und `/session/start`), die Frontend-Seiten nutzen nur eine davon
**Begründung:** `/hhttps/session/email/start` (L2676–2711) und `/hhttps/session/start` (L2720–2752) erzeugen beide `userId`/`sid` per uuid, `db.sessions.create` mit `credentialId: null, backedUp: false, verified: true, trustScore: 0, pseudonym`, 15 min TTL, `stats.increment('verifications')` und antworten mit derselben Struktur. Einziger Unterschied: `deviceType: 'email-only'` vs `'pending'` und der `method`-String. `grep` über `public/`, `sites/`, `extension/`, `privacy-pass/public/` findet keinen Aufrufer von `/session/email/start` (nur die Doku in `sites/spec.html:783`); alle Seiten und Tests (`test/helpers/identity-flow.mjs`, e2e) benutzen `/session/start`.
**Auswirkung:** Jede Änderung am Session-Bootstrap (TTL, Felder, Rate-Limit) muss an zwei Stellen nachgezogen werden; die ungenutzte Route ist praktisch toter Code mit eigener Angriffsfläche, und der veraltete Kommentarblock (siehe nächstes Finding) belegt bereits, dass sie nicht mehr gepflegt wird.
**Empfehlung:** `/session/email/start` auf einen dünnen Alias von `/session/start` reduzieren (gleicher Handler, `deviceType` als Parameter) oder deprecaten und nach einer Übergangsfrist entfernen; `sites/spec.html` entsprechend anpassen.

### [S3] [Wartbarkeit] server/server.js:L2658-2674 — Kommentarblock zu `/session/email/start` widerspricht dem Code in drei Punkten
**Begründung:** Der Kommentar sagt „Sessions werden mit trust_score: 30 erstellt“ und „Response: { …, trustScore: 30, … }“ (L2666–2674), der Code setzt `trustScore: 0` (L2693, L2702). Er sagt „Rate-limit: identisch mit limit.email (5 Req / 60 min pro IP)“ (L2670), tatsächlich ist `limit.email = rl(30, 60*60_000)` (L428). Ebenso nennt `server/email.js:L86-97` eine „email-verified baseline (30)“ und „base 30 + domainBonus + (passkey ? 30 : 0)“ berechnet „in /role/declare“, während `roles.js:L28-29` email → 20 als Fundament definiert und der Score über `computeVerification` (roles.js L182) läuft. Auch `server.js:L2586-2590` („email 20 + passkey 30“, Seed 50) und L2624 („20 // email floor“) verwenden bereits die neuen Werte.
**Auswirkung:** Wer das Trust-Modell aus den Kommentaren ableitet (z. B. beim Anpassen der Domain-Boni), arbeitet mit falschen Zahlen; die Doku für den öffentlichen Endpunkt ist irreführend.
**Empfehlung:** Kommentarblöcke auf `trustScore: 0`, `limit.email` (30/h) und das `computeVerification`-Modell (email 20, passkey +30) korrigieren; besser Werte aus `roles.js` referenzieren statt Zahlen im Kommentar zu wiederholen.

### [S3] [Wartbarkeit] server/email.js:L403-412,L498-502,L553-557,L602-606,L725-730,L871-875 — Sechsfach kopierter „kein Transport → devLog → return“-Block mit abweichender Semantik
**Begründung:** Jede Sende-Funktion enthält denselben Block `const transporter = createTransport(); if (!transporter) { devLog(...); return { sent:false, devMode:true }; }`. Nur `sendVerificationEmail` (L404–409) prüft `emailDevModeAllowed()` und wirft `email_transport_unavailable`; die fünf anderen Funktionen (Plattform-Registrierung, Verified, Rejected, Admin-Benachrichtigung, Privacy-Pass-Verifikation) fallen ohne diese Prüfung still in den Dev-Modus — auch in Produktion.
**Auswirkung:** Die F-3/S-4-Absicht „fail closed ohne Transport“ ist nur für einen von sechs Pfaden umgesetzt, und es ist nicht erkennbar, ob das Absicht ist; jede Änderung an Transport-Handling oder Rückgabeform muss sechsmal erfolgen.
**Empfehlung:** Einen gemeinsamen `sendMail({ kind, to, subject, text, html, devMeta, failClosed })`-Helfer einführen, der Transport-Erzeugung, Dev-Fallback und `buildMailOptions` kapselt; das Fail-closed-Verhalten dort einmal festlegen (ggf. per Parameter) und alle sechs Funktionen darauf umstellen.

### [S3] [Wartbarkeit] server/server.js:L2896-2928 vs L2940-2987 — Der Bestätigungspfad (Token vs. Code) ist doppelt implementiert und liefert Fehler in zwei verschiedenen Formaten
**Begründung:** `/hhttps/email/verify` (GET, Magic-Link) und `/hhttps/email/confirm-code` (POST) führen dieselbe Sequenz aus: Verifikation prüfen → Session laden → `readEmailContext` → `emailContextMatches` → `bindSessionToEmailAnchor` → 409-Behandlung. Die Reihenfolge weicht ab (verify konsumiert den Token vor dem Session-Lookup L2900/L2905, confirm-code lädt die Session zuerst L2947/L2950 — der #22-Fix wurde nur in einem Pfad umgesetzt). Fehler werden im einen Pfad als Redirect-`reason` (`missing_params`, `session_mismatch`, `email_context_missing`, …), im anderen als JSON `{error}` mit 400/404/409/500 transportiert.
**Auswirkung:** Bugfixes (wie #22) und neue Prüfungen müssen zweimal eingebaut werden und driften nachweislich schon auseinander; Clients müssen zwei Fehlerkataloge kennen.
**Empfehlung:** Gemeinsame Funktion `confirmEmailVerification({ sessionId, verification })`, die Session-Lookup, Kontext-Prüfung und Bind ausführt und `{ ok, code, status, bound }` zurückgibt; beide Routen mappen das Ergebnis nur noch auf Redirect bzw. JSON.

### [S3] [Wartbarkeit] server/server.js:L2611-2616 — `/token/refresh` reimplementiert den Refresh-Zweig von `checkTokenValid` von Hand
**Begründung:** L2611–2616 macht `verifyToken` → `sub !== 'refresh'` → `revokedTokens.has` → `refreshTokens.get`; `checkTokenValid` (L702–711) enthält exakt diese Prüfungen (Revocation + `refreshTokens.get` für `sub === 'refresh'`) und wird an neun anderen Stellen benutzt (L880, L965, L1095, …). Zudem ist die Fehlermeldung `'Refresh-Token nicht aktiv'` (L2616) wörtlich aus L707 kopiert.
**Auswirkung:** Eine spätere Ergänzung in `checkTokenValid` (z. B. zusätzliche Revocation-Quelle, Clock-Skew) gilt nicht für den Refresh-Endpunkt.
**Empfehlung:** `const d = await checkTokenValid(refreshToken); if (d.sub !== 'refresh') throw …` und `stored = await db.refreshTokens.get(d.jti)` nur noch für `user_id`/`credential_id` verwenden.

### [S3] [Wartbarkeit] server/server.js:L2775 vs server/email.js:L391 — Der Hash-Vertrag „sha256(normalisierte E-Mail)“ ist in zwei Dateien unabhängig definiert
**Begründung:** `email.js:L391` schreibt `sha256(email.toLowerCase())` in `email_verifications`; `server.js:L2773-2777` (`emailContextMatches`) vergleicht gegen `sha256(normalizeEmail(ctx.email))` (= trim + lowercase, identity.js L9–12). Beide Seiten stimmen heute nur überein, weil `/email/send` die Adresse vorher normalisiert (L2852); `email.js` importiert `normalizeEmail` nicht. Die Kommentare an L757/L787 („caller must match it against its context“) verlangen den Abgleich, ohne die Hash-Funktion zu benennen.
**Auswirkung:** Ändert jemand die Normalisierung nur an einer Stelle (z. B. Unicode-NFC oder Plus-Adressen), scheitert jede Verifikation still mit `email_context_mismatch`.
**Empfehlung:** In `identity.js` eine Funktion `emailVerificationHash(email)` (sha256 über `normalizeEmail`) exportieren und sowohl in `sendVerificationEmail` als auch in `emailContextMatches` benutzen; die fünf `createHash('sha256')…digest('hex')`-Wiederholungen in email.js (L379, L381, L391, L746, L776) auf einen `sha256hex()`-Helfer reduzieren.

### [S3] [Wartbarkeit] server/email.js:L53 vs server/server.js:L78 — `BASE_URL` wird zweimal mit unterschiedlichem Default aus der Umgebung gelesen
**Begründung:** `server.js:L76-78` definiert `BASE_URL = process.env.BASE_URL || ORIGIN` (ORIGIN aus `RP_ID`), `email.js:L53` definiert `BASE_URL = process.env.BASE_URL || 'https://hhttps.org'`. Nur `sendVerificationEmail` bekommt `baseUrl` explizit übergeben (L2869); `sendPlatformVerifiedEmail`/`sendPlatformRejectedEmail`/`sendAdminPlatformNotification` bauen ihre Links aus dem email.js-Default (L539, L590, L651). Weitere Konfiguration (`SMTP_*`, `ADMIN_NOTIFY_EMAIL`, `EMAIL_DEV_MODE`, `HHTTPS_VERIFICATION_PEPPER` in identity.js L15) liegt ebenfalls verstreut in Modul-Toplevels.
**Auswirkung:** Eine Instanz mit gesetztem `RP_ID`/`ORIGIN`, aber ohne `BASE_URL`, verschickt Dashboard-Links auf hhttps.org; zwei Wahrheiten für denselben Konfigurationswert.
**Empfehlung:** Ein zentrales `config.js` (oder Export aus server.js) mit `BASE_URL`, `ORIGIN`, `RP_ID`; email.js importiert daraus statt `process.env` erneut zu lesen.

### [S3] [Wartbarkeit] server/server.js:L2413-3093 — Uneinheitliche Fehlerformate, Sprachen und Body-Handling zwischen den Identitäts-Routen
**Begründung:** (a) Sprache: deutsche Fehlertexte `'Verifikation fehlgeschlagen.'` (L2480), `'Passkey nicht registriert.'` (L2539), `'WebAuthn fehlgeschlagen.'` (L2553), `'Kein Refresh-Token'` (L2612), `'Zu viele E-Mail-Anfragen pro Session.'` (L2858), `'E-Mail-Fehler: '` (L2892), `'Session erstellt. Bitte E-Mail verifizieren.'` (L2705) neben englischen (`'Unknown or expired session.'` L2424, `'Session created. Verify with any method.'` L2746). (b) Form: teils Fehler-Codes (`email_verification_required`, `session_user_mismatch`, `email_context_missing`), teils Sätze, teils `e.message` roh (L2453, L2502, L2601, L2654, L3024); `/verify/github/start` antwortet bei fehlender Session mit `res.status(401).send('Invalid session.')` als Text (L3007, L3010), drei Zeilen später mit JSON (L3014). (c) Body: `req.body || {}` in L2421, L2463, L2678, L2722, L2941, aber nacktes `req.body` in L2509, L2534, L2607, L2848, L2990, L3090.
**Auswirkung:** Clients (Extension, SDK, Wallet) können Fehler nicht programmatisch unterscheiden; Übersetzung/Anzeige ist nicht möglich; Reviewer müssen jede Route einzeln lesen.
**Empfehlung:** Einheitliches `{ error: <snake_case_code>, detail?: <englischer Satz> }` über einen `sendError(res, status, code, detail)`-Helfer, Katalog der Codes dokumentieren; `req.body` einmalig in einer Middleware normalisieren.

### [S3] [Wartbarkeit] server/server.js:L2534-2539 — `/webauthn/auth/finish` liest `response.id` ohne Validierung außerhalb des try-Blocks
**Begründung:** `const { sessionId, response, … } = req.body;` (L2534), dann `db.challenges.get(sessionId)` und `db.credentials.get(response.id)` (L2538) vor dem `try` (L2541). Fehlt `response` im Body, wirft `response.id` einen TypeError, der nicht vom Handler abgefangen wird; Express antwortet mit der Default-HTML-500-Seite statt mit dem JSON-Format der Route. `/webauthn/register/finish` (L2463) prüft zwar `sessionId`, aber ebenfalls nicht `response`, hat den Zugriff aber im try (L2474).
**Auswirkung:** Unterschiedliches Fehlerbild je nach fehlendem Feld; kein Sicherheitsproblem, aber undefiniertes API-Verhalten und Log-Rauschen mit Stacktrace.
**Empfehlung:** Am Routen-Anfang `if (!sessionId || !response?.id) return res.status(400).json({ error: 'sessionId and response required' })`; idealerweise ein kleines Schema pro Route (z. B. `zod`/manuelle `requireFields`).

### [S3] [Wartbarkeit] server/server.js:L2692,L2733,L2850,L3010 — `session.verified` ist bei jeder Session `true`; die Gates darauf sind wirkungslos und der Name irreführend
**Begründung:** Alle drei `db.sessions.create`-Aufrufe im Server (L2579–2592, L2687–2695, L2728–2736) setzen `verified: true`; der Kommentar an L2733 sagt selbst „‚session exists‘ — NOT a trust statement“. Trotzdem prüfen `/email/send` (L2850) und `/verify/github/start` (L3010) (und AP4-Routen) `if (!session?.verified)` mit der Meldung „Invalid session“, was so aussieht, als gäbe es unverifizierte Sessions.
**Auswirkung:** Leser nehmen ein Gate an, das nichts filtert; echte Gates (`requireEmailVerified`) stehen daneben und werden leichter verwechselt. Die Spalte ist faktisch tot.
**Empfehlung:** Entweder das Feld entfernen (Migration, alle Prüfungen zu `if (!session)`), oder es umbenennen/bedeutungsvoll belegen (z. B. nur nach erster echter Methode setzen) und dann konsistent nutzen.

### [S3] [Wartbarkeit] server/email.js:L1-7 vs L62,L280,L743,L827 — Widersprüchliche „LEGACY“-Marker für den obligatorischen ersten Anmeldeschritt
**Begründung:** Der Datei-Header (L4–7) erklärt die E-Mail-Verifikation zum „MANDATORY first step of every sign-in (Phase 8, email-anchored identity)“; dieselbe Funktionalität ist an L62 („legacy flow“), L280 („LEGACY: User email verification (role declaration flow)“), L743 („legacy user flow“) und L827 („the legacy HHTTPS role declaration flow“) als Altlast markiert. Weitere veraltete Marker: L86–97 (Trust-Baseline 30, „.edu“ steht nicht in `DOMAIN_RULES`), Phase-Marker „Phase 3b“ (L11, L420), „Phase 8“ (L5).
**Auswirkung:** Ein Entwickler könnte den „legacy“-Pfad für entfernbar halten, obwohl er der zentrale Anmeldeweg ist; Phase-Nummern sind ohne Projektkenntnis nicht auflösbar.
**Empfehlung:** „LEGACY“-Marker entfernen bzw. durch die tatsächliche Rolle ersetzen („primary sign-in verification“), Phase-Marker durch Verweise auf Spec-Dokumente (docs/specs/…) ersetzen.

### [S3] [Wartbarkeit] server/email.js:L435-741 und server/server.js:L3056-3087 — Module ohne Tests: Plattform-/Admin-Mails, `classifyDomain`, GitHub-Return-Seite, `/session/email/start`
**Begründung:** `grep` über `server/test/**` findet keine Tests für `sendPlatformRegistrationEmail`, `sendPlatformVerifiedEmail`, `sendPlatformRejectedEmail`, `sendAdminPlatformNotification`, `sendPrivacyPassVerification`, `classifyDomain` (L99–115; treibt `expectedLevel`/`trustBonus`), `renderGithubReturnPage` (server.js L3056) und die Route `/hhttps/session/email/start`. `email-template.test.mjs` deckt nur `renderVerificationEmail` ab, `identity.test.mjs` deckt identity.js gut ab; `/verify/github/callback` wird nur indirekt über den Config-Check (503) berührt.
**Auswirkung:** Änderungen an den Domain-Regeln (z. B. Duplikat `.uni-` L70/L71, `includes` statt `endsWith` für Universitäten L105) oder am Mail-Shell bleiben ungetestet; die Renderer sind bereits reine Funktionen und wären billig zu testen.
**Empfehlung:** Unit-Tests für `classifyDomain` (je Kategorie + Negativfall) und für die vier Plattform-Mail-Renderer (Escaping von `platformName`/`reason`, Subject); dafür Render und Send trennen wie bei `renderVerificationEmail`.

### [S4] [Wartbarkeit] server/server.js:L2451,L2522,L2524,L2590,L2592,L2624,L2695,L2736,L2857,L2880 — Magic Numbers/Strings für TTLs, Trust-Seeds und Limits ohne benannte Konstante
**Begründung:** Challenge-TTLs `120_000` (L2451), `60_000`/`90_000` (L2522/L2524), Session-TTLs `1800_000` (L2592) und `900_000` (L2695, L2736), Trust-Seeds `50` (L2590; = `HUMAN_CONFIRMED_THRESHOLD` aus roles.js L154, importiert an L41, aber laut ESLint ungenutzt) und `20` (L2624), Send-Limit `> 3` (L2857), `expiresIn: '15 Minuten'` (L2880) sowie in email.js die hartkodierten „15 minutes / 15 Minuten“ an L323, L349–350, L363–364, L751, L781, L851, L854, L867–868 — obwohl `EMAIL_VERIFICATION_TTL_MS` (L45) als „single source of truth“ existiert. Außerdem `'0.5.0'` als Literal an L2646 (und 30 weiteren Stellen der Datei).
**Auswirkung:** TTL-Änderungen erfordern Suchen über Code und Mailtexte; der Trust-Seed 50 kann von `HUMAN_CONFIRMED_THRESHOLD` abdriften.
**Empfehlung:** `SESSION_TTL_MS`, `BOOTSTRAP_SESSION_TTL_MS`, `REG_CHALLENGE_TTL_MS`, `AUTH_CHALLENGE_TTL_MS`, `MAX_EMAILS_PER_SESSION`, `PROTOCOL_VERSION` als Konstanten; Minuten-Angabe in Mails aus `EMAIL_VERIFICATION_TTL_MS / 60000` ableiten; `HUMAN_CONFIRMED_THRESHOLD` an L2590 verwenden.

### [S4] [Wartbarkeit] server/server.js:L2636 — `tokenSurface` wird mit einem Pseudo-Session-Objekt aufgerufen
**Begründung:** Die Signatur `tokenSurface(session, v, pseudonym = session?.pseudonym)` (L2400) suggeriert eine DB-Session; `/token/refresh` übergibt `{ emailDomain: domainVal }` (L2636), weil nur `session.emailDomain` gelesen wird. Die anderen Aufrufer (L3176, L3555) übergeben echte Sessions.
**Auswirkung:** Wer `tokenSurface` um weitere Session-Felder erweitert, bricht den Refresh-Pfad still (Felder undefined).
**Empfehlung:** Signatur auf explizite Eingaben umstellen: `tokenSurface({ methods, emailDomain, pseudonym })`.

### [S4] [Wartbarkeit] server/server.js:L2697,L2738 — `stats.increment('verifications')` beim reinen Session-Bootstrap zählt keine Verifikation
**Begründung:** Beide Bootstrap-Routen erhöhen den Zähler `verifications`, obwohl noch keine Methode bestätigt ist (Trust 0); derselbe Zähler wird bei Passkey-Registrierung (L2496) und -Login (L2593) erhöht. `/hhttps/stats` (AP5) gibt diesen Wert öffentlich aus.
**Auswirkung:** Die Kennzahl ist doppeldeutig (Sessions + Passkey-Events) und nicht mehr als „Verifikationen“ interpretierbar.
**Empfehlung:** Eigenen Zähler `sessions_started` oder Inkrement erst in `bindSessionToEmailAnchor`/nach erfolgreicher Methode.

### [S4] [Wartbarkeit] server/server.js:L2779-2790 — JSDoc von `bindSessionToEmailAnchor` hängt an `anchorConflict`
**Begründung:** Der Kommentar `@returns {{ userId, pseudonym, created, methods, trust }} … Priority for the pseudonym …` (L2779–2784) steht direkt über `function anchorConflict(code)` (L2785), beschreibt aber `bindSessionToEmailAnchor` (L2792).
**Auswirkung:** IDE-Hover/Doku-Tools zeigen die Rückgabebeschreibung an der falschen Funktion.
**Empfehlung:** Block vor L2792 verschieben; für `anchorConflict` eine eigene Einzeiler-Doku.

### [S4] [Wartbarkeit] server/email.js:L810-818 vs server/server.js:L2370 — `escapeHtml` doppelt implementiert
**Begründung:** Beide Dateien definieren eine byte-identische `escapeHtml` (5 Replace-Aufrufe). `renderGithubReturnPage` (server.js L3077) nutzt die server.js-Variante, alle Mail-Renderer die email.js-Variante.
**Auswirkung:** Eine Härtung (z. B. Escaping von `` ` `` oder `/`) muss an zwei Stellen erfolgen.
**Empfehlung:** Nach `identity.js` oder ein kleines `html.js` exportieren und aus beiden Dateien importieren.

### [S4] [Wartbarkeit] server/server.js:L535,L612,L2573; server/email.js:L159,L249,L511,L573 — ESLint-Warnungen (no-unused-vars, no-useless-escape) im AP3-Bereich
**Begründung:** Aus `docs/review/ap/eslint-output.txt`: server.js L535 `token` in `setHHTPPS` wird destrukturiert, aber (laut NOTE L565–571 absichtlich) nicht gesetzt; L612 unnötiges `\-` im Regex; L2573 `catch (e)` ungenutzt. email.js L159 `catch(e)` ungenutzt; L249 Parameter `title` von `emailShell` wird nie gerendert — alle Mails haben dadurch keinen `<title>`; L511 `homepageUrl` in `sendPlatformVerifiedEmail` ungenutzt (Aufrufer L4577 übergibt ihn); L573 `reasonDe` berechnet, aber `reasonEn` auch im deutschen Block verwendet (L579 nur einmal eingesetzt).
**Auswirkung:** Rauschen im Lint-Lauf verdeckt neue Warnungen; fehlender `<title>` verschlechtert Mail-Client-Darstellung.
**Empfehlung:** `token` aus der Destrukturierung entfernen, `catch {}` ohne Binding, `title` als `<title>` rendern, `homepageUrl` und `reasonDe` entweder verwenden oder streichen.

---

## Zusammenfassung

Findings: S1: 0 · S2: 0 · S3: 12 · S4: 6 (gesamt 18).

Der AP3-Code ist in identity.js sauber (reine Funktionen, gut getestet) und die neueren Teile (bindSessionToEmailAnchor, resolvePasskeySession) sind nachvollziehbar kommentiert. Die Wartbarkeitsmängel konzentrieren sich auf Duplikate, die nachweislich schon auseinanderdriften (zwei Bootstrap-Routen, zwei Bestätigungspfade, sechs Transport-Fallbacks mit nur einem fail-closed, handgeschriebener Refresh-Check neben `checkTokenValid`), auf veraltete Kommentare mit falschen Zahlen (Trust 30 vs. 20/0, Rate-Limit 5 vs. 30, „LEGACY“ für den Pflichtpfad) sowie auf ein uneinheitliches Fehler-/Sprach-Format über die Routen hinweg. Mit einem gemeinsamen Mail-Sende-Helfer, einem zentralen Fehlerformat und dem Zusammenlegen der beiden Bestätigungspfade ließe sich der Großteil mit geringem Risiko beheben.

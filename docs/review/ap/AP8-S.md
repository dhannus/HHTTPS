# AP8 — Sicherheit

Geprüfte Dateien: server/public/index.html, server/public/email-verify.html, server/public/workload.html, server/public/email-patch.js, server/public/.well-known/hhttps-role-assurance.json; sites/hhttps.html, sites/iamhmn.html, sites/spec.html; extension/manifest.json, extension/background.js, extension/content-universal.js, extension/content-issuer.js, extension/popup.js, extension/popup.html; server/test/unit/signin-page.test.mjs, server/test/unit/legacy-pages.test.mjs, server/test/e2e/signin.e2e.test.mjs (zum Kontext gelesen: server/server.js L392-410 CSP, L1077-1097 `/hhttps/signatures`, L2898-2924 `/hhttps/email/verify`).

### [S1] [Sicherheit] server/public/email-verify.html:L71,L97-99,L111-113 — DOM-XSS auf der IdP-Origin: URL-Parameter `domain`, `level`, `reason` landen ungeprüft in `innerHTML`.
**Begründung:** Die Seite wird über `express.static` (server.js L519) unter `https://hhttps.org/email-verify.html` ausgeliefert. `show()` setzt `body.innerHTML = extra` (L71); `extra` wird aus `params.get('domain')` (L87/L98), `levelLabels[level]||level` (L99) und `decodeURIComponent(params.get('reason'))` (L113) per Template-String gebaut, ohne Escaping. Die CSP erlaubt `script-src 'unsafe-inline'` (server.js L396), also läuft z. B. `?token=x&session=y&email_verify=error&reason=%3Cimg%20src%3Dx%20onerror%3D...%3E`. Die Seite ist ein verwaistes Legacy-Artefakt (der Server leitet nach `/?email_verify=…` auf index.html um, L2898ff.), bleibt aber erreichbar.
**Auswirkung:** Skript-Ausführung auf `hhttps.org`. Dort liegen in `localStorage['hhttps_identity']` Access- **und Refresh-Token** (index.html L807); die Extension liest denselben Schlüssel (content-issuer.js L36). Ein Angreifer mit Link an ein Opfer kann Identität + Refresh-Token per `location=` exfiltrieren (CSP `connect-src 'self'` verhindert Top-Level-Navigation nicht) und beliebige Signaturen im Namen des Opfers erstellen (`/hhttps/signatures` akzeptiert das Token als Bearer, server.js L1077).
**Empfehlung:** Datei entfernen (wird vom Server nicht mehr angesteuert) oder alle Parameter per `textContent`/Escaping rendern und `level` gegen eine Whitelist prüfen; zusätzlich `unsafe-inline` aus der CSP durch Nonces ersetzen.

### [S2] [Sicherheit] extension/popup.js:L176-184,L279 — „Signatur-Snippet“ kopiert das vollständige Bearer-Token in die Zwischenablage zum öffentlichen Einfügen.
**Begründung:** `buildSnippet()` gibt `[HHTTPS ✓ … · ${ident.token}]` zurück (L183); `doCopySnippet()` (L279) legt genau das in die Zwischenablage, mit der UI-Absicht, es „in jedes Textfeld“ zu pasten (Kommentar L168-170). `ident.token` ist dasselbe Access-Token, das `background.js` L387 als `HHTTPS-Token`-Header an `/hhttps/signatures` sendet und das `/hhttps/check` als Identitätsnachweis akzeptiert.
**Auswirkung:** Jeder Leser eines Forums-/Mail-Beitrags mit dem Snippet besitzt bis zum Ablauf ein gültiges Bearer-Token des Nutzers und kann damit Signatur-Slugs erzeugen bzw. sich gegenüber Plattformen als dieser Mensch ausgeben. Das Slug-Verfahren (`#hhttps:s:`) existiert genau, um das zu vermeiden; das Legacy-Snippet unterläuft es.
**Empfehlung:** Snippet-Funktion entfernen oder nur einen serverseitig erzeugten, domain-gebundenen Slug einfügen; niemals das Access-Token in Klartext-Content exportieren.

### [S3] [Sicherheit] sites/hhttps.html:L1232-1250 — Open Redirect ohne Interaktion: `?returnTo=<beliebige URL>` leitet eingeloggte Nutzer sofort weiter.
**Begründung:** `showOAuthReturnBanner()` liest `returnTo` (L1235), prüft nur `new URL()`-Parsebarkeit (L1237) und setzt bei vorhandener Identität in `localStorage` direkt `window.location.href = returnTo` (L1247) — ohne Protokoll-/Host-Prüfung, auch `javascript:`-URLs werden von `new URL()` akzeptiert. Der zweite Pfad L1612-1625 sowie server/public/index.html L812-826 erlauben nach Login jede `https:`-URL (Kommentar L1616-1618: „Phase 3b will tighten this“).
**Auswirkung:** Phishing-Links der Form `https://hhttps.org/?returnTo=https://evil.example` wirken vertrauenswürdig und landen ohne Klick beim Angreifer; im Fall `javascript:`-URL auf L1247 sogar Skriptausführung in der Origin der Seite.
**Empfehlung:** `returnTo` gegen die registrierten `oauth_clients`-Redirect-URIs bzw. gegen `same-origin` prüfen; mindestens `protocol === 'https:'` auch in L1237-1247 erzwingen und `javascript:`/`data:` ausschließen.

### [S3] [Sicherheit] server/public/index.html:L1034-1052 — `?login_hint=<E-Mail>` löst beim bloßen Öffnen des Links automatisch einen Code-Versand an eine fremde Adresse aus.
**Begründung:** `handleLoginHint()` nimmt `login_hint` aus der URL, füllt das Feld und ruft ohne Nutzeraktion `emailStart()` (L1051) → `POST /hhttps/email/send` an die übergebene Adresse. Der einzige Schutz ist das IP-Rate-Limit `limit.email` (30/h pro IP, server.js L428), das bei verteilten Klicks (Link in Foren/Mail) nicht greift. E2E-Test signin.e2e.test.mjs L152 dokumentiert das Verhalten als gewollt.
**Auswirkung:** E-Mail-Bombing/Spam mit Absender hhttps.org gegen beliebige Adressen; Reputationsschaden für den Mailversand (Blacklisting), Belästigung der Opfer.
**Empfehlung:** Den Versand nur nach explizitem Klick auslösen (Feld vorbefüllen, Button fokussieren) oder `login_hint` nur akzeptieren, wenn `returnTo` auf einen registrierten OAuth-Client zeigt und der Consent-Flow einen kurzlebigen, signierten Parameter mitgibt.

### [S3] [Sicherheit] extension/popup.js:L222-227 (mit content-universal.js L57-68,L881-882) — Seitengesteuerte `<meta name="hhttps-*">`-Tags werden ungeprüft als „HHTTPS aktiv / verifiziert“ angezeigt.
**Begründung:** `readMetaTags()` liest `hhttps-status`, `hhttps-human`, `hhttps-role` aus dem DOM jeder beliebigen Seite und meldet sie als `PAGE_STATE`; das Popup zeigt bei `status === 'verified'` das Häkchen und „HHTTPS aktiv · <role>“ (L223-226). Es findet keinerlei kryptografische oder serverseitige Prüfung statt; die Werte stammen vollständig aus dem Seiteninhalt (bzw. aus vom Server frei setzbaren Response-Headern, L844-876).
**Auswirkung:** Jede Website kann sich gegenüber Extension-Nutzern als „HHTTPS-verifiziert“ mit beliebiger Rolle ausgeben (Vertrauenssiegel-Spoofing), was den Zweck des Trust-Indikators aushebelt.
**Empfehlung:** Seitenstatus nur anzeigen, wenn er durch ein serverseitig verifizierbares Artefakt belegt ist (z. B. signierter Slug/Token, den die Extension gegen `hhttps.org` prüft), sonst neutral „Seite behauptet HHTTPS-Unterstützung“ darstellen.

### [S3] [Sicherheit] server/public/index.html:L807 (analog sites/hhttps.html:L1593) — Refresh-Token im `localStorage` der IdP-Origin.
**Begründung:** `publishIdentity()` persistiert `refreshToken` und `refreshExpiresAt` zusammen mit dem Access-Token in `localStorage['hhttps_identity']`; `restoreIdentity()` (L962-990) nutzt das Refresh-Token stateless per `POST /hhttps/token/refresh`. `localStorage` ist für jedes Skript der Origin lesbar; ein HttpOnly-Cookie-Pfad existiert bereits (server.js L445-452).
**Auswirkung:** Jede XSS auf hhttps.org (siehe S1 oben) oder ein kompromittiertes Drittskript (`script-src` erlaubt `unpkg.com`, server.js L396) liefert langlebige Sitzungsfortsetzung statt nur ein kurzlebiges Access-Token.
**Empfehlung:** Refresh-Token ausschließlich als HttpOnly-Cookie halten und die Verlängerung serverseitig über den bestehenden Cookie-Pfad durchführen; im `localStorage` höchstens das kurzlebige Access-Token belassen.

### [S4] [Sicherheit] extension/manifest.json:L54,L57 — Nicht genutzte Berechtigungen `activeTab` und `scripting`.
**Begründung:** Weder `chrome.scripting` noch ein `activeTab`-abhängiger Aufruf kommen in background.js/popup.js/content-*.js vor (grep leer); alle Injektionen laufen über statische `content_scripts`.
**Auswirkung:** Größere Angriffsfläche und abschreckender Install-Prompt ohne Nutzen; ein Bug/Kompromittierung im Extension-Code hätte mehr Rechte als nötig.
**Empfehlung:** Beide Permissions entfernen (Least Privilege).

### [S4] [Sicherheit] extension/content-universal.js:L113,L177-183,L484 — Debug-`console.log` auf jeder besuchten Seite inkl. iframe-`src` und gefundenen Slugs.
**Begründung:** Der Universal-Content-Script läuft mit `<all_urls>`, `all_frames` und `match_about_blank` (manifest L42-49) und loggt Slug-Listen und iframe-Metadaten (`iframeSrc`, `bodyLen`) in die Seitenkonsole.
**Auswirkung:** Informationsabfluss in Konsolen/Fehlerreporting-Tools fremder Seiten (z. B. Webmail-iframe-URLs), Fingerprinting der installierten Extension.
**Empfehlung:** Logs hinter ein Debug-Flag legen oder entfernen.

## Zusammenfassung

S1: 1 · S2: 1 · S3: 4 · S4: 2

Der gravierendste Punkt ist eine verwaiste Legacy-Seite (`email-verify.html`), die auf der IdP-Origin DOM-XSS aus URL-Parametern erlaubt — kombiniert mit `unsafe-inline`-CSP und Access-/Refresh-Token im `localStorage` ergibt das einen realen Identitätsdiebstahl-Pfad. Die Extension ist im Kern solide (Origin-Check beim `postMessage`, Escaping der meisten Server-Daten, enge `host_permissions`), leakt aber per „Snippet“ das Bearer-Token und vertraut seitengesteuerten Meta-Tags als Vertrauenssiegel. Die `returnTo`-Open-Redirects und der automatische Code-Versand via `login_hint` sind bekannte, aber noch nicht geschlossene Design-Lücken.

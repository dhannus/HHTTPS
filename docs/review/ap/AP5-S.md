# AP5 — Sicherheit

Geprüfte Dateien: server/server.js L3768–4829 (machine/*, webhooks*, apexDomain*, authenticatedUser/requireUser/requireAdmin/requirePortalUser, isValidRedirectUri, generateClientId, whoami, developers/*, admin/*, stats, serializeClient*, renderSimplePage, main), server/workload-identity.js, server/pop-verify.js, server/wp-plugin-registration.js, developers/index.html, developers/register.html, developers/dashboard.html, developers/admin.html, developers/assets/portal.js, developers/assets/portal.css. Zum Verständnis gelesen (keine Findings dort): server/webhooks.js, server/db.js (machineOperators, webhooks, oauthClients, admins, challenges), server/keys.js (signToken/verifyToken), server/server.js L76–130, L386–480, L533–560, L607–625, L702–712, L1809–1830, L3678–3700, scripts/deploy-all.sh (nginx-Block).

### [S2] [Sicherheit] server/server.js:L3889-3910 — Webhook-Registrierung, -Auflistung und -Löschung sind vollständig unauthentifiziert; GET liefert alle HMAC-Secrets aus
**Begründung:** Die drei Routen `GET/POST /hhttps/webhooks` und `DELETE /hhttps/webhooks/:id` haben nur `limit.webhooks` (20/h pro IP), aber weder `requireUser` noch `requireAdmin` noch einen Besitzer-Bezug. `GET` gibt `await listWebhooks()` unverändert zurück; `db.webhooks.list()` (db.js L657-669) enthält `secret: r.secret`. `DELETE` löscht jede beliebige `webhook_id` ohne Eigentümer-Prüfung.
**Auswirkung:** Jeder Internetteilnehmer kann (a) alle registrierten Webhooks fremder Betreiber inkl. Ziel-URL und HMAC-Secret auslesen, damit gültig signierte gefälschte Events (`token.issued`, `token.revoked`, `role.declared`) an fremde Endpunkte senden, (b) fremde Webhooks löschen (Denial of Service für Integrationen), (c) beliebig viele eigene Webhooks anlegen, die bei jedem Token-Ereignis des Issuers beliefert werden.
**Empfehlung:** Routen mit `requireUser`/`requireAdmin` schützen, Webhooks an eine Owner-ID (User oder Operator) binden und `list`/`delete` darauf filtern; `secret` nur einmalig bei der Registrierung zurückgeben (wie beim Machine-API-Key) und in der Liste nie mehr ausliefern.

### [S2] [Sicherheit] server/wp-plugin-registration.js:L103-107 — Rate-Limit der Plugin-Registrierung ist per `X-Forwarded-For` trivial umgehbar (unbegrenzter E-Mail-Versand + DB-Wachstum)
**Begründung:** `const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip` nimmt den ERSTEN Eintrag des Headers. nginx ist mit `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` konfiguriert (scripts/deploy-all.sh L289/298), d. h. der vom Client gesendete Header wird nur ergänzt, nicht ersetzt — der erste Eintrag ist frei wählbar. Express ist mit `trust proxy 1` korrekt konfiguriert, `req.ip` wäre die richtige Quelle. `rateLimited()` (L82-88) ist zudem eine unbegrenzt wachsende `Map`. Der Endpunkt hat keinerlei Authentifizierung und sendet an ein beliebiges `contact_email` eine Bestätigungs-E-Mail mit frei wählbarem `site_name`/`homepage_url` (L164-176) und legt pro Aufruf einen `oauth_clients`-Datensatz an (L142-155).
**Auswirkung:** Ein Angreifer setzt pro Request einen anderen XFF-Wert und umgeht das 5/h-Limit; Ergebnis: Mail-Bombing/Phishing beliebiger Adressen mit Absender des Issuers, unbegrenzte `oauth_clients`-Zeilen und speicherseitig unbegrenztes Wachstum von `regHits`.
**Empfehlung:** `req.ip` verwenden (trust proxy ist gesetzt) oder den vorhandenen `express-rate-limit`-Limiter (`limit.email`) an die Route hängen; `regHits` entfernen oder mit Ablauf/Obergrenze versehen.

### [S3] [Sicherheit] server/server.js:L3893-3904 — Webhook-Ziel-URL wird ohne Schema-/Host-Restriktion akzeptiert (blindes SSRF vom Issuer aus)
**Begründung:** `registerWebhook({ url, events, secret })` prüft nur `new URL(url)` (webhooks.js L17) — keine Einschränkung auf `https:`, keine Sperre für Loopback/Link-Local/private Netze. Bei jedem Event POSTet der Server mit `fetch(wh.url, …)` (webhooks.js L60-70) inkl. dreifacher Wiederholung an diese URL. In Kombination mit der fehlenden Authentifizierung (Finding oben) kann jeder diese Requests auslösen.
**Auswirkung:** Der Issuer kann als Proxy für POST-Requests gegen interne Dienste (localhost:3000, Metadaten-Endpunkte, interne HTTP-Dienste im Deployment-Netz) missbraucht werden; Antworten sind nicht sichtbar (blind), aber Status/Erreichbarkeit lässt sich über `deliveries`/`failures` in `GET /hhttps/webhooks` ablesen. Zusätzlich Amplifikation gegen Dritte (3 Versuche je Webhook je Event).
**Empfehlung:** Nur `https:` zulassen, Hostname auflösen und Loopback-, Link-Local-, private und ULA-Adressen ablehnen (auch nach Redirects: `redirect: 'manual'`), Anzahl Webhooks pro Owner begrenzen.

### [S3] [Sicherheit] server/pop-verify.js:L83 und L136 — PoP-Challenge und PoP-gated Endpunkt ignorieren die Revocation-Liste
**Begründung:** `verifyPoP()` (L83) und `/hhttps/pop/challenge` (L136) rufen nur `verifyToken(token)` (reine Signatur-/exp-Prüfung, keys.js L164-173) auf, nicht `checkTokenValid()` (server.js L702-711), das `db.revokedTokens.has(jti)` und `db.tokens.exists(jti)` prüft. Ein per `/hhttps/revoke` (server.js L3678) widerrufenes Maschinen-Token bleibt daher bis zum JWT-`exp` (24 h) für Challenge-Ausgabe und PoP-Verifikation gültig.
**Auswirkung:** Genau der Fall, für den PoP gedacht ist (kompromittierter Operator → Token widerrufen), wird an der PoP-Grenze nicht durchgesetzt; der Besitzer von Token + Schlüssel passiert `/hhttps/pop/demo` und jeden künftigen mit `verifyPoP` geschützten Endpunkt weiter.
**Empfehlung:** `mountPopVerify` zusätzlich `checkTokenValid` übergeben und in `verifyPoP`/`challenge` statt `verifyToken` verwenden (async, Fehler → `token_invalid`).

### [S3] [Sicherheit] server/server.js:L4302-4358 — PATCH auf Clients ist in jedem Status erlaubt, auch `pending_review`/`verified`; Admin prüft und genehmigt veränderbare Daten (TOCTOU)
**Begründung:** Der PATCH-Handler prüft nur Ownership (L4306-4309) und Feldformate, nie `client.verification_status`. `updateMetadata` (db.js L946-958) schreibt `name`, `description`, `redirect_uris`, `logo_url`, `impressum_url` und erhält den Status ausdrücklich. Das Dashboard blendet „Bearbeiten“ in `pending_review` lediglich aus (dashboard.html L268), die API nicht. Der Admin-Queue-Eintrag (`serializeClientForAdmin`) zeigt den Stand zum Zeitpunkt des Ladens.
**Auswirkung:** Ein Owner reicht eine harmlose Plattform ein, ändert nach Klick auf „Approve“ (oder kurz davor) Name, Beschreibung, Impressum und Redirect-URIs; die Prüfung des Admins bezieht sich auf andere Daten als die, die später als „verified“ mit Vertrauenssiegel im Consent-Screen erscheinen. Auch bei `verified` sind Änderungen von Redirect-URIs/Impressum ohne Rückfall in `unverified` möglich.
**Empfehlung:** PATCH in `pending_review` mit 409 ablehnen; bei `verified` sicherheitsrelevante Felder (`redirect_uris`, `impressum_url`, `name`) nur mit Rückfall auf `unverified` bzw. neuer Review zulassen; `adminApprove` optional mit einem vom Admin gesehenen Content-Hash absichern.

### [S3] [Sicherheit] server/server.js:L3970-3982 — `authenticatedUser` akzeptiert Maschinen-Token und bildet für alle Operatoren die gemeinsame `userId: 'machine'`
**Begründung:** Maschinen-Token (L3853-3866) tragen `sub: 'machine'` ohne `uid`/`userId` und werden in `db.tokens` angelegt (L3868-3870), passieren also `checkTokenValid`. `authenticatedUser` setzt `userId: d.uid || d.userId || d.sub` (L3976) → `'machine'` für jeden Operator; `actorType` wird zwar mitgeführt, aber von `requireUser`/`requirePortalUser`/`requireAdmin` nicht ausgewertet. Aktuell scheitern Maschinen an `requirePortalUser` nur, weil `verified_methods` fehlt und `admins` keinen Eintrag `'machine'` hat.
**Auswirkung:** Kein unmittelbarer Bypass; aber ein einziger Admin-Grant auf die ID `machine` (z. B. durch das in `/hhttps/whoami` vorgeschlagene Kommando, das für ein Maschinen-Token `--grant machine` ausgibt, L4114-4116) würde ALLEN registrierten Bots Admin-Rechte im Portal geben, und jede künftige Route, die nur `requireUser` nutzt, behandelt alle Bots als denselben Nutzer.
**Empfehlung:** In `requireUser` (oder `authenticatedUser`) `actorType === 'bot'`/`sub === 'machine'` mit 403 ablehnen; `/hhttps/whoami` für Maschinen-Token kein `grant_admin_command` ausgeben.

### [S3] [Sicherheit] server/workload-identity.js:L173 und L197 — OIDC-Audience-Prüfung entfällt, wenn ein Binding ohne `expected_audience` angelegt wird
**Begründung:** `bindWorkload` speichert `expectedAudience || null` (L197); `verifyOidcToken` übergibt `audience: expectedAudience` an `jwt.verify` (L173). Bei `undefined`/`null` prüft jsonwebtoken `aud` überhaupt nicht. Ein GitHub-Actions-/GitLab-/Buildkite-Token, das das Repository für einen ganz anderen Dienst (andere `aud`) ausgestellt hat, würde damit akzeptiert. Hinweis: Das Modul ist derzeit in keiner Route gemountet (kein Import in server.js), also heute nicht erreichbar.
**Auswirkung:** Sobald die Exchange-Route aktiviert wird: Token-Replay von CI-OIDC-Tokens, die für Dritte (z. B. Cloud-Provider) bestimmt sind, gegen HHTTPS → Maschinen-Token für ein fremdes Repository-Binding ohne Wissen des Repos.
**Empfehlung:** `expected_audience` in `bindWorkload` verpflichtend machen (Default: `BASE_URL`), in `verifyOidcToken` bei fehlender Audience mit Fehler abbrechen.

### [S3] [Sicherheit] server/server.js:L4125-4126 und L4311-4358 — `logo_url` und `impressum_url` werden serverseitig nicht validiert (beliebiger String/Schema)
**Begründung:** Bei POST (L4125) und PATCH (L4311) werden `impressum_url` und `logo_url` unverändert an `createDraft`/`updateMetadata` durchgereicht; nur das Dashboard prüft clientseitig `^https?://`. `impressum_url` wird im Owner-Dashboard als `href` gerendert (dashboard.html L301, escapeHtml schützt nicht vor `javascript:`-Schema), `logo_url` im Consent-Screen als `<img src>` (server.js L2125) — dort durch CSP `img-src 'self' data:` effektiv geblockt, aber `data:`-URIs beliebiger Größe wären erlaubt (Body-Limit 2 MB, keine Längenprüfung).
**Auswirkung:** Self-XSS im eigenen Dashboard (gering); ein Admin, der die Impressum-URL aus der Admin-Liste kopiert/öffnet, kann auf ein `javascript:`/Datei-Schema stoßen; `impressum_url` ist Pflichtkriterium für die Freigabe und muss daher belastbar eine https-URL sein.
**Empfehlung:** Beide Felder mit `new URL()` parsen, nur `https:` (Impressum) bzw. `https:`/`data:image/*` mit Längenlimit (Logo) zulassen, sonst 400.

### [S4] [Sicherheit] server/server.js:L4184, L4415, L4513, L4526 — Interne Fehlermeldungen (PostgreSQL, DNS, Mailer) werden 1:1 an den Client zurückgegeben
**Begründung:** `message: err.message` bei `creation_failed` (DB-Fehler inkl. Spalten-/Constraint-Namen), `token_refresh_failed`, `send_failed` (SMTP-Fehlertext inkl. Host) und `err.code || err.message` beim DNS-Lookup.
**Auswirkung:** Information Disclosure über Schema, SMTP-Konfiguration und Resolver-Interna an authentifizierte Portal-Nutzer.
**Empfehlung:** Generische Fehlercodes ausgeben, Details nur ins Server-Log.

### [S4] [Sicherheit] server/server.js:L4114-4116 — `/hhttps/whoami` gibt einen absoluten Server-Dateipfad an jeden Token-Inhaber aus
**Begründung:** `grant_admin_command: '/var/www/hhttps/scripts/make-admin.sh --grant <uid> …'` wird jedem authentifizierten Nutzer (auch Maschinen-Token) geliefert.
**Auswirkung:** Preisgabe von Deployment-Pfad und Admin-Tooling-Namen; Komfortfunktion, die nur für Operatoren relevant ist.
**Empfehlung:** Nur ausgeben, wenn `admins`-Tabelle leer ist (Bootstrap) oder der Aufrufer bereits Admin ist; sonst weglassen.

### [S4] [Sicherheit] server/server.js:L3847 — API-Key-Vergleich nicht timing-sicher
**Begründung:** `if (keyHash !== op.api_key_hash)` vergleicht zwei Hex-Hashes mit `!==`. Da vorher SHA-256 auf den Klartext angewendet wird, leakt ein Timing-Kanal nur Bytes des Hashes, nicht des Keys; praktisch nicht ausnutzbar, aber Abweichung von der Konvention (`crypto.timingSafeEqual`).
**Auswirkung:** Keine reale Ausnutzbarkeit; Stilfrage/Defense-in-depth.
**Empfehlung:** `crypto.timingSafeEqual(Buffer.from(keyHash,'hex'), Buffer.from(op.api_key_hash,'hex'))`.

### [S4] [Sicherheit] server/server.js:L4132-4135 und server/wp-plugin-registration.js:L116-120 — Fehlermeldung verspricht „HTTPS URL“, akzeptiert wird aber jede parsebare Host-Angabe
**Begründung:** `apexDomainFromUrl` (server.js L3927-3936, wp-plugin L36-49) akzeptiert `http://…` und sogar nackte Hostnamen; die 400-Meldung lautet dennoch `homepage_url must be a valid HTTPS URL`. Die Homepage wird im Consent-Screen und in der Bestätigungs-Mail als Link ausgegeben.
**Auswirkung:** Verifizierte Plattformen mit `http://`-Homepage sind möglich; Abweichung Doku/Verhalten.
**Empfehlung:** `new URL(homepage_url).protocol === 'https:'` erzwingen.

## Zusammenfassung

Findings: S1: 0 · S2: 2 · S3: 6 · S4: 4 (gesamt 12).

Die Portal-/Admin-Routen sind sauber gebaut (konsequente Ownership-Prüfung `owner_user_id === u.userId`, Admin-Check per DB, parametrisierte SQL, Escaping in allen gerenderten Seiten, PKCE/State im Portal-Login, keine cookie-basierten POSTs). Die zwei gewichtigen Schwachstellen liegen an den Rändern: Die Webhook-API hat gar keine Authentifizierung (Secrets fremder Betreiber lesbar, Löschung, SSRF-Vektor), und die WordPress-Plugin-Registrierung liest die Client-IP aus dem fälschbaren `X-Forwarded-For`-Kopf, womit ihr einziger Missbrauchsschutz entfällt. Dazu kommen Konsistenzlücken (PoP ohne Revocation-Check, PATCH während der Review, Maschinen-Token als Portal-„User“), die heute nicht direkt ausnutzbar sind, aber mit der nächsten Route zum Bypass werden können.

# AP5 — Wartbarkeit

Geprüfte Dateien: server/server.js L3768-4829 (/hhttps/machine/*, /hhttps/webhooks*, apexDomain*, authenticatedUser, requireUser, requireAdmin, requirePortalUser, isValidRedirectUri, generateClientId, /hhttps/whoami, /hhttps/developers/*, /hhttps/admin/*, /hhttps/stats, serializeClient*, renderSimplePage, main()); server/workload-identity.js; server/pop-verify.js; server/wp-plugin-registration.js; developers/index.html; developers/register.html; developers/dashboard.html; developers/admin.html; developers/assets/portal.js; developers/assets/portal.css. Zum Verständnis gelesen (keine Findings): server/db.js (oauthClients), server/webhooks.js, server/sql/migration-phase-6-workload-identity.sql, server/test/integration/acceptance.test.mjs, sites/spec.html, docs/spec.md.

Stand: `main` @ `bf0a82b`; Zeilennummern per `grep -n`/`sed -n` verifiziert.

---

### [S3] [Wartbarkeit] server/workload-identity.js:L1-260 — Komplettes Modul ist toter Code: wird nirgends importiert, es gibt keine Route dafür

**Begründung:** `grep -rn "workload-identity\|bindWorkload\|verifyOidcToken\|findBinding"` über das Repo (ohne node_modules) trifft ausschließlich das Modul selbst und den CHANGELOG. `server/server.js` importiert es nicht (Import-Block L1-71), keine Route unter `/hhttps/workload/*` oder `/hhttps/machine/exchange` existiert. Das Modul enthält gleichwohl 260 Zeilen produktiven Codes inkl. Netzwerkzugriff (`fetch(cfg.jwksUri)` L126), JWKS-Cache, RS256-Verifikation und fünf DB-Funktionen gegen die Tabelle `workload_identities`, die `migration-phase-6-workload-identity.sql` weiterhin anlegt.
**Auswirkung:** Ungetesteter, nicht erreichbarer Code mit Sicherheitsrelevanz (OIDC-Token-Verifikation) driftet unbemerkt von den Providern (GitHub/GitLab/Buildkite-Claims) ab; die Migration erzeugt eine leere Tabelle mit Index in jeder Installation; Leser des Codes (und das Inventar) gehen von einer existierenden Workload-Federation aus, die es zur Laufzeit nicht gibt.
**Empfehlung:** Entweder die geplanten Routen (`POST /hhttps/machine/workload/bind|exchange|unbind`) mit Tests anbinden oder Modul + Migration entfernen und den Verweis im CHANGELOG als „nicht ausgeliefert" markieren.

### [S3] [Wartbarkeit] server/wp-plugin-registration.js:L35-81 — Vier Helfer sind Kopien aus server.js mit abweichender Semantik (Apex-Domain, Redirect-URI-Regeln, Client-ID)

**Begründung:** Der Kommentar L32-33 sagt es selbst: „server.js keeps its own copies; duplicated here so this module stays self-contained and server.js untouched". Die Kopien sind aber nicht identisch:
- `TWO_PART_TLDS` L35-36 hat 10 Einträge, `server/server.js:L600-605` 23 (u. a. `co.za`, `gov.uk`, `com.cn`, `ac.jp` fehlen im Plugin). Für `https://stadt.gov.uk` liefert `apexDomainFromUrl` im Plugin `gov.uk`, in server.js `stadt.gov.uk`.
- `isValidRedirectUri` L74-81: erlaubt jedes Protokoll bei Hostname `localhost`, lehnt `127.0.0.1` ab, hat kein Längenlimit, verbietet Fragmente; `server/server.js:L4047-4057`: nur `https:` oder `http:` mit `localhost`/`127.0.0.1`, ≤500 Zeichen, Fragment erlaubt.
- `emailMatchesPlatform` L57-63 vs. `server/server.js:L3956-3960` und `generateClientId` L69-72 vs. `L4061-4069` (unterschiedliche Slug-Länge 24/32, Präfix `wp-`, Suffix-Erzeugung).
**Auswirkung:** Derselbe Client-Datensatz (Tabelle `oauth_clients`) wird je nach Registrierungspfad nach unterschiedlichen Regeln validiert. Konkret: Eine Plugin-Site unter `example.gov.uk` bekommt `expected_host = _hhttps-verify.gov.uk` (L227) und kann den TXT-Record nie setzen, während dieselbe Site im Developer-Portal `_hhttps-verify.example.gov.uk` erhält. Jede Änderung der TLD-Liste oder Redirect-Regel muss an zwei Stellen nachgezogen werden und wird es erfahrungsgemäß nicht.
**Empfehlung:** `normalizeApexDomain`, `apexDomainFromUrl`, `apexDomainFromEmail`, `emailMatchesPlatform`, `isValidRedirectUri`, `randomToken`, `generateClientId` in ein Modul `server/client-registration.js` (oder `domain.js`) auslagern und aus beiden Stellen importieren; die Kopien im Plugin-Modul löschen.

### [S3] [Wartbarkeit] server/server.js:L4374-4432 — DNS-TXT-Prüfung ist in server.js und wp-plugin-registration.js:L205-266 nahezu zeilengleich dupliziert, mit unterschiedlichem Resolver

**Begründung:** Beide Handler laden den Client, prüfen `dns_token`/Apex, rufen `resolveTxt('_hhttps-verify.<apex>')`, vergleichen `parts.join('').trim() === client.dns_token.trim()`, rufen `touchDnsCheck` und bauen dasselbe Fehlerobjekt (`dns_lookup_failed`, `record_not_found`, `expected_record`, `expected_host`, `found_records`). Unterschied: `server/server.js:L4393-4395` pinnt `resolver.setServers(['1.1.1.1','8.8.8.8'])` (per dynamischem `await import('dns/promises')`, obwohl statischer Import möglich wäre), `server/wp-plugin-registration.js:L221-222` benutzt den System-Resolver. Zusätzlich ist der Auto-Approve-Block L250-259 (Plugin) eine Regel, die nur dort existiert.
**Auswirkung:** Derselbe Record kann über den Plugin-Pfad „gefunden" und über das Portal „nicht gefunden" werden (Propagation/Split-DNS) – schwer diagnostizierbar; Bugfixes (z. B. Vergleich mehrerer TXT-Chunks, Timeout) müssen doppelt erfolgen.
**Empfehlung:** Einen Helfer `verifyDnsToken(client) → { found, records, error }` (z. B. in `server/dns-verify.js`) einführen, der den Resolver konfiguriert, und ihn aus beiden Routen aufrufen; die Auto-Approve-Entscheidung als eigene Funktion `maybeAutoVerify(client)` daneben.

### [S3] [Wartbarkeit] server/server.js:L4621-4653 — Roh-SQL und JSON-Parsing im Routen-Handler statt in db.js; Semantik weicht von `db.oauthClients.get` ab

**Begründung:** `GET /hhttps/admin/clients` (L4626-4631) und `GET /hhttps/admin/stats` (L4644-4648) sind die einzigen zwei Stellen in server.js, die `db.pool().query(...)` direkt aufrufen; alle anderen Routen gehen über `db.oauthClients.*`. L4633-4634 kopiert das `JSON.parse(r.redirect_uris)`-Muster, das in `server/db.js` bereits fünfmal steht (L829, 840, 896, 1052, 1067). Die Roh-Query filtert nicht auf `is_active = TRUE`, `db.oauthClients.get` (db.js L824-826) hingegen schon.
**Auswirkung:** Die Admin-Liste zeigt deaktivierte Clients, die bei „approve/reject/suspend" anschließend über `db.oauthClients.get` als `404 not_found` scheitern (L4566, L4591, L4611). Die Persistenzschicht-Kapselung ist an dieser Stelle durchbrochen; Schemaänderungen an `oauth_clients` müssen in server.js nachgezogen werden.
**Empfehlung:** `db.oauthClients.listAll({ status, limit })` und `db.oauthClients.countByStatus()` in db.js ergänzen (inkl. eines gemeinsamen `parseClientRow()`-Helfers) und in den Admin-Routen verwenden.

### [S3] [Wartbarkeit] server/server.js:L3926-3937 — Dokumentierte Zustandsmaschine wird nur von `approve` durchgesetzt; `reject`/`suspend` akzeptieren jeden Zustand, `draft` existiert nicht

**Begründung:** Der Header-Kommentar beschreibt `draft → email_pending → unverified → pending_review → verified/rejected` und `verified/unverified/pending_review → suspended`. Im Code: `createDraft` (db.js L861-873) setzt direkt `'email_pending'`, `draft` kommt nur noch in `deleteIfDraft` (db.js L1090) vor. `POST /admin/clients/:id/approve` prüft `verification_status !== 'pending_review'` (L4568), `reject` (L4583-4602) und `suspend` (L4605-4619) prüfen keinerlei Ausgangszustand — ein `email_pending`- oder bereits `rejected`-Client kann erneut „rejected" werden, ein `rejected` „suspended". `GET /admin/clients/pending` und das Admin-Frontend (`developers/admin.html:L138-151`, `actionsFor`) rendern hingegen die Aktionen zustandsabhängig, d. h. die Regel lebt nur im UI.
**Auswirkung:** Kommentar und Verhalten laufen auseinander; über die API (curl) sind Übergänge möglich, die die Doku ausschließt, was Admin-Log-Einträge mit unerwartetem `previous_status` erzeugt.
**Empfehlung:** Erlaubte Übergänge als Konstante (`ALLOWED_TRANSITIONS = { reject: ['pending_review'], suspend: ['verified','unverified','pending_review'], … }`) definieren, in einer gemeinsamen `assertTransition(client, action)`-Prüfung vor allen drei Admin-Routen anwenden und den Kommentar auf den realen Start-Zustand `email_pending` korrigieren.

### [S3] [Wartbarkeit] server/pop-verify.js:L1-172, server/wp-plugin-registration.js:L1-282, server/server.js:L3888-3913, L4121-4653 — Keine Tests für PoP, Plugin-Registrierung, Webhook-Routen, Developer-Portal-, Admin- und whoami-Endpunkte

**Begründung:** `grep -rln "pop/\|plugin/\|webhooks\|developers/clients\|admin/clients\|whoami" server/test` liefert für diese Routen keine Treffer. Von AP5 sind nur `/hhttps/machine/token` (acceptance.test.mjs L443-476) und `/hhttps/machine/register` (L573-601, Regressionstest #7) abgedeckt. `verifyPoP` (pop-verify.js L79-135) enthält vier kryptographische Prüfschritte inkl. eigenem DER-Encoder (L64-75), die WP-Auto-Verifikation (L250-259) ist eine Freigabe-Entscheidung ohne Admin, und die Zustandslogik des Portals (submit-review L4437-4487, resend L4494-4535) hat mehrere 409/412-Pfade — alles ungetestet, obwohl `server/test/helpers` bereits eine Server-Fixture bereitstellt.
**Auswirkung:** Refactorings (z. B. die oben empfohlene Zusammenführung der Helfer) können nicht abgesichert werden; ein Fehler in `rawToDer` oder in der Nonce-Bindung fällt erst im Betrieb auf.
**Empfehlung:** Unit-Tests für `verifyPoP`/`jwkThumbprint`/`rawToDer` mit einem Node-`crypto.generateKeyPairSync('ec')`-Schlüssel; Integrationstests für den Portal-Lebenszyklus (register → confirm → dns-check(gemockt) → submit-review → approve) und für `/hhttps/plugin/*` inkl. Auto-Verify; Smoke-Tests für `/hhttps/webhooks` CRUD und `/hhttps/whoami`.

### [S4] [Wartbarkeit] server/server.js:L3774-3911 — Fehlerformat der Machine-/Webhook-Routen (Freitext-Sätze) weicht vom Rest des AP ab (snake_case-Codes + `message`)

**Begründung:** L3774 `{ error: 'operatorName and purpose are required.' }`, L3844 `'operatorId and apiKey are required.'`, L3846 `'Operator not found.'`, L3850 `'Invalid API key.'`, L3894 `'url is required.'`, L3903 `{ error: e.message }` (rohe Exception-Nachricht als Code), L3911 `'Webhook not found.'`, L3909 `'payload, signature, secret are required.'`. Dieselbe Route mischt beides: L3778 `error: 'operator_email_required', detail: …`. Ab L4128 verwendet das Portal durchgängig `{ error: '<snake_code>', message: '…' }`, die Auth-Helfer L3987/L3992/L4000 ebenfalls. Außerdem ist `/hhttps/webhooks/verify` (L3907) die einzige Webhook-Route ohne `limit.webhooks`.
**Auswirkung:** Clients (SDK, Portal-`api()` in portal.js L479-496, das `data.message || data.error` liest) können `error` nicht als stabilen Code behandeln; Fehler-Strings sind gleichzeitig Code und Anzeigetext, Änderungen an der Formulierung brechen Client-Vergleiche.
**Empfehlung:** Einheitlich `{ error: '<snake_code>', message: '<text>' }` (ggf. `detail` → `message` vereinheitlichen); für die Webhook-Registrierung Fehlercode `invalid_webhook` mit `message: e.message`; Rate-Limit auch auf `/webhooks/verify` legen.

### [S4] [Wartbarkeit] server/server.js:L3823, L3877, L3890, L3899, L4750, L4810 — Magic Strings/Numbers ohne Konstante: Versionsliteral (23×, widersprüchlich zum Boot-Banner), E-Mail-Regex und 48h-Ablauf mehrfach, Deploy-Pfad und Sentinel-Owner hart codiert

**Begründung:**
- `hhttps: { version: '0.5.0' }` steht 23-mal wörtlich in server.js (im AP u. a. L3823, L3877, L3890, L3899, L4750), während `app.listen` L4810 `HHTTPS v4.1` loggt.
- E-Mail-Regex `/^[^@\s]+@[^@\s]+\.[^@\s]+$/` viermal: L3777, L4146, L4333, wp-plugin-registration.js L132.
- Token-Ablauf `48 * 3600 * 1000` viermal: L4165, L4338, L4507, wp-plugin-registration.js L139; `randomToken(24)`/`randomToken(20)`-Längen ebenso.
- `'wp-plugin'` als Sentinel für `owner_user_id`: L4256 sowie wp-plugin-registration.js L152, L187, L204.
- L4115: absoluter Deploy-Pfad `/var/www/hhttps/scripts/make-admin.sh` in einer API-Antwort (`grant_admin_command`); das Skript liegt im Repo unter `server/scripts/make-admin.sh`.
- L3773-3779: `MACHINE_TTL` ist zwar Konstante (L95), aber `120_000`/`expires_in: 120` in pop-verify.js L152-153 und `300` (Freshness-Fenster) L129 sind unbenannt.
**Auswirkung:** Versionsbump oder Regeländerung (z. B. Ablauf 72 h) erfordert Suchen-und-Ersetzen über zwei Dateien; Bannerversion und API-Version widersprechen sich bereits heute.
**Empfehlung:** `HHTTPS_VERSION`, `EMAIL_RE`, `EMAIL_TOKEN_TTL_MS`, `WP_PLUGIN_OWNER_ID`, `POP_CHALLENGE_TTL_S`, `POP_IAT_SKEW_S` als benannte Konstanten (idealerweise in einem gemeinsamen `constants.js`) einführen; `grant_admin_command` aus `process.env.HHTTPS_HOME` oder relativ ableiten.

### [S4] [Wartbarkeit] server/server.js:L82-89 — `jwkThumbprint` ist identisch in server/pop-verify.js:L41-45 definiert und dort bereits exportiert

**Begründung:** Beide Funktionen kanonisieren `{crv,kty,x,y}` und hashen SHA-256/base64url; pop-verify.js exportiert sie (L172 `export { verifyPoP, jwkThumbprint }`), server.js importiert aus derselben Datei bereits `mountPopVerify` (L2), nutzt aber seine eigene Kopie (L3816). Zusätzlich implementiert pop-verify.js L31-38 `b64uDecode`/`b64uEncode` von Hand, obwohl dieselbe Datei in L44 schon Nodes natives `'base64url'`-Encoding verwendet.
**Auswirkung:** Zwei Wahrheiten für den `cnf.jkt`-Wert; wenn eine Seite z. B. auf RFC-7638-konformes Sortieren für weitere Kurven erweitert wird, weicht die andere ab und die PoP-Bindung (Prüfung 1 in `verifyPoP`) schlägt fehl.
**Empfehlung:** In server.js `import { mountPopVerify, jwkThumbprint } from './pop-verify.js'` und die lokale Kopie löschen; `b64uDecode`/`b64uEncode` durch `Buffer.from(s, 'base64url')` / `buf.toString('base64url')` ersetzen.

### [S4] [Wartbarkeit] server/server.js:L2-3, L4806-4807 — Zusatzmodule werden per Patch-Marker-Kommentar und uneingerückt innerhalb von `main()` gemountet, abweichend von allen anderen Routen

**Begründung:** L2-3 stehen als einzige Imports vor dem eigentlichen Import-Block (L24-71) und tragen die Marker `// POP-VERIFY` / `// WP-PLUGIN-REG`; L4806-4807 sind ohne Einrückung in `main()` eingefügt (`cat -A` bestätigt Spalte 0) und werden erst nach `db.ensureBootSchema()` registriert, während alle 68 anderen Routen auf Modulebene registriert werden. Der Marker-Stil deutet auf sed/Skript-Patching hin; in `scripts/` gibt es keinen Verweis mehr auf die Marker.
**Auswirkung:** Leser suchen die Plugin-/PoP-Routen an der falschen Stelle; die Mount-Reihenfolge (nach dem 404-/Error-Handling? – hier zufällig unkritisch, da kein Catch-all existiert) ist nicht offensichtlich; Formatierungs-Tools stolpern.
**Empfehlung:** Imports in den Import-Block einsortieren, Mounts neben die Router-Mounts (L523-529, `/privacy-pass`, `/eudi`) auf Modulebene ziehen, Marker-Kommentare entfernen.

### [S4] [Wartbarkeit] developers/assets/portal.js:L413, developers/dashboard.html:L109, developers/index.html:L264 — Veraltete Kommentare („no confirmed e-mail") und ungenutzte Deprecated-Aliase aus v4

**Begründung:** Seit v5 ist die Portal-Zugangsregel „Passkey" (portal.js L246, `PORTAL_REQUIRED_METHOD = 'passkey'`; Server L4017). Die Kommentare an portal.js L413 („gate page if the identity has no confirmed e-mail"), dashboard.html L109 („shows gate page if e-mail unconfirmed") und index.html L264 („signed in but no confirmed e-mail") beschreiben noch die alte Regel. `isDeveloper` (L284-287) und `requireDeveloper` (L424-426) sind als `@deprecated` markiert und in `window.HHTTPS.auth` (L633-634) exportiert, werden aber von keiner der vier Seiten aufgerufen (`grep -n "isDeveloper\|requireDeveloper" developers/*.html` = leer). Ferner enthält index.html L268-282 einen `setTimeout(renderHint, 600)`-Re-Check des Admin-Status statt auf das Promise von `verifyAdmin()` zu warten, das `initNav` (L624) ohnehin startet.
**Auswirkung:** Irreführung beim nächsten Umbau der Zugangsregel; toter Export-Ballast; timing-abhängige UI-Logik.
**Empfehlung:** Kommentare auf „passkey-verified" anpassen, die beiden Aliase entfernen (kein Aufrufer), Admin-Hint an `verifyAdmin().then(...)` hängen.

### [S4] [Wartbarkeit] developers/register.html:L346-352 — Formular erhebt Felder (`category`, `expected_volume`, `use_case`, `display_name`), die das Backend-Schema nicht kennt und die in `description` gefaltet werden

**Begründung:** Der Kommentar L346-347 räumt ein: „backend has no separate fields for these, so we fold them into the description". Der Server (`POST /hhttps/developers/clients` L4125-4126) akzeptiert nur `name, description, homepage_url, redirect_uris, contact_email, impressum_url, logo_url`. Zusätzlich validiert L337 clientseitig „Redirect URI must be https://", während der Server `http://localhost` erlaubt (L4053) — die Dashboard-Bearbeitung (dashboard.html L405-407) wiederholt dieselbe abweichende Client-Regel.
**Auswirkung:** Strukturierte Angaben landen als Freitext und sind für Admin-Filter (admin.html) nicht auswertbar; Entwickler mit lokaler Redirect-URI werden vom Frontend blockiert, obwohl die API es erlaubt.
**Empfehlung:** Entweder die Felder aus dem Formular streichen oder in `oauth_clients` (JSONB `metadata`) modellieren; Client-Validierung auf dieselbe Regel wie `isValidRedirectUri` bringen (Helfer serverseitig als `/hhttps/developers/validation`-Antwort oder gemeinsam dokumentiert).

### [S4] [Wartbarkeit] sites/spec.html:L964-1141, docs/spec.md:L147-157 — Öffentliche Endpunkt-Doku unvollständig: `/hhttps/pop/*`, `/hhttps/plugin/*`, `/hhttps/whoami`, `/developers/clients/:id/resend-email` fehlen; docs/spec.md kennt Developer-/Admin-API gar nicht

**Begründung:** `grep -n "pop/challenge\|plugin/register\|hhttps/whoami\|resend-email" docs/spec.md sites/spec.html README.md` liefert keinen Treffer. sites/spec.html dokumentiert machine/webhooks/developers/admin (L964-1141), docs/spec.md nur machine/webhooks (L147-157, L429-470). Die WordPress-Registrierung ist ausschließlich im Modul-Header (wp-plugin-registration.js L19-26) beschrieben, PoP nur in pop-verify.js L11-25.
**Auswirkung:** Integratoren (WP-Plugin, Bot-Betreiber) müssen den Servercode lesen; Vertragsänderungen (z. B. `HHTTPS-PoP`-Headerformat) sind nicht nachvollziehbar dokumentiert.
**Empfehlung:** Die vier Endpunktgruppen in sites/spec.html und docs/spec.md ergänzen (Request/Response-Beispiele aus den Modul-Headern übernehmen).

### [S4] [Wartbarkeit] server/server.js:L3945, L4054, L4633-4634; server/pop-verify.js:L129 — ESLint-Warnungen (gesammelt)

**Begründung:** Aus docs/review/ap/eslint-output.txt für den AP5-Bereich: server.js L3945 `'e' is defined but never used` (apexDomainFromUrl), L4054 dito (isValidRedirectUri), L4633-4634 dito (Admin-Liste); pop-verify.js L129 `'RP_ID' is assigned a value but never used` (wird über `deps` hereingereicht, L4807, aber nie benutzt).
**Auswirkung:** Rauschen im Lint-Lauf, unnötige Abhängigkeit (`RP_ID`) in der PoP-Schnittstelle.
**Empfehlung:** `catch {` ohne Binding verwenden; `RP_ID` aus `mountPopVerify`-Deps und dem Aufruf L4807 entfernen.

---

## Zusammenfassung

- S1: 0
- S2: 0
- S3: 6
- S4: 8

Gesamteindruck: Der AP5-Bereich ist funktional dicht kommentiert und die Routen-Handler bleiben unter 150 Zeilen, aber die Wartbarkeit leidet an drei strukturellen Punkten: (1) ein komplettes, migrationsgestütztes Modul (`workload-identity.js`) ist toter Code; (2) die WordPress-Registrierung wurde bewusst als Kopie der Portal-Logik gebaut („server.js untouched"), sodass Apex-Domain-, Redirect- und DNS-Regeln jetzt in zwei Versionen mit abweichendem Verhalten existieren; (3) PoP, Plugin-Registrierung, Webhooks, Portal- und Admin-API haben keinerlei Tests. Dazu kommen kleinere Inkonsistenzen (Fehlerformat der älteren Machine-/Webhook-Routen, Version `0.5.0` vs. Banner `v4.1`, Roh-SQL in Admin-Routen, veraltete v4-Kommentare im Portal-Frontend). Empfohlene Reihenfolge: Helfer-Modul extrahieren und Plugin-Kopien löschen → Portal-/Plugin-Integrationstests → Workload-Modul anbinden oder entfernen.

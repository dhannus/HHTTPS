# AP6 — Sicherheit

Geprüfte Dateien: server/db.js; server/sql/schema.sql; server/sql/migration-phase-2.5.sql, migration-phase-3a.sql, migration-phase-3a1-authcodes-text.sql, migration-phase-3b.sql, migration-phase-3b.1.sql, migration-phase-4-machine-roles.sql, migration-phase-4b-machine-key-jkt.sql, migration-phase-5-external-verify.sql, migration-phase-6-workload-identity.sql, migration-phase-7-age-group.sql, migration-phase-8-email-anchored-identity.sql, migration-portal-oauth-client.sql; server/privacy-pass/migrations.js; server/scripts/deploy-phase8.sh, migrate.sh, install-pg.sh, make-admin.sh; scripts/deploy-all.sh, deploy-privacy-pass.sh, patch-coop-popups.sh, patch-pseudonym-stage1.sh, force-verify-client.mjs; .github/workflows/ci.yml; server/package.json; server/eslint.config.js; server/test/helpers/db.mjs, identity-flow.mjs, server.mjs. (`server/scripts/migrate.js` und `db-check.js` aus package.json existieren nicht.)

Vorbemerkung zur SQL-Parametrisierung: Alle 90+ Queries in `server/db.js` verwenden Platzhalter (`$n`). Die einzige dynamische SQL-Konstruktion ist `sessions.update` (L171–196), die Spaltennamen ausschließlich aus der Whitelist `allowedColumns` übernimmt und Werte parametrisiert — kein Injektionspfad. Die Boot-DDL (`ensureBootSchema`, L469–487) liest nur feste Dateinamen aus `sql/`. Intervall-Parameter (`($n || ' milliseconds')::interval`) sind ebenfalls gebunden. In db.js gibt es damit kein SQL-Injection-Finding.

---

### [S2] [Sicherheit] server/scripts/make-admin.sh:L380-391 — `--grant-recent` vergibt Admin-Rechte an „wer auch immer zuletzt ein Token bekam“ (TOCTOU auf einem öffentlichen Dienst)
**Begründung:** Der Modus ermittelt zur Laufzeit die `user_id` mit dem jüngsten unabgelaufenen Token aus `tokens` und schreibt sie ohne Bestätigung, ohne Anzeige-vor-Schreiben und ohne Vergleich mit einer erwarteten ID in `admins`:
```
USER_ID="$(psql_run -tAc "SELECT user_id FROM tokens WHERE expires_at > NOW() ... ORDER BY issued_at DESC LIMIT 1;")"
psql_run -c "INSERT INTO admins (user_id, granted_by, note) VALUES ('${USER_ID}', ...)"
```
`tokens` wird von jedem Login auf hhttps.org befüllt (`/session/start` → E-Mail-Code → Token). Zwischen dem Einloggen des Operators und dem Skriptlauf kann sich jeder beliebige Nutzer einloggen; sein Token ist dann „most recent“.
**Auswirkung:** Ein fremder Nutzer erhält vollen Admin-Zugriff (Client-Freigabe/Sperre, Audit-Log, Admin-Liste) — ein reiner Timing-Zufall auf einem produktiven, öffentlichen Issuer reicht. Der Kommentar in Z. 244 („grant to the most recent live token“) bewirbt genau diesen Modus.
**Empfehlung:** `--grant-recent` entfernen oder so umbauen, dass die ermittelte `user_id` (plus `method`, `issued_at`) angezeigt und explizit per `read` bestätigt werden muss; besser: nur `--grant <USER_ID>` mit einer ID, die der Operator aus `/hhttps/whoami` kopiert.

### [S3] [Sicherheit] server/scripts/make-admin.sh:L390,L401,L408,L413 — `USER_ID` wird unescaped in SQL interpoliert (NOTE wird escaped, USER_ID nicht)
**Begründung:** `NOTE` wird korrekt mit `${NOTE//\'/\'\'}` escaped, `USER_ID` aus `--grant/--revoke/--whoami <arg>` bzw. aus der DB dagegen direkt in String-Literale eingesetzt: `VALUES ('${USER_ID}', ...)`, `DELETE FROM admins WHERE user_id = '${USER_ID}'`. Ein Argument wie `x'); DELETE FROM admins; --` wird als SQL ausgeführt (psql `-c`, `ON_ERROR_STOP` verhindert das nicht).
**Auswirkung:** Kein Remote-Pfad (user_id ist serverseitig `uuid()`, siehe server.js L2725), aber ein Copy-Paste-Fehler oder eine manipulierte ID aus einem Support-Ticket führt zu beliebigem SQL als App-User (der Owner aller Tabellen ist).
**Empfehlung:** `USER_ID` vor Verwendung auf `^[A-Za-z0-9_:-]{1,64}$` validieren und zusätzlich via psql-Variable binden (`psql -v uid="$USER_ID" -c "... WHERE user_id = :'uid'"`).

### [S3] [Sicherheit] server/db.js:L861-899,L916-942 — E-Mail-Bestätigungstoken der OAuth-Clients werden im Klartext gespeichert und im Klartext nachgeschlagen
**Begründung:** `createDraft` (L869/L881), `refreshEmailToken` (L919) und `updateContactEmail` (L932) schreiben `emailToken` unverändert in `oauth_clients.email_token`; `getByEmailToken` (L889) sucht `WHERE email_token = $1`. Der Aufrufer (server.js L4164/L4337/L4506) übergibt `randomToken(24)` roh. Im Gegensatz dazu speichert der E-Mail-Anker-Flow konsequent nur `sha256(token)` (email.js L381–389, db.js L321–366) — das eigene Projekt kennt das Muster also.
**Auswirkung:** Jede Leseberechtigung auf die DB (Backup unter `/root/hhttps-backups`, pg_dump, Read-Replica, SQL-Log, `identity_claims_cache`-Export) genügt, um für einen fremden Client die Kontakt-E-Mail als „bestätigt“ zu markieren und damit die erste Stufe des Verifikations-Workflows (`email_pending → unverified`) zu überspringen; der Index `idx_oauth_clients_email_token` (migration-phase-3b.sql L115) macht das Token zudem im Klartext durchsuchbar.
**Empfehlung:** In db.js nur `sha256(token)` speichern/vergleichen (wie `emailVerifications`), Hashing zentral in `createDraft/refreshEmailToken/updateContactEmail/getByEmailToken` erledigen, bestehende Zeilen per Migration invalidieren (`email_token = NULL`).

### [S3] [Sicherheit] server/db.js:L656-668 — `webhooks.list()` liefert das HMAC-Secret jedes Webhooks an den Aufrufer zurück
**Begründung:** `list()` mappt `secret: r.secret` in das Ergebnis, obwohl das Secret außerhalb des Signierens (`findForEvent`, L670–678) nirgends gebraucht wird. Einziger Konsument ist `listWebhooks()` (webhooks.js L41) → `GET /hhttps/webhooks` (server.js L3889), das das Array unverändert als JSON ausgibt — und dieser Endpunkt hat keinerlei Authentifizierung (nur `limit.webhooks`).
**Auswirkung:** Jeder anonyme Aufrufer erhält alle Webhook-URLs und die zugehörigen Signatur-Secrets und kann damit gefälschte, korrekt signierte Events (`HHTTPS-Webhook-Sig`) an fremde Endpunkte senden. (Fehlende Auth am Endpunkt selbst gehört zu AP5; hier: das Datenmodell darf das Secret in einer Listing-Funktion gar nicht erst herausgeben.)
**Empfehlung:** `secret` aus `list()` entfernen (nur `findForEvent` behält es), zusätzlich Secret gehasht/verschlüsselt ablegen oder nur beim Anlegen einmalig zurückgeben; Endpunkt-Auth in AP5 nachziehen.

### [S3] [Sicherheit] server/scripts/migrate.sh:L77-84, scripts/deploy-all.sh:L414-424 — `.env` wird als Shell-Skript gesourct und alle Secrets werden in die pm2-Prozessumgebung und `dump.pm2` übernommen
**Begründung:** `set -a; source .env; set +a` (migrate.sh L77, deploy-all.sh L414) führt die `.env` als Bash aus (make-admin.sh L280–283 dokumentiert selbst, warum das falsch ist: unquotierte Werte mit Leerzeichen werden als Kommando ausgeführt, Werte mit `$(...)`/Backticks werden evaluiert). Anschließend `pm2 start server.js`/`pm2 restart --update-env` und `pm2 save` (L82–84 bzw. L417–424): pm2 friert die komplette exportierte Umgebung (DB_PASSWORD, SMTP_PASS, HHTTPS_VERIFICATION_PEPPER, GITHUB_CLIENT_SECRET, EUDI_VERIFIER_SECRET) im Prozess-Environment ein und persistiert sie in `~/.pm2/dump.pm2`.
**Auswirkung:** Secrets liegen dauerhaft an einem zweiten Ort (dump.pm2, `pm2 env`, `pm2 describe`, `/proc/<pid>/environ` aller Kindprozesse), der bei Rotation der `.env` nicht mitgeändert wird — ein rotierter Pepper/DB-Passwort in `.env` wird durch `--update-env` bzw. den alten Dump überschrieben oder bleibt lesbar. Eine `.env` mit einer Zeile `SMTP_FROM_NAME=HHTTPS Open Issuer` bricht das Deploy zusätzlich mit „command not found“.
**Empfehlung:** Das `source .env` entfernen — der Server lädt `.env` selbst per dotenv; für Skript-eigene Werte den `envval`/`env_get`-Ansatz aus deploy-phase8.sh/make-admin.sh verwenden. `pm2 start` ohne exportierte Secrets ausführen.

### [S3] [Sicherheit] scripts/deploy-all.sh:L269-281,L367-381 — Nginx: `add_header` in `location`-Blöcken verwirft die serverweiten Security-Header (HSTS, nosniff, X-Frame-Options)
**Begründung:** Nginx vererbt `add_header` nur, wenn der innere Block **kein** eigenes `add_header` hat. `location = /spec` (L276–281) setzt `Content-Type`/`Cache-Control` per `add_header` und verliert damit HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` aus L269–272. Bei iamhmn.org setzt `location /` (L377–381) `Cache-Control` — d. h. die **gesamte** Marketing-Site liefert keinen der in L367–370 definierten Header aus.
**Auswirkung:** iamhmn.org ohne HSTS/Frame-Schutz (Clickjacking, SSL-Stripping beim Erstbesuch); `/spec` auf hhttps.org ebenso. Das Deploy-Skript ist die einzige Quelle der Nginx-Konfiguration, der Fehler landet also 1:1 in Produktion.
**Empfehlung:** Security-Header in jeder `location` mit eigenem `add_header` wiederholen oder in ein `include security-headers.conf;` auslagern und überall einbinden; alternativ `Cache-Control` per `expires` statt `add_header` setzen.

### [S3] [Sicherheit] .github/workflows/ci.yml:L21-30 — CI ohne Test-, Lint- und Audit-Gate; `npm ci` fällt still auf `npm install` zurück
**Begründung:** Der Server-Job prüft nur `node --check` (L25–30). `npm test` (203 Tests, u. a. Auth-Code-Claim, E-Mail-Anker, Consent), `eslint` und `npm audit` laufen nicht. L23 `npm ci --omit=dev || npm install --omit=dev`: schlägt `npm ci` wegen Lockfile-Mismatch fehl, installiert der Fallback ungepinnt nach `package.json` (`^`-Ranges) und die Lockfile-Integritätsprüfung (SHA-512 `integrity`) entfällt — genau der Fall, in dem `npm ci` absichtlich bricht. Außerdem fehlt ein `permissions:`-Block (Datei L1–8), d. h. `GITHUB_TOKEN` läuft mit den Repo-Defaults (bei älteren Repos read/write), und alle Actions sind per Major-Tag statt SHA gepinnt (L14, L17, L62, L67).
**Auswirkung:** Sicherheitsrelevante Regressionen (die 5 bekannten `npm audit`-Findings inkl. nodemailer high, siehe 01-automatische-checks.md, oder ein fehlschlagender Auth-Test) werden auf `main` nicht erkannt; ein PR mit manipuliertem Lockfile/Package wird grün. Ein kompromittiertes Third-Party-Action-Tag (`shivammathur/setup-php@v2`) hätte Schreibrechte.
**Empfehlung:** `npm ci` ohne Fallback, Jobs für `npm test` (Postgres-Service-Container, `EMAIL_DEV_MODE=1`), `npm run lint` und `npm audit --audit-level=high` ergänzen; `permissions: contents: read` auf Workflow-Ebene; Actions per Commit-SHA pinnen.

### [S3] [Sicherheit] server/scripts/deploy-phase8.sh:L107-110 + scripts/deploy-privacy-pass.sh:L386-389 — Lokale Kopie der `docker-compose.yaml` (mit Keystore-Passwort) landet ungeschützt im Repo-Arbeitsverzeichnis, `git add -A && git push` pusht sie
**Begründung:** Beim `--link`-Umbau kopiert deploy-phase8.sh eine lokal abweichende `eudi-verifier/docker/docker-compose.yaml` nach `${DC}.local-${TS}` **ins Repo-Verzeichnis** (L109). Diese Datei enthält laut Issue #32 das Keystore-Passwort des EUDI-Verifiers (Produktionswert, da lokal geändert). `.gitignore` ignoriert `*.bak`, `*.backup`, `_backup_*/` — nicht `*.local-*`. deploy-privacy-pass.sh Schritt 7 macht anschließend `git add -A; git commit; git push origin main` (L387–389), interaktiv bestätigt oder mit `ALLOW_COMMIT=1` automatisch.
**Auswirkung:** Produktions-Secret (Keystore-Passwort) und ggf. weitere lokale Extras (`force-verify-client.mjs`, `developers/`-Anpassungen, L100–103) werden nach GitHub gepusht; Git-History lässt sich nicht folgenlos bereinigen.
**Empfehlung:** Lokale Kopien außerhalb des Repos ablegen (`$BACKUP_ROOT`), `*.local-*` in `.gitignore` aufnehmen, in deploy-privacy-pass.sh `git add -A` durch explizite Pfade ersetzen bzw. den Commit/Push-Schritt ganz aus dem Deploy entfernen.

### [S4] [Sicherheit] server/scripts/deploy-phase8.sh:L168,L192,L216 — `PGPASSWORD` für die gesamte Skriptlaufzeit exportiert (npm-Lifecycle-Skripte, pm2 `--update-env`)
**Begründung:** `export PGPASSWORD="$DB_PASSWORD"` (L168) gilt auch für `npm ci` (L192; ein Paket mit Install-Script sieht das DB-Passwort) und für `pm2 restart --update-env` (L216), das die aktuelle Shell-Umgebung in den App-Prozess und `pm2 save` (L221) übernimmt.
**Auswirkung:** DB-Passwort in Umgebung fremder npm-Skripte und dauerhaft in `dump.pm2`.
**Empfehlung:** Passwort nur pro psql-Aufruf setzen (`PGPASSWORD=… "${PSQL[@]}"` oder `PSQL=(env PGPASSWORD=… psql …)`), `npm ci --ignore-scripts` wo möglich.

### [S4] [Sicherheit] server/scripts/install-pg.sh:L157,L165, scripts/deploy-all.sh:L79,L89 — DB-Passwort als Kommandozeilenargument an psql (`/proc/*/cmdline`)
**Begründung:** `psql -c "ALTER USER … WITH PASSWORD '${DB_PASSWORD}';"` übergibt das frisch generierte Passwort in argv; für die Dauer des Aufrufs für alle lokalen Nutzer via `ps`/`/proc` lesbar. install-pg.sh L189–191 fällt außerdem still (`>/dev/null 2>&1 ||`) auf den Superuser zurück, wodurch Tabellen `postgres` gehören und die App später `permission denied` bekommt (Hinweis in migration-phase-6 L19–23).
**Auswirkung:** Gering auf einem Single-User-VPS; Fehlkonfiguration wird verdeckt.
**Empfehlung:** Passwort per stdin (`psql <<<"ALTER USER … PASSWORD '…'"` mit `\password`-Variante) oder `psql -v pw=… -c "ALTER USER hhttps WITH PASSWORD :'pw'"`; Superuser-Fallback laut ausgeben statt zu verstecken.

### [S4] [Sicherheit] scripts/deploy-all.sh:L51 — `curl … | bash` (NodeSource-Setup) ohne Prüfsumme/Pinning
**Begründung:** `curl -fsSL https://deb.nodesource.com/setup_20.x | bash -` führt Remote-Code als root aus; Output unterdrückt.
**Auswirkung:** Supply-Chain-Risiko beim Erstdeploy; keine Nachvollziehbarkeit.
**Empfehlung:** Distro-Paket oder NodeSource-Repo mit hinterlegtem GPG-Key manuell einrichten; Skript vorher herunterladen und Hash prüfen.

### [S4] [Sicherheit] scripts/deploy-privacy-pass.sh:L324-371 — `curl -k` deaktiviert TLS-Verifikation bei den Live-Checks
**Begründung:** Alle Verifikationsaufrufe (auch gegen `https://hhttps.org`) nutzen `-k`; ein MITM/Zertifikatsfehler wird als „grün“ gemeldet.
**Auswirkung:** Deploy-Verifikation erkennt ein kaputtes/fremdes Zertifikat nicht.
**Empfehlung:** `-k` entfernen (Zertifikat ist per Certbot vorhanden); für Loopback `http://127.0.0.1` braucht es kein `-k`.

### [S4] [Sicherheit] scripts/force-verify-client.mjs:L441-460 + server/scripts/deploy-phase8.sh:L100 — Prod-fähiges „Verified-Badge erzwingen“-Tool mit Default-Client wird ins Live-/Repo-Verzeichnis kopiert
**Begründung:** Das Skript setzt ohne State-Guard `verification_status='verified'` (L460) und hat einen Default-Client `songbird-2423` (L441); einziger Schutz ist ein `console.warn`. deploy-phase8.sh nimmt die Datei beim `--link` explizit ins Repo-Verzeichnis auf (L100), sodass sie auf dem Produktionsserver neben `.env` liegt und mit `node force-verify-client.mjs` sofort wirkt.
**Auswirkung:** Ein versehentlicher Aufruf auf Prod vergibt ein nicht verdientes Vertrauenssiegel (das der Consent-Screen Nutzern anzeigt).
**Empfehlung:** Guard einbauen (`NODE_ENV==='production'` → abbrechen, Default-Client entfernen, explizites `--yes-i-know`), Datei nicht auf den Prod-Host kopieren.

### [S4] [Sicherheit] scripts/patch-coop-popups.sh:L40-110, scripts/patch-pseudonym-stage1.sh:L150-279 — Produktionscode wird per Python-Textersetzung außerhalb von Git/CI geändert und neu gestartet
**Begründung:** Beide Skripte patchen `/var/www/hhttps/server.js` direkt (Backup nach `/var/backups`, `pm2 restart`), ohne Review, ohne Tests; patch-pseudonym-stage1 fügt dabei einen neuen Token-Claim (`preferred_username`) aus Nutzereingabe hinzu (L169–171, L200).
**Auswirkung:** Prod-Code weicht von `main` ab; Sicherheitsreviews (wie dieses) sehen den laufenden Code nicht. Die Änderungen sind inzwischen laut deploy-phase8.sh-Layout wohl in `main` — die Skripte sollten dann entfernt werden.
**Empfehlung:** Skripte löschen bzw. nach `docs/archive` verschieben; Deploys ausschließlich über `deploy-phase8.sh` aus `main`.

### [S4] [Sicherheit] scripts/deploy-all.sh:L21, server/sql/schema.sql:L2, server/sql/migration-portal-oauth-client.sql:L46 — Persönliche E-Mail-Adresse hart im Repo
**Begründung:** Certbot-Kontakt, Schema-Header und Portal-Client-`contact_email` enthalten eine persönliche Adresse; die Portal-Adresse wird per Migration in die DB geschrieben und ist über den Consent-Screen/Admin-UI sichtbar.
**Auswirkung:** PII/Spam-Ziel in einem (öffentlichen) Repo; Rotation erfordert Codeänderung.
**Empfehlung:** Rollenadresse (`security@`/`ops@`) verwenden bzw. über Umgebungsvariable (`ADMIN_NOTIFY_EMAIL`) beziehen.

### [S4] [Sicherheit] server/db.js:L1213-1233 — OAuth-Authorization-Codes werden im Klartext gespeichert
**Begründung:** `authCodes.create` schreibt `code` roh als Primärschlüssel; `claim` (L1245–1253) sucht `WHERE a.code = $1`. Codes sind 60 s gültig, single-use und PKCE-gebunden — der Schaden bei DB-Leak ist daher begrenzt, das Muster widerspricht aber der Hash-Praxis von `email_verifications`/`pp_email_pending`.
**Auswirkung:** Ein Leser der DB (Backup/Log) könnte in der 60-s-Frist einen Code einlösen — nur ohne PKCE-Verifier bei `plain`-Methode oder confidential clients mit bekanntem Secret.
**Empfehlung:** `sha256(code)` speichern und in `claim` vergleichen; kostet eine Zeile im Aufrufer.

---

## Zusammenfassung

- S1: 0
- S2: 1
- S3: 7
- S4: 8

Die Persistenzschicht ist bezüglich SQL-Injection sauber: sämtliche Queries in `db.js` sind parametrisiert, dynamische Spalten laufen über eine Whitelist, die Boot-DDL nutzt nur feste Dateien. Die relevanten Schwächen liegen in der Betriebs-/Skriptebene: `make-admin.sh --grant-recent` ist auf einem öffentlichen Dienst eine echte Privilege-Escalation-Lotterie, die Deploy-Skripte behandeln Secrets nachlässig (`source .env` → pm2-Dump, `PGPASSWORD` global, Passwörter in argv, lokale Secret-Kopien im Repo-Tree mit `git add -A`), die Nginx-Konfiguration verliert durch das `add_header`-Vererbungsverhalten ihre Security-Header, und die CI hat kein Sicherheits-Gate (kein `npm test`/`audit`, `npm ci`-Fallback). Im Datenmodell sollten OAuth-Client-E-Mail-Token wie die E-Mail-Anker-Token gehasht und Webhook-Secrets nicht aus `list()` herausgegeben werden.

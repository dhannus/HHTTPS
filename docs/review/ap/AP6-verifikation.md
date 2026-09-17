# AP6 — Verifikation
Geprüft: 2026-09-17, Basis main@bf0a82b

Vorgehen: Alle 60 Rohbefunde (K 12, S 16, P 10, W 22) wurden gegen den Arbeitsstand geprüft (`sed -n`/`grep -n`), Zeilennummern korrigiert wo nötig. Repros liefen gegen den Wegwerf-Cluster `TEST_PG_HOST=/var/lib/pgtest` (PostgreSQL 16.13): (a) leere DB `ap6fresh` = `createdb` + nur `sql/schema.sql`, dann `db.ensureBootSchema()` in-process; (b) db.js-Funktionen gegen die vollständig migrierte DB `hhttps`; (c) Owner-Mismatch mit einer zusätzlichen Nicht-Owner-Rolle; (d) Shell-Repros (git detached HEAD, `shift 2`, Patch-Skripte im `--dry-run` gegen eine Kopie von `server.js`). Es wurden keine Projektdateien verändert.

IDs in Reihenfolge K (AP6-01…12), S (AP6-13…28), P (AP6-29…38), W (AP6-39…60).

## Bestätigte Findings

### AP6-01 [S2] [Korrektheit] server/db.js:L432-439, server/scripts/install-pg.sh:L72-82, scripts/deploy-all.sh:L145-152 — Installationsskripte spielen nur schema.sql ein; Boot-DDL setzt `authorization_codes` voraus → frische Installation bootet nicht
**Urteil:** BESTÄTIGT (Severity unverändert S2; AP6-39/W1 hierher zusammengeführt)
**Beleg:** Repro gegen leere DB: `createdb ap6fresh && psql -f sql/schema.sql` → 12 Tabellen (kein `authorization_codes`, das erst `migration-phase-3a.sql:L47` anlegt). Anschließend `node -e 'import("./db.js").then(m=>m.ensureBootSchema())'` mit `DB_NAME=ap6fresh`:
```
[DB] Query failed: relation "authorization_codes" does not exist
[db] ensureBootSchema: relation "authorization_codes" does not exist
BOOT FAILED: 42P01 relation "authorization_codes" does not exist
```
Ursache: `BOOT_DDL_FILES` (db.js:L432-439) enthält Phase 8 (`ALTER TABLE authorization_codes ADD COLUMN …`, migration-phase-8:L67-70) und 3a1 (`ALTER TABLE authorization_codes ALTER COLUMN …`), aber keine der Basismigrationen 2.5/3a/3b/3b.1/4/5/6/7. Weder `install-pg.sh:L73,L79-81` noch `deploy-all.sh:L145-151` laden etwas außer `sql/schema.sql`; `npm run migrate` zeigt auf eine nicht existierende Datei (AP6-10). `server.js:L4799-4804` reagiert mit `process.exit(1)`. Zusätzlich scheitert danach auch `sessions.create` (`column "pseudonym" of relation "sessions" does not exist`, 42703) — d. h. selbst ohne den Abbruch wäre der Server nicht funktionsfähig. README.md:L286 nennt die Pflicht nur in einem Nebensatz ohne Reihenfolge.
**Auswirkung:** Jede Neuinstallation nach Skript/README (und jede nach `install-pg.sh` aufgesetzte Testumgebung) endet mit „Boot schema migration failed“; die Fehlermeldung nennt die fehlenden Vor-Migrationen nicht. Die Produktionsinstanz ist nicht betroffen (bereits migriert), daher S2 statt S1. Kein Test deckt den Pfad ab (`db-phase8.test.mjs` läuft nur gegen eine voll migrierte DB).
**Empfehlung:** Einen Migrationslauf (`server/scripts/migrate.js`, den `package.json:L9` bereits referenziert) mit Ledger `schema_migrations` und fester Reihenfolge (schema → 2.5 → 3a → 3b → 3b.1 → 4 → 5 → 6 → 7 → portal → 8 → 4b → 3a1) einführen und aus `install-pg.sh`/`deploy-all.sh` aufrufen; alternativ die Basismigrationen mit Applied-Checks in `BOOT_DDL_FILES` aufnehmen. Integrationstest „schema.sql only → ensureBootSchema()“ ergänzen.

### AP6-02 [S2] [Korrektheit] server/db.js:L1264-1267 — `authCodes.cleanup()` wird nirgends aufgerufen; abgelaufene, nie eingelöste Codes (inkl. Klartext-E-Mail) bleiben unbegrenzt liegen
**Urteil:** BESTÄTIGT (Severity unverändert S2; AP6-30/P2 und AP6-41/W3 hierher zusammengeführt; Owner-Finding — Dubletten in AP2-P (erstes Finding, S3 Performance) und AP3-P vermerkt)
**Beleg:** `grep -rn "\.cleanup()" server --include=*.js --include=*.mjs` liefert außerhalb der Tests (`track.cleanup()` der Test-Helfer) keinen Aufrufer. `cleanupExpired()` (db.js:L1339-1347) ruft nur `cleanup_expired()` (schema.sql:L192-206: tokens, refresh_tokens, sessions, challenges, email_verifications) plus `identity_claims_cache`. `claim()` (db.js:L1245-1253) nullt `email` nur beim erfolgreichen Einlösen (`SET used = TRUE, used_at = NOW(), email = NULL`); `create()` (L1213-1233) schreibt `email` aus `identity_claims_cache` (server.js:L1599 `codeEmail = … cache?.email`), also Klartext. Pro `/oauth/approve` entsteht eine Zeile (server.js:L1601).
**Auswirkung:** `authorization_codes` und `idx_authcodes_expires` wachsen linear mit den Logins; nicht eingelöste Codes behalten `email`, `pseudonym`, `user_id`, `state`/`nonce` (bis 2 KB) dauerhaft. Die Zusicherung AK-17/D5 (Klartext-E-Mail ≤ 7 Tage) gilt für abgebrochene Flows nicht.
**Empfehlung:** In `cleanupExpired()` `DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour'` ergänzen (bzw. `authCodes.cleanup()` aufrufen) und das Ergebnis in die `[CLEANUP]`-Ausgabe (server.js:L714-724) aufnehmen; optional `email` bereits bei Ablauf nullen.

### AP6-03 [S3] [Korrektheit] server/sql/schema.sql:L203 — `cleanup_expired()` löscht nur `used = FALSE`; eingelöste/invalidierte `email_verifications`-Zeilen werden nie entfernt
**Urteil:** BESTÄTIGT (herabgestuft von S2 auf S3: die Spalte `email` enthält NICHT die Klartext-Adresse, sondern `sha256(email.toLowerCase())` — email.js:L391 und Header L26-27; es bleibt unbegrenztes Wachstum plus `domain`/`session_id`, kein Klartext-PII-Leck. AP6-31/P3 hierher zusammengeführt; Owner-Finding — Dublette in AP3-P (erstes Finding, S2) vermerkt.)
**Beleg:** schema.sql:L203 `DELETE FROM email_verifications WHERE expires_at < NOW() AND used = FALSE`. Alle drei Konsumpfade setzen `used = TRUE` (db.js:L337, L350, L360); ein weiterer `DELETE FROM email_verifications` existiert im Repo nicht (grep). Da jede Anmeldung mit einer E-Mail-Bestätigung beginnt, bleibt pro Login mindestens eine Zeile dauerhaft stehen. Index-Lage (aus P3, geprüft per `pg_indexes`): nur `email_verifications_pkey`, `_expires_at_idx`, `_email_idx`; die Hot-Path-Queries filtern auf `code`/`session_id` (db.js:L351, L361) — ohne Index, also Seq-Scan über die nie schrumpfende Tabelle.
**Auswirkung:** Unbegrenztes Wachstum der Tabelle und des toten `email`-Index (keine Query filtert auf `email`); Seq-Scans auf dem Login-Pfad, die mit der Lebensdauer der Installation langsamer werden; unnötige Datenhaltung von `sha256(email)`, `domain`, `session_id`.
**Empfehlung:** `AND used = FALSE` streichen (nach Ablauf ist eine eingelöste Zeile nicht mehr konsumierbar, beide UPDATEs prüfen `expires_at > NOW()`). Wenn die Tabelle damit klein bleibt, ist ein Index auf `session_id` optional; `email_verifications_email_idx` entfernen.

### AP6-04 [S3] [Korrektheit] server/db.js:L147-234 — `sessions` hat keine Methode `delete`; `server.js:L2573` ruft `db.sessions.delete(priorId)` im leeren `catch` auf
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** In-process: `typeof db.sessions.delete === 'undefined'`. server.js:L2573 `try { await db.sessions.delete(priorId); } catch (e) {}` — der `TypeError` wird verschluckt. Kommentar L2559-2560 verspricht „delete the old session so the user keeps exactly ONE active session“. (AP3-P nennt den Punkt ebenfalls, mit Verweis auf Korrektheit.)
**Auswirkung:** Nach dem Passkey-Merge bleibt die Vor-Session (E-Mail/GitHub/EUDI) bis zum TTL gültig; zwei aktive Sessions mit denselben Verifikationsdaten, doppelte Zählung in `sessions.count()`.
**Empfehlung:** `async delete(sessionId) { await q('DELETE FROM sessions WHERE session_id = $1', [sessionId]); }` ergänzen; den leeren `catch` loggen; Test für den Merge-Pfad.

### AP6-05 [S4] [Korrektheit] server/db.js:L158 — `data.trustScore || 60` überschreibt ein explizites `trustScore: 0` mit 60
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: kein Server-Pfad liest `session.trustScore` — `grep "session\.trustScore\|prior\.trustScore"` über server/*.js leer; der Fehler ist rein latent)
**Beleg:** Repro gegen die migrierte DB: `sessions.create('…', {trustScore: 0})` → `sessions.get().trustScore === 60`. Aufrufer server.js:L2694 und L2735 übergeben bewusst `trustScore: 0` („email pending — 0 until confirmed“).
**Auswirkung:** Persistierter Wert widerspricht API-Antwort (`trustScore: 0`) und Kommentar; jede künftige Nutzung der Spalte bekäme 60 für unverifizierte Sessions.
**Empfehlung:** `data.trustScore ?? 60` (oder Default 0).

### AP6-06 [S3] [Korrektheit] server/db.js:L372-383 — `email_verifications.code` existiert in keiner SQL-Datei; wird nur per Fire-and-forget beim Modul-Import angelegt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep 'ADD COLUMN IF NOT EXISTS code' server/sql/` leer; schema.sql:L105-116 kennt die Spalte nicht; nicht in `BOOT_DDL_FILES`. `ensureCodeColumn()` läuft einmalig bei Import (L383), Fehler werden nur geloggt, es gibt keinen Retry. Owner-Repro: für eine Rolle, die nicht Owner von `email_verifications` ist, scheitert das ALTER mit `must be owner of table` (siehe AP6-08); dann liefern `emailVerifications.create()` (L328) und `getAndConsumeByCode()` (L360) 42703, obwohl `ensureBootSchema()` erfolgreich war. In der leeren Test-DB (Owner = App-Rolle) wurde die Spalte beim Import korrekt angelegt — der Pfad hängt also allein von Owner/Erreichbarkeit zum Importzeitpunkt ab.
**Auswirkung:** `/hhttps/email/send` und `/email/confirm-code` mit 500 bei „gesundem“ Server.
**Empfehlung:** Spalte in schema.sql bzw. als Eintrag in `BOOT_DDL_FILES` (`columns: [['email_verifications','code']]`) führen; Import-seitiges Fire-and-forget entfernen.

### AP6-07 [S3] [Korrektheit] server/privacy-pass/migrations.js:L117-138 — fehlgeschlagene Privacy-Pass-Migrationen werden nur gezählt, der Server startet trotzdem; Aufruf vor `db.ping()`
**Urteil:** BESTÄTIGT (Severity unverändert; AP6-53/W15 hierher zusammengeführt)
**Beleg:** L123-131 `try { await pool.query(m.sql) } catch { failed++; console.error(…) }`, L133-137 nur `console.warn`; kein Rückgabewert, `initPrivacyPass()` (privacy-pass/index.js:L36-42) und `main()` (server.js:L4784) werten nichts aus. Gegensatz: `ensureBootSchema()` → `process.exit(1)` (server.js:L4800-4804). Reihenfolge in `main()`: `initPrivacyPass()` L4784 vor `db.init()`/`db.ping()` L4790-4795 — ein nicht erreichbarer Postgres erzeugt fünf `[PRIVACY-PASS] migration … failed`-Zeilen vor „Database connection failed“. L118 `await import('../db.js')` ohne Zyklusgrund; jeder Block läuft bei jedem Start (kein Ledger, trotz Header „Inline-versioniert“).
**Auswirkung:** Fehlende `pp_*`-Tabellen (Owner/CREATE-Recht) fallen erst im Request mit 42P01/500 auf; Double-Spend-Prüfung über `pp_redeemed` dann wirkungslos. Uneinheitliche Boot-Semantik gegenüber `ensureBootSchema`.
**Empfehlung:** Bei `failed > 0` werfen und in `main()` wie `ensureBootSchema` behandeln; Aufruf hinter `db.ping()` verschieben; statischer Import; langfristig in `BOOT_DDL_FILES` integrieren (siehe AP6-40).

### AP6-08 [S3] [Korrektheit] server/scripts/install-pg.sh:L79-81, scripts/deploy-all.sh:L146-151 — stiller Superuser-Fallback macht `postgres` zum Tabellen-Owner; Boot-DDL scheitert mit „must be owner“
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** install-pg.sh:L50 setzt `DB_PASSWORD=""`, wenn das Passwort nicht neu gesetzt wird; L79-81 `PGPASSWORD="" psql -U hhttps … >/dev/null 2>&1 || sudo -u postgres psql … -f schema.sql`; L82 meldet danach bedingungslos „Schema angewendet“. schema.sql enthält keinen OWNER/GRANT-Block (L208-209 nur Kommentar). Repro mit einer Nicht-Owner-Rolle gegen die per Superuser angelegten Tabellen: `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS pseudonym TEXT` → `ERROR: must be owner of table sessions`; `INSERT INTO stats …` → `ERROR: permission denied for table stats`.
**Auswirkung:** `ensureBootSchema()` bricht ab → `process.exit(1)`, obwohl das Installationsskript Erfolg meldet; auch DML der App scheitert.
**Empfehlung:** Fallback entfernen (bei Fehler abbrechen) oder danach `REASSIGN OWNED BY postgres TO hhttps` / Schleife über `pg_tables` + `ALTER DEFAULT PRIVILEGES`; Fehlerausgabe nicht unterdrücken.

### AP6-09 [S3] [Korrektheit] server/scripts/deploy-phase8.sh:L267 — dokumentierter Rollback-Befehl scheitert am eigenen Preflight
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L267 empfiehlt `git checkout $(cat …/repo-head-before.txt) && bash $0 --skip-operator`. Repro in einem Klon: nach `git checkout <sha>` liefert `git rev-parse --abbrev-ref HEAD` den String `HEAD`; L125-126 vergleicht mit `$BRANCH` (main) → `fail "Repo steht auf 'HEAD', erwartet 'main'"`. Selbst mit `BRANCH=HEAD` würde L189 `git pull --ff-only origin HEAD` den Zustand nicht auf den alten Stand bringen.
**Auswirkung:** Die einzige im Skript genannte Rollback-Anweisung funktioniert im Störfall nicht.
**Empfehlung:** `--rollback <sha>`-Modus (Branch-Check und Pull überspringen, z. B. `git checkout -B rollback <sha>`), oder Meldung auf `git reset --hard <sha>` auf `main` umstellen und testen.

### AP6-10 [S4] [Korrektheit] server/package.json:L9-10 — `npm run migrate` / `npm run db:check` zeigen auf nicht existierende Skripte; kein `engines`-Feld; veraltete Beschreibung
**Urteil:** BESTÄTIGT (Severity unverändert; AP6-59/W21 hierher zusammengeführt)
**Beleg:** `ls server/scripts/` → nur `deploy-phase8.sh install-pg.sh make-admin.sh migrate.sh`; `scripts/migrate.js`/`scripts/db-check.js` fehlen → `MODULE_NOT_FOUND`. Kein `engines.node` trotz Node-20-Prod/CI und Node ≥ 20-Check in deploy-phase8.sh:L134; L4 „14 roles“ vs. `server.js:L4814` „ESCO-dynamic“.
**Auswirkung:** Kein funktionierender Einstieg für Migrationen (verschärft AP6-01); keine maschinell prüfbare Node-Untergrenze.
**Empfehlung:** `scripts/migrate.js` bereitstellen (Grundlage für AP6-01) oder Einträge entfernen; `"engines": { "node": ">=20" }`; Beschreibung aktualisieren.

### AP6-11 [S4] [Korrektheit] server/sql/migration-phase-2.5.sql:L85-87, migration-phase-3a.sql:L86-88 — Zähler als Spalten auf der zeilenbasierten `stats`-Tabelle angelegt
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `stats` ist `(metric PK, value, updated_at)` (schema.sql:L177-181); `stats.increment()`/`getAll()` (db.js:L1321-1334) arbeiten ausschließlich zeilenbasiert. Die sechs per `ALTER TABLE stats ADD COLUMN` angelegten INTEGER-Spalten werden nirgends gelesen/geschrieben.
**Auswirkung:** Irreführendes Schema; sechs tote Spalten.
**Empfehlung:** Aufräum-Migration `DROP COLUMN IF EXISTS …`; Metriken als `INSERT … ON CONFLICT DO NOTHING` wie schema.sql:L183-189.

### AP6-12 [S4] [Korrektheit] server/scripts/make-admin.sh:L107-109 — `shift 2` ohne zweites Argument beendet das Skript stumm
**Urteil:** BESTÄTIGT (Severity unverändert; der zweite Teil des Rohbefunds — unmaskiertes `USER_ID` — ist Gegenstand von AP6-14)
**Beleg:** Repro mit Kopie des Skripts und Dummy-`.env`: `make-admin.sh --grant` → keine Ausgabe, `exit=1`. Ursache: `bash -c 'set -e; set -- a; shift 2; echo reached'` → `exit=1` ohne „reached“; die vorgesehene Meldung L117-119 wird nie erreicht.
**Auswirkung:** Fehlbedienung ohne Diagnose.
**Empfehlung:** `shift; shift` bzw. `shift $(( $# >= 2 ? 2 : 1 ))`.

### AP6-13 [S2] [Sicherheit] server/scripts/make-admin.sh:L146-157 — `--grant-recent` vergibt Admin-Rechte an „wer auch immer zuletzt ein Token bekam“ (TOCTOU auf öffentlichem Dienst)
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilen korrigiert von L380-391 auf L146-157)
**Beleg:** L147-149 `SELECT user_id FROM tokens WHERE expires_at > NOW() AND user_id IS NOT NULL ORDER BY issued_at DESC LIMIT 1`, L155-157 direkt `INSERT INTO admins` — ohne Anzeige-vor-Schreiben, ohne Bestätigung, ohne Soll-ID. `tokens` wird von jedem Login auf hhttps.org befüllt. Der Modus ist in L11 und L160-162 als Standardweg beworben.
**Auswirkung:** Ein fremder Nutzer, der sich zwischen Operator-Login und Skriptlauf anmeldet, erhält vollen Admin-Zugriff (Client-Freigabe/Sperre, Audit-Log). Rein zeitlicher Zufall genügt.
**Empfehlung:** `--grant-recent` entfernen oder ermittelte `user_id` (+ `method`, `issued_at`) anzeigen und per `read` bestätigen lassen; bevorzugt nur `--grant <USER_ID>` mit ID aus `/hhttps/whoami`.

### AP6-14 [S3] [Sicherheit] server/scripts/make-admin.sh:L156,L167,L174,L179 — `USER_ID` wird unescaped in SQL interpoliert (NOTE wird escaped, USER_ID nicht)
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilen korrigiert von L390/401/408/413)
**Beleg:** `'${NOTE//\'/\'\'}'` (L156/L167) vs. `'${USER_ID}'` roh in L156, L167, L174, L179. `-v ON_ERROR_STOP=1` verhindert keine Injektion in `-c`.
**Auswirkung:** Kein Remote-Pfad (user_id ist serverseitig `uuid()`), aber ein manipulierter Wert aus einem Support-Ticket ergibt beliebiges SQL als Tabellen-Owner.
**Empfehlung:** `USER_ID` auf `^[A-Za-z0-9_:-]{1,64}$` validieren und per `psql -v uid="$USER_ID"` / `:'uid'` binden.

### AP6-15 [S3] [Sicherheit] server/db.js:L861-899, L916-942 — E-Mail-Bestätigungstoken der OAuth-Clients im Klartext gespeichert und nachgeschlagen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `createDraft` (L869/L881), `refreshEmailToken` (L919), `updateContactEmail` (L932) schreiben `emailToken` roh; `getByEmailToken` (L889) `WHERE email_token = $1`. Aufrufer server.js:L4164/L4506 `randomToken(24)` ungehasht. Gegenbeispiel im selben Projekt: `email_verifications` speichert nur `sha256` (email.js:L379-381). Index `idx_oauth_clients_email_token` (migration-phase-3b.sql:L115-117).
**Auswirkung:** Lesezugriff auf DB/Backup (`/root/hhttps-backups`, pg_dump) genügt, um fremde Clients auf `unverified` zu heben.
**Empfehlung:** Nur `sha256(token)` speichern/vergleichen, zentral in den vier Methoden; Bestandszeilen per Migration invalidieren.

### AP6-16 [S3] [Sicherheit] server/db.js:L656-668 — `webhooks.list()` liefert das HMAC-Secret jedes Webhooks an den (unauthentifizierten) Aufrufer
**Urteil:** BESTÄTIGT (Severity unverändert; Endpunkt-Auth gehört zu AP5)
**Beleg:** L662 `secret: r.secret`; einziger Konsument `listWebhooks()` (webhooks.js:L41-43) → `GET /hhttps/webhooks` (server.js:L3889-3891) gibt das Array unverändert aus, nur `limit.webhooks` (20/h, L430), keine Auth.
**Auswirkung:** Anonyme Aufrufer erhalten alle Webhook-URLs samt Secret und können korrekt signierte Events (`HHTTPS-Webhook-Sig`) an fremde Endpunkte fälschen.
**Empfehlung:** `secret` aus `list()` entfernen (nur `findForEvent` behält es); Secret nur beim Anlegen einmal zurückgeben; Endpunkt-Auth in AP5.

### AP6-17 [S3] [Sicherheit] server/scripts/migrate.sh:L77-84, scripts/deploy-all.sh:L414-424 — `.env` wird als Shell gesourct; alle Secrets landen in pm2-Prozessumgebung und `dump.pm2`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** migrate.sh:L77 und deploy-all.sh:L414 `set -a; source .env; set +a`, danach `pm2 restart --update-env`/`pm2 start` + `pm2 save` (L80-84 bzw. L417-424). make-admin.sh:L46-48 begründet selbst, warum `source` falsch ist (unquotierte Werte mit Leerzeichen → Kommandoausführung). Der Server lädt `.env` ohnehin per dotenv.
**Auswirkung:** DB_PASSWORD, SMTP_PASS, Pepper, GITHUB_CLIENT_SECRET, EUDI_VERIFIER_SECRET dauerhaft in `~/.pm2/dump.pm2` und `/proc/<pid>/environ`; Rotation in `.env` greift nicht bzw. wird überschrieben; `.env`-Zeilen wie `SMTP_FROM_NAME=HHTTPS Open Issuer` brechen das Deploy.
**Empfehlung:** `source .env` entfernen; skripteigene Werte per `env_get` lesen; `pm2 start` ohne exportierte Secrets.

### AP6-18 [S3] [Sicherheit] scripts/deploy-all.sh:L269-281, L367-381 — Nginx `add_header` in `location`-Blöcken verwirft die serverweiten Security-Header
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Nginx-Semantik: `add_header` wird nur vererbt, wenn der innere Block kein eigenes `add_header` hat. `location = /spec` (L276-281) setzt `Content-Type`/`Cache-Control` → verliert L269-272 (nosniff, X-Frame-Options, Referrer-Policy, HSTS). iamhmn.org `location /` (L377-381) setzt `Cache-Control` → die gesamte Site verliert L367-370. Das Skript ist die einzige Quelle der Nginx-Konfiguration.
**Auswirkung:** iamhmn.org und hhttps.org/spec ohne HSTS/Frame-Schutz.
**Empfehlung:** Header in jeder `location` mit eigenem `add_header` wiederholen bzw. `include security-headers.conf;`; `Cache-Control` über `expires` setzen.

### AP6-19 [S3] [Sicherheit] .github/workflows/ci.yml:L1-30, L44, L94-105 — CI ohne Test-/Lint-/Audit-Gate; `npm ci` fällt still auf `npm install` zurück; kein `permissions:`; Actions per Major-Tag; `docs-lint` kann nie fehlschlagen
**Urteil:** BESTÄTIGT (Severity unverändert; AP6-51/W13 hierher zusammengeführt)
**Beleg:** L23 `npm ci --omit=dev || npm install --omit=dev` (Lockfile-Mismatch → ungepinnte Installation ohne Integritätsprüfung); L25-30 nur `node --check` über `*.js` (die `.mjs`-Tests werden nicht einmal syntaxgeprüft); kein `npm test` (203 Tests), kein `npm run lint`, kein `npm audit`; kein `permissions:`-Block (L1-8); Actions `@v4`/`@v5`/`@v2` (L14, L17, L36, L54, L57, L62, L67); L44 `sudo apt-get install -y nodejs` statt `setup-node`; L102 „Don't fail yet“ — `docs-lint` ist permanent grün.
**Auswirkung:** Sicherheits- und Funktionsregressionen (inkl. bekannter `npm audit`-Findings) werden auf `main` nicht erkannt; ein PR mit manipuliertem Lockfile wird grün; Third-Party-Action-Tags mit Default-Token-Rechten.
**Empfehlung:** `npm ci` ohne Fallback; Job `server-test` mit `services: postgres:16`, `TEST_PG_HOST`, `EMAIL_DEV_MODE=1`, `npm run lint`, `npm test`, `npm audit --audit-level=high`; `permissions: contents: read`; Actions per SHA pinnen; `docs-lint` scharf schalten oder entfernen.

### AP6-20 [S4] [Sicherheit] server/scripts/deploy-phase8.sh:L107-111 + scripts/deploy-privacy-pass.sh:L386-389 — lokale Kopie der `docker-compose.yaml` landet im Repo-Arbeitsverzeichnis; `git add -A && git push` würde sie pushen
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: erfordert die Kette `--link` (einmalig) + späterer `deploy-privacy-pass.sh`-Lauf mit bestätigtem Commit; außerdem enthält die getrackte `server/eudi-verifier/docker/docker-compose.yaml` bereits Keystore-Passwörter im Klartext (L34, L36; Issue #32), sodass der Zusatzschaden auf lokal abweichende Werte beschränkt ist)
**Beleg:** deploy-phase8.sh:L109 `cp -a "$INSTALL_DIR/$DC" "$SRC_DIR/${DC}.local-${TS}"` (im Repo); `.gitignore` kennt `*.bak`, `*.backup`, `_backup_*/`, nicht `*.local-*`; deploy-phase8-Preflight L127 (`--untracked-files=no`) und L129-130 blockieren die untracked Datei nicht; deploy-privacy-pass.sh:L387-389 `git add -A; git commit; git push origin main` (interaktiv oder `ALLOW_COMMIT=1`).
**Auswirkung:** Lokale Secrets/Extras (`force-verify-client.mjs`, `developers/`, L100-103) können nach GitHub gelangen.
**Empfehlung:** Kopien nach `$BACKUP_ROOT`; `*.local-*` in `.gitignore`; `git add -A` durch explizite Pfade ersetzen oder Commit/Push aus dem Deploy entfernen (siehe AP6-45).

### AP6-21 [S4] [Sicherheit] server/scripts/deploy-phase8.sh:L168, L192, L216 — `PGPASSWORD` für die gesamte Skriptlaufzeit exportiert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L168 `export PGPASSWORD="$DB_PASSWORD"`; danach `npm ci` (L192, Install-Skripte sehen die Variable) und `pm2 restart --update-env` (L216) + `pm2 save` (L221).
**Auswirkung:** DB-Passwort in Umgebung fremder npm-Skripte und in `dump.pm2`.
**Empfehlung:** `PSQL=(env PGPASSWORD=… psql …)` bzw. pro Aufruf setzen; `npm ci --ignore-scripts` wo möglich.

### AP6-22 [S4] [Sicherheit] server/scripts/install-pg.sh:L47, L55; scripts/deploy-all.sh:L79, L89 — DB-Passwort als Kommandozeilenargument an psql
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilen korrigiert: install-pg.sh hat 124 Zeilen, die im Rohbefund genannten L157/L165/L189-191 existieren nicht — gemeint sind L47/L55 (ALTER/CREATE USER) und L79-81 (Superuser-Fallback, siehe AP6-08))
**Beleg:** `psql -c "ALTER USER … WITH PASSWORD '${DB_PASSWORD}';"` in argv, kurzzeitig via `ps`/`/proc/*/cmdline` lesbar.
**Auswirkung:** Gering auf Single-User-VPS.
**Empfehlung:** `psql -v pw=… -c "ALTER USER hhttps WITH PASSWORD :'pw'"` oder per stdin.

### AP6-23 [S4] [Sicherheit] scripts/deploy-all.sh:L51 — `curl … | bash` (NodeSource) ohne Prüfsumme/Pinning
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L51 `curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1` als root.
**Auswirkung:** Supply-Chain-Risiko beim Erstdeploy.
**Empfehlung:** Distro-Paket oder NodeSource-Repo mit GPG-Key manuell; Skript vorab laden und Hash prüfen.

### AP6-24 [S4] [Sicherheit] scripts/deploy-privacy-pass.sh:L324-371 (auch scripts/deploy-all.sh:L445) — `curl -k` deaktiviert TLS-Verifikation bei den Live-Checks
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Alle Verifikationsaufrufe nutzen `-sk`, auch gegen `https://hhttps.org`; deploy-all.sh:L445 ebenso.
**Auswirkung:** Kaputtes/fremdes Zertifikat wird als „grün“ gemeldet.
**Empfehlung:** `-k` entfernen.

### AP6-25 [S4] [Sicherheit] scripts/force-verify-client.mjs:L22, L41 + server/scripts/deploy-phase8.sh:L100 — Prod-fähiges „Verified-Badge erzwingen“-Tool mit Default-Client wird ins Live-/Repo-Verzeichnis kopiert
**Urteil:** BESTÄTIGT (Severity unverändert; Zeilen korrigiert: die Datei hat 52 Zeilen — Default-Client L22 `'songbird-2423'`, ungeguardeter `adminApprove` L41; `oauthClients.adminApprove` (db.js:L999-1011) hat keinerlei Status-Bedingung)
**Beleg:** Einziger Schutz ist `console.warn` (L25-26). deploy-phase8.sh:L100 nimmt `force-verify-client.mjs` bei `--link` als „lokales Extra“ ins Repo-Verzeichnis, wo es neben `.env` sofort lauffähig ist.
**Auswirkung:** Versehentlicher Aufruf auf Prod vergibt ein unverdientes Vertrauenssiegel.
**Empfehlung:** Guard `NODE_ENV==='production'` → Abbruch, Default-Client entfernen, `--yes-i-know`; nicht auf Prod kopieren (siehe AP6-58).

### AP6-26 [S4] [Sicherheit] scripts/patch-coop-popups.sh:L31-33, L40-110; scripts/patch-pseudonym-stage1.sh:L35-279 — Live-Patcher für `/var/www/hhttps/server.js`, inhaltlich obsolet oder driftend
**Urteil:** BESTÄTIGT (Severity unverändert S4; AP6-44/W6 hierher zusammengeführt)
**Beleg:** Beide Skripte patchen die Live-Datei per Python-Textersetzung und `pm2 restart`. Dry-Run gegen eine Kopie des aktuellen `server.js`: `patch-coop-popups.sh --dry-run` → „already patched — per-route unsafe-none present“ (Marker `COOP-POPUP-ROUTE` steht in server.js:L1420, `popupCoop` L1429-1433/L1530); `patch-pseudonym-stage1.sh --dry-run` → `ERROR: drift — anchors not found exactly once` (zwei von mehreren Ankern fehlen; der Anker `touchLastUsed(client_id)`/`stats.increment('oauth_authorizations')` existiert dagegen noch, server.js:L1625-1626). Der `pseudo:<code>`-Umweg ist laut server.js:L1597 „gone (W-7)“.
**Auswirkung:** Skripte tun nichts (COOP) oder brechen ab (Pseudonym) — bzw. würden bei zufällig passenden Ankern eine bewusst entfernte Mechanik reaktivieren; Hotfix-Historie außerhalb von Git.
**Empfehlung:** Beide Skripte löschen; Hotfixes nur über `deploy-phase8.sh` aus `main`.

### AP6-28 [S4] [Sicherheit] server/db.js:L1213-1233, L1245-1253 — OAuth-Authorization-Codes im Klartext gespeichert
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `create` schreibt `code` roh als PK, `claim` sucht `WHERE a.code = $1`. Codes sind 60 s gültig (L1211), single-use, PKCE-gebunden.
**Auswirkung:** Begrenzt (60-s-Fenster, PKCE); widerspricht der Hash-Praxis von `email_verifications`/`pp_email_pending`.
**Empfehlung:** `sha256(code)` speichern/vergleichen.

### AP6-29 [S3] [Performance] server/db.js:L90-93, L206-209, L263-266, L291-294, L313-316, L640-643 — sechs ungecachte `COUNT(*)` pro Aufruf von `/hhttps/info` (vom App-Rate-Limit ausgenommen)
**Urteil:** BESTÄTIGT (herabgestuft von S2 auf S3: der Reviewer hat die Nginx-Ebene übersehen — `scripts/deploy-all.sh:L183` definiert `hhttps_api` mit 60 r/min pro IP und L302-303 wendet sie auf `location /hhttps/` an, sodass der geschilderte Pool-Ausfall nicht mit „3–4 Aufrufen“ von einer IP erreichbar ist; die linear wachsenden Scan-Kosten und das Fehlen eines Caches bleiben)
**Beleg:** server.js:L802-805 `Promise.all([credentials.count(), tokens.count(), refreshTokens.count(), sessions.count(), revokedTokens.count(), machineOperators.count()])` bei jedem Request; L435 nimmt `/hhttps/info` vom `limit.global` aus; `/hhttps/stats` (L4735-4744) dasselbe plus `rolesDeclared.distribution()`. Pool `max: 20`, `connectionTimeoutMillis: 5000` (db.js:L36-38). `credentials`/`revoked_tokens` wachsen dauerhaft (schema.sql:L94 „permanent“).
**Auswirkung:** Sechs parallel belegte Pool-Verbindungen pro Hit; Kosten steigen mit dem Datenbestand; ohne Cache trivial teuer, mit verteilten Quellen weiterhin ein Ausfallhebel.
**Empfehlung:** Zähler mit kurzem In-Memory-Cache (30–60 s, geteiltes Promise) kapseln oder `pg_stat_user_tables.n_live_tup` nutzen; `/hhttps/info` nicht vom App-Rate-Limit ausnehmen (Hinweis an AP1).

### AP6-32 [S3] [Performance] server/privacy-pass/migrations.js:L65-77, L106-113, L17-28 — `pp_email_pending`, `pp_redeemed`, `pp_issuance_log` ohne Cleanup
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rn DELETE server/privacy-pass` → nur Consume-Pfade (verifications.js:L110 `DELETE FROM pp_email_pending WHERE token_hash = $1 AND expires_at > NOW()`, L148 Recovery-Codes). Abgelaufene, nie geklickte `pp_email_pending`-Zeilen, alle `pp_redeemed`-Nonces und das Append-only-Log `pp_issuance_log` (Rate-Limit-Query issuance.js:L164-173 liest nur das letzte Fenster) werden nie entfernt; weder `cleanup_expired()` noch `cleanupExpired()` kennen die Tabellen.
**Auswirkung:** Drei Tabellen wachsen unbegrenzt; `pp_email_pending_expires_idx`/`pp_redeemed_at_idx` existieren nur für einen Cleanup, der nicht läuft.
**Empfehlung:** In `cleanupExpired()`: `pp_email_pending` nach `expires_at`, `pp_redeemed` nach maximaler Token-Lebensdauer, `pp_issuance_log` nach größtem Rate-Limit-Fenster löschen.

### AP6-33 [S3] [Performance] server/db.js:L30-39 — Pool ohne `statement_timeout`/`query_timeout`
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Nur `max`, `idleTimeoutMillis`, `connectionTimeoutMillis` gesetzt. Kandidaten für Langläufer: die COUNT(*)-Scans (AP6-29) und die unbatched DELETEs in `cleanup_expired()` (schema.sql:L199-203) nach längerem Stillstand; `pg_dump` in deploy-phase8.sh:L180 auf demselben Host.
**Auswirkung:** Hängende Queries blockieren Verbindungen unbegrenzt; nach 20 belegten Verbindungen antwortet der Server nur noch mit Connection-Timeouts.
**Empfehlung:** `statement_timeout`/`query_timeout` (z. B. 10 s) in der Pool-Konfiguration; Cleanup mit eigenem höherem Timeout und Batching.

### AP6-34 [S4] [Performance] server/sql/schema.sql:L24, L48, L78, L92, L102, L119 — sechs Indizes ohne Query-Nutzung auf Hot-Insert-Tabellen
**Urteil:** BESTÄTIGT (Severity unverändert; Anzahl korrigiert: der Rohbefund sagt „fünf“, listet aber sechs)
**Beleg:** grep über db.js, server.js, privacy-pass/*, scripts: keine Query filtert `credentials.registered_at` (privacy-pass/verifications-api.js:L217-221 nutzt es nur als `ORDER BY` innerhalb eines `WHERE user_id = $1`-Subsets), `sessions.user_id`, `tokens.user_id` (make-admin.sh:L133-143 gruppiert nach `user_id` unter `expires_at`-Filter — kein Lookup), `refresh_tokens.user_id`, `revoked_tokens.revoked_at` oder `email_verifications.email`.
**Auswirkung:** Zusätzliche B-Tree-Pflege bei jedem Login-Insert und dem 5-Minuten-Massen-DELETE; Index-Bloat.
**Empfehlung:** In Produktion `pg_stat_user_indexes.idx_scan` prüfen und ungenutzte Indizes per Migration droppen.

### AP6-35 [S4] [Performance] server/sql/schema.sql:L163-174 — `webhook_deliveries` ohne Retention
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `grep -rn webhook_deliveries server` → nur der INSERT in db.js:L687; keine Lese-Query, kein DELETE.
**Auswirkung:** Unbegrenztes Wachstum mit jedem Event × Retry; zwei nur gepflegte, nie gelesene Indizes.
**Empfehlung:** Retention (z. B. 30 Tage) in `cleanupExpired()`.

### AP6-36 [S4] [Performance] server/db.js:L685-699, L701-708 — Webhook-Statistik in 2–3 Roundtrips statt einem Statement
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `recordDelivery`: INSERT + UPDATE sequentiell ohne Transaktion; `deactivateIfFailing`: SELECT, dann UPDATE.
**Auswirkung:** Doppelte Latenz pro Zustellung; harmloses Konsistenzfenster.
**Empfehlung:** `UPDATE … WHERE failures >= $2 RETURNING 1`; INSERT+UPDATE als CTE.

### AP6-37 [S4] [Performance] server/db.js:L372-383 + server/privacy-pass/migrations.js:L117-131 — DDL bei jedem Prozessstart
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `ensureCodeColumn()` feuert bei Import ein `ALTER TABLE` (ACCESS EXCLUSIVE, auch als No-op); `runMigrations()` schickt bei jedem Boot fünf DDL-Blöcke. `BOOT_DDL_FILES` (db.js:L432-487) zeigt bereits das Applied-Check-Muster.
**Auswirkung:** Kurze Exklusiv-Locks bei jedem `pm2 restart`.
**Empfehlung:** Beides in `BOOT_DDL_FILES` mit Applied-Check überführen (deckt sich mit AP6-06/AP6-07/AP6-40).

### AP6-38 [S4] [Performance] server/scripts/deploy-phase8.sh:L216, scripts/deploy-privacy-pass.sh:L302, server/scripts/migrate.sh:L80 — `pm2 restart` im Fork-Modus: Downtime bei jedem Deploy
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Alle `pm2 start server.js --name …` (deploy-phase8.sh:L219, migrate.sh:L82, deploy-all.sh:L420) ohne `-i` → Fork-Modus; `pm2 restart` beendet den einzigen Prozess; deploy-phase8.sh:L222-226 wartet bis 30 s auf `/hhttps/info`, währenddessen laufen Boot-DDL und PP-Migrationen ohne lauschenden Prozess.
**Auswirkung:** Harter Ausfall im Sekundenbereich pro Deploy; laufende WebAuthn-/OAuth-Flows brechen ab.
**Empfehlung:** Cluster-Modus (`-i 1`) + `pm2 reload`, oder Wartungsantwort in nginx während des Neustarts.

### AP6-40 [S3] [Wartbarkeit] server/db.js:L372-383, L432-439; server/privacy-pass/migrations.js:L117-138; server/sql/*.sql — vier konkurrierende Schema-Mechanismen ohne gemeinsames Ledger
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** (1) `ensureCodeColumn` bei Import, Fehler nur geloggt; (2) `BOOT_DDL_FILES` mit Applied-Check und Boot-Abbruch; (3) Privacy-Pass-`MIGRATIONS` bei jedem Start, Fehler nur gezählt; (4) manuelle SQL-Dateien ohne Reihenfolge-Ledger. Kommentar db.js:L325 verweist auf ein nicht existierendes „ensureSchema below“. Folge bereits eingetreten: Issue #7 (`key_jkt` ohne Migration, migration-phase-4b Header) und AP6-01.
**Auswirkung:** Unvorhersehbares Boot-Verhalten (abbrechen vs. weiterlaufen), Herkunft von Spalten nicht ablesbar.
**Empfehlung:** Ein Mechanismus (Ledger-basiert, siehe AP6-01) mit einheitlicher Abbruchsemantik; `ensureCodeColumn` und PP-Migrationen dorthin überführen.

### AP6-42 [S4] [Wartbarkeit] server/db.js:L829-830, L840-841, L896-897, L1052-1053, L1067-1068, L1295 — `JSON.parse`-try/catch elfmal kopiert, obwohl `parseJsonArray()` (L577-585) existiert
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: reine Duplikation ohne Fehlverhalten; `authCodes.claim` L1256-1257 zeigt die vorhandene Alternative)
**Beleg:** Identischer Zweizeiler an sechs Stellen (elf Zeilen); `listByOwner` (L834-844) und `listAllByOwner` (L1059-1071) sind bis auf den Namen identisch.
**Auswirkung:** Formatänderung (z. B. `jsonb`) muss sechsfach nachgezogen werden; elf ESLint-Warnungen (AP6-60).
**Empfehlung:** `hydrateClient(row)` mit `parseJsonArray` für beide Spalten; `listByOwner` streichen.

### AP6-43 [S3] [Wartbarkeit] server/db.js:L254-257, L280-285, L601-604, L625-631, L656-678 — Rückgabeformat der Zugriffsobjekte inkonsistent (camelCase-normalisiert vs. rohe snake_case-Rows)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `credentials`, `sessions`, `challenges`, `identityAnchors`, `identityClaimsCache`, `webhooks.list` normalisieren; `tokens.get`, `refreshTokens.get`, `rolesDeclared.get`, `machineOperators.get`, `signatures.*`, `oauthClients.*`, `authCodes.claim`, `adminActions.*` geben `rows[0]` roh zurück. `webhooks.list` (L658-667) und `findForEvent` (L674-677) mappen dieselben Felder zweimal mit unterschiedlichem Umfang.
**Auswirkung:** Aufrufer müssen pro Tabelle die Konvention kennen; die DB-Schicht kapselt das Schema nicht.
**Empfehlung:** Einheitliches `_normalize` bzw. generischer snake→camel-Mapper.

### AP6-45 [S3] [Wartbarkeit] scripts/deploy-privacy-pass.sh:L132-145, L147-278, L294, L386-393 — Deploy-Skript mit wirkungsloser Sync-Logik, veralteten Annahmen und Commit/Push aus dem Deploy
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L137 rsync überschreibt `email.js`/`db.js`, L139 vergleicht dann mit `${f}.bak`, das nie erzeugt wird → `cmp` schlägt immer fehl → L140 legt bei jedem Lauf `.bak.<ts>` der bereits überschriebenen Datei an. L153-155 prüfen Import/Init/Mount, die seit langem in `main` sind (server.js:L62-63, L523, L4784). L294/L345/L409/L417-418 sprechen von „501-Stub“/„TODO-Blöcke“, obwohl `@cloudflare/voprf-ts` fest in package.json:L16 hängt. L386-389 `git add -A && git commit && git push origin main`.
**Auswirkung:** Irreführende Operator-Führung, `.bak`-Müll im Live-Verzeichnis, ungeprüfte Pushes nach `main` (siehe AP6-20).
**Empfehlung:** Skript entfernen — `deploy-phase8.sh` deployt `server/` inkl. `privacy-pass/`.

### AP6-46 [S4] [Wartbarkeit] server/scripts/migrate.sh:L12-14, L24-27, L69, L77 — veraltetes ZIP-basiertes v4.0→v4.1-Migrationsskript
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: totes Skript, das mangels ZIP sofort in `fail` läuft; das `source .env`-Problem ist in AP6-17 erfasst)
**Beleg:** Erwartet `HumanProof_HHTTPS_v4.1.zip` (L14, L24-27), das im Repo nicht existiert; `npm install --production` (L69, deprecated); der Name „migrate“ ist dreifach belegt (ZIP-Upgrade, fehlendes `scripts/migrate.js`, SQL-Migrationen).
**Auswirkung:** Verwirrung, welches Skript wofür ist.
**Empfehlung:** Löschen; Namen `migrate` für den Migrationslauf aus AP6-01 freimachen.

### AP6-47 [S3] [Wartbarkeit] scripts/deploy-all.sh:L75-101, L120-152 — PostgreSQL-Provisionierung und .env-Schreiben sind eine driftende Kopie von install-pg.sh:L42-70, L84-104
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Nahezu zeilengleiche Blöcke (User/DB/Grants, .env-Zeilen, Schema mit Superuser-Fallback); Drift bereits sichtbar (`ask` vs. `read -p`, `RESET_PW` nur in deploy-all, `grep|cut`-Passwortlesen L145 nur dort). `migrate.sh:L73` ruft install-pg.sh, deploy-all seine Kopie.
**Auswirkung:** Die für AP6-01 nötige Änderung muss an zwei Stellen erfolgen.
**Empfehlung:** deploy-all Schritt 2/3 auf `bash server/scripts/install-pg.sh "$SERVER_DIR"` reduzieren.

### AP6-48 [S3] [Wartbarkeit] server/scripts/deploy-phase8.sh:L59; server/scripts/make-admin.sh:L51-70; server/scripts/migrate.sh:L77; scripts/deploy-all.sh:L145, L414 — vier verschiedene .env-Parser mit unterschiedlicher Semantik
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `envval` (entfernt alle Quotes, keine Kommentare, kein `export`), `env_get` (vollständig, mit Begründung gegen `source`), `set -a; source .env` (zweimal), `grep ^DB_PASSWORD | cut -d= -f2` (bricht bei `=` im Passwort).
**Auswirkung:** Derselbe `.env`-Wert wird je Skript anders interpretiert.
**Empfehlung:** `env_get` nach `scripts/lib/env.sh` auslagern und überall sourcen; `source .env` entfernen (AP6-17).

### AP6-49 [S3] [Wartbarkeit] server/sql/migration-phase-5-external-verify.sql:L22-64 (und 4, 6, 7, portal) — Migrationsdateien uneinheitlich bezüglich Ownership/Grants und Ausführungsrolle; Doku widerspricht sich
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** OWNER/GRANT-Block in 2.5 (L101-109), 3a (L91-101), 3b (L173-186), 8 (L88-96); keiner in 4, 5, 6, 7, portal (`grep -c hhttps migration-phase-5…` = 0). 6 (L19-23), 7 (L20-22), 8 (L34-36) verlangen „AS THE APP USER“; 5 legt zwei Tabellen an (L22, L54) ohne Grant-Block und ohne Hinweis; CHANGES.md:L77-78 dokumentiert `sudo -u postgres psql -f migration-phase-3b.sql`. 3b/3b.1/portal in `BEGIN…COMMIT`, die übrigen nicht; 5 nutzt `DO $$ … information_schema` (L40-50) statt `ADD COLUMN IF NOT EXISTS`.
**Auswirkung:** Phase 5 nach CHANGES.md-Muster als `postgres` eingespielt → Tabellen ohne App-Rechte (Repro-Fehlerbild wie AP6-08: `permission denied`).
**Empfehlung:** Konvention „immer als App-User, keine Grant-Blöcke“ festlegen, in allen Dateien gleich dokumentieren, CHANGES.md korrigieren — entfällt mit dem Migrationslauf aus AP6-01.

### AP6-50 [S4] [Wartbarkeit] server/scripts/make-admin.sh:L16-21, L160-162 — Operator-Hinweis zur Identitätsstabilität ist seit Phase 8 falsch
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: reine Doku-/Meldungsaussage ohne funktionale Wirkung)
**Beleg:** Hinweis: „An e-mail-only sign-in mints a fresh uuid per session“. Seit Phase 8 liefert `identityAnchors.resolveOrCreate` (db.js:L500-524; migration-phase-8:L43-49 `user_id … stable`) für dieselbe E-Mail dieselbe `user_id`; server.js:L2783 „the session is rebound to them (AK-2)“, L2803.
**Auswirkung:** Operatoren registrieren unnötig Passkeys bzw. misstrauen korrekt vergebenen Rechten.
**Empfehlung:** Hinweisblock und Meldung auf das Anker-Modell umschreiben.

### AP6-52 [S4] [Wartbarkeit] server/eslint.config.js:L21 — Browser-Globals für den gesamten Server-Code freigeschaltet
**Urteil:** BESTÄTIGT (herabgestuft von S3 auf S4: ESLint läuft derzeit ohnehin nicht in CI (AP6-19); Wirkung beschränkt sich auf lokale Lint-Läufe)
**Beleg:** `globals: { ...globals.node, ...globals.browser }` gilt für alle nicht ignorierten Dateien (`public/**` ist ignoriert, L10), also für db.js, server.js, email.js und alle Tests; `no-undef` kann `window`/`document`/`localStorage`-Tippfehler im Node-Code nicht mehr melden.
**Auswirkung:** Ein wesentlicher Teil von `js.configs.recommended` ist für den Server wirkungslos.
**Empfehlung:** `globals.browser` nur in einem separaten Block für `privacy-pass/public/**`/`test/e2e/**`.

### AP6-54 [S4] [Wartbarkeit] server/db.js:L1-15, L325, L490 — veralteter/irreführender Modul-Header und Kommentare
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L5 „prepared statements“ (es sind parametrisierte Queries ohne `name:`), L12 „DB_PASSWORD — required“ (nirgends geprüft, L35 übergibt `undefined`), L14 „Reconnects automatically“ (Pool ersetzt tote Clients, wiederholt keine Query), L325 „see ensureSchema below“ (Funktion heißt `ensureCodeColumn`), L490 `ensurePhase8Schema`-Alias nur noch in `db-phase8.test.mjs:L31,L169` genutzt.
**Auswirkung:** Falsche Erwartungen an Fehlerverhalten und Konfiguration.
**Empfehlung:** Header aktualisieren; Alias entfernen und Test auf `ensureBootSchema` umstellen.

### AP6-55 [S4] [Wartbarkeit] server/db.js:L112, L148, L326, L545, L1211, L701, L36-38 — TTL-/Schwellen-Defaults als Magic Numbers, teils doppelt zu den Aufrufern
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** `ttlMs = 120_000`, `600_000`, `900_000`, `7*24*3600*1000`, `ttlSec = 60`, `threshold = 10`, Poolgrößen; server.js übergibt eigene Werte (L2451 `120_000`, L2524 `90_000`, L2696/L2737 `900_000`).
**Auswirkung:** Wirksame Lebensdauer nur durch Lesen zweier Dateien ermittelbar.
**Empfehlung:** Benannte Konstanten am Modulanfang bzw. `config.js`.

### AP6-56 [S4] [Wartbarkeit] server/sql/schema.sql:L55, L208-209 — veraltete Kommentare im Schema
**Urteil:** BESTÄTIGT (Severity unverändert; der Teil „tote `stats`-Spalten“ ist in AP6-11 erfasst)
**Beleg:** L55 `context 'registration' | 'authentication'` — tatsächlich auch `'email-pending'` (server.js:L2874) und `'pop'` (pop-verify.js); L208-209 „real grants happen in install-pg.sh“ — install-pg.sh vergibt nur `GRANT ALL ON SCHEMA public` (L69), keine Tabellen-Grants.
**Auswirkung:** Falsche Modellannahmen für neue Entwickler.
**Empfehlung:** Kommentare korrigieren/entfernen.

### AP6-57 [S4] [Wartbarkeit] scripts/deploy-all.sh:L23-28 (+ deploy-privacy-pass.sh:L43-48, migrate.sh:L16-20, install-pg.sh:L18-23, deploy-phase8.sh:L51-55) — Farb-/Log-Präambel fünffach kopiert, uneinheitliche Shell-Optionen, deprecated npm-Flag
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** Identische `G= Y= R= B= N=`/`ok/warn/step`-Blöcke; `set -e` (deploy-all L10, deploy-privacy-pass L31) vs. `set -euo pipefail` (übrige); `npm install --production` (deploy-all L155, migrate.sh L69) vs. `npm ci --omit=dev` (deploy-phase8 L192).
**Auswirkung:** Verhalten bei unset Variablen/Pipes differiert; Korrekturen fünffach.
**Empfehlung:** `scripts/lib/common.sh`; überall `set -euo pipefail`, `npm ci --omit=dev`.

### AP6-58 [S4] [Wartbarkeit] scripts/force-verify-client.mjs:L9-11, L20 + server/scripts/deploy-phase8.sh:L100 — Skript liegt unter `scripts/`, erwartet aber, aus `server/` zu laufen
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** L20 `import * as db from './db.js'`, L9-11 „cd /var/www/hhttps“; deploy-phase8.sh:L100 kopiert eine Kopie aus `INSTALL_DIR` ins Repo, obwohl die Datei bereits im Repo liegt.
**Auswirkung:** Zwei potenziell divergierende Kopien; aus dem Repo-Pfad nicht ausführbar.
**Empfehlung:** Nach `server/scripts/`, Import `../db.js`, Eintrag in deploy-phase8.sh:L100 entfernen (siehe AP6-25).

### AP6-60 [S4] [Wartbarkeit] server/db.js:L829, L830, L840, L841, L896, L897, L1052, L1053, L1067, L1068, L1295 — ESLint-Sammelfinding: 11 × `no-unused-vars` (`'e' is defined but never used`)
**Urteil:** BESTÄTIGT (Severity unverändert)
**Beleg:** docs/review/ap/eslint-output.txt, Abschnitt `server/db.js` — exakt die elf Zeilen der `catch (e)`-Klauseln aus AP6-42.
**Auswirkung:** Lint-Rauschen.
**Empfehlung:** `catch {` (optional catch binding) oder AP6-42 umsetzen.

## Verworfen
- AP6-27 [S4] [Sicherheit] scripts/deploy-all.sh:L21, server/sql/schema.sql:L2, server/sql/migration-portal-oauth-client.sql:L46 — Persönliche E-Mail-Adresse hart im Repo → VERWORFEN: Die Adresse ist die bewusst veröffentlichte Projekt-Kontaktadresse und wird vom Server selbst an jeden anonymen Aufrufer ausgegeben (`server/server.js:L809` `contact: 'daniel.hannuschka@tweakz.de'` in `/hhttps/info`, außerdem Header L6). Es gibt keine Vertraulichkeitserwartung, die das Repo verletzen könnte; das Hardcoding ist allenfalls eine Wartbarkeits-Notiz (Rollenadresse/ENV), kein Sicherheitsbefund.

## Zusammengeführt
- AP6-30 (P2, `authCodes.cleanup()` nie aufgerufen) → in AP6-02 (gleiche Ursache; Perf-Aspekt dort ergänzt).
- AP6-31 (P3, `email_verifications` used-Zeilen + fehlender Index) → in AP6-03 (gleiche Ursache; Index-Befund dort ergänzt).
- AP6-39 (W1, Installationsskripte spielen nur schema.sql ein) → in AP6-01 (identischer Befund, identische Repro).
- AP6-41 (W3, `authCodes.cleanup()` toter Code / verstreute Cleanup-Logik) → in AP6-02.
- AP6-44 (W6, `patch-*.sh` obsolet/driftend) → in AP6-26 (gleiche Skripte, gleiche Empfehlung; Drift-Repro dort ergänzt).
- AP6-51 (W13, CI ohne test/lint/audit, `docs-lint` nie rot) → in AP6-19 (gleiche Datei, gleiche Ursache; W-Details dort ergänzt).
- AP6-53 (W15, PP-Migrationen nur gezählt, Aufruf vor `db.ping()`, dynamischer Import) → in AP6-07.
- AP6-59 (W21, tote npm-Scripts, `engines`, Beschreibung) → in AP6-10.

Dubletten in anderen Arbeitspaketen (hier Owner, dort nur vermerkt): AP2-P (erstes Finding) ≙ AP6-02; AP3-P (erstes Finding) ≙ AP6-03; AP3-P (Hinweis auf `sessions.delete`) ≙ AP6-04.

## Statistik
| Dimension | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Korrektheit (K) | 12 | 12 | 0 | 0 |
| Sicherheit (S) | 16 | 15 | 1 | 0 |
| Performance (P) | 10 | 8 | 0 | 2 |
| Wartbarkeit (W) | 22 | 16 | 0 | 6 |
| **Gesamt** | **60** | **51** | **1** | **8** |

Je Severity bestätigt: S1 0, S2 3, S3 21, S4 27.

Severity-Änderungen: herabgestuft AP6-03 (S2→S3, E-Mail liegt als sha256 vor), AP6-05 (S3→S4, latent), AP6-20 (S3→S4, Skript-Kette + Passwort bereits im getrackten File), AP6-29 (S2→S3, Nginx-Rate-Limit übersehen), AP6-42 (S3→S4), AP6-46 (S3→S4), AP6-50 (S3→S4), AP6-52 (S3→S4). Keine Hochstufung.

Bestätigte S2: AP6-01 (frische Installation bootet nicht), AP6-02 (`authCodes.cleanup()` nie aufgerufen, Klartext-E-Mail unbefristet), AP6-13 (`make-admin.sh --grant-recent` TOCTOU-Privilege-Escalation).

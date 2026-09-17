# AP6 — Performance

Geprüfte Dateien: server/db.js; server/sql/schema.sql; server/sql/migration-phase-2.5.sql; migration-phase-3a.sql; migration-phase-3a1-authcodes-text.sql; migration-phase-3b.sql; migration-phase-3b.1.sql; migration-phase-4-machine-roles.sql; migration-phase-4b-machine-key-jkt.sql; migration-phase-5-external-verify.sql; migration-phase-6-workload-identity.sql; migration-phase-7-age-group.sql; migration-phase-8-email-anchored-identity.sql; migration-portal-oauth-client.sql; server/privacy-pass/migrations.js; server/scripts/{deploy-phase8.sh,migrate.sh,install-pg.sh}; scripts/{deploy-all.sh,deploy-privacy-pass.sh}; .github/workflows/ci.yml; server/package.json; server/test/helpers/db.mjs. Zum Verständnis der Aufrufer gelesen (keine Findings dort): server/server.js, server/email.js, server/webhooks.js, server/privacy-pass/{verifications,verifier,issuance}.js, server/external-verify.js.

Stand: Zeilennummern gegen den aktuellen Arbeitsstand geprüft (`sed -n` / `grep -n`).

---

### [S2] [Performance] server/db.js:L90-93, L206-209, L263-266, L291-294, L313-316, L640-643 — Sechs ungecachte `COUNT(*)`-Vollscans pro Aufruf des öffentlichen, ratelimit-freien `/hhttps/info`
**Begründung:** Die `count()`-Methoden führen jeweils `SELECT COUNT(*) FROM <tabelle>` aus (`credentials`, `revoked_tokens`, `machine_operators` ohne WHERE = Seq-Scan; `tokens`, `refresh_tokens`, `sessions` mit `expires_at > NOW()` = Index-Range + Heap-Besuche). `/hhttps/info` (server/server.js:L799-805) ruft alle sechs per `Promise.all` auf — bei jedem Request, ohne Cache — und ist in server/server.js:L435 ausdrücklich vom globalen Rate-Limit ausgenommen. `/hhttps/stats` (L4736-4743) macht dasselbe zusätzlich mit `rolesDeclared.distribution()`. `credentials` und `revoked_tokens` wachsen dauerhaft (Revoked-Liste ist per Design „permanent", schema.sql:L94).
**Auswirkung:** Pro `/info`-Hit werden 6 Pool-Verbindungen gleichzeitig belegt; bei `max: 20` (db.js:L36) reichen ~3–4 parallele, unauthentifizierte, nicht limitierte Aufrufe, um den Pool zu füllen. Alle anderen Requests warten dann bis `connectionTimeoutMillis: 5000` und schlagen mit Fehler fehl → trivial auslösbarer Teilausfall; die Scan-Kosten steigen linear mit dem Datenbestand.
**Empfehlung:** Zähler in db.js mit kurzem In-Memory-Cache (z. B. 30–60 s TTL, ein gemeinsames `Promise` gegen Thundering-Herd) kapseln oder aus `pg_stat_user_tables.n_live_tup` lesen; unabhängig davon `/hhttps/info` nicht vom Rate-Limit ausnehmen (Hinweis an AP1).

### [S3] [Performance] server/db.js:L1264-1267 — `authCodes.cleanup()` wird nirgends aufgerufen; `authorization_codes` wächst unbegrenzt
**Begründung:** Die Methode existiert (`DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour'`), aber `grep -rn "\.cleanup()" server --include=*.js` findet außerhalb der Tests keinen Aufrufer. Weder `cleanupExpired()` (db.js:L1339-1347) noch die SQL-Funktion `cleanup_expired()` (schema.sql:L192-206) berühren `authorization_codes`. Pro OAuth-Login entsteht eine Zeile (server.js:L1601); `claim()` setzt nur `used = TRUE`, löscht nicht. Nicht eingelöste Codes behalten zudem die Spalte `email` im Klartext (migration-phase-8:L68 — Datenschutzaspekt für AP2/AP6-Sicherheit).
**Auswirkung:** Tabelle und ihr Index `idx_authcodes_expires` wachsen linear mit der Login-Zahl, ohne Nutzen; Autovacuum/Backups werden teurer; die `phase8SchemaApplied`-Checks bleiben unbeeinflusst, aber jede spätere `ALTER TABLE authorization_codes` (Boot-DDL) arbeitet auf einer unnötig großen Tabelle.
**Empfehlung:** `cleanupExpired()` um `authCodes.cleanup()` erweitern (oder die DELETE-Zeile in `cleanup_expired()` aufnehmen) und beim Aufräumen auch `used = TRUE`-Zeilen älter als z. B. 1 h entfernen.

### [S3] [Performance] server/sql/schema.sql:L203 + server/db.js:L358-366, L348-354 — `email_verifications`: benutzte Zeilen werden nie gelöscht, und die Hot-Path-Lookups über `code`/`session_id` haben keinen Index
**Begründung:** `cleanup_expired()` löscht nur `expires_at < NOW() AND used = FALSE` (schema.sql:L203). Jede erfolgreich bestätigte Verifikation (`getAndConsumeByCode`, `getAndConsume`) und jede per `invalidateForSession` (db.js:L348-354, aufgerufen bei jedem Re-Send in server.js:L2866) invalidierte Zeile bleibt mit `used = TRUE` für immer stehen. Gleichzeitig filtern die beiden Request-Pfad-Queries auf `code = $1 AND session_id = $2` bzw. `session_id = $1 AND used = FALSE`; für `code` (db.js:L376, per ALTER ergänzt) und `session_id` existiert kein Index — vorhanden sind nur `expires_at` und `email` (schema.sql:L118-119), und `email` wird von keiner Query gefiltert.
**Auswirkung:** Jede Code-Bestätigung und jeder E-Mail-Versand macht einen Sequential Scan über eine Tabelle, die mit jeder Anmeldung um eine Zeile wächst und nie schrumpft. Bei 10⁵–10⁶ Zeilen sind das zweistellige Millisekunden pro Request auf dem Login-Pfad; zusätzlich toter Ballast in `email_verifications_email_idx`.
**Empfehlung:** In `cleanup_expired()` `DELETE FROM email_verifications WHERE expires_at < NOW()` ohne `used`-Bedingung (benutzte Zeilen sind nach Ablauf wertlos); Index `CREATE INDEX ... ON email_verifications(session_id) WHERE used = FALSE` und ggf. `(code)`; den ungenutzten `email`-Index entfernen.

### [S3] [Performance] server/privacy-pass/migrations.js:L65-77, L106-113, L17-28 — Privacy-Pass-Tabellen `pp_email_pending`, `pp_redeemed`, `pp_issuance_log` haben keinerlei Cleanup
**Begründung:** `pp_email_pending` hat `expires_at` und den Index `pp_email_pending_expires_idx` (L75-76), aber Zeilen werden nur beim Einlösen gelöscht (privacy-pass/verifications.js:L109-115); abgelaufene, nie geklickte Tokens bleiben. `pp_redeemed` (L106-113) bekommt pro eingelöstem Token eine Zeile und wird nie geleert, obwohl ein Nonce nach Ablauf des Issuer-Schlüssels wertlos ist. `pp_issuance_log` (L17-28) ist ein Append-only-Log ohne Retention; die Rate-Limit-Query (issuance.js:L166-172) fragt nur das letzte Fenster. Weder `cleanup_expired()` (schema.sql) noch `cleanupExpired()` (db.js) noch privacy-pass/index.js enthalten einen DELETE für diese Tabellen (`grep -rn "DELETE" server/privacy-pass`: nur Consume-Pfade).
**Auswirkung:** Drei Tabellen wachsen unbegrenzt mit der Nutzung; `pp_redeemed_at_idx` und `pp_email_pending_expires_idx` existieren nur für einen Cleanup, der nie läuft (reiner Schreib-Overhead).
**Empfehlung:** In `cleanupExpired()` ergänzen: `DELETE FROM pp_email_pending WHERE expires_at < NOW()`, `DELETE FROM pp_redeemed WHERE redeemed_at < NOW() - <max. Token-Lebensdauer>`, `DELETE FROM pp_issuance_log WHERE issued_at < NOW() - <größtes Rate-Limit-Fenster>`.

### [S3] [Performance] server/db.js:L30-39 — Pool ohne `statement_timeout`/`query_timeout`; eine hängende Query blockiert eine von 20 Verbindungen unbegrenzt
**Begründung:** Die `Pool`-Konfiguration setzt nur `max`, `idleTimeoutMillis` und `connectionTimeoutMillis`. Es gibt keinerlei `statement_timeout` (Server-seitig) oder `query_timeout` (pg-Client). Die Vollscans aus dem ersten Finding und die unbatched DELETEs in `cleanup_expired()` (schema.sql:L199-203; nach längerem Stillstand potenziell Millionen Zeilen in einer Transaktion) sind reale Kandidaten für Langläufer.
**Auswirkung:** Bei Lock-Kontention oder langsamer DB (z. B. Autovacuum, Backup mit `pg_dump` in deploy-phase8.sh:L180 auf demselben Host) sammeln sich Requests im Pool an; nach 20 belegten Verbindungen antwortet der gesamte Server nur noch mit Connection-Timeout-Fehlern, statt einzelne Queries abzubrechen.
**Empfehlung:** `statement_timeout: 10_000` (oder `query_timeout`) in der Pool-Konfiguration setzen; für den Cleanup-Job einen eigenen, höheren Timeout und batched DELETEs (`LIMIT`/CTE) verwenden.

### [S4] [Performance] server/sql/schema.sql:L24, L48, L78, L92, L102, L119 — Fünf Indizes ohne jede Query-Nutzung erzeugen Schreib-Overhead auf Hot-Insert-Tabellen
**Begründung:** `grep` über db.js und alle Aufrufer zeigt keine Query, die `credentials.registered_at`, `sessions.user_id`, `tokens.user_id`, `refresh_tokens.user_id`, `revoked_tokens.revoked_at` oder `email_verifications.email` filtert oder sortiert. `tokens`/`sessions`/`refresh_tokens` werden bei jedem Login geschrieben und alle 5 Minuten massenhaft gelöscht (schema.sql:L199-201).
**Auswirkung:** Jeder Insert/Delete pflegt zusätzliche B-Trees; bei kleinem Datenbestand irrelevant, bei Wachstum messbar (Index-Bloat nach Massen-DELETE).
**Empfehlung:** Ungenutzte Indizes per Migration droppen oder eine Query benennen, die sie braucht; `pg_stat_user_indexes.idx_scan` in Produktion prüfen.

### [S4] [Performance] server/sql/schema.sql:L163-174 — `webhook_deliveries` (Audit-Log) ohne Retention
**Begründung:** `webhooks.recordDelivery` (db.js:L685-690) schreibt pro Zustellversuch eine Zeile; kein Cleanup, keine Abfrage liest die Tabelle (grep: nur der INSERT).
**Auswirkung:** Unbegrenztes Wachstum mit jedem Webhook-Event × Retry; die beiden Indizes (L173-174) werden nur gepflegt, nie gelesen.
**Empfehlung:** Retention (z. B. 30 Tage) in `cleanup_expired()` aufnehmen oder das Log auf einen Ring pro Webhook begrenzen.

### [S4] [Performance] server/db.js:L685-699, L701-708 — Webhook-Statistik in 2–3 Roundtrips statt einem Statement
**Begründung:** `recordDelivery` führt INSERT + UPDATE sequentiell und ohne Transaktion aus; `deactivateIfFailing` macht SELECT und danach UPDATE. Beide werden pro Zustellversuch aus `webhooks.js` aufgerufen.
**Auswirkung:** Doppelte Latenz pro Zustellung und ein (harmloses) Konsistenzfenster; bei Retries mit mehreren Webhooks belegt das Pool-Verbindungen länger als nötig.
**Empfehlung:** `UPDATE webhooks SET active = FALSE WHERE webhook_id = $1 AND failures >= $2 RETURNING 1` bzw. INSERT+UPDATE als eine CTE.

### [S4] [Performance] server/db.js:L372-383 + server/privacy-pass/migrations.js:L117-131 — DDL bei jedem Prozessstart (ALTER TABLE, 5× CREATE ... IF NOT EXISTS)
**Begründung:** `ensureCodeColumn()` feuert beim Modul-Import ein `ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS` (ACCESS-EXCLUSIVE-Lock, auch wenn No-op); `runMigrations()` schickt bei jedem Boot fünf Multi-Statement-DDL-Blöcke. Der Boot-DDL-Mechanismus in db.js:L432-487 zeigt bereits das bessere Muster (Applied-Check zuerst, DDL nur bei Bedarf).
**Auswirkung:** Kurze Exklusiv-Locks auf `email_verifications` und den pp_-Tabellen bei jedem `pm2 restart`; bei laufenden Requests (Cluster-/Reload-Szenario) kurze Blockade.
**Empfehlung:** `ensureCodeColumn` und die Privacy-Pass-Migrationen in `BOOT_DDL_FILES` mit Applied-Check überführen.

### [S4] [Performance] server/scripts/deploy-phase8.sh:L216, scripts/deploy-privacy-pass.sh:L302, server/scripts/migrate.sh:L80 — `pm2 restart` statt `reload`: jeder Deploy erzeugt eine Downtime von mehreren Sekunden
**Begründung:** Alle Deploy-Skripte nutzen `pm2 restart` im Fork-Modus (einzelner Prozess, `pm2 start server.js`). deploy-phase8.sh:L222-226 wartet danach bis zu 30 s auf `/hhttps/info`. Während Boot-DDL (`ensureBootSchema`) und Privacy-Pass-Migrationen läuft kein Prozess, der Requests annimmt.
**Auswirkung:** Jeder Deploy = harter Ausfall im Sekundenbereich; laufende WebAuthn-/OAuth-Flows brechen mit Verbindungsfehler ab.
**Empfehlung:** pm2 im Cluster-Modus (`-i 1` reicht) starten und `pm2 reload` verwenden, oder alternativ vor dem Restart per nginx auf eine Wartungsantwort umschalten.

---

## Zusammenfassung

- S1: 0
- S2: 1
- S3: 4
- S4: 5

Gesamteindruck: Die Zugriffsschicht ist sauber parametrisiert, nutzt ausschließlich `pool.query` (keine `pool.connect`-Client-Leaks möglich) und die Primärschlüssel-Lookups der Hot-Paths (`sessions`, `tokens`, `challenges`, `authorization_codes`, `identity_anchors`) sind korrekt indiziert. Die Schwächen liegen im Lebenszyklus der Daten: `cleanup_expired()` deckt nur fünf der inzwischen rund zwölf TTL-Tabellen ab (fehlend: `authorization_codes`, benutzte `email_verifications`, alle Privacy-Pass-Tabellen, `webhook_deliveries`), und die ungeschützten `COUNT(*)`-Vollscans auf dem ratelimit-freien `/hhttps/info` bilden zusammen mit dem fehlenden Statement-Timeout den einzigen realen Ausfallpfad. Alle Punkte sind mit wenigen Zeilen in `cleanupExpired()`, zwei Indizes und einer Pool-Option behebbar.

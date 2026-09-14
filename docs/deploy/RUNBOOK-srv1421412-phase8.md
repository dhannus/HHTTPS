# Runbook: Deploy „email-anchored identity“ (Phase 8 + 4b) auf srv1421412.hstgr.cloud

Stand: 2026-09-14 · Betrifft PR #19 (merged in `main`, Merge-Commit `2b1dd61`) · Skript: `server/scripts/deploy-phase8.sh`

## 1. Ausgangslage auf dem Server

| Was | Pfad | Bemerkung |
|---|---|---|
| Git-Repo | `/root/HHTTPS` (Server-Code in `/root/HHTTPS/server`) | Quelle für Deploys |
| Laufender Server | `/var/www/hhttps` | pm2-App `hhttps-v4`, Node startet `server.js` aus diesem Verzeichnis |
| Zustand (nicht im Git) | `/var/www/hhttps/.env`, `/var/www/hhttps/keys/` (Signaturschlüssel), `/var/www/hhttps/eudi-keys/` (EUDI-Verifier, Docker-Mount) | dürfen beim Deploy nie überschrieben werden |
| Datenbank | PostgreSQL, Zugangsdaten in `.env` (`DB_*`) | |

Bisheriger Ablauf: Repo aktualisieren, dann manuell nach `/var/www/hhttps` kopieren. Das Skript macht das Kopieren automatisch (rsync, Zustandsdateien ausgenommen) und kann das Kopieren durch einen Symlink ganz abschaffen (Abschnitt 6).

## 2. Was dieses Release am Betrieb ändert

1. **Neue Pflicht-Umgebungsvariablen in `.env`:**
   - `HHTTPS_VERIFICATION_PEPPER=<64 hex>` — trägt ab jetzt die Identitäts-Anker (E-Mail → stabile `userId`). **Nie rotieren**, sonst verlieren alle Nutzer ihre Identität. Falls die Variable für die GitHub-Verifikation schon existiert: denselben Wert behalten. Ohne Pepper startet der Server in `production` nicht.
   - `NODE_ENV=production` — aktiviert Pepper-Pflicht und schaltet den Dev-Mail-Modus ab.
   - `EMAIL_DEV_MODE` darf **nicht** gesetzt sein.
2. **E-Mail ist Pflicht:** ohne funktionierendes SMTP (`SMTP_HOST/USER/PASS/FROM`) kann sich niemand mehr anmelden (`/hhttps/email/send` antwortet 503).
3. **Datenbank:** Boot-DDL (Tabellen `identity_anchors`, `identity_claims_cache`, Spalten `sessions.pseudonym`, `authorization_codes.email/pseudonym/verified_methods`, `machine_operators.key_jkt`) legt der Server beim Start selbst an. Der **OPERATOR-Abschnitt** (Grants + `allowed_scopes += "email"` für Bestandsclients) muss **einmalig per psql** laufen — das Skript tut das in Schritt 6. Ohne diesen Schritt bekommen ask.iamhmn.org und das WordPress-Plugin `invalid_scope`, sobald sie `email` anfordern.
4. **Breaking für Clients:** Passkey-Registrierung braucht `sessionId` einer E-Mail-bestätigten Session; `role/declare`, `eid/upgrade`, `verify/github/start`, `age/upgrade` → 403 ohne E-Mail; `age/direct` → immer 403. Sign-in-Seite, Wallet-Seite und `sites/hhttps.html` sind umgestellt.

## 3. Vorbereitung (einmalig, 5 Minuten)

```bash
# als root auf srv1421412
cd /root/HHTTPS && git fetch origin && git checkout main && git pull --ff-only
# Pepper prüfen / anlegen (NUR wenn noch keiner existiert!)
grep -q '^HHTTPS_VERIFICATION_PEPPER=' /var/www/hhttps/.env \
  || echo "HHTTPS_VERIFICATION_PEPPER=$(openssl rand -hex 32)" >> /var/www/hhttps/.env
grep -q '^NODE_ENV=' /var/www/hhttps/.env || echo "NODE_ENV=production" >> /var/www/hhttps/.env
sed -i '/^EMAIL_DEV_MODE=/d' /var/www/hhttps/.env
# Trockenlauf: prüft alles, ändert nichts
bash /root/HHTTPS/server/scripts/deploy-phase8.sh --dry-run
```

Der Trockenlauf muss mit „Preflight bestanden“ enden. Typische Abbrüche: Repo nicht auf `main`, lokale Änderungen im Repo, Pepper fehlt, `NODE_ENV` fehlt, Postgres nicht erreichbar.

## 4. Deploy

```bash
bash /root/HHTTPS/server/scripts/deploy-phase8.sh
```

Das Skript läuft in sieben Schritten und bricht beim ersten Fehler ab:

| Schritt | Tut | Prüft |
|---|---|---|
| 1 Preflight | nichts | git, Node ≥ 20, pm2/psql/rsync, `.env`-Pflichtwerte, DB-Verbindung |
| 2 Backup | `.env`, `keys/`, `eudi-keys/`, `pg_dump` → `/root/hhttps-backups/<zeitstempel>/` | |
| 3 Build | `git pull --ff-only`, `npm ci --omit=dev` im Repo | `node --check server.js` |
| 4 Sync | `rsync --delete` Repo → `/var/www/hhttps` (ohne `.env`, `keys/`, `eudi-keys/`, `.git/`, `test/`) | entfällt im Symlink-Layout |
| 5 Restart | `pm2 restart hhttps-v4 --update-env` | wartet bis `/hhttps/info` antwortet (30 s), sonst Logs + Abbruch |
| 6 Operator | OPERATOR-Abschnitt der Phase-8-Migration per psql (idempotent) | zählt Clients mit Scope `email` |
| 7 Verify | nichts | Discovery enthält `email`/`passkey_verified`, fünf Schema-Spalten vorhanden, `register/start` ohne Session → 400, `email/send` mit falscher Session → 401, `https://<RP_ID>/hhttps/info` erreichbar |

Dauer: etwa 1–2 Minuten, davon ~10 s Ausfall beim Restart.

## 5. Nach dem Deploy prüfen

1. `https://hhttps.org/.well-known/openid-configuration` → `scopes_supported` enthält `email`, `claims_supported` enthält `verified_methods`, `passkey_verified`.
2. Anmeldung auf hhttps.org: E-Mail eingeben → Code kommt als `123456` (ohne Leerzeichen) im hellen Design → nach Bestätigung werden Passkey/EUDI/GitHub freigeschaltet.
3. Login bei ask.iamhmn.org mit derselben E-Mail von zwei Geräten → gleicher Benutzer (`sub` identisch), `preferred_username` gesetzt. Mit Scope `email`: Adresse im ID-Token/`userinfo`.
4. `pm2 logs hhttps-v4 --lines 50` ohne `[UNHANDLED]` oder `[DB] Query failed`.

## 6. Kopieren abschaffen: `/var/www/hhttps` als Symlink

Ziel: `/var/www/hhttps → <Repo>/server`, damit `git pull` + `pm2 restart` reichen.

**Wichtige Einschränkung:** Das Repo darf dafür **nicht unter `/root`** liegen. nginx läuft als `www-data` und darf `/root` (Rechte 700) nicht betreten. Falls nginx statische Dateien direkt aus `/var/www/hhttps/public` ausliefert (statt alles an Node zu proxien), würden diese Dateien 403 liefern. Lösung: Repo einmalig nach `/var/www/HHTTPS` verschieben.

```bash
pm2 stop hhttps-v4
mv /root/HHTTPS /var/www/HHTTPS          # Repo verschieben (Git bleibt intakt)
cd /var/www/HHTTPS && git status         # Kontrolle
REPO_DIR=/var/www/HHTTPS bash /var/www/HHTTPS/server/scripts/deploy-phase8.sh --link
```

`--link` übernimmt `.env`, `keys/`, `eudi-keys/` in `/var/www/HHTTPS/server/` (dort per `.gitignore` geschützt), benennt das alte Verzeichnis in `/var/www/hhttps_pre-link_<ts>` um, setzt den Symlink und startet pm2 neu. Ab dann ist `INSTALL_DIR` = Repo, Schritt 4 entfällt und jeder weitere Deploy ist:

```bash
REPO_DIR=/var/www/HHTTPS bash /var/www/HHTTPS/server/scripts/deploy-phase8.sh
```

Danach zwei Dinge dauerhaft anpassen (einmalig):
- `eudi-keys/` in `.gitignore` aufnehmen (Repo), damit die Schlüssel nicht versehentlich committet werden.
- Docker-Mount in `server/eudi-verifier/docker/docker-compose.yaml` zeigt auf `/var/www/hhttps/eudi-keys/…` — über den Symlink weiterhin gültig, Docker löst Symlinks als root auf.

Rückweg: `rm /var/www/hhttps && mv /var/www/hhttps_pre-link_<ts> /var/www/hhttps && pm2 restart hhttps-v4`.

## 7. Rollback

- Code: `git -C <Repo> checkout <alter-Head>` (steht in `/root/hhttps-backups/<ts>/repo-head-before.txt`), dann `deploy-phase8.sh --skip-operator`.
- Konfiguration: `.env`, `keys/`, `eudi-keys/` aus dem Backup-Ordner zurückkopieren.
- Datenbank: die Schema-Änderungen sind additiv (neue Tabellen/Spalten) und stören den alten Code nicht. Vollständiges Zurücksetzen nur per `gunzip -c db.sql.gz | psql …` — normalerweise nicht nötig. Der `allowed_scopes`-Zusatz `email` ist für alten Code unschädlich.

## 8. Offene Informationen, die ich vor dem ersten echten Lauf gern sehen würde

Bitte einmal auf dem Server ausführen und die Ausgabe schicken; danach passe ich Skript und Runbook exakt an:

```bash
pm2 describe hhttps-v4 | grep -E 'script path|exec cwd|exec mode|node.js version|status'
nginx -T 2>/dev/null | grep -E 'server_name|root |alias |proxy_pass|location' | head -40
ls -la /var/www/hhttps | head -40
ls -la /root/HHTTPS/server | head -40
cd /root/HHTTPS && git status -sb && git log --oneline -3 && git remote -v
diff -rq --exclude=node_modules --exclude=.git --exclude=keys --exclude=.env --exclude=eudi-keys /root/HHTTPS/server /var/www/hhttps | head -30
node -v && psql --version && docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null
grep -E '^(NODE_ENV|HHTTPS_VERIFICATION_PEPPER|EMAIL_DEV_MODE|SMTP_HOST|EUDI_VERIFIER_SECRET|RP_ID|DB_HOST)=' /var/www/hhttps/.env | sed 's/=.*/=***/'
```

Entscheidend sind die nginx-Zeilen (liefert nginx `public/` selbst aus?) und das `diff` (gibt es in `/var/www/hhttps` lokale Änderungen, die nicht im Repo sind?).

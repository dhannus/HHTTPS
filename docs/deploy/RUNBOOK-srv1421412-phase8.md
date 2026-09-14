# Runbook: Deploy „email-anchored identity“ (Phase 8 + 4b) auf srv1421412.hstgr.cloud

Stand: 2026-09-14 · Betrifft PR #19 (merged in `main`, Merge-Commit `2b1dd61`) · Skript: `server/scripts/deploy-phase8.sh`

## 1. Ausgangslage auf dem Server

| Was | Pfad | Bemerkung |
|---|---|---|
| Git-Repo | `/root/HHTTPS` (Server-Code in `/root/HHTTPS/server`) | Quelle für Deploys |
| Laufender Server | `/var/www/hhttps` | pm2-App `hhttps-v4`, Node startet `server.js` aus diesem Verzeichnis |
| Zustand (nicht im Git) | `/var/www/hhttps/.env`, `/var/www/hhttps/keys/` (Signaturschlüssel), `/var/www/hhttps/eudi-keys/` (EUDI-Verifier, Docker-Mount) | dürfen beim Deploy nie überschrieben werden |
| Datenbank | PostgreSQL, Zugangsdaten in `.env` (`DB_*`) | |

Befund vom 2026-09-14 (Serverausgabe):
- pm2 `hhttps-v4`: `script path /var/www/hhttps/server.js`, `exec cwd /var/www/hhttps`, fork_mode, Node 20.20.2 (ausreichend, ≥ 20).
- nginx: `hhttps.org` → `location /` proxied vollständig an `localhost:3000`; nur `/spec` (alias `/var/www/hhttps-static/spec.html`), ACME (`/var/www/html`) und die EUDIPLO-`.well-known`-Pfade (Port 3002) sind Ausnahmen. **nginx liest nicht aus `/var/www/hhttps`** → ein Symlink auf `/root/HHTTPS/server` ist unproblematisch (Abschnitt 6). Offen: die Ausgabe war auf 40 Zeilen gekürzt; bitte nachreichen, ob es eine `location /developers` oder `/privacy-pass` mit `alias`/`root` gibt.
- Repo `/root/HHTTPS` steht auf `main` @ `c5b67d0` (Stand vor PR #19). `scripts/deploy-phase8.sh` liegt dort als manuell kopierte, untracked Datei — **vor dem `git pull` löschen**, sonst blockiert Git den Pull (das Skript prüft das und bricht mit Hinweis ab).
- In `/var/www/hhttps` liegen Dinge, die nicht im Repo sind: `developers/` (Portal, im Repo unter `../developers`), `privacy-pass/public/demo.html`, `force-verify-client.mjs`, `examples/`, `extension/`, diverse `*.bak*`/`*.backup*`/`privacy-pass.backup_*`. Außerdem weicht `eudi-verifier/docker/docker-compose.yaml` lokal vom Repo ab. Das Skript kopiert deshalb **ohne `--delete`** und rührt `docker-compose.yaml` nicht an.
- `.env`: `HHTTPS_VERIFICATION_PEPPER` ist bereits gesetzt (**diesen Wert behalten**, er trägt die GitHub-Anker), `SMTP_HOST`, `EUDI_VERIFIER_SECRET`, `RP_ID`, `DB_HOST` vorhanden. **`NODE_ENV=production` fehlt** und muss ergänzt werden. `EMAIL_DEV_MODE` ist nicht gesetzt (gut).
- Docker: `eudi-verifier-backend` ist seit 3 Monaten `unhealthy` — unabhängig von diesem Deploy, aber prüfenswert.

Bisheriger Ablauf: Repo aktualisieren, dann manuell nach `/var/www/hhttps` kopieren. Das Skript macht das Kopieren automatisch (rsync ohne `--delete`, Zustandsdateien und lokale Extras ausgenommen) und kann das Kopieren durch einen Symlink ganz abschaffen (Abschnitt 6).

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
rm -f /root/HHTTPS/server/scripts/deploy-phase8.sh      # manuell kopierte Fassung entfernen
cd /root/HHTTPS && git fetch origin && git checkout main && git pull --ff-only   # holt das Skript aus main
# Pepper existiert bereits — NICHT neu erzeugen. Nur NODE_ENV ergänzen:
grep -q '^NODE_ENV=' /var/www/hhttps/.env || echo "NODE_ENV=production" >> /var/www/hhttps/.env
sed -i '/^EMAIL_DEV_MODE=/d' /var/www/hhttps/.env
# Trockenlauf: prüft alles, ändert nichts
bash /root/HHTTPS/server/scripts/deploy-phase8.sh --dry-run
```

Voraussetzung: das Skript muss in `main` gemerged sein (PR „ops: deploy runbook and script“). Bis dahin: `git fetch origin claude/kind-pasteur-kweqf1 && git checkout claude/kind-pasteur-kweqf1` und das Skript mit `BRANCH=claude/kind-pasteur-kweqf1` starten.

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

Ziel: `/var/www/hhttps → /root/HHTTPS/server`, damit `git pull` + `pm2 restart` reichen.

Laut nginx-Konfiguration proxied nginx alles an Node und liest keine Dateien aus `/var/www/hhttps`. Damit ist ein Symlink nach `/root` in Ordnung (Node läuft als root und liest das Repo direkt). Das Skript prüft das selbst: referenziert nginx `/var/www/hhttps` per `root`/`alias` (z. B. eine bisher nicht gezeigte `location /developers`), bricht `--link` ab und verlangt ein Repo außerhalb von `/root` (z. B. `mv /root/HHTTPS /var/www/HHTTPS`, dann `REPO_DIR=/var/www/HHTTPS`).

```bash
bash /root/HHTTPS/server/scripts/deploy-phase8.sh --link
```

`--link` übernimmt in `/root/HHTTPS/server/`: `.env`, `keys/`, `eudi-keys/` (per `.gitignore` geschützt) sowie die lokalen Extras `developers/`, `privacy-pass/public/demo.html`, `force-verify-client.mjs`; die lokal abweichende `docker-compose.yaml` wird als `docker-compose.yaml.local-<ts>` daneben abgelegt (die laufenden Container sind nicht betroffen; Unterschiede bitte ins Repo übernehmen). Danach wird `/var/www/hhttps` in `/var/www/hhttps_pre-link_<ts>` umbenannt, der Symlink gesetzt und pm2 neu gestartet. pm2 behält `script path`/`exec cwd` `/var/www/hhttps/...`, was über den Symlink weiter gilt. Ab dann ist `INSTALL_DIR` = Repo, Schritt 4 entfällt und jeder weitere Deploy ist:

```bash
bash /root/HHTTPS/server/scripts/deploy-phase8.sh
```

Aufräumen (optional, nach erfolgreichem Betrieb): `/var/www/hhttps_pre-link_<ts>` enthält nur noch Altlasten (`*.bak*`, `privacy-pass.backup_*`, `public.before-gh-rename`, `server.js.backup_*`) und kann gelöscht werden.

Dauerhaft im Repo erledigt bzw. offen:
- `eudi-keys/` steht jetzt in `.gitignore`.
- Docker-Mount in `server/eudi-verifier/docker/docker-compose.yaml` zeigt auf `/var/www/hhttps/eudi-keys/…` — über den Symlink weiterhin gültig, Docker löst Symlinks als root auf.
- Offen: `developers/` liegt im Repo unter `/developers` (Repo-Wurzel), auf dem Server aber unter `server/developers`. Wie es ausgeliefert wird (nginx-`alias` oder Node), klärt die nachgereichte nginx-Ausgabe; ggf. ein `express.static` in `server.js` oder ein Symlink `server/developers → ../developers`.

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

Stand 2026-09-14: Ausgabe liegt vor und ist oben eingearbeitet. Noch offen:

```bash
nginx -T 2>/dev/null | grep -n -E 'location|alias|root |proxy_pass' | grep -v acme      # vollständig, nicht gekürzt
diff /root/HHTTPS/server/eudi-verifier/docker/docker-compose.yaml /var/www/hhttps/eudi-verifier/docker/docker-compose.yaml
diff /root/HHTTPS/server/package.json /var/www/hhttps/package.json
head -20 /var/www/hhttps/force-verify-client.mjs        # wird das noch gebraucht?
grep -n 'demo' /var/www/hhttps/privacy-pass/index.js    # wird demo.html ausgeliefert?
```

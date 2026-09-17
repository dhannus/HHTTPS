# Deploy-Runbook — Projekt-Review 2026-09 (Wellen 0–3)

Gilt für `srv1421412.hstgr.cloud` (pm2 `hhttps-v4`, nginx → :3000, Repo `/var/www/HHTTPS`,
Server-Symlink `/var/www/hhttps → /var/www/HHTTPS/server`). Ergänzt den Phase-8-Runbook,
ersetzt ihn nicht.

> **Reihenfolge:** Wellen einzeln deployen und je Welle die Prüfschritte abarbeiten.
> Jede Welle ist für sich lauffähig; Welle 1 setzt Welle 0 voraus usw.

## 0. Vor dem ersten Deploy einer Welle

```bash
cd /var/www/HHTTPS && git pull --ff-only
cd server && npm ci --omit=dev
```

## Welle 0 — Angriffsfläche schließen (PR #252)

**Was sich am Betrieb ändert**

| Punkt | Aktion |
|---|---|
| Privacy-Pass-Modul entfernt | Die Routen `/privacy-pass/*` antworten ab jetzt 404. Falls nginx eine eigene `location /privacy-pass` hat: entfernen. Verzeichnis `/var/www/hhttps/privacy-pass/` (inkl. `keys/`) nach dem Deploy manuell löschen, wenn nichts mehr gebraucht wird. |
| Webhooks brauchen Auth | `GET/POST/DELETE /hhttps/webhooks` verlangen jetzt einen HHTTPS-Token. Bestehende, ownerlose Webhooks werden von der OPERATOR-Sektion der Phase-9-Migration deaktiviert — vorher ansehen, ob eine davon produktiv gebraucht wird. |
| Webhook-Ziele | Nur noch öffentliche `https`-Hosts. Interne Ziele (127.0.0.1, 10.x, …) werden abgelehnt. `WEBHOOK_ALLOW_PRIVATE=1` ist nur für lokale Tests und darf in Produktion **nicht** gesetzt werden. |
| Strengere E-Mail-Syntax | Adressen mit Klammern, Anführungszeichen oder Nicht-ASCII werden abgelehnt (400). |

**Migration (nach dem Deploy, einmalig)**

```bash
# 1. Ansehen, welche Webhooks keinen Owner haben (werden gleich deaktiviert):
psql -U hhttps -d hhttps -c "SELECT webhook_id, url, events, created_at FROM webhooks WHERE owner_user_id IS NULL;"
# 2. OPERATOR-Sektion einspielen (deaktiviert ownerlose Webhooks, droppt die pp_*-Tabellen):
psql -U hhttps -d hhttps -f /var/www/hhttps/sql/migration-phase-9-review-welle-0.sql
```

Die BOOT-DDL-Sektion (Spalte `webhooks.owner_user_id`) spielt der Server beim Start selbst ein.

**Prüfen**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://hhttps.org/privacy-pass/        # 404
curl -s -o /dev/null -w '%{http_code}\n' https://hhttps.org/email-verify.html    # 404
curl -s -o /dev/null -w '%{http_code}\n' https://hhttps.org/hhttps/webhooks      # 401
```

## Welle 1 — Kernflow (PR #253)

**Was sich am Betrieb ändert**

| Punkt | Aktion |
|---|---|
| Migrationsläufer | Neu: `server/scripts/migrate.js` mit Ledger `schema_migrations`. **Einmalig auf dem bestehenden Server:** `cd /var/www/hhttps && node scripts/migrate.js --baseline` — markiert die vorhandenen Migrationen als angewendet, ohne sie auszuführen. Ohne diesen Schritt würde ein späterer Lauf alte Dateien erneut einspielen. |
| Refresh-Tokens | Werden nicht mehr als Bearer akzeptiert. Integrationen, die bisher den Refresh-Token an `/hhttps/whoami`, `/hhttps/validate` oder das Portal geschickt haben, bekommen 401 und müssen den Access-Token verwenden. |
| Widerruf | `/hhttps/revoke` beendet jetzt die gesamte Refresh-Kette des Nutzers, `/hhttps/oauth/revoke` die der Plattform. |
| Geschützte Berufe | `documentProvided:true` erzeugt keine „verified"-Karte mehr; reservierte Berufe brauchen eine qualifizierte Bescheinigung (RAL2). |
| `make-admin.sh --grant-recent` | Fragt jetzt nach einer Bestätigung. Für Skripte: `--yes`. |
| EUDI-PID-Trust | Optional `EUDI_PID_TRUST_LIST` in `.env` setzen, sobald die PID-LoTE in EUDIPLO installiert ist (Issue #133). Ohne die Variable warnt der Server beim Start. |

**Prüfen**

```bash
pm2 logs hhttps-v4 --lines 40 | grep -E 'EUDI_PID_TRUST_LIST|CLEANUP'
psql -U hhttps -d hhttps -c "SELECT name FROM schema_migrations ORDER BY name;"
```

## Welle 2 — Betrieb und Härtung (PR folgt)

| Punkt | Aktion |
|---|---|
| `PAIRWISE_SECRET` **(Pflicht)** | Neu erzwungen: ohne die Variable startet der Server in `production` nicht. **Einmalig festlegen und sichern** — der Wert bestimmt die pairwise `sub` jeder Plattform; eine spätere Änderung lässt jeden Nutzer für jede Plattform wie ein neuer Account aussehen. `echo "PAIRWISE_SECRET=$(openssl rand -hex 32)" >> /var/www/hhttps/.env` **vor** dem Neustart. |

Weitere Punkte werden ergänzt, sobald Welle 2 abgeschlossen ist.

## Welle 3 — Wartbarkeit (PR folgt)

Keine Betriebsänderungen erwartet.

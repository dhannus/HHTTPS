#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# HHTTPS — Deploy: email-anchored identity (Phase 8 + 4b) auf srv1421412
#
# Führt einen kompletten, geprüften Deploy von `main` aus:
#   1. Preflight   git (main, sauber), Node ≥ 20, .env-Pflichtwerte (Pepper,
#                  NODE_ENV=production, kein EMAIL_DEV_MODE), Postgres erreichbar
#   2. Backup      .env, keys/, eudi-keys/ und pg_dump nach /root/hhttps-backups/<ts>/
#   3. Build       git pull --ff-only, npm ci --omit=dev
#   4. Sync        (nur wenn INSTALL_DIR KEIN Symlink auf das Repo ist)
#                  rsync Repo → INSTALL_DIR, Zustandsdateien bleiben unberührt
#   5. Restart     pm2 restart --update-env, wartet auf /hhttps/info
#   6. Operator    OPERATOR-Abschnitt der Phase-8-Migration per psql (idempotent)
#   7. Verify      Discovery enthält Scope "email", Boot-DDL-Spalten vorhanden,
#                  age/direct = 403, machine_operators.key_jkt vorhanden
#
# Aufruf (auf dem Server, als root):
#   bash /root/HHTTPS/server/scripts/deploy-phase8.sh            # voller Deploy
#   bash .../deploy-phase8.sh --dry-run                          # nur prüfen
#   bash .../deploy-phase8.sh --skip-operator                    # ohne Schritt 6
#   bash .../deploy-phase8.sh --link                             # einmalig:
#        INSTALL_DIR durch Symlink auf REPO_DIR/server ersetzen (siehe Runbook)
#   bash .../deploy-phase8.sh --rollback <sha>                   # Rollback:
#        BRANCH auf <sha> zuruecksetzen (kein git pull), Build/Sync/Restart
#        wie beim Deploy, Operator-Schritt uebersprungen. <sha> steht in
#        <BACKUP>/repo-head-before.txt. Schema-Aenderungen sind additiv und
#        bleiben; der naechste normale Deploy holt BRANCH per --ff-only wieder
#        auf den aktuellen Stand.
#
# Variablen (per Umgebung überschreibbar):
#   REPO_DIR=/root/HHTTPS  INSTALL_DIR=/var/www/hhttps  PM2_APP=hhttps-v4
#   BRANCH=main  BACKUP_ROOT=/root/hhttps-backups  PORT=3000
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="${REPO_DIR:-/root/HHTTPS}"
SRC_DIR="${REPO_DIR}/server"
INSTALL_DIR="${INSTALL_DIR:-/var/www/hhttps}"
PM2_APP="${PM2_APP:-hhttps-v4}"
BRANCH="${BRANCH:-main}"
BACKUP_ROOT="${BACKUP_ROOT:-/root/hhttps-backups}"
PORT="${PORT:-3000}"
MIGRATION="sql/migration-phase-8-email-anchored-identity.sql"
OPERATOR_MARKER="-- >>> BOOT-DDL END"

DRY_RUN=0; SKIP_OPERATOR=0; DO_LINK=0; ROLLBACK_SHA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)       DRY_RUN=1; shift ;;
    --skip-operator) SKIP_OPERATOR=1; shift ;;
    --link)          DO_LINK=1; shift ;;
    # AP6-09 (#89): Rollback ist ein eigener Modus. Der alte Rat
    # (`git checkout <sha> && bash $0 --skip-operator`) scheiterte am
    # Branch-Preflight ("Repo steht auf 'HEAD'"), und `git pull` haette den
    # neuen Stand ohnehin wieder geholt.
    --rollback)
      ROLLBACK_SHA="${2:-}"
      [[ -n "$ROLLBACK_SHA" ]] || { echo "--rollback braucht einen Commit (siehe <BACKUP>/repo-head-before.txt)"; exit 2; }
      SKIP_OPERATOR=1; shift 2 ;;
    -h|--help)       sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1"; exit 2 ;;
  esac
done

G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; B=$'\033[0;36m'; N=$'\033[0m'
ok()   { printf "  ${G}✓${N} %s\n" "$1"; }
warn() { printf "  ${Y}⚠${N}  %s\n" "$1"; }
step() { printf "\n${B}═══ %s ═══${N}\n" "$1"; }
fail() { printf "  ${R}✗${N} %s\n" "$1"; exit 1; }
run()  { if [[ $DRY_RUN -eq 1 ]]; then printf "  ${Y}[dry-run]${N} %s\n" "$*"; else "$@"; fi; }

# .env-Wert lesen (ohne die Datei zu sourcen)
envval() { { grep -E "^${1}=" "$2" 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" ; return 0; }

TS="$(date +%Y%m%d-%H%M%S)"

# ─── 0. Layout erkennen ───────────────────────────────────────────────────────
step "0/7 Layout"
[[ -d "$SRC_DIR" ]] || fail "Repo nicht gefunden: $SRC_DIR"
LINKED=0
if [[ -L "$INSTALL_DIR" ]]; then
  TARGET="$(readlink -f "$INSTALL_DIR")"
  if [[ "$TARGET" == "$(readlink -f "$SRC_DIR")" ]]; then
    LINKED=1; ok "$INSTALL_DIR ist Symlink auf $SRC_DIR (kein Kopieren nötig)"
  else
    fail "$INSTALL_DIR ist Symlink auf $TARGET, erwartet $SRC_DIR"
  fi
else
  [[ -d "$INSTALL_DIR" ]] || fail "$INSTALL_DIR existiert nicht"
  ok "$INSTALL_DIR ist ein Verzeichnis (Kopier-Layout); Zustand liegt dort"
fi
# Zustandsdateien liegen im aktiven Verzeichnis (bei Symlink == Repo)
STATE_DIR="$INSTALL_DIR"
ENV_FILE="$STATE_DIR/.env"
[[ -f "$ENV_FILE" ]] || fail ".env fehlt: $ENV_FILE"

# ─── --link: einmalige Umstellung auf Symlink ─────────────────────────────────
if [[ $DO_LINK -eq 1 ]]; then
  step "LINK: $INSTALL_DIR → $SRC_DIR"
  [[ $LINKED -eq 1 ]] && { ok "bereits verlinkt"; exit 0; }
  # nginx (www-data) darf /root nicht betreten. Auf srv1421412 proxied nginx alles
  # an Node (kein Dateizugriff auf INSTALL_DIR) — dann ist ein Symlink nach /root ok.
  # Referenziert nginx INSTALL_DIR aber direkt (alias/root), muss das Repo außerhalb
  # von /root liegen.
  if command -v nginx >/dev/null && nginx -T 2>/dev/null | grep -E '^\s*(root|alias)\s' | grep -q "$INSTALL_DIR"; then
    case "$(readlink -f "$SRC_DIR")" in
      /root/*) fail "nginx liest Dateien direkt aus $INSTALL_DIR und das Repo liegt unter /root (für www-data unlesbar). Repo z. B. nach /var/www/HHTTPS verschieben, dann --link mit REPO_DIR=/var/www/HHTTPS" ;;
    esac
    warn "nginx referenziert $INSTALL_DIR direkt — Symlink-Ziel muss für www-data lesbar sein"
  else
    ok "nginx liest nicht direkt aus $INSTALL_DIR (nur Proxy) — Symlink-Ziel darf unter /root liegen"
  fi
  # Lokale Zustände/Extras, die nicht im Git-Repo liegen, mit übernehmen
  for f in .env keys eudi-keys developers force-verify-client.mjs; do
    if [[ -e "$INSTALL_DIR/$f" && ! -e "$SRC_DIR/$f" ]]; then
      run mkdir -p "$(dirname "$SRC_DIR/$f")"
      run cp -a "$INSTALL_DIR/$f" "$SRC_DIR/$f"; ok "übernommen: $f"
    fi
  done
  # Lokal geänderte, aber git-getrackte Dateien: Kopie ablegen, nicht überschreiben
  DC="eudi-verifier/docker/docker-compose.yaml"
  if [[ -f "$INSTALL_DIR/$DC" ]] && ! cmp -s "$INSTALL_DIR/$DC" "$SRC_DIR/$DC"; then
    run cp -a "$INSTALL_DIR/$DC" "$SRC_DIR/${DC}.local-${TS}"
    warn "$DC weicht lokal ab — Kopie unter ${DC}.local-${TS}; Unterschiede ins Repo übernehmen (laufende Container sind nicht betroffen)"
  fi
  run pm2 stop "$PM2_APP"
  run mv "$INSTALL_DIR" "${INSTALL_DIR}_pre-link_${TS}"
  run ln -s "$SRC_DIR" "$INSTALL_DIR"
  ok "Symlink gesetzt; altes Verzeichnis: ${INSTALL_DIR}_pre-link_${TS}"
  run pm2 restart "$PM2_APP" --update-env
  ok "Fertig. Jetzt normal deployen: bash $0"
  exit 0
fi

# ─── 1. Preflight ─────────────────────────────────────────────────────────────
step "1/7 Preflight"
cd "$REPO_DIR"
git fetch -q origin "$BRANCH" || fail "git fetch fehlgeschlagen"
CUR="$(git rev-parse --abbrev-ref HEAD)"
if [[ -n "$ROLLBACK_SHA" ]]; then
  # Rollback: der Commit muss lokal existieren; ein losgeloester HEAD (von
  # einem frueheren manuellen `git checkout <sha>`) ist in Ordnung — BRANCH
  # wird unten auf das Ziel gesetzt.
  ROLLBACK_SHA="$(git rev-parse --verify --quiet "${ROLLBACK_SHA}^{commit}")" \
    || fail "Rollback-Commit nicht gefunden: ${ROLLBACK_SHA}"
  ok "Rollback-Ziel: $(git rev-parse --short "$ROLLBACK_SHA") (aktuell: $(git rev-parse --short HEAD) auf '$CUR')"
else
  [[ "$CUR" == "$BRANCH" ]] || fail "Repo steht auf '$CUR', erwartet '$BRANCH' (git checkout $BRANCH)"
fi
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || fail "Repo hat lokale Änderungen — erst committen/stashen"
# Untracked Dateien, die auf origin/BRANCH getrackt sind, würden `git pull` blockieren
CONFLICTS="$(comm -12 <(git ls-files --others --exclude-standard | sort) <(git ls-tree -r --name-only "origin/$BRANCH" | sort) || true)"
[[ -z "$CONFLICTS" ]] || fail "Untracked Dateien kollidieren mit origin/$BRANCH (vor dem Pull entfernen): $(echo "$CONFLICTS" | tr '\n' ' ')"
ok "Repo auf $BRANCH, sauber; Remote-Head $(git rev-parse --short "origin/$BRANCH")"

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
[[ "$NODE_MAJOR" -ge 20 ]] || fail "Node ≥ 20 nötig (gefunden: $(node -v 2>/dev/null || echo keins))"
ok "Node $(node -v)"
command -v pm2 >/dev/null || fail "pm2 nicht gefunden"
command -v psql >/dev/null || fail "psql nicht gefunden"
command -v rsync >/dev/null || fail "rsync nicht gefunden"

PEPPER="$(envval HHTTPS_VERIFICATION_PEPPER "$ENV_FILE")"
if [[ -z "$PEPPER" ]]; then
  echo
  echo "  HHTTPS_VERIFICATION_PEPPER fehlt in $ENV_FILE."
  echo "  Der Pepper trägt ab jetzt die Identitäts-Anker (E-Mail → userId) und darf"
  echo "  NIE rotiert werden. Vorschlag (einmalig eintragen, dann Skript erneut starten):"
  echo "    echo \"HHTTPS_VERIFICATION_PEPPER=$(openssl rand -hex 32)\" >> $ENV_FILE"
  echo "  ACHTUNG: Falls die GitHub-Verifikation bereits mit einem Pepper lief, DIESEN"
  echo "  Wert verwenden (external-verify.js nutzt dieselbe Variable)."
  fail "Pepper fehlt"
fi
[[ ${#PEPPER} -ge 32 ]] || warn "Pepper ist kurz (${#PEPPER} Zeichen) — ≥ 32 empfohlen"
ok "HHTTPS_VERIFICATION_PEPPER gesetzt"

NODE_ENV_VAL="$(envval NODE_ENV "$ENV_FILE")"
[[ "$NODE_ENV_VAL" == "production" ]] || fail "NODE_ENV=production fehlt in $ENV_FILE (ohne das greifen Pepper-Pflicht und Dev-Mail-Schutz nicht)"
ok "NODE_ENV=production"
[[ -z "$(envval EMAIL_DEV_MODE "$ENV_FILE")" ]] || fail "EMAIL_DEV_MODE darf in Produktion nicht gesetzt sein"
for k in SMTP_HOST SMTP_USER SMTP_PASS; do
  [[ -n "$(envval "$k" "$ENV_FILE")" ]] || warn "$k leer — ohne SMTP antwortet /hhttps/email/send mit 503 (E-Mail ist jetzt Pflicht!)"
done
[[ -n "$(envval EUDI_VERIFIER_SECRET "$ENV_FILE")" ]] || warn "EUDI_VERIFIER_SECRET leer — EUDI/Age-Upgrade antwortet 503"

DB_HOST="$(envval DB_HOST "$ENV_FILE")"; DB_HOST="${DB_HOST:-localhost}"
DB_PORT="$(envval DB_PORT "$ENV_FILE")"; DB_PORT="${DB_PORT:-5432}"
DB_NAME="$(envval DB_NAME "$ENV_FILE")"; DB_NAME="${DB_NAME:-hhttps}"
DB_USER="$(envval DB_USER "$ENV_FILE")"; DB_USER="${DB_USER:-hhttps}"
DB_PASSWORD="$(envval DB_PASSWORD "$ENV_FILE")"
export PGPASSWORD="$DB_PASSWORD"
PSQL=(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -qtA)
"${PSQL[@]}" -c "SELECT 1" >/dev/null 2>&1 || fail "Postgres nicht erreichbar ($DB_USER@$DB_HOST:$DB_PORT/$DB_NAME)"
ok "Postgres erreichbar"
[[ $DRY_RUN -eq 1 ]] && { ok "Dry-run: Preflight bestanden, keine Änderungen"; exit 0; }

# ─── 2. Backup ────────────────────────────────────────────────────────────────
step "2/7 Backup → $BACKUP_ROOT/$TS"
BK="$BACKUP_ROOT/$TS"; mkdir -p "$BK"
cp -a "$ENV_FILE" "$BK/.env"
for d in keys eudi-keys; do [[ -e "$STATE_DIR/$d" ]] && cp -a "$STATE_DIR/$d" "$BK/$d"; done
if command -v pg_dump >/dev/null; then
  pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "$BK/db.sql.gz" && ok "pg_dump: $BK/db.sql.gz"
else
  warn "pg_dump nicht gefunden — kein DB-Backup"
fi
echo "$(git rev-parse HEAD)" > "$BK/repo-head-before.txt"
ok "Backup: .env, keys/, eudi-keys/, Repo-Head $(git rev-parse --short HEAD)"

# ─── 3. Build ─────────────────────────────────────────────────────────────────
step "3/7 Build"
if [[ -n "$ROLLBACK_SHA" ]]; then
  # Auf BRANCH bleiben (damit der naechste normale Deploy wieder
  # fast-forwarden kann) und ihn auf den Rollback-Commit setzen. Kein pull —
  # der wuerde den gerade zurueckgenommenen Stand wieder holen.
  git checkout -q -B "$BRANCH" "$ROLLBACK_SHA" || fail "git checkout -B $BRANCH $ROLLBACK_SHA fehlgeschlagen"
  ok "Rollback: $BRANCH steht auf $(git rev-parse --short HEAD) (kein git pull)"
else
  git pull -q --ff-only origin "$BRANCH" || fail "git pull --ff-only fehlgeschlagen"
  ok "Repo auf $(git rev-parse --short HEAD)"
fi
cd "$SRC_DIR"
npm ci --omit=dev --no-audit --no-fund >/dev/null || fail "npm ci fehlgeschlagen"
ok "npm ci --omit=dev"
node --check server.js && ok "server.js Syntax OK"

# ─── 4. Sync (nur Kopier-Layout) ──────────────────────────────────────────────
step "4/7 Sync"
if [[ $LINKED -eq 1 ]]; then
  ok "übersprungen (Symlink-Layout)"
else
  # Kein --delete: in INSTALL_DIR liegen lokale Extras (developers/, demo.html,
  # force-verify-client.mjs, Backups), die nicht im Repo sind. Lokal angepasste,
  # git-getrackte Dateien (docker-compose.yaml) werden nicht überschrieben.
  rsync -a \
    --exclude '.env' --exclude 'keys/' --exclude 'eudi-keys/' \
    --exclude '.git/' --exclude 'test/' --exclude 'node_modules/.cache/' \
    --exclude 'eudi-verifier/docker/docker-compose.yaml' \
    "$SRC_DIR/" "$INSTALL_DIR/"
  ok "rsync $SRC_DIR → $INSTALL_DIR (ohne --delete; .env, keys/, eudi-keys/, docker-compose.yaml unberührt)"
fi

# ─── 5. Restart ───────────────────────────────────────────────────────────────
step "5/7 Restart $PM2_APP"
cd "$INSTALL_DIR"
if pm2 describe "$PM2_APP" >/dev/null 2>&1; then
  pm2 restart "$PM2_APP" --update-env >/dev/null
else
  warn "$PM2_APP nicht in pm2 — starte neu"
  pm2 start server.js --name "$PM2_APP" --cwd "$INSTALL_DIR" >/dev/null
fi
pm2 save >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/hhttps/info" >/dev/null 2>&1; then ok "Server antwortet (nach ${i}s)"; break; fi
  sleep 1
  [[ $i -eq 30 ]] && { pm2 logs "$PM2_APP" --lines 40 --nostream || true; fail "Server antwortet nicht auf :$PORT — Logs oben"; }
done

# ─── 6. Operator-Migration ────────────────────────────────────────────────────
step "6/7 Operator-Migration (Phase 8: Grants + allowed_scopes += email)"
if [[ $SKIP_OPERATOR -eq 1 ]]; then
  warn "übersprungen (--skip-operator) — Bestandsclients bekommen den Scope 'email' NICHT"
else
  MIG="$INSTALL_DIR/$MIGRATION"
  [[ -f "$MIG" ]] || fail "Migration nicht gefunden: $MIG"
  grep -qF -- "$OPERATOR_MARKER" "$MIG" || fail "Marker '$OPERATOR_MARKER' nicht in $MIG"
  # Nur den OPERATOR-Abschnitt (alles NACH dem Marker) ausführen; idempotent.
  awk -v m="$OPERATOR_MARKER" 'f{print} index($0,m)==1{f=1}' "$MIG" | "${PSQL[@]}" >/dev/null \
    || fail "Operator-Abschnitt fehlgeschlagen"
  N_EMAIL="$("${PSQL[@]}" -c "SELECT count(*) FROM oauth_clients WHERE allowed_scopes::jsonb ? 'email'")"
  N_ALL="$("${PSQL[@]}" -c "SELECT count(*) FROM oauth_clients")"
  ok "Operator-Abschnitt angewendet — Clients mit Scope email: $N_EMAIL / $N_ALL"
fi

# ─── 7. Verify ────────────────────────────────────────────────────────────────
step "7/7 Verify"
BASE="http://127.0.0.1:$PORT"
DISC="$(curl -fsS "$BASE/.well-known/openid-configuration")"
echo "$DISC" | grep -q '"email"' && ok "Discovery: Scope/Claim email vorhanden" || fail "Discovery ohne 'email' — läuft der neue Code?"
echo "$DISC" | grep -q 'passkey_verified' && ok "Discovery: claims_supported enthält passkey_verified"
for col in "identity_anchors:email_hash" "identity_claims_cache:user_id" "sessions:pseudonym" "authorization_codes:verified_methods" "machine_operators:key_jkt"; do
  t="${col%%:*}"; c="${col##*:}"
  n="$("${PSQL[@]}" -c "SELECT count(*) FROM information_schema.columns WHERE table_name='$t' AND column_name='$c'")"
  [[ "$n" == "1" ]] && ok "Schema: $t.$c" || fail "Schema fehlt: $t.$c (Boot-DDL nicht angewendet? pm2 logs $PM2_APP)"
done
# #31: state/nonce/pkce_challenge müssen TEXT sein (migration-phase-3a1-authcodes-text.sql, Boot-DDL)
n="$("${PSQL[@]}" -c "SELECT count(*) FROM information_schema.columns WHERE table_name='authorization_codes' AND column_name IN ('state','nonce','pkce_challenge') AND data_type='text'")"
[[ "$n" == "3" ]] && ok "Schema: authorization_codes.state/nonce/pkce_challenge = text" || fail "Schema: authorization_codes.state/nonce/pkce_challenge nicht text (Boot-DDL phase 3a.1 nicht angewendet? pm2 logs $PM2_APP)"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{}' "$BASE/hhttps/webauthn/register/start")"
[[ "$CODE" == "400" ]] && ok "register/start ohne sessionId → 400 (Gate aktiv)" || warn "register/start ohne sessionId → $CODE (erwartet 400)"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{"sessionId":"x","email":"deploy-check@example.org"}' "$BASE/hhttps/email/send")"
[[ "$CODE" == "401" ]] && ok "email/send mit unbekannter Session → 401" || warn "email/send → $CODE (erwartet 401)"
RP="$(envval RP_ID "$ENV_FILE")"
[[ -n "$RP" ]] && { curl -fsS "https://$RP/hhttps/info" >/dev/null && ok "https://$RP/hhttps/info erreichbar" || warn "https://$RP/hhttps/info nicht erreichbar (nginx/TLS prüfen)"; }

echo
echo "  ${G}Deploy abgeschlossen.${N} Repo $(cd "$REPO_DIR" && git rev-parse --short HEAD) · Backup $BK"
echo "  Rollback: bash $0 --rollback \$(cat $BK/repo-head-before.txt)"
echo "  (Schema-Änderungen sind additiv und bleiben; .env/keys aus $BK bei Bedarf zurückkopieren)"

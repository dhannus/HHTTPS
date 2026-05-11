#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# HHTTPS — Migration v4.0 → v4.1
# Updates code, installs PostgreSQL, preserves keys/ and existing .env values.
# Existing in-memory state (sessions, tokens) is lost — by design (was ephemeral).
#
# Usage:  bash migrate.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

INSTALL_DIR="/var/www/hhttps"
PM2_APP="hhttps-v4"
ZIP_NAME="HumanProof_HHTTPS_v4.1.zip"

G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; B=$'\033[0;36m'; N=$'\033[0m'
ok()    { printf "  ${G}✓${N} %s\n" "$1"; }
warn()  { printf "  ${Y}⚠${N}  %s\n" "$1"; }
step()  { printf "\n${B}═══ %s ═══${N}\n" "$1"; }
fail()  { printf "  ${R}✗${N} %s\n" "$1"; exit 1; }

# ─── Locate ZIP ───────────────────────────────────────────────────────────────
ZIP_PATH=""
for c in "./${ZIP_NAME}" "${HOME}/${ZIP_NAME}" "/tmp/${ZIP_NAME}"; do
  [[ -f "$c" ]] && ZIP_PATH="$c" && break
done
[[ -z "$ZIP_PATH" ]] && fail "Datei ${ZIP_NAME} nicht gefunden in ./, ~/, oder /tmp/"
ok "ZIP gefunden: ${ZIP_PATH}"

# ─── Sanity checks ────────────────────────────────────────────────────────────
[[ ! -d "${INSTALL_DIR}" ]] && fail "${INSTALL_DIR} existiert nicht — erst v4 installieren!"
[[ ! -f "${INSTALL_DIR}/.env" ]] && fail ".env fehlt — Konfiguration neu erstellen!"

step "v4.1 Migration startet"

# ─── 1. Backup ────────────────────────────────────────────────────────────────
BACKUP="${INSTALL_DIR}_backup_$(date +%Y%m%d-%H%M%S)"
sudo cp -r "${INSTALL_DIR}" "${BACKUP}"
ok "Backup: ${BACKUP}"

# ─── 2. Stop server ───────────────────────────────────────────────────────────
if pm2 list 2>/dev/null | grep -q "${PM2_APP}"; then
  pm2 stop "${PM2_APP}" >/dev/null 2>&1 || true
  ok "Server gestoppt"
fi

# ─── 3. Extract new code ──────────────────────────────────────────────────────
TMP=$(mktemp -d)
unzip -oq "${ZIP_PATH}" -d "${TMP}"

SOURCE_DIR=""
for d in "${TMP}/hhttps-v4.1" "${TMP}"; do
  [[ -f "${d}/server.js" ]] && SOURCE_DIR="${d}" && break
done
[[ -z "${SOURCE_DIR}" ]] && fail "server.js nicht im ZIP gefunden"

# ─── 4. Copy new files (preserve .env, keys/, node_modules) ───────────────────
sudo rsync -a --exclude='.env' --exclude='keys/' --exclude='node_modules/' \
  "${SOURCE_DIR}/" "${INSTALL_DIR}/"
ok "Neue Dateien kopiert"
rm -rf "${TMP}"

# ─── 5. Make scripts executable ───────────────────────────────────────────────
sudo chmod +x "${INSTALL_DIR}/scripts/"*.sh 2>/dev/null || true

# ─── 6. Install dependencies (adds 'pg') ──────────────────────────────────────
cd "${INSTALL_DIR}"
echo "  npm install läuft..."
npm install --production >/dev/null 2>&1 || warn "npm install hatte Warnungen"
ok "Dependencies aktualisiert"

# ─── 7. Setup PostgreSQL ──────────────────────────────────────────────────────
bash "${INSTALL_DIR}/scripts/install-pg.sh" "${INSTALL_DIR}"

# ─── 8. Restart ───────────────────────────────────────────────────────────────
cd "${INSTALL_DIR}"
set -a; source .env; set +a

if pm2 list 2>/dev/null | grep -q "${PM2_APP}"; then
  pm2 restart "${PM2_APP}" --update-env >/dev/null
else
  pm2 start server.js --name "${PM2_APP}" >/dev/null
fi
pm2 save >/dev/null 2>&1
ok "Server gestartet"

# ─── 9. Verify ────────────────────────────────────────────────────────────────
sleep 3
if curl -sf http://localhost:3000/hhttps/info >/dev/null 2>&1; then
  ok "Server antwortet auf localhost:3000"
else
  warn "Server antwortet nicht — Logs prüfen: pm2 logs ${PM2_APP}"
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
printf "${G}╔══════════════════════════════════════════════════════════╗${N}\n"
printf "${G}║  v4.1 Migration erfolgreich                              ║${N}\n"
printf "${G}╚══════════════════════════════════════════════════════════╝${N}\n"
echo ""
echo "  Backup:    ${BACKUP}"
echo "  Status:    pm2 status"
echo "  Logs:      pm2 logs ${PM2_APP}"
echo "  Test API:  curl https://\$(grep RP_ID ${INSTALL_DIR}/.env | cut -d= -f2)/hhttps/info"
echo ""
echo "  Falls etwas schief geht, Rollback:"
echo "    sudo rm -rf ${INSTALL_DIR}"
echo "    sudo mv ${BACKUP} ${INSTALL_DIR}"
echo "    pm2 restart ${PM2_APP}"
echo ""

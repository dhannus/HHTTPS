#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# HHTTPS v4.1 — PostgreSQL Setup
# Installs PostgreSQL, creates DB + user, applies schema, writes credentials to .env
#
# Idempotent: safe to run multiple times.
# Usage: bash install-pg.sh [INSTALL_DIR]
#   INSTALL_DIR defaults to /var/www/hhttps
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

INSTALL_DIR="${1:-/var/www/hhttps}"
DB_NAME="hhttps"
DB_USER="hhttps"

# Colors
G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; B=$'\033[0;36m'; N=$'\033[0m'

ok()    { printf "  ${G}✓${N} %s\n" "$1"; }
warn()  { printf "  ${Y}⚠${N}  %s\n" "$1"; }
err()   { printf "  ${R}✗${N} %s\n" "$1"; }
step()  { printf "\n${B}═══ %s ═══${N}\n" "$1"; }

step "PostgreSQL Setup für HHTTPS v4.1"

# 1. Install PostgreSQL (if not already present)
if ! command -v psql &>/dev/null; then
  echo "  PostgreSQL wird installiert..."
  sudo apt-get update -qq
  sudo apt-get install -y postgresql postgresql-contrib >/dev/null
  ok "PostgreSQL installiert"
else
  ok "PostgreSQL bereits installiert ($(psql --version | head -1))"
fi

# 2. Ensure service is running
sudo systemctl enable --now postgresql >/dev/null 2>&1
ok "PostgreSQL-Dienst läuft"

# 3. Create or update DB user
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
  warn "User '${DB_USER}' existiert bereits"
  read -p "  Passwort neu setzen? [y/N]: " resetpw
  if [[ "${resetpw,,}" == "y" ]]; then
    DB_PASSWORD=$(openssl rand -hex 24)
    sudo -u postgres psql -c "ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" >/dev/null
    ok "Passwort neu gesetzt"
  else
    DB_PASSWORD=""
    warn "Bestehende Credentials beibehalten — sicherstellen, dass die .env das alte Passwort hat!"
  fi
else
  DB_PASSWORD=$(openssl rand -hex 24)
  sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" >/dev/null
  ok "DB-User '${DB_USER}' angelegt"
fi

# 4. Create DB if not exists
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
  ok "Datenbank '${DB_NAME}' existiert bereits"
else
  sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" >/dev/null
  ok "Datenbank '${DB_NAME}' angelegt"
fi

# 5. Grant privileges
sudo -u postgres psql -d "${DB_NAME}" -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null
sudo -u postgres psql -d "${DB_NAME}" -c "GRANT ALL ON SCHEMA public TO ${DB_USER};" >/dev/null
ok "Berechtigungen erteilt"

# 6. Apply schema
SCHEMA_FILE="${INSTALL_DIR}/sql/schema.sql"
if [[ ! -f "${SCHEMA_FILE}" ]]; then
  err "Schema-Datei nicht gefunden: ${SCHEMA_FILE}"
  exit 1
fi

PGPASSWORD="${DB_PASSWORD:-}" psql -h localhost -U "${DB_USER}" -d "${DB_NAME}" \
  -f "${SCHEMA_FILE}" -v ON_ERROR_STOP=1 >/dev/null 2>&1 || \
  sudo -u postgres psql -d "${DB_NAME}" -f "${SCHEMA_FILE}" -v ON_ERROR_STOP=1 >/dev/null
ok "Schema angewendet (Tabellen erstellt/aktualisiert)"

# 7. Update .env (only if we set a new password)
ENV_FILE="${INSTALL_DIR}/.env"
if [[ -n "${DB_PASSWORD}" ]]; then
  if [[ -f "${ENV_FILE}" ]]; then
    # Remove old DB_* lines
    sudo sed -i '/^DB_HOST=/d; /^DB_PORT=/d; /^DB_NAME=/d; /^DB_USER=/d; /^DB_PASSWORD=/d' "${ENV_FILE}"
  else
    sudo touch "${ENV_FILE}"
  fi
  cat <<EOF | sudo tee -a "${ENV_FILE}" >/dev/null

# PostgreSQL (v4.1)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
EOF
  sudo chmod 600 "${ENV_FILE}"
  ok ".env aktualisiert mit DB-Credentials"
fi

# 8. Verify
TABLES=$(sudo -u postgres psql -d "${DB_NAME}" -tAc \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
ok "Verifikation: ${TABLES} Tabellen in ${DB_NAME}"

# Done
echo ""
printf "${G}╔══════════════════════════════════════════════════════════╗${N}\n"
printf "${G}║  PostgreSQL Setup erfolgreich.                           ║${N}\n"
printf "${G}╚══════════════════════════════════════════════════════════╝${N}\n"
echo ""
echo "  Datenbank:  ${DB_NAME}"
echo "  User:       ${DB_USER}"
echo "  Tabellen:   ${TABLES}"
echo "  Connection: postgresql://${DB_USER}@localhost/${DB_NAME}"
echo ""
echo "  Test mit:    psql -h localhost -U ${DB_USER} ${DB_NAME}"
echo "  PM2 Restart: pm2 restart hhttps-v4"
echo ""

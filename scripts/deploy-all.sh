#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# HumanProof / HHTTPS — Master Deployment Script v2
#
# Vollständige Configs (kein Regex-Bastel mehr), idempotent ausführbar.
# Funktioniert mit allen Nginx-Versionen ≥ 1.18.
# Nutzung: sudo bash scripts/deploy-all.sh
# ═════════════════════════════════════════════════════════════════════════════

set -e

SERVER_DIR="/var/www/hhttps"
IAMHMN_DIR="/var/www/iamhmn"
SPEC_DIR="/var/www/hhttps-static"
PM2_APP="hhttps-v4"
DB_NAME="hhttps"
DB_USER="hhttps"

DOMAIN_HHTTPS="hhttps.org"
DOMAIN_IAMHMN="iamhmn.org"
DOMAIN_LEGACY="funnysearch.eu"
EMAIL_CERTBOT="daniel.hannuschka@tweakz.de"

G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; B=$'\033[0;36m'; N=$'\033[0m'
ok()   { printf "  ${G}✓${N} %s\n" "$1"; }
warn() { printf "  ${Y}⚠${N}  %s\n" "$1"; }
err()  { printf "  ${R}✗${N} %s\n" "$1"; exit 1; }
step() { printf "\n${B}════════ %s ════════${N}\n" "$1"; }
ask()  { read -p "  $1 [y/N]: " a; [[ "${a,,}" == "y" ]]; }

[[ $EUID -ne 0 ]] && err "Bitte als root ausführen oder mit sudo"

RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step "HumanProof HHTTPS — Master Deployment v2"
echo ""
echo "  Ziel-Domains:"
echo "    ${DOMAIN_HHTTPS}         (Protokoll-Server + Spec)"
echo "    ${DOMAIN_IAMHMN}         (Marketing-Landing)"
echo "    ${DOMAIN_LEGACY}         (bestehend, bleibt funktionsfähig)"
echo ""
if ! ask "Mit Deployment beginnen?"; then
  echo "  Abgebrochen."
  exit 0
fi

# ─── 1. System-Pakete ────────────────────────────────────────────────────────
step "[1/9] System-Pakete"

apt-get update -qq

if ! command -v node >/dev/null || [[ $(node -v | sed 's/v//;s/\..*//') -lt 20 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
  apt-get install -y nodejs >/dev/null
fi
ok "Node.js $(node -v)"

command -v psql >/dev/null || { apt-get install -y postgresql postgresql-contrib >/dev/null; }
systemctl enable --now postgresql >/dev/null 2>&1
ok "PostgreSQL: $(psql --version | head -1)"

command -v nginx >/dev/null || apt-get install -y nginx >/dev/null
ok "Nginx $(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"

command -v certbot >/dev/null || apt-get install -y certbot python3-certbot-nginx >/dev/null
ok "Certbot"

command -v pm2 >/dev/null || npm install -g pm2 >/dev/null 2>&1
ok "PM2 $(pm2 -v)"

apt-get install -y unzip rsync curl >/dev/null
ok "Tools (unzip, rsync, curl)"

# ─── 2. PostgreSQL ───────────────────────────────────────────────────────────
step "[2/9] PostgreSQL"

if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
  warn "User '${DB_USER}' existiert bereits"
  if ask "Passwort neu generieren?"; then
    DB_PASSWORD=$(openssl rand -hex 24)
    sudo -u postgres psql -c "ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" >/dev/null
    ok "Neues Passwort gesetzt"
    RESET_PW=1
  else
    DB_PASSWORD=""
    RESET_PW=0
    warn "Behalte bestehendes Passwort (muss in .env stimmen)"
  fi
else
  DB_PASSWORD=$(openssl rand -hex 24)
  sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" >/dev/null
  ok "DB-User '${DB_USER}' angelegt"
  RESET_PW=1
fi

if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
  ok "DB '${DB_NAME}' existiert"
else
  sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" >/dev/null
  ok "DB '${DB_NAME}' angelegt"
fi

sudo -u postgres psql -d "${DB_NAME}" -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER}; GRANT ALL ON SCHEMA public TO ${DB_USER};" >/dev/null
ok "Berechtigungen erteilt"

# ─── 3. HHTTPS Server ────────────────────────────────────────────────────────
step "[3/9] HHTTPS Server v4.1"

[[ ! -d "${RELEASE_DIR}/server" ]] && err "Server-Quellen fehlen"

if [[ -d "${SERVER_DIR}" ]]; then
  BACKUP="${SERVER_DIR}_backup_$(date +%Y%m%d-%H%M%S)"
  cp -r "${SERVER_DIR}" "${BACKUP}"
  ok "Backup: ${BACKUP}"
fi

mkdir -p "${SERVER_DIR}"
rsync -a --exclude='.env' --exclude='keys/' --exclude='node_modules/' \
  "${RELEASE_DIR}/server/" "${SERVER_DIR}/"
ok "Server-Code installiert"

if [[ ! -f "${SERVER_DIR}/.env" ]] || [[ "${RESET_PW}" == "1" ]]; then
  if [[ -f "${SERVER_DIR}/.env" ]]; then
    sed -i '/^DB_HOST=/d; /^DB_PORT=/d; /^DB_NAME=/d; /^DB_USER=/d; /^DB_PASSWORD=/d; /^PORT=/d; /^RP_ID=/d; /^ORIGIN=/d; /^BASE_URL=/d' "${SERVER_DIR}/.env"
  fi
  cat >> "${SERVER_DIR}/.env" <<EOF

# === HHTTPS Server v4.1 ===
PORT=3000
RP_ID=${DOMAIN_HHTTPS}
ORIGIN=https://${DOMAIN_HHTTPS}
BASE_URL=https://${DOMAIN_HHTTPS}

# === PostgreSQL ===
DB_HOST=localhost
DB_PORT=5432
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
EOF
  chmod 600 "${SERVER_DIR}/.env"
  ok ".env aktualisiert"
else
  ok ".env unverändert"
fi

ENV_PW=$(grep ^DB_PASSWORD "${SERVER_DIR}/.env" | cut -d= -f2)
if PGPASSWORD="${ENV_PW}" psql -h localhost -U "${DB_USER}" -d "${DB_NAME}" \
    -f "${SERVER_DIR}/sql/schema.sql" -v ON_ERROR_STOP=1 >/dev/null 2>&1; then
  ok "Schema angewendet"
else
  sudo -u postgres psql -d "${DB_NAME}" -f "${SERVER_DIR}/sql/schema.sql" -v ON_ERROR_STOP=1 >/dev/null
  ok "Schema angewendet (via postgres-User)"
fi

cd "${SERVER_DIR}"
npm install --production --silent 2>&1 | tail -2
ok "Dependencies installiert"

mkdir -p "${SERVER_DIR}/keys"
chown -R www-data:www-data "${SERVER_DIR}/keys"
ok "Berechtigungen gesetzt"

# ─── 4. Marketing-Webseite ───────────────────────────────────────────────────
step "[4/9] Marketing-Webseite iamhmn.org"

mkdir -p "${IAMHMN_DIR}"
cp "${RELEASE_DIR}/sites/iamhmn.html" "${IAMHMN_DIR}/index.html"
chown -R www-data:www-data "${IAMHMN_DIR}"
ok "iamhmn.org installiert"

# ─── 5. Spec-Seite ───────────────────────────────────────────────────────────
step "[5/9] Spec-Seite hhttps.org/spec"

mkdir -p "${SPEC_DIR}"
cp "${RELEASE_DIR}/sites/spec.html" "${SPEC_DIR}/spec.html"
chown -R www-data:www-data "${SPEC_DIR}"
ok "spec.html installiert"

# ─── 6. Rate-Limit-Zones + HTTP-Configs ──────────────────────────────────────
step "[6/9] Nginx Rate-Limits"

cat > /etc/nginx/conf.d/hhttps-ratelimits.conf <<'EOF'
# HHTTPS Rate-Limit-Zones (Nginx-Layer, vor dem Node-Backend)
limit_req_zone $binary_remote_addr zone=hhttps_api:10m       rate=60r/m;
limit_req_zone $binary_remote_addr zone=hhttps_webauthn:10m  rate=10r/m;
limit_req_zone $binary_remote_addr zone=hhttps_email:10m     rate=3r/m;
limit_req_zone $binary_remote_addr zone=hhttps_static:10m    rate=300r/m;
limit_conn_zone $binary_remote_addr zone=hhttps_conn:10m;
EOF
ok "Rate-Limit-Zones definiert"

# Wenn noch keine SSL-Certs da: erstmal nur HTTP für Certbot-Challenge
if [[ ! -d /etc/letsencrypt/live/${DOMAIN_HHTTPS} ]] || [[ ! -d /etc/letsencrypt/live/${DOMAIN_IAMHMN} ]]; then
  cat > /etc/nginx/sites-available/hhttps.org <<EOF
server {
    listen 80;
    server_name ${DOMAIN_HHTTPS} www.${DOMAIN_HHTTPS};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
  cat > /etc/nginx/sites-available/iamhmn.org <<EOF
server {
    listen 80;
    server_name ${DOMAIN_IAMHMN} www.${DOMAIN_IAMHMN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
  ln -sf /etc/nginx/sites-available/hhttps.org /etc/nginx/sites-enabled/
  ln -sf /etc/nginx/sites-available/iamhmn.org /etc/nginx/sites-enabled/
  rm -f /etc/nginx/sites-enabled/default
  nginx -t >/dev/null 2>&1 && systemctl reload nginx
  ok "HTTP-Configs für Certbot-Challenge aktiv"
else
  ok "SSL-Certs vorhanden, HTTP-Phase übersprungen"
fi

# ─── 7. SSL-Zertifikate ──────────────────────────────────────────────────────
step "[7/9] SSL-Zertifikate"

mkdir -p /var/www/html

if [[ ! -d /etc/letsencrypt/live/${DOMAIN_HHTTPS} ]]; then
  certbot certonly --webroot -w /var/www/html \
    -d ${DOMAIN_HHTTPS} -d www.${DOMAIN_HHTTPS} \
    --email "${EMAIL_CERTBOT}" --agree-tos --non-interactive --no-eff-email
  ok "Zertifikat ${DOMAIN_HHTTPS} ausgestellt"
else
  ok "Zertifikat ${DOMAIN_HHTTPS} existiert"
fi

if [[ ! -d /etc/letsencrypt/live/${DOMAIN_IAMHMN} ]]; then
  certbot certonly --webroot -w /var/www/html \
    -d ${DOMAIN_IAMHMN} -d www.${DOMAIN_IAMHMN} \
    --email "${EMAIL_CERTBOT}" --agree-tos --non-interactive --no-eff-email
  ok "Zertifikat ${DOMAIN_IAMHMN} ausgestellt"
else
  ok "Zertifikat ${DOMAIN_IAMHMN} existiert"
fi

systemctl enable --now certbot.timer >/dev/null 2>&1
ok "Auto-Renewal aktiv"

# ─── 8. Nginx HTTPS-Configs (vollständig) ────────────────────────────────────
step "[8/9] Nginx HTTPS-Configs"

cat > /etc/nginx/sites-available/hhttps.org <<EOF
# HTTP → HTTPS Redirect
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN_HHTTPS} www.${DOMAIN_HHTTPS};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://${DOMAIN_HHTTPS}\$request_uri; }
}

# HTTPS Main (Apex) — http2 nur hier (vermeidet "protocol options redefined")
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN_HHTTPS};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN_HHTTPS}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN_HHTTPS}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    limit_conn hhttps_conn 30;

    location = /spec {
        limit_req zone=hhttps_static burst=20 nodelay;
        alias ${SPEC_DIR}/spec.html;
        add_header Content-Type "text/html; charset=utf-8";
        add_header Cache-Control "public, max-age=300";
    }
    location = /spec.html { return 301 /spec; }

    location ~ ^/hhttps/webauthn/ {
        limit_req zone=hhttps_webauthn burst=5 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location = /hhttps/email/send {
        limit_req zone=hhttps_email burst=2 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /hhttps/ {
        limit_req zone=hhttps_api burst=30 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /.well-known/ {
        limit_req zone=hhttps_static burst=30 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        limit_req zone=hhttps_api burst=20 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

# www → Apex Redirect (kein http2 hier, ist schon im Apex-Block aktiviert)
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name www.${DOMAIN_HHTTPS};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN_HHTTPS}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN_HHTTPS}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    return 301 https://${DOMAIN_HHTTPS}\$request_uri;
}
EOF
ok "hhttps.org Config geschrieben"

cat > /etc/nginx/sites-available/iamhmn.org <<EOF
# HTTP → HTTPS Redirect
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN_IAMHMN} www.${DOMAIN_IAMHMN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://${DOMAIN_IAMHMN}\$request_uri; }
}

# HTTPS Marketing (Apex)
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${DOMAIN_IAMHMN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN_IAMHMN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN_IAMHMN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    limit_conn hhttps_conn 30;

    root ${IAMHMN_DIR};
    index index.html;

    location / {
        limit_req zone=hhttps_static burst=30 nodelay;
        try_files \$uri \$uri/ =404;
        add_header Cache-Control "public, max-age=300";
    }
}

# www → Apex Redirect
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name www.${DOMAIN_IAMHMN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN_IAMHMN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN_IAMHMN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    return 301 https://${DOMAIN_IAMHMN}\$request_uri;
}
EOF
ok "iamhmn.org Config geschrieben"

ln -sf /etc/nginx/sites-available/hhttps.org /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/iamhmn.org /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

if nginx -t 2>&1 | grep -qE "emerg|fail"; then
  err "Nginx-Config fehlerhaft — siehe Output"
else
  systemctl reload nginx
  ok "Nginx neu geladen"
fi

# ─── 9. PM2 ──────────────────────────────────────────────────────────────────
step "[9/9] PM2 + Auto-Start"

cd "${SERVER_DIR}"
set -a; source .env; set +a

if pm2 list 2>/dev/null | grep -q "${PM2_APP}"; then
  pm2 restart "${PM2_APP}" --update-env >/dev/null
  ok "${PM2_APP} neu gestartet"
else
  pm2 start server.js --name "${PM2_APP}" >/dev/null
  ok "${PM2_APP} gestartet"
fi

pm2 save >/dev/null 2>&1

if [[ ! -f /etc/systemd/system/pm2-root.service ]]; then
  pm2 startup systemd -u root --hp /root 2>&1 | tail -1 | bash 2>&1 || true
  ok "PM2 Auto-Start aktiviert"
else
  ok "PM2 Auto-Start bereits aktiv"
fi

# ─── Verifikation ────────────────────────────────────────────────────────────
step "Verifikation"

sleep 3

if curl -sf http://localhost:3000/hhttps/info >/dev/null; then
  ok "Server localhost:3000 antwortet"
else
  warn "Server antwortet nicht — pm2 logs ${PM2_APP}"
fi

for url in https://${DOMAIN_HHTTPS}/ https://${DOMAIN_HHTTPS}/spec https://${DOMAIN_IAMHMN}/ https://www.${DOMAIN_HHTTPS}/ https://www.${DOMAIN_IAMHMN}/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${url}" || echo "000")
  if [[ "${code}" =~ ^[23] ]]; then
    ok "${url} → ${code}"
  else
    warn "${url} → ${code}"
  fi
done

if curl -sf "https://${DOMAIN_HHTTPS}/.well-known/jwks.json" | grep -q "kty"; then
  ok "JWKS verfügbar"
else
  warn "JWKS nicht erreichbar"
fi

echo ""
echo "  ${B}Datenbank:${N}"
TBL=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null || echo "?")
CRED=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "SELECT COUNT(*) FROM credentials;" 2>/dev/null || echo "?")
echo "    Tabellen:           ${TBL}"
echo "    Registrierte Keys:  ${CRED}"

echo ""
printf "${G}╔════════════════════════════════════════════════════════════════╗${N}\n"
printf "${G}║  Deployment abgeschlossen                                      ║${N}\n"
printf "${G}╚════════════════════════════════════════════════════════════════╝${N}\n"
echo ""
echo "  Live:"
echo "    https://${DOMAIN_HHTTPS}/              Service + Login"
echo "    https://${DOMAIN_HHTTPS}/spec          Protokoll-Spec"
echo "    https://${DOMAIN_HHTTPS}/hhttps/info   API-Info"
echo "    https://${DOMAIN_IAMHMN}/              Marketing"
echo ""
echo "  Verwaltung:"
echo "    pm2 status               Server-Status"
echo "    pm2 logs ${PM2_APP}      Logs"
echo "    pm2 restart ${PM2_APP}   Neustart"
echo "    nginx -t                 Nginx-Config testen"
echo "    systemctl reload nginx   Nginx neu laden"
echo ""
[[ -n "${BACKUP:-}" ]] && echo "  Backup: ${BACKUP}"
echo ""

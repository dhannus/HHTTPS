#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# HumanProof / HHTTPS — Master Deployment Script v2
#
# Vollständige Configs (kein Regex-Bastel mehr), idempotent ausführbar.
# Funktioniert mit allen Nginx-Versionen ≥ 1.18.
# Nutzung: sudo bash scripts/deploy-all.sh
# ═════════════════════════════════════════════════════════════════════════════

# AP6-57 (#213): the same shell options as every other script in the project.
set -euo pipefail

SERVER_DIR="/var/www/hhttps"
IAMHMN_DIR="/var/www/iamhmn"
SPEC_DIR="/var/www/hhttps-static"
PM2_APP="hhttps-v4"
DB_NAME="hhttps"
DB_USER="hhttps"

DOMAIN_HHTTPS="hhttps.org"
DOMAIN_IAMHMN="iamhmn.org"
EMAIL_CERTBOT="daniel.hannuschka@tweakz.de"

# AP6-57 (#213) / AP6-48 (#192): Farben, Log-Helfer und der .env-Leser aus
# der einen gemeinsamen Bibliothek statt aus fünf Kopien.
RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${RELEASE_DIR}/server/scripts/lib/common.sh"
# In diesem Skript bricht `err` den Lauf ab (wie bisher). Nicht über `fail`
# aus der Bibliothek definieren — `fail` ruft selbst `err` auf.
err()  { printf "  ${R}✗${N} %s\n" "$1" >&2; exit 1; }
ask()  { read -r -p "  $1 [y/N]: " a; [[ "${a,,}" == "y" ]]; }

[[ $EUID -ne 0 ]] && err "Bitte als root ausführen oder mit sudo"

step "HumanProof HHTTPS — Master Deployment v2"
echo ""
echo "  Ziel-Domains:"
echo "    ${DOMAIN_HHTTPS}         (Protokoll-Server + Spec)"
echo "    ${DOMAIN_IAMHMN}         (Marketing-Landing)"
echo ""
if ! ask "Mit Deployment beginnen?"; then
  echo "  Abgebrochen."
  exit 0
fi

# ─── 1. System-Pakete ────────────────────────────────────────────────────────
step "[1/9] System-Pakete"

apt-get update -qq

if ! command -v node >/dev/null || [[ $(node -v | sed 's/v//;s/\..*//') -lt 20 ]]; then
  # AP6-23 (#213): kein `curl … | bash`. Das NodeSource-Repo wird mit seinem
  # GPG-Schlüssel eingetragen; ab da prüft apt jede Signatur selbst.
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
    || err "NodeSource-GPG-Schlüssel konnte nicht geholt werden"
  chmod 0644 /usr/share/keyrings/nodesource.gpg
  echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq
  apt-get install -y nodejs >/dev/null || err "nodejs konnte nicht installiert werden"
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

# ─── 2. HHTTPS Server ─────────────────────────────────────────────────
step "[2/9] HHTTPS Server v4.1"

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

# Anwendungs-Teil der .env (der DB-Teil kommt aus install-pg.sh, Schritt 3).
if [[ ! -f "${SERVER_DIR}/.env" ]] || [[ -z "$(env_get RP_ID "${SERVER_DIR}/.env")" ]]; then
  cat >> "${SERVER_DIR}/.env" <<EOF

# === HHTTPS Server v4.1 ===
PORT=3000
RP_ID=${DOMAIN_HHTTPS}
ORIGIN=https://${DOMAIN_HHTTPS}
BASE_URL=https://${DOMAIN_HHTTPS}
EOF
  chmod 600 "${SERVER_DIR}/.env"
  ok ".env: Anwendungswerte geschrieben"
else
  ok ".env: Anwendungswerte unverändert"
fi

cd "${SERVER_DIR}"
# AP6-57 (#213): `--production` ist seit npm 7 deprecated.
npm ci --omit=dev --no-audit --no-fund >/dev/null || err "npm ci fehlgeschlagen"
ok "Dependencies installiert"

# ─── 3. PostgreSQL ────────────────────────────────────────────────────
step "[3/9] PostgreSQL (server/scripts/install-pg.sh)"

# AP6-47 (#186): Dieses Skript hatte eine eigene, bereits driftende Kopie der
# Provisionierung (User/DB/Grants, .env-Zeilen, Ownership-Reparatur,
# Migrationslauf). Es gibt jetzt EINE Quelle: server/scripts/install-pg.sh —
# dasselbe Skript, das auch einzeln aufgerufen wird. Es ist idempotent, läuft
# als App-User und wendet die ganze Migrationskette über das Ledger an.
bash "${SERVER_DIR}/scripts/install-pg.sh" "${SERVER_DIR}" \
  || err "PostgreSQL-Setup fehlgeschlagen"

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

# AP6-18 (#126): nginx does NOT inherit `add_header` into a block that sets
# its own add_header — a `location` with e.g. Cache-Control silently drops
# every server-level security header. The headers therefore live in one
# snippet per site, included at server level AND in every location that needs
# headers of its own. Cache-Control is set via `expires`, which is not an
# add_header and therefore never triggers the inheritance cut-off.
mkdir -p /etc/nginx/snippets
cat > /etc/nginx/snippets/hhttps-security-headers.conf <<'EOF'
# HHTTPS security headers (hhttps.org). Include in `server` AND in every
# `location` that uses add_header itself — add_header is not inherited then.
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options SAMEORIGIN always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
EOF
cat > /etc/nginx/snippets/iamhmn-security-headers.conf <<'EOF'
# Security headers (iamhmn.org). Include in `server` AND in every `location`
# that uses add_header itself — add_header is not inherited then.
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
EOF
ok "Security-Header-Snippets geschrieben"

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

    include snippets/hhttps-security-headers.conf;

    limit_conn hhttps_conn 30;

    location = /spec {
        limit_req zone=hhttps_static burst=20 nodelay;
        alias ${SPEC_DIR}/spec.html;
        # .html → text/html via mime.types; `charset` appends "; charset=utf-8"
        # and `expires` sets Cache-Control — neither is an add_header, so the
        # included security headers below are the only ones in this block.
        charset utf-8;
        expires 5m;
        include snippets/hhttps-security-headers.conf;
    }
    location = /spec.html { return 301 /spec; }

    # AP4-27 (Review 2026-09): the three verifier endpoints are called ONLY by
    # the in-process EUDI verifier over http://127.0.0.1:3000, which bypasses
    # nginx entirely. Nothing from the outside has any business here — and a
    # loopback check inside the app cannot tell an external proxied request
    # apart on its own, because nginx runs on this very host.
    location ~ ^/hhttps/(age/upgrade|age/direct|eid/upgrade)$ {
        deny all;
    }

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

    include snippets/iamhmn-security-headers.conf;

    limit_conn hhttps_conn 30;

    root ${IAMHMN_DIR};
    index index.html;

    location / {
        limit_req zone=hhttps_static burst=30 nodelay;
        try_files \$uri \$uri/ =404;
        # Cache-Control via `expires`, not add_header (AP6-18).
        expires 5m;
        include snippets/iamhmn-security-headers.conf;
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

# AP6-17 (#118): the .env is NOT sourced. server.js loads it itself via dotenv;
# sourcing would export every secret into the pm2 process environment and into
# ~/.pm2/dump.pm2, and unquoted values with spaces or `$(…)` would be executed.
cd "${SERVER_DIR}"

if pm2 list 2>/dev/null | grep -q "${PM2_APP}"; then
  pm2 restart "${PM2_APP}" --update-env >/dev/null
  ok "${PM2_APP} neu gestartet"
else
  # --cwd so dotenv finds the .env when pm2 resurrects the process later.
  pm2 start server.js --name "${PM2_APP}" --cwd "${SERVER_DIR}" >/dev/null
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
  # AP6-24 (#213): kein -k. Der Live-Check soll gerade feststellen, ob das
  # ausgelieferte Zertifikat gültig ist — mit -k wäre ein kaputtes TLS grün.
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${url}" || echo "000")
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

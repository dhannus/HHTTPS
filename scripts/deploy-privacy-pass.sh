#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# iamhmn / HHTTPS — Privacy Pass Module Deployment
#
# Additives Deployment des Privacy-Pass-Moduls (RFC 9576–9578).
# Berührt KEINE bestehenden v4.1-Endpoints — fügt nur /privacy-pass/* und
# /.well-known/private-token-issuer-directory hinzu.
#
# Workflow:
#   1. Repo nach ${RELEASE_DIR} synchronisieren (git pull / clone)
#   2. Privacy-Pass-Modul nach ${SERVER_DIR}/privacy-pass/ rsync
#   3. Prüfen, ob server.js die drei Eingriffe (Import, Init, Mount) hat
#      — wenn nicht: Patch vorschlagen, nach Bestätigung anwenden
#   4. npm install (für @cloudflare/voprf-ts)
#   5. PM2 restart
#   6. Verifikation: drei neue Endpoints abklopfen
#   7. (Optional, getrennt) Änderungen committen und pushen
#
# Nutzung (auf dem VPS, als root):
#   cd /root/HHTTPS && sudo bash scripts/deploy-privacy-pass.sh
#
# Optional ENV-Vars:
#   REPO_URL=https://github.com/dhannus/HHTTPS.git
#   REPO_BRANCH=main
#   RELEASE_DIR=/root/HHTTPS
#   SKIP_GIT=1          überspringt git pull, nutzt lokalen Stand
#   AUTO_PATCH=1        wendet server.js-Patch ohne Rückfrage an
#   ALLOW_COMMIT=1      erlaubt Commit/Push am Ende (sonst übersprungen)
# ═════════════════════════════════════════════════════════════════════════════

set -e

# ─── Konfiguration ────────────────────────────────────────────────────────────
SERVER_DIR="/var/www/hhttps"
PM2_APP="hhttps-v4"
DOMAIN_HHTTPS="hhttps.org"

REPO_URL="${REPO_URL:-https://github.com/dhannus/HHTTPS.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
RELEASE_DIR="${RELEASE_DIR:-/root/HHTTPS}"

# ─── Output (identisch zu deploy-all.sh) ──────────────────────────────────────
G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; B=$'\033[0;36m'; N=$'\033[0m'
ok()   { printf "  ${G}✓${N} %s\n" "$1"; }
warn() { printf "  ${Y}⚠${N}  %s\n" "$1"; }
err()  { printf "  ${R}✗${N} %s\n" "$1"; exit 1; }
step() { printf "\n${B}════════ %s ════════${N}\n" "$1"; }
ask()  { read -p "  $1 [y/N]: " a; [[ "${a,,}" == "y" ]]; }

[[ $EUID -ne 0 ]] && err "Bitte als root ausführen oder mit sudo"

step "iamhmn / HHTTPS — Privacy Pass Module Deployment"
echo ""
echo "  Ziel-Verzeichnisse:"
echo "    Release:   ${RELEASE_DIR}"
echo "    Server:    ${SERVER_DIR}"
echo "    Domain:    https://${DOMAIN_HHTTPS}"
echo "    PM2-App:   ${PM2_APP}"
echo "    Repo:      ${REPO_URL} (${REPO_BRANCH})"
echo ""
if ! ask "Mit Deployment beginnen?"; then
  echo "  Abgebrochen."
  exit 0
fi

# ─── 1. Repository synchronisieren ────────────────────────────────────────────
step "[1/7] Repository synchronisieren"

if [[ "${SKIP_GIT:-0}" == "1" ]]; then
  warn "SKIP_GIT=1 — überspringe git pull, nutze lokalen Stand in ${RELEASE_DIR}"
else
  if [[ ! -d "${RELEASE_DIR}/.git" ]]; then
    if [[ -d "${RELEASE_DIR}" ]] && [[ -n "$(ls -A "${RELEASE_DIR}" 2>/dev/null)" ]]; then
      err "${RELEASE_DIR} existiert, ist aber kein Git-Repo. Bitte manuell aufräumen."
    fi
    mkdir -p "${RELEASE_DIR}"
    git clone --branch "${REPO_BRANCH}" "${REPO_URL}" "${RELEASE_DIR}"
    ok "Repo neu geklont (${REPO_BRANCH})"
  else
    cd "${RELEASE_DIR}"
    # Schutz: bei lokalen Änderungen warnen
    if ! git diff --quiet HEAD -- 2>/dev/null; then
      warn "Lokale Änderungen in ${RELEASE_DIR}"
      git status --short
      if ! ask "Trotzdem fortfahren (lokale Änderungen bleiben erhalten)?"; then
        echo "  Abgebrochen."
        exit 0
      fi
    fi
    git fetch --quiet origin "${REPO_BRANCH}"
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse "origin/${REPO_BRANCH}")
    if [[ "${LOCAL}" == "${REMOTE}" ]]; then
      ok "Repo bereits aktuell (${LOCAL:0:8})"
    else
      git checkout "${REPO_BRANCH}" --quiet
      git pull --rebase --quiet origin "${REPO_BRANCH}"
      ok "Repo aktualisiert: ${LOCAL:0:8} → $(git rev-parse HEAD | cut -c1-8)"
    fi
  fi
fi

[[ ! -d "${RELEASE_DIR}/server/privacy-pass" ]] && \
  err "Modul ${RELEASE_DIR}/server/privacy-pass/ fehlt im Repo. Erst comitten."

# ─── 2. Modul ins Server-Verzeichnis kopieren ─────────────────────────────────
step "[2/7] Privacy-Pass-Modul installieren"

[[ ! -d "${SERVER_DIR}" ]] && err "${SERVER_DIR} existiert nicht. Erst deploy-all.sh laufen lassen."

# Backup nur des Moduls (falls schon vorhanden), nicht des ganzen Servers
if [[ -d "${SERVER_DIR}/privacy-pass" ]]; then
  BACKUP="${SERVER_DIR}/privacy-pass.backup_$(date +%Y%m%d-%H%M%S)"
  cp -r "${SERVER_DIR}/privacy-pass" "${BACKUP}"
  ok "Modul-Backup: ${BACKUP}"
fi

# Modul rsyncen; Keys bleiben erhalten (nicht überschreiben)
rsync -a \
  --exclude='keys/' \
  --exclude='*.bin' \
  "${RELEASE_DIR}/server/privacy-pass/" \
  "${SERVER_DIR}/privacy-pass/"
ok "Modul-Code installiert in ${SERVER_DIR}/privacy-pass/"

# Keys-Verzeichnis anlegen mit korrekten Rechten (Privacy-Pass-Keys)
mkdir -p "${SERVER_DIR}/privacy-pass/keys"
chown -R www-data:www-data "${SERVER_DIR}/privacy-pass/keys"
chmod 700 "${SERVER_DIR}/privacy-pass/keys"
ok "Keys-Verzeichnis vorbereitet (www-data, 0700)"

# Auch geänderte Server-Files mitnehmen, die das Privacy-Pass-Modul nutzt.
# email.js wird von verifications-api.js aufgerufen, db.js liefert die Pool-Funktion.
# Wir syncen nur wenn der Repo-Stand neuer ist (rsync -u).
for f in email.js db.js; do
  if [[ -f "${RELEASE_DIR}/server/${f}" ]]; then
    if rsync -au --checksum "${RELEASE_DIR}/server/${f}" "${SERVER_DIR}/${f}" 2>/dev/null; then
      # Prüfen ob tatsächlich überschrieben wurde
      if ! cmp -s "${RELEASE_DIR}/server/${f}" "${SERVER_DIR}/${f}.bak" 2>/dev/null; then
        cp "${SERVER_DIR}/${f}" "${SERVER_DIR}/${f}.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
      fi
      ok "Server-Datei ${f} synchronisiert"
    fi
  fi
done

# ─── 3. server.js Patch prüfen / anwenden ─────────────────────────────────────
step "[3/7] server.js auf Privacy-Pass-Mount prüfen"

SERVER_JS="${SERVER_DIR}/server.js"
[[ ! -f "${SERVER_JS}" ]] && err "${SERVER_JS} fehlt"

HAS_IMPORT=$(grep -c "from './privacy-pass/index.js'" "${SERVER_JS}" || true)
HAS_INIT=$(grep -c "initPrivacyPass()" "${SERVER_JS}" || true)
HAS_MOUNT=$(grep -c "privacyPassRouter" "${SERVER_JS}" || true)

if [[ "${HAS_IMPORT}" -ge 1 ]] && [[ "${HAS_INIT}" -ge 1 ]] && [[ "${HAS_MOUNT}" -ge 1 ]]; then
  ok "server.js enthält bereits alle drei Eingriffe — kein Patch nötig"
else
  warn "server.js noch nicht gepatcht:"
  echo "      Import:  $([[ ${HAS_IMPORT} -ge 1 ]] && echo '✓' || echo '✗')"
  echo "      Init:    $([[ ${HAS_INIT}   -ge 1 ]] && echo '✓' || echo '✗')"
  echo "      Mount:   $([[ ${HAS_MOUNT}  -ge 1 ]] && echo '✓' || echo '✗')"
  echo ""
  echo "  Vorgeschlagene Eingriffe:"
  echo ""
  echo "    1. Nach den anderen import-Statements (oben in server.js):"
  echo "       import { initPrivacyPass, privacyPassRouter, privacyPassWellKnownRouter }"
  echo "         from './privacy-pass/index.js';"
  echo ""
  echo "    2. Im Bootstrap (nach loadOrCreateKeys()):"
  echo "       await initPrivacyPass();"
  echo ""
  echo "    3. Nach den anderen app.use() / Routen-Definitionen:"
  echo "       app.use(privacyPassWellKnownRouter);"
  echo "       app.use('/privacy-pass', privacyPassRouter);"
  echo ""

  if [[ "${AUTO_PATCH:-0}" == "1" ]] || ask "Patch automatisch anwenden?"; then
    # Backup vor dem Patch
    cp "${SERVER_JS}" "${SERVER_JS}.backup_$(date +%Y%m%d-%H%M%S)"

    # Eingriff 1: Import — vor dem ersten "const __dirname" oder "// ─── Bootstrap"
    if [[ "${HAS_IMPORT}" -eq 0 ]]; then
      # Füge Import nach dem letzten "^import .* from " ein
      python3 - "${SERVER_JS}" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

# Letzte Zeile finden, die mit "import" beginnt (auch mehrzeilige imports beachten)
last_import_end = 0
in_import = False
for i, ln in enumerate(lines):
    stripped = ln.strip()
    if stripped.startswith('import '):
        in_import = True
        if stripped.rstrip(';').endswith("'") or stripped.rstrip(';').endswith('"'):
            last_import_end = i + 1
            in_import = False
    elif in_import and stripped.rstrip(';').endswith("'") or (in_import and stripped.rstrip(';').endswith('"')):
        last_import_end = i + 1
        in_import = False

inject = (
    "\n"
    "// Privacy Pass module (additive, RFC 9576-9578)\n"
    "import { initPrivacyPass, privacyPassRouter, privacyPassWellKnownRouter }\n"
    "  from './privacy-pass/index.js';\n"
)
lines.insert(last_import_end, inject)
with open(path, 'w') as f:
    f.writelines(lines)
PYEOF
      ok "Import eingefügt"
    fi

    # Eingriff 2: Init — direkt nach loadOrCreateKeys();
    if [[ "${HAS_INIT}" -eq 0 ]]; then
      python3 - "${SERVER_JS}" <<'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    src = f.read()

# Sucht nach loadOrCreateKeys() und fügt initPrivacyPass() direkt danach ein
pat = re.compile(r'(loadOrCreateKeys\(\)\s*;?\s*\n)')
m = pat.search(src)
if m:
    inject = m.group(1) + "await initPrivacyPass();\n"
    src = src[:m.start()] + inject + src[m.end():]
    with open(path, 'w') as f:
        f.write(src)
    print("  Init nach loadOrCreateKeys() eingefügt")
else:
    print("  WARN: loadOrCreateKeys() nicht gefunden — Init muss manuell platziert werden")
PYEOF
      ok "Init eingefügt (siehe Output oben)"
    fi

    # Eingriff 3: Mount — vor dem app.listen()
    if [[ "${HAS_MOUNT}" -eq 0 ]]; then
      python3 - "${SERVER_JS}" <<'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    src = f.read()

pat = re.compile(r'(app\.listen\s*\()')
m = pat.search(src)
if m:
    inject = (
        "// Privacy Pass routes (additive)\n"
        "app.use(privacyPassWellKnownRouter);\n"
        "app.use('/privacy-pass', privacyPassRouter);\n\n"
    )
    src = src[:m.start()] + inject + src[m.start():]
    with open(path, 'w') as f:
        f.write(src)
    print("  Mount vor app.listen() eingefügt")
else:
    print("  WARN: app.listen() nicht gefunden — Mount muss manuell platziert werden")
PYEOF
      ok "Mount eingefügt"
    fi

    # Syntax-Check
    if node --check "${SERVER_JS}" 2>/dev/null; then
      ok "server.js Syntax-Check bestanden"
    else
      err "server.js Syntax-Fehler nach Patch — Backup zurückspielen!"
    fi
  else
    warn "Patch übersprungen — Privacy-Pass-Endpoints werden nicht aktiv sein"
    echo "  Du kannst den Patch später manuell anwenden (siehe Anleitung oben)"
  fi
fi

# ─── 4. Dependencies installieren ─────────────────────────────────────────────
step "[4/7] Dependencies"

cd "${SERVER_DIR}"

# Prüfen, ob voprf-ts schon installiert ist
if [[ -d node_modules/@cloudflare/voprf-ts ]]; then
  ok "@cloudflare/voprf-ts bereits installiert"
else
  warn "@cloudflare/voprf-ts noch nicht installiert"
  if ask "Jetzt installieren?"; then
    npm install --silent @cloudflare/voprf-ts 2>&1 | tail -2
    ok "@cloudflare/voprf-ts installiert"
  else
    warn "Übersprungen — Token-Issuance bleibt im 501-Stub-Modus"
  fi
fi

# ─── 5. PM2 Restart ───────────────────────────────────────────────────────────
step "[5/7] PM2 Restart"

if pm2 list 2>/dev/null | grep -q "${PM2_APP}"; then
  pm2 restart "${PM2_APP}" --update-env >/dev/null
  ok "${PM2_APP} neu gestartet"
  sleep 3
else
  err "PM2-App ${PM2_APP} nicht gefunden. Erst deploy-all.sh laufen lassen."
fi

# ─── 6. Verifikation ──────────────────────────────────────────────────────────
step "[6/7] Verifikation"

# Lokaler Test über loopback (umgeht Nginx, prüft Backend direkt)
LOCAL_DIR="http://127.0.0.1:3000/.well-known/private-token-issuer-directory"
LOCAL_KEYS="http://127.0.0.1:3000/privacy-pass/keys"
LOCAL_TOKEN="http://127.0.0.1:3000/privacy-pass/token-request"

LIVE_DIR="https://${DOMAIN_HHTTPS}/.well-known/private-token-issuer-directory"
LIVE_KEYS="https://${DOMAIN_HHTTPS}/privacy-pass/keys"

# 1) Backend direkt
echo ""
echo "  Backend (localhost:3000):"

CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${LOCAL_DIR}" || echo "000")
if [[ "${CODE}" == "200" ]]; then
  ok "Issuer Directory → 200"
else
  warn "Issuer Directory → ${CODE}  (pm2 logs ${PM2_APP} prüfen)"
fi

CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${LOCAL_KEYS}" || echo "000")
if [[ "${CODE}" == "200" ]]; then
  ok "Keys-Endpoint → 200"
else
  warn "Keys-Endpoint → ${CODE}"
fi

# Token-Request mit invalidem Body — soll 400 zurückgeben (Parser arbeitet)
CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/private-token-request" \
  --data-binary "ungültig" "${LOCAL_TOKEN}" || echo "000")
if [[ "${CODE}" == "400" ]]; then
  ok "Token-Request Parser aktiv → 400 bei invalidem Body"
elif [[ "${CODE}" == "501" ]]; then
  ok "Token-Request → 501 (Stub, VOPRF noch nicht verdrahtet)"
else
  warn "Token-Request → ${CODE}"
fi

# 2) Live über Nginx + HTTPS
echo ""
echo "  Live (${DOMAIN_HHTTPS}):"

CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${LIVE_DIR}" || echo "000")
if [[ "${CODE}" == "200" ]]; then
  ok "Issuer Directory live → 200"
else
  warn "Issuer Directory live → ${CODE}"
fi

CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${LIVE_KEYS}" || echo "000")
if [[ "${CODE}" == "200" ]]; then
  ok "Keys-Endpoint live → 200"
else
  warn "Keys-Endpoint live → ${CODE}  (Nginx-Config prüfen — location / fängt es ab)"
fi

# Inhalt der Discovery anzeigen
echo ""
echo "  ${B}Issuer Directory Inhalt:${N}"
curl -sk --max-time 5 "${LIVE_DIR}" 2>/dev/null | head -20 | sed 's/^/    /'

# ─── 7. Commit / Push (optional, separat bestätigen) ──────────────────────────
step "[7/7] Änderungen ins Repo zurückspielen (optional)"

cd "${RELEASE_DIR}"

# Prüfen, ob es überhaupt was zu commiten gibt
if git diff --quiet HEAD -- && [[ -z "$(git status --porcelain)" ]]; then
  ok "Keine Änderungen im Repo — nichts zu committen"
else
  echo "  Geänderte Dateien im Repo:"
  git status --short | sed 's/^/    /'
  echo ""

  if [[ "${ALLOW_COMMIT:-0}" == "1" ]] || ask "Änderungen committen und pushen?"; then
    git add -A
    git commit -m "deploy: privacy-pass module sync $(date +%Y-%m-%d)" || warn "Nichts zu committen"
    if git push origin "${REPO_BRANCH}"; then
      ok "Push nach origin/${REPO_BRANCH} erfolgreich"
    else
      warn "Push fehlgeschlagen — manuell prüfen (Credentials, Netzwerk)"
    fi
  else
    warn "Commit/Push übersprungen — Änderungen bleiben lokal in ${RELEASE_DIR}"
  fi
fi

# ─── Abschluss ────────────────────────────────────────────────────────────────

echo ""
printf "${G}╔════════════════════════════════════════════════════════════════╗${N}\n"
printf "${G}║  Privacy Pass Module Deployment abgeschlossen                  ║${N}\n"
printf "${G}╚════════════════════════════════════════════════════════════════╝${N}\n"
echo ""
echo "  Neue Endpoints:"
echo "    https://${DOMAIN_HHTTPS}/.well-known/private-token-issuer-directory"
echo "    https://${DOMAIN_HHTTPS}/privacy-pass/keys"
echo "    https://${DOMAIN_HHTTPS}/privacy-pass/token-request   (501 bis VOPRF verdrahtet)"
echo ""
echo "  Verwaltung:"
echo "    pm2 logs ${PM2_APP}                Live-Logs"
echo "    pm2 restart ${PM2_APP}             Neustart"
echo "    cat ${SERVER_DIR}/privacy-pass/INSTALL.md   Manuelle Patch-Anleitung"
echo ""
echo "  Nächster Schritt:"
echo "    VOPRF-Crypto in privacy-pass/issuer.js und verifier.js verdrahten"
echo "    (siehe TODO-Blöcke — Library @cloudflare/voprf-ts ist installiert)"
echo ""

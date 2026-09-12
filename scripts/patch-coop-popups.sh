#!/usr/bin/env bash
#
# patch-coop-popups.sh  (KORRIGIERT nach COOP-Spec-Recherche)
#
# Der frühere Ansatz (same-origin-allow-popups überall) war falsch: Laut
# COOP-Spec (MDN/Chrome) überlebt die opener-Beziehung nur, wenn
#   - die ÖFFNENDE Seite  = same-origin-allow-popups   (tweakz.de, im Plugin)
#   - die POPUP-Zielseite = unsafe-none ODER kein COOP  (hhttps.org, hier)
# same-origin-allow-popups auf der Popup-Seite ISOLIERT — genau der Bug.
#
# Fix: hhttps.org sendet global weiter das sichere same-origin-allow-popups
# (Schutz vor Fremd-Einbettung), ABER auf den im Popup SICHTBAREN OAuth-Routen
# (authorize/consent) wird COOP pro Route auf 'unsafe-none' überschrieben,
# damit die opener-Beziehung zur öffnenden Plattform-Seite erhalten bleibt und
# window.opener.postMessage funktioniert.
#
# Idempotent, Backup, node --check, pm2 restart.
# Usage: ./patch-coop-popups.sh --dry-run | ./patch-coop-popups.sh

set -euo pipefail
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

LIVE_DIR="/var/www/hhttps"
SERVER_JS="$LIVE_DIR/server.js"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/hhttps/coop-popups-$TS"

log(){ echo "[coop-popups] $*"; }
[[ -f "$SERVER_JS" ]] || { echo "ERROR: $SERVER_JS not found"; exit 1; }

if grep -q "COOP-POPUP-ROUTE" "$SERVER_JS"; then
  log "already patched — per-route unsafe-none present."; exit 0
fi

if [[ $DRY -eq 0 ]]; then
  mkdir -p "$BACKUP_DIR"; cp -a "$SERVER_JS" "$BACKUP_DIR/server.js"
  log "Backup: $BACKUP_DIR/server.js"
fi

python3 - "$SERVER_JS" "$DRY" << 'PYEOF'
import sys, io
sjs, dry = sys.argv[1], sys.argv[2] == '1'
S = io.open(sjs, encoding='utf-8').read()

subs = []

# 1) Global COOP auf same-origin-allow-popups sicherstellen (öffnende-Rolle,
#    schützt hhttps.org vor Fremd-Einbettung). Beide Varianten des Ankers
#    abdecken: mit oder ohne mein früheres (live-only) Edit.
if "crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }" not in S:
    # Fall A: unpatched original
    a_old = "  crossOriginEmbedderPolicy: false  // required for WebAuthn\n}));"
    a_new = ("  crossOriginEmbedderPolicy: false,  // required for WebAuthn\n"
             "  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }\n"
             "}));")
    if S.count(a_old) == 1:
        subs.append((a_old, a_new))
    else:
        # Fall B: früheres live-only Edit hatte evtl. Komma+Zeile schon
        b_old = "  crossOriginEmbedderPolicy: false,  // required for WebAuthn\n}));"
        b_new = ("  crossOriginEmbedderPolicy: false,  // required for WebAuthn\n"
                 "  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }\n"
                 "}));")
        if S.count(b_old) == 1:
            subs.append((b_old, b_new))

# 2) Pro-Route Middleware VOR der authorize-Route: COOP auf unsafe-none für die
#    im Popup sichtbaren OAuth-Seiten, damit die opener-Beziehung überlebt.
route_old = "app.get('/hhttps/oauth/authorize', async (req, res) => {"
route_new = (
"// COOP-POPUP-ROUTE: the pages a login popup actually renders (the consent\n"
"// screen at authorize, and the approve result) must NOT isolate, or the\n"
"// opener relationship to the platform page breaks and postMessage fails.\n"
"// Per the COOP spec the popup target must send unsafe-none while the opener\n"
"// sends same-origin-allow-popups. We scope unsafe-none to these routes only.\n"
"function popupCoop(_req, res, next) {\n"
"  res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');\n"
"  next();\n"
"}\n"
"app.get('/hhttps/oauth/authorize', popupCoop, async (req, res) => {")
if S.count(route_old) == 1:
    subs.append((route_old, route_new))
else:
    print('ERROR: authorize route anchor not unique (%d)' % S.count(route_old)); sys.exit(2)

# 3) approve-Route ebenfalls unsafe-none (die Ergebnis-Navigation)
approve_old = "app.post('/hhttps/oauth/approve', async (req, res) => {"
if S.count(approve_old) == 1:
    subs.append((approve_old, "app.post('/hhttps/oauth/approve', popupCoop, async (req, res) => {"))

problems = [str(S.count(o)) + 'x ' + o.strip().splitlines()[0][:50] for o, _ in subs if S.count(o) != 1]
if problems:
    print('ERROR: drift:')
    for p in problems: print('  -', p)
    sys.exit(2)

if dry:
    print('[dry-run] would apply %d edits (global COOP + per-route unsafe-none)' % len(subs)); sys.exit(0)

for o, n in subs: S = S.replace(o, n, 1)
io.open(sjs, 'w', encoding='utf-8').write(S)
print('server: global same-origin-allow-popups + unsafe-none on OAuth popup routes')
PYEOF

if [[ $DRY -eq 1 ]]; then log "[dry-run] nichts geschrieben."; exit 0; fi

node --check "$SERVER_JS" && log "node --check: OK" || {
  echo "ERROR: syntax — restoring backup"; cp -a "$BACKUP_DIR/server.js" "$SERVER_JS"; exit 1
}
pm2 restart hhttps-v4
log "pm2 restart done."
log "VERIFY authorize route now sends unsafe-none:"
log "  curl -s -D - -o /dev/null 'https://hhttps.org/hhttps/oauth/authorize?client_id=x&response_type=code&redirect_uri=https://tweakz.de&scope=openid&state=x&code_challenge=x&code_challenge_method=S256' | grep -i cross-origin-opener"
log "  → sollte 'unsafe-none' zeigen."
log "Rollback: cp $BACKUP_DIR/server.js $SERVER_JS && pm2 restart hhttps-v4"

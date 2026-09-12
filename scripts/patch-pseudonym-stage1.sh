#!/usr/bin/env bash
#
# patch-pseudonym-stage1.sh   (Neufassung — sauber)
#
# Stufe 1 der Pseudonym-Wahl: der Nutzer legt seinen Anzeigenamen selbst fest.
# SCHEMAFREI, kein persistenter PII-Speicher auf hhttps.org.
#
# Flow:
#   1. Consent-Seite: optionales Feld "Anzeigename". Wert reist mit /approve.
#   2. /approve: saeubert und bindet den Namen 120 s an den Authorization-Code
#      ueber die vorhandene challenges-Tabelle (Key 'pseudo:<code>').
#   3. /token: liest das Mapping EINMAL, setzt preferred_username in
#      Access-Token UND id_token, loescht das Mapping (single use).
#   4. /userinfo: gibt preferred_username aus (das Plugin liest userinfo).
#
# Idempotent, Drift-sicher, Backup, node --check, pm2 restart.
# Usage: ./patch-pseudonym-stage1.sh --dry-run | ./patch-pseudonym-stage1.sh

set -euo pipefail
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

LIVE_DIR="/var/www/hhttps"
SERVER_JS="$LIVE_DIR/server.js"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/hhttps/pseudonym-s1-$TS"

log(){ echo "[pseudonym-s1] $*"; }
[[ -f "$SERVER_JS" ]] || { echo "ERROR: $SERVER_JS not found"; exit 1; }

if [[ $DRY -eq 0 ]]; then
  mkdir -p "$BACKUP_DIR"; cp -a "$SERVER_JS" "$BACKUP_DIR/server.js"
  log "Backup: $BACKUP_DIR/server.js"
fi

python3 - "$SERVER_JS" "$DRY" << 'PYEOF'
import sys, io
sjs, dry = sys.argv[1], sys.argv[2] == '1'
S = io.open(sjs, encoding='utf-8').read()

if 'preferred_username' in S and '_preferredUsername' in S:
    print('already patched'); sys.exit(0)

subs = []

subs.append((
"""  const { token, client_id, redirect_uri, scope, state, nonce,
          code_challenge, code_challenge_method } = req.body || {};""",
"""  const { token, client_id, redirect_uri, scope, state, nonce,
          code_challenge, code_challenge_method, pseudonym } = req.body || {};"""))

subs.append((
"""    await db.oauthClients.touchLastUsed(client_id);
    await db.stats.increment('oauth_authorizations');""",
"""    const cleanPseudo = pseudonym
      ? (String(pseudonym).replace(/[^\\w\\-. \u00e4\u00f6\u00fc\u00c4\u00d6\u00dc\u00df]/gu, '').slice(0, 32).trim() || null)
      : null;
    if (cleanPseudo) {
      try { await db.challenges.create('pseudo:' + code, cleanPseudo, null, 'pseudonym', 120000); }
      catch (e) { console.error('[OAUTH] pseudonym bind failed:', e.message); }
    }

    await db.oauthClients.touchLastUsed(client_id);
    await db.stats.increment('oauth_authorizations');"""))

subs.append((
"  const accessToken = signToken({",
"""  let _preferredUsername = null;
  try {
    const _pr = await db.challenges.get('pseudo:' + code);
    if (_pr && _pr.challenge) {
      _preferredUsername = _pr.challenge;
      await db.challenges.delete('pseudo:' + code);
    }
  } catch (e) { /* none bound */ }

  const accessToken = signToken({"""))

subs.append((
"""    scope:      claimed.scopes.join(' '),
    role:       claimed.role,
    trustScore: claimed.trust_score,""",
"""    scope:      claimed.scopes.join(' '),
    role:       claimed.role,
    trustScore: claimed.trust_score,
    ...(_preferredUsername ? { preferred_username: _preferredUsername } : {}),"""))

subs.append((
"  const idToken = signToken(idTokenClaims, { expiresIn: OAUTH_TOKEN_TTL });",
"""  if (_preferredUsername) { idTokenClaims.preferred_username = _preferredUsername; }
  const idToken = signToken(idTokenClaims, { expiresIn: OAUTH_TOKEN_TTL });"""))

subs.append((
"""    const out = {
      sub: d.sub,
      iss: d.iss
    };""",
"""    const out = {
      sub: d.sub,
      iss: d.iss
    };
    if (d.preferred_username) { out.preferred_username = d.preferred_username; }"""))

subs.append((
"""    <div class="status" id="status"></div>
    <div class="actions">
      <button class="btn btn-deny" id="denyBtn" data-i18n="consent.deny">Ablehnen</button>""",
"""    <div class="pseudo-field" style="margin:14px 0 4px;">
      <label for="pseudoInput" style="display:block;font-size:13px;opacity:.75;margin-bottom:6px;" data-i18n="consent.pseudoLabel">Anzeigename (frei w\u00e4hlbar, optional)</label>
      <input id="pseudoInput" type="text" maxlength="32" autocomplete="nickname"
             style="width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid rgba(0,0,0,.15);border-radius:10px;font-size:15px;background:#fff;" />
      <div style="font-size:12px;opacity:.6;margin-top:5px;" data-i18n="consent.pseudoHint">Muss nicht dein echter Name sein. Du entscheidest, was du preisgibst.</div>
    </div>
    <div class="status" id="status"></div>
    <div class="actions">
      <button class="btn btn-deny" id="denyBtn" data-i18n="consent.deny">Ablehnen</button>"""))

subs.append((
"""        code_challenge:        params.get('code_challenge'),
        code_challenge_method: params.get('code_challenge_method')
      })
    });
    const d = await r.json();""",
"""        code_challenge:        params.get('code_challenge'),
        code_challenge_method: params.get('code_challenge_method'),
        pseudonym:             (document.getElementById('pseudoInput') || {}).value || null
      })
    });
    const d = await r.json();"""))

subs.append((
"""              code_challenge:        params.get('code_challenge'),
              code_challenge_method: params.get('code_challenge_method')""",
"""              code_challenge:        params.get('code_challenge'),
              code_challenge_method: params.get('code_challenge_method'),
              pseudonym:             (document.getElementById('pseudoInput') || {}).value || null"""))

subs.append((
'    "consent.scopeHead":"Folgende Daten werden geteilt","consent.deny":"Ablehnen","consent.allow":"Erlauben",',
'    "consent.scopeHead":"Folgende Daten werden geteilt","consent.deny":"Ablehnen","consent.allow":"Erlauben",\n    "consent.pseudoLabel":"Anzeigename (frei w\u00e4hlbar, optional)","consent.pseudoHint":"Muss nicht dein echter Name sein. Du entscheidest, was du preisgibst.",'))

subs.append((
'    "consent.scopeHead":"The following data will be shared","consent.deny":"Deny","consent.allow":"Allow",',
'    "consent.scopeHead":"The following data will be shared","consent.deny":"Deny","consent.allow":"Allow",\n    "consent.pseudoLabel":"Display name (your choice, optional)","consent.pseudoHint":"It does not have to be your real name. You decide what to reveal.",'))

problems = [str(S.count(o)) + 'x ' + o.strip().splitlines()[0][:56] for o, _ in subs if S.count(o) != 1]
if problems:
    print('ERROR: drift — anchors not found exactly once:')
    for p in problems: print('  -', p)
    sys.exit(2)

if dry:
    print('[dry-run] would apply ' + str(len(subs)) + ' server edits'); sys.exit(0)

for o, n in subs: S = S.replace(o, n, 1)
io.open(sjs, 'w', encoding='utf-8').write(S)
print('server: pseudonym stage 1 fully wired')
PYEOF

if [[ $DRY -eq 1 ]]; then log "[dry-run] nichts geschrieben."; exit 0; fi

node --check "$SERVER_JS" && log "node --check: OK" || {
  echo "ERROR: syntax — restoring backup"; cp -a "$BACKUP_DIR/server.js" "$SERVER_JS"; exit 1
}
pm2 restart hhttps-v4
log "pm2 restart done."
log "Rollback: cp $BACKUP_DIR/server.js $SERVER_JS && pm2 restart hhttps-v4"

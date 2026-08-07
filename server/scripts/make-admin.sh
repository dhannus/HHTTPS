#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# HHTTPS — grant / revoke / list admin privileges
#
# Admin is membership-based: a user_id is admin iff a row exists in `admins`.
# This script is the supported way to manage that — no hand-written SQL.
#
# Usage:
#   ./make-admin.sh --list
#   ./make-admin.sh --recent [N]             # user_ids with a live token (default 10)
#   ./make-admin.sh --grant-recent           # grant to the most recent live token
#   ./make-admin.sh --grant  <USER_ID> [--note "Project operator"]
#   ./make-admin.sh --revoke <USER_ID>
#   ./make-admin.sh --whoami <USER_ID>      # is this user an admin?
#
# NOTE ON IDENTITY DURABILITY
#   user_id is stable ONLY for passkey- or eID-anchored identities: it comes
#   from the stored credential. An e-mail-only sign-in mints a fresh uuid per
#   session, so admin rights granted to such an id are gone at the next login.
#   The developer portal therefore requires a passkey — sign in with yours
#   FIRST, then grant. Check the anchor at: GET /hhttps/whoami
#
# Reads DB credentials from ../.env (DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD).
# Runs as the application DB user — never as postgres superuser.
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"

# --help must work without a database or an .env file.
for a in "$@"; do
  if [[ "$a" == "-h" || "$a" == "--help" ]]; then
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
  fi
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: .env not found at $ENV_FILE" >&2
  exit 1
fi

# Read a single key from the .env file.
#
# Deliberately NOT `source`: an .env may legitimately contain unquoted values
# with spaces (e.g. SMTP_FROM_NAME=HHTTPS Open Issuer), which bash would parse
# as a command invocation. This reads the file as data, not as script.
# Handles: leading whitespace, optional `export `, surrounding quotes,
# trailing inline comments, CRLF line endings. Last occurrence wins.
env_get() {
  local key="$1" line value
  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=" "$ENV_FILE" | tail -1 || true)"
  [[ -z "$line" ]] && return 0
  value="${line#*=}"
  value="${value%$'\r'}"                      # strip CR from CRLF files
  value="${value#"${value%%[![:space:]]*}"}"  # ltrim

  if [[ "${value:0:1}" == '"' ]]; then
    value="${value#\"}"; value="${value%%\"*}"        # up to the closing "
  elif [[ "${value:0:1}" == "'" ]]; then
    value="${value#\'}"; value="${value%%\'*}"        # up to the closing '
  else
    # Unquoted: strip a trailing comment only when the # is preceded by
    # whitespace. A password like abc#def stays intact; "abc  # note" does not.
    value="$(printf '%s' "$value" | sed -E 's/[[:space:]]+#.*$//')"
    value="${value%"${value##*[![:space:]]}"}"        # rtrim
  fi
  printf '%s' "$value"
}

DB_HOST="$(env_get DB_HOST)";     DB_HOST="${DB_HOST:-localhost}"
DB_PORT="$(env_get DB_PORT)";     DB_PORT="${DB_PORT:-5432}"
DB_NAME="$(env_get DB_NAME)";     DB_NAME="${DB_NAME:-hhttps}"
DB_USER="$(env_get DB_USER)";     DB_USER="${DB_USER:-hhttps}"
DB_PASSWORD="$(env_get DB_PASSWORD)"
[[ -z "$DB_PASSWORD" ]] && DB_PASSWORD="$(env_get DB_PASS)"

if [[ -z "$DB_PASSWORD" ]]; then
  echo "ERROR: DB_PASSWORD (or DB_PASS) not set in $ENV_FILE" >&2
  exit 1
fi

psql_run() {
  PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 --no-psqlrc "$@"
}

usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 1
}

ACTION=""
USER_ID=""
RECENT_N=10
NOTE="granted via make-admin.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)   ACTION="list";   shift ;;
    --recent)
      ACTION="recent"
      if [[ "${2:-}" =~ ^[0-9]+$ ]]; then RECENT_N="$2"; shift 2; else shift; fi ;;
    --grant-recent) ACTION="grant-recent"; shift ;;
    --grant)  ACTION="grant";  USER_ID="${2:-}"; shift 2 ;;
    --revoke) ACTION="revoke"; USER_ID="${2:-}"; shift 2 ;;
    --whoami) ACTION="whoami"; USER_ID="${2:-}"; shift 2 ;;
    --note)   NOTE="${2:-}";   shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ -z "$ACTION" ]] && usage
if [[ "$ACTION" != "list" && "$ACTION" != "recent" && "$ACTION" != "grant-recent" && -z "$USER_ID" ]]; then
  echo "ERROR: --$ACTION requires a USER_ID" >&2
  exit 1
fi

case "$ACTION" in
  list)
    echo "Admins in ${DB_NAME}:"
    psql_run -c "SELECT user_id, granted_at, COALESCE(granted_by,'—') AS granted_by, COALESCE(note,'—') AS note
                 FROM admins ORDER BY granted_at ASC;"
    ;;

  recent)
    echo "Identities with a live (unexpired) token — newest first:"
    echo "  The one you are signed in with right now is at the top."
    echo ""
    psql_run -c "SELECT t.user_id,
                        max(t.issued_at)                      AS last_token,
                        max(t.trust_score)                    AS trust,
                        string_agg(DISTINCT t.method, ', ')   AS methods,
                        (a.user_id IS NOT NULL)               AS is_admin
                 FROM tokens t
                 LEFT JOIN admins a ON a.user_id = t.user_id
                 WHERE t.expires_at > NOW() AND t.user_id IS NOT NULL
                 GROUP BY t.user_id, a.user_id
                 ORDER BY max(t.issued_at) DESC
                 LIMIT ${RECENT_N};"
    ;;

  grant-recent)
    USER_ID="$(psql_run -tAc "SELECT user_id FROM tokens
                              WHERE expires_at > NOW() AND user_id IS NOT NULL
                              ORDER BY issued_at DESC LIMIT 1;")"
    if [[ -z "$USER_ID" ]]; then
      echo "ERROR: no identity with a live token found. Sign in first, then re-run." >&2
      exit 1
    fi
    echo "Most recent live identity: ${USER_ID}"
    psql_run -c "INSERT INTO admins (user_id, granted_by, note)
                 VALUES ('${USER_ID}', 'make-admin.sh', '${NOTE//\'/\'\'}')
                 ON CONFLICT (user_id) DO NOTHING;"
    echo "✓ ${USER_ID} is now an admin."
    echo ""
    echo "  IMPORTANT: if you signed in with e-mail only, this id dies with the"
    echo "  session. Register a passkey and re-grant, or you will lose admin again."
    echo "  Check the anchor at https://hhttps.org/developers/ (identity panel)."
    ;;

  grant)
    psql_run -c "INSERT INTO admins (user_id, granted_by, note)
                 VALUES ('${USER_ID}', 'make-admin.sh', '${NOTE//\'/\'\'}')
                 ON CONFLICT (user_id) DO NOTHING;"
    echo "✓ ${USER_ID} is now an admin."
    echo "  Verify in the browser: hard-reload /developers/ — the badge should show '· admin'."
    ;;

  revoke)
    psql_run -c "DELETE FROM admins WHERE user_id = '${USER_ID}';"
    echo "✓ Admin privileges revoked for ${USER_ID} (no-op if they weren't an admin)."
    ;;

  whoami)
    RESULT="$(psql_run -tAc "SELECT 1 FROM admins WHERE user_id = '${USER_ID}' LIMIT 1;")"
    if [[ "$RESULT" == "1" ]]; then
      echo "yes — ${USER_ID} is an admin"
    else
      echo "no — ${USER_ID} is NOT an admin"
      exit 2
    fi
    ;;
esac

#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# HHTTPS — grant / revoke / list admin privileges
#
# Admin is membership-based: a user_id is admin iff a row exists in `admins`.
# This script is the supported way to manage that — no hand-written SQL.
#
# Usage:
#   ./make-admin.sh --list
#   ./make-admin.sh --grant  <USER_ID> [--note "Project operator"]
#   ./make-admin.sh --revoke <USER_ID>
#   ./make-admin.sh --whoami <USER_ID>      # is this user an admin?
#
# Reads DB credentials from ../.env (DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD).
# Runs as the application DB user — never as postgres superuser.
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: .env not found at $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-hhttps}"
DB_USER="${DB_USER:-hhttps}"
DB_PASSWORD="${DB_PASSWORD:-${DB_PASS:-}}"

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
  sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 1
}

ACTION=""
USER_ID=""
NOTE="granted via make-admin.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)   ACTION="list";   shift ;;
    --grant)  ACTION="grant";  USER_ID="${2:-}"; shift 2 ;;
    --revoke) ACTION="revoke"; USER_ID="${2:-}"; shift 2 ;;
    --whoami) ACTION="whoami"; USER_ID="${2:-}"; shift 2 ;;
    --note)   NOTE="${2:-}";   shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ -z "$ACTION" ]] && usage
if [[ "$ACTION" != "list" && -z "$USER_ID" ]]; then
  echo "ERROR: --$ACTION requires a USER_ID" >&2
  exit 1
fi

case "$ACTION" in
  list)
    echo "Admins in ${DB_NAME}:"
    psql_run -c "SELECT user_id, granted_at, COALESCE(granted_by,'—') AS granted_by, COALESCE(note,'—') AS note
                 FROM admins ORDER BY granted_at ASC;"
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

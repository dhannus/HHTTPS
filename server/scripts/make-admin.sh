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
#   ./make-admin.sh --grant-recent           # grant to the most recent live token (asks for confirmation; --yes skips)
#   ./make-admin.sh --grant  <USER_ID> [--note "Project operator"]
#   ./make-admin.sh --revoke <USER_ID>
#   ./make-admin.sh --whoami <USER_ID>      # is this user an admin?
#
# NOTE ON IDENTITY DURABILITY (phase 8: e-mail-anchored identity)
#   user_id is stable for every ANCHORED identity: a passkey (from the stored
#   credential) and, since phase 8, a confirmed e-mail address as well — the
#   anchor table maps HMAC(pepper, e-mail) to one permanent user_id, so the
#   same address yields the same id on every future sign-in.
#   Not stable: a session that has neither a passkey nor a confirmed address
#   (it carries a per-session uuid). Grant only to an anchored id.
#   Check which one you have at: GET /hhttps/whoami
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
    sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
  fi
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: .env not found at $ENV_FILE" >&2
  exit 1
fi

# AP6-48 (#192): env_get and the log helpers live in the one shared library.
source "${SCRIPT_DIR}/lib/common.sh"

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
  sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
    --yes)          ASSUME_YES=1; shift ;;
    --grant)  ACTION="grant";  USER_ID="${2:-}"; shift $(( $# >= 2 ? 2 : 1 )) ;;
    --revoke) ACTION="revoke"; USER_ID="${2:-}"; shift $(( $# >= 2 ? 2 : 1 )) ;;
    --whoami) ACTION="whoami"; USER_ID="${2:-}"; shift $(( $# >= 2 ? 2 : 1 )) ;;
    --note)   NOTE="${2:-}";   shift $(( $# >= 2 ? 2 : 1 )) ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ -z "$ACTION" ]] && usage
if [[ "$ACTION" != "list" && "$ACTION" != "recent" && "$ACTION" != "grant-recent" && -z "$USER_ID" ]]; then
  echo "ERROR: --$ACTION requires a USER_ID" >&2
  exit 1
fi

# AP6-14 (#103): USER_ID is never interpolated into SQL. It is validated
# against the id alphabet and then bound as a psql variable (:'uid' quotes it
# as a literal). NOTE is bound the same way. `-c` does not expand psql
# variables, hence the here-documents on stdin.
USER_ID_RE='^[A-Za-z0-9_:-]{1,64}$'
check_user_id() {
  if [[ ! "$1" =~ $USER_ID_RE ]]; then
    printf 'ERROR: invalid USER_ID (expected 1-64 chars of [A-Za-z0-9_:-]): %q\n' "$1" >&2
    exit 1
  fi
}
if [[ -n "$USER_ID" ]]; then check_user_id "$USER_ID"; fi

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
    # AP6-13 (Review 2026-09): "the most recent token" is whoever signed in
    # last on a PUBLIC service — show who that is and require an explicit
    # confirmation before granting admin. Prefer --grant <USER_ID> (from
    # /hhttps/whoami) in scripts.
    check_user_id "$USER_ID"
    psql_run -v uid="$USER_ID" <<'SQL'
SELECT user_id, method, trust_score, issued_at FROM tokens
 WHERE user_id = :'uid' AND expires_at > NOW()
 ORDER BY issued_at DESC LIMIT 3;
SQL
    echo "Most recent live identity: ${USER_ID}"
    if [[ "${ASSUME_YES:-0}" != "1" ]]; then
      if [[ ! -t 0 ]]; then
        echo "ERROR: --grant-recent needs an interactive confirmation (or --yes). Use --grant <USER_ID> instead." >&2
        exit 1
      fi
      read -r -p "Grant ADMIN to ${USER_ID}? Type the first 8 characters of the id to confirm: " CONFIRM
      if [[ "${CONFIRM}" != "${USER_ID:0:8}" ]]; then
        echo "Aborted — confirmation did not match." >&2
        exit 1
      fi
    fi
    psql_run -q -v uid="$USER_ID" -v note="$NOTE" <<'SQL'
INSERT INTO admins (user_id, granted_by, note)
VALUES (:'uid', 'make-admin.sh', :'note')
ON CONFLICT (user_id) DO NOTHING;
SQL
    echo "✓ ${USER_ID} is now an admin."
    echo ""
    echo "  IMPORTANT: this only lasts if the id is ANCHORED — by a passkey or by"
    echo "  a confirmed e-mail address (phase 8). An id from a session with"
    echo "  neither is per-session and the grant dies with it."
    echo "  Check the anchor at https://hhttps.org/developers/ (identity panel)."
    ;;

  grant)
    psql_run -q -v uid="$USER_ID" -v note="$NOTE" <<'SQL'
INSERT INTO admins (user_id, granted_by, note)
VALUES (:'uid', 'make-admin.sh', :'note')
ON CONFLICT (user_id) DO NOTHING;
SQL
    echo "✓ ${USER_ID} is now an admin."
    echo "  Verify in the browser: hard-reload /developers/ — the badge should show '· admin'."
    ;;

  revoke)
    psql_run -q -v uid="$USER_ID" <<'SQL'
DELETE FROM admins WHERE user_id = :'uid';
SQL
    echo "✓ Admin privileges revoked for ${USER_ID} (no-op if they weren't an admin)."
    ;;

  whoami)
    RESULT="$(psql_run -tA -v uid="$USER_ID" <<'SQL'
SELECT 1 FROM admins WHERE user_id = :'uid' LIMIT 1;
SQL
)"
    if [[ "$RESULT" == "1" ]]; then
      echo "yes — ${USER_ID} is an admin"
    else
      echo "no — ${USER_ID} is NOT an admin"
      exit 2
    fi
    ;;
esac

# shellcheck shell=bash
# ─────────────────────────────────────────────────────────────────────────────
# HHTTPS — shared shell helpers.  source, never execute:
#
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"
#
# AP6-57 (#213): the colour/log preamble used to be copied into five scripts.
# AP6-48 (#192): there used to be four different .env parsers with four
#                different notions of quoting, comments and `export `.
# This file is the one copy of both. It deliberately sets no shell options —
# each script keeps its own `set -euo pipefail` on the first executable line.
# ─────────────────────────────────────────────────────────────────────────────

# ─── Colours / logging ───────────────────────────────────────────────────────
G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; B=$'\033[0;36m'; N=$'\033[0m'

ok()   { printf "  ${G}✓${N} %s\n" "$1"; }
warn() { printf "  ${Y}⚠${N}  %s\n" "$1"; }
err()  { printf "  ${R}✗${N} %s\n" "$1"; }
step() { printf "\n${B}═══ %s ═══${N}\n" "$1"; }
fail() { err "$1"; exit 1; }

# ─── .env access ─────────────────────────────────────────────────────────────
# env_get KEY [FILE]  — print the value of ONE key, nothing else.
#
# Deliberately NOT `source` (AP6-17 / #118): an .env may legitimately contain
# unquoted values with spaces (SMTP_FROM_NAME=HHTTPS Open Issuer), which bash
# would parse as a command invocation, and sourcing exports every secret into
# the shell and into everything it starts. This reads the file as data.
#
# Handles leading whitespace, an optional `export `, single or double quotes,
# trailing inline comments (only when the `#` is preceded by whitespace, so a
# password `abc#def` survives) and CRLF line endings. Last occurrence wins.
# A missing key or a missing file prints nothing and succeeds.
env_get() {
  local key="$1" file="${2:-${ENV_FILE:-}}" line value
  [[ -n "$file" && -f "$file" ]] || return 0
  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=" "$file" 2>/dev/null | tail -1 || true)"
  [[ -z "$line" ]] && return 0
  value="${line#*=}"
  value="${value%$'\r'}"                      # strip CR from CRLF files
  value="${value#"${value%%[![:space:]]*}"}"  # ltrim

  if [[ "${value:0:1}" == '"' ]]; then
    value="${value#\"}"; value="${value%%\"*}"        # up to the closing "
  elif [[ "${value:0:1}" == "'" ]]; then
    value="${value#\'}"; value="${value%%\'*}"        # up to the closing '
  else
    value="$(printf '%s' "$value" | sed -E 's/[[:space:]]+#.*$//')"
    value="${value%"${value##*[![:space:]]}"}"        # rtrim
  fi
  printf '%s' "$value"
}

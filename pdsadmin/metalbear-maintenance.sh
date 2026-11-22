#!/usr/bin/env bash
#
# Offline operator commands for a STOPPED MetalBear instance.
#
#   METALBEAR_DATA=/var/lib/metalbear metalbear-maintenance.sh \
#       publish-identity did:plc:abc
#
# These commands open the server's SQLite stores directly. Running them while
# the daemon holds those stores risks corrupting them, so this wrapper refuses
# when the instance answers its health endpoint and takes an exclusive lock for
# the duration of the command. The admin XRPC CLI (metalbear-admin.sh) is the
# right tool for a live instance.
set -euo pipefail
umask 077

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DATA_DIR="${METALBEAR_DATA:-}"
HEALTH_URL="${METALBEAR_HEALTH_URL:-http://127.0.0.1:2583/xrpc/_health}"
ASSUME_YES=0

fail() { echo "ERROR: $*" >&2; exit 1; }

# --yes may be placed before or after the command; strip it wherever it is.
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--yes" ]]; then
    ASSUME_YES=1
  else
    ARGS+=("$arg")
  fi
done
if [[ ${#ARGS[@]} -gt 1 ]]; then
  COMMAND="${ARGS[0]}"
  ARGS=("${ARGS[@]:1}")
elif [[ ${#ARGS[@]} -eq 1 ]]; then
  COMMAND="${ARGS[0]}"
  ARGS=()
else
  COMMAND="help"
fi

if [[ "$COMMAND" == "help" || -z "$COMMAND" ]]; then
  cat <<'EOF'
MetalBear offline maintenance (requires a stopped instance)

Usage:
  METALBEAR_DATA=DIR metalbear-maintenance.sh [--yes] publish-identity DID
  METALBEAR_DATA=DIR metalbear-maintenance.sh [--yes] sequencer-recover
  METALBEAR_DATA=DIR metalbear-maintenance.sh [--yes] rebuild-repo DID
  METALBEAR_DATA=DIR metalbear-maintenance.sh [--yes] --plc-url URL rotate-keys DID...

Environment:
  METALBEAR_DATA        data directory of the stopped instance (required)
  METALBEAR_HEALTH_URL  health endpoint used to detect a live instance
  METALBEAR_MAINT_BIN   path to metalbear-maint (auto-detected from build dirs)
  METALBEAR_PLC_URL     PLC directory for rotate-keys (or pass --plc-url)

rotate-keys publishes the repo's existing signing key to did:plc; it does not
mint a new key. rebuild-repo verifies the head and rebuilds the derived SQL
indexes from it; it does not reconstruct a damaged MST.
EOF
  exit 1
fi

[[ -n "$DATA_DIR" ]] || fail "METALBEAR_DATA is not set"
[[ -d "$DATA_DIR" ]] || fail "data directory does not exist: $DATA_DIR"
for required in accounts.sqlite3 sequencer.sqlite3; do
  [[ -f "$DATA_DIR/$required" ]] || fail "not a MetalBear data dir (missing $required): $DATA_DIR"
done

# A live instance must be stopped before touching its stores. A reachable
# health endpoint is treated as live; a connection failure means stopped.
if curl --fail --silent --show-error --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
  fail "instance at $HEALTH_URL is running; stop it before maintenance"
fi

HELPER="${METALBEAR_MAINT_BIN:-}"
if [[ -z "$HELPER" ]]; then
  for candidate in "$repo_root"/build/metalbear-maint "$repo_root"/build-*/metalbear-maint; do
    if [[ -x "$candidate" ]]; then HELPER="$candidate"; break; fi
  done
fi
[[ -n "$HELPER" && -x "$HELPER" ]] || fail "metalbear-maint not built; set METALBEAR_MAINT_BIN"

# Serialise maintenance commands on this data dir. The daemon does not take
# this lock; the health check above is what rules out a running instance.
exec 9>"$DATA_DIR/.maintenance.lock"
flock -n 9 || fail "another maintenance command holds the lock on $DATA_DIR"

if [[ "$COMMAND" == "rebuild-repo" || "$COMMAND" == "rotate-keys" ]]; then
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    echo "This command modifies $DATA_DIR. Type 'yes' to continue:" >&2
    read -r answer || true
    [[ "$answer" == "yes" ]] || fail "aborted"
  fi
fi

final_args=()
PLC_URL="${METALBEAR_PLC_URL:-}"
if [[ "$COMMAND" == "rotate-keys" ]]; then
  i=0
  while [[ $i -lt ${#ARGS[@]} ]]; do
    arg="${ARGS[$i]}"
    if [[ "$arg" == "--plc-url" ]]; then
      i=$((i + 1))
      [[ $i -lt ${#ARGS[@]} ]] || fail "rotate-keys: --plc-url needs a URL"
      PLC_URL="${ARGS[$i]}"
    else
      final_args+=("$arg")
    fi
    i=$((i + 1))
  done
  [[ -n "$PLC_URL" ]] || fail "rotate-keys needs --plc-url or METALBEAR_PLC_URL"
  [[ ${#final_args[@]} -gt 0 ]] || fail "rotate-keys needs at least one DID"
elif [[ ${#ARGS[@]} -gt 0 ]]; then
  final_args=("${ARGS[@]}")
fi

# The helper expects global options before the subcommand.
helper_args=(--data-dir "$DATA_DIR")
if [[ "$COMMAND" == "rotate-keys" ]]; then
  helper_args+=(--plc-url "$PLC_URL")
fi
helper_args+=("$COMMAND")
if [[ ${#final_args[@]} -gt 0 ]]; then
  helper_args+=("${final_args[@]}")
fi

exec "$HELPER" "${helper_args[@]}"

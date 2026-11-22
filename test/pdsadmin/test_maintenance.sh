#!/usr/bin/env bash
#
# CLI-level test for the offline maintenance commands (issue #162). Seeds a
# throwaway data directory, runs every subcommand through the pdsadmin wrapper,
# and checks that a live health endpoint is refused. Needs bash, python3 and
# curl; no network and no root.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
WRAPPER="$PWD/pdsadmin/metalbear-maintenance.sh"
ADMIN="$PWD/pdsadmin/metalbear-admin.sh"
HELPER="${METALBEAR_MAINT_BIN:-$PWD/build/metalbear-maint}"
[[ -x "$HELPER" ]] || { echo "not ok - metalbear-maint not built" >&2; exit 1; }

T="$(mktemp -d)"
HPORT=$((21000 + RANDOM % 20000))
trap 'kill $(cat "$T"/*.pid 2>/dev/null) 2>/dev/null || true; rm -rf "$T"' EXIT
pass=0
ok() { pass=$((pass + 1)); echo "ok - $*"; }
die() { echo "not ok - $*" >&2; exit 1; }

mkdir -p "$T/data/accounts/alice" "$T/live/xrpc"
echo '{"version":"test"}' >"$T/live/xrpc/_health"
python3 - "$T/data" <<'PY'
import sqlite3, sys, os
root = sys.argv[1]
db = sqlite3.connect(os.path.join(root, "accounts.sqlite3"))
db.executescript("""
CREATE TABLE accounts(
  did TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, data_directory TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT '');
""")
db.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?)",
           ("did:web:alice.example.com", "alice.example.com", "hash",
            os.path.join(root, "accounts", "alice"), 1, "2026-11-22T00:00:00.000Z"))
db.commit()
db.close()
open(os.path.join(root, "accounts", "alice", "repo.sqlite3"), "wb").close()
open(os.path.join(root, "sequencer.sqlite3"), "wb").close()
PY

export METALBEAR_DATA="$T/data"
export METALBEAR_MAINT_BIN="$HELPER"
export METALBEAR_HEALTH_URL="http://127.0.0.1:9/xrpc/_health"

"$WRAPPER" sequencer-recover >"$T/recover.log" 2>&1 || die "sequencer-recover failed: $(cat "$T/recover.log")"
grep -q 'reconciled did:web:alice.example.com' "$T/recover.log" || die "no reconcile report"
ok "sequencer-recover reconciles a seeded account"

"$WRAPPER" publish-identity did:web:alice.example.com >"$T/identity.log" 2>&1 || die "publish-identity failed: $(cat "$T/identity.log")"
grep -q 'sequenced #identity for did:web:alice.example.com' "$T/identity.log" || die "no identity report"
ok "publish-identity sequences an event"

"$WRAPPER" rebuild-repo --yes did:web:alice.example.com >"$T/rebuild.log" 2>&1 || die "rebuild-repo failed: $(cat "$T/rebuild.log")"
grep -q 'reindexed did:web:alice.example.com' "$T/rebuild.log" || die "no reindex report"
ok "rebuild-repo verifies and reindexes an empty repo"

if printf 'no\n' | "$WRAPPER" rebuild-repo did:web:alice.example.com >"$T/confirm.log" 2>&1; then
  die "rebuild-repo ran without confirmation"
fi
ok "rebuild-repo refuses without confirmation"

METALBEAR_PLC_URL=http://127.0.0.1:9 "$WRAPPER" rotate-keys --yes did:web:alice.example.com >"$T/rotate.log" 2>&1 || die "rotate-keys failed: $(cat "$T/rotate.log")"
grep -q 'published repo key for did:web:alice.example.com' "$T/rotate.log" || die "no rotation report"
ok "rotate-keys republishes a did:web key without network access"

"$ADMIN" sequencer-recover >"$T/admin.log" 2>&1 || die "admin dispatch failed: $(cat "$T/admin.log")"
grep -q 'reconciled did:web:alice.example.com' "$T/admin.log" || die "unexpected admin dispatch output: $(cat "$T/admin.log")"
ok "metalbear-admin dispatches offline commands through the wrapper"

python3 -m http.server "$HPORT" --bind 127.0.0.1 --directory "$T/live" >/dev/null 2>&1 &
echo $! >"$T/server.pid"
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$HPORT/xrpc/_health" >/dev/null 2>&1 && break
  sleep 0.1
done
if METALBEAR_HEALTH_URL="http://127.0.0.1:$HPORT/xrpc/_health" "$WRAPPER" sequencer-recover >"$T/live.log" 2>&1; then
  die "maintenance ran against a live instance"
fi
grep -q 'is running' "$T/live.log" || die "unexpected live refusal: $(cat "$T/live.log")"
ok "a live instance is refused safely"

echo "1..$pass"

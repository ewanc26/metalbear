#!/usr/bin/env bash
#
# End-to-end test of pdsadmin/metalbear-update.sh against a local release
# server and a stub "metalbear" binary. Needs bash, python3, curl, tar and
# ssh-keygen; no network and no root. Throwaway signing keys are generated in
# the scratch directory and never leave it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
UPDATER="$PWD/pdsadmin/metalbear-update.sh"
T="$(mktemp -d)"
trap 'kill $(cat "$T"/*.pid 2>/dev/null) 2>/dev/null || true; rm -rf "$T"' EXIT
PORT=$((20000 + RANDOM % 20000))
HPORT=$((PORT + 1))
pass=0
ok() { pass=$((pass + 1)); echo "ok - $*"; }
die() { echo "not ok - $*" >&2; exit 1; }

PLAT="$(case "$(uname -s)-$(uname -m)" in Linux-x86_64) echo linux-x86_64;; Linux-aarch64|Linux-arm64) echo linux-aarch64;; Darwin-arm64) echo macos-arm64;; *) echo unsupported;; esac)"
[ "$PLAT" != unsupported ] || { echo "skip: unsupported platform"; exit 0; }

# --- stub binary: --version prints $VERSION; running serves /health unless BAD.
mkstub() { # dir version bad
	mkdir -p "$1"
	cat >"$1/metalbear" <<STUB
#!/usr/bin/env bash
[ "\${1:-}" = --version ] && { echo $2; exit 0; }
[ "$3" = bad ] && exit 1
exec python3 -m http.server $HPORT --bind 127.0.0.1 --directory "$T/health" >/dev/null 2>&1
STUB
	chmod +x "$1/metalbear"
}
mkdir -p "$T/health/xrpc"; echo '{}' >"$T/health/xrpc/_health"

# --- release builder: dir name version bad
mkrelease() { # tag bad [corrupt]
	local tag="$1" bad="$2" d="$T/rel/download/$1"
	rm -rf "$d" "$T/pk"; mkdir -p "$d" "$T/pk/metalbear-$PLAT/lexicons"
	mkstub "$T/pk/metalbear-$PLAT" "${tag#v}" "$bad"
	echo "lex-${tag}" >"$T/pk/metalbear-$PLAT/lexicons/x.json"
	tar -C "$T/pk" -czf "$d/metalbear-$PLAT.tar.gz" "metalbear-$PLAT"
	(cd "$d" && sha256sum "metalbear-$PLAT.tar.gz" >SHA256SUMS)
	ssh-keygen -q -Y sign -f "$T/key" -n file "$d/SHA256SUMS" >/dev/null 2>&1
	[ "${3:-}" = corrupt ] && echo tampered >>"$d/metalbear-$PLAT.tar.gz"
	return 0
}
ssh-keygen -q -t ed25519 -N '' -f "$T/key" -C test >/dev/null
echo "metalbear-release $(cut -d' ' -f1,2 "$T/key.pub")" >"$T/signers"
ssh-keygen -q -t ed25519 -N '' -f "$T/otherkey" -C other >/dev/null
echo "metalbear-release $(cut -d' ' -f1,2 "$T/otherkey.pub")" >"$T/othersigners"

# --- local release server: /latest redirects to $T/latest_tag; downloads static.
cat >"$T/srv.py" <<PY
import http.server, os
T = "$T"
class H(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/latest":
            self.send_response(302); self.send_header("Location", "/tag/" + open(T + "/latest_tag").read().strip()); self.end_headers(); return
        return super().do_GET()
    def log_message(self, *a): pass
os.chdir(T + "/rel")
http.server.ThreadingHTTPServer(("127.0.0.1", $PORT), H).serve_forever()
PY
mkdir -p "$T/rel"
python3 "$T/srv.py" >/dev/null 2>&1 </dev/null & echo $! >"$T/srv.pid"
for _ in $(seq 50); do curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break; sleep 0.1; done

# --- install under test
setup() { # installed_version
	rm -rf "$T/inst" "$T/data" "$T/bk"; mkdir -p "$T/inst" "$T/data" "$T/bk" "$T/lex"
	mkstub "$T/inst" "$1" ok
	echo "lex-old" >"$T/lex/x.json"
	echo "old-row" >"$T/data/repo.sqlite3"
	echo "salt" >"$T/data/.blobstore.salt"
	echo "blob" >"$T/data/not-backed-up.bin"
	cat >"$T/svc.sh" <<SVC
#!/usr/bin/env bash
case "\$1" in
stop) [ -f "$T/svc.pid" ] && kill \$(cat "$T/svc.pid") 2>/dev/null; rm -f "$T/svc.pid"; sleep 0.3;;
start) "$T/inst/metalbear" >/dev/null 2>&1 </dev/null & echo \$! >"$T/svc.pid"; sleep 0.2;;
esac
exit 0
SVC
	chmod +x "$T/svc.sh"
	cat >"$T/update.conf" <<CONF
BIN="$T/inst/metalbear"
LEXICON_DIR="$T/lex"
DATA_DIR="$T/data"
BACKUP_DIR="$T/bk"
HEALTH_URL="http://127.0.0.1:$HPORT/xrpc/_health"
HEALTH_TIMEOUT=4
BASE_URL="http://127.0.0.1:$PORT"
CURL_PROTO="=http"
REQUIRE_ROOT=0
STOP_CMD="$T/svc.sh stop"
START_CMD="$T/svc.sh start"
${2:-ALLOW_UNSIGNED=1}
CONF
	export METALBEAR_UPDATE_CONF="$T/update.conf" TMPDIR="$T"
	"$T/svc.sh" stop; "$T/svc.sh" start; sleep 0.5
}
upd() { "$UPDATER" "$@"; }

mkrelease v0.2.0 ok
echo v0.2.0 >"$T/latest_tag"

# 1. check reports an available update and changes nothing.
setup 0.1.0
set +e; out="$(upd check 2>&1)"; rc=$?; set -e
[ "$rc" = 10 ] && grep -q "update available: 0.1.0 -> 0.2.0" <<<"$out" || die "check: rc=$rc $out"
[ "$("$T/inst/metalbear" --version)" = 0.1.0 ] || die "check changed the binary"
ok "check reports update, changes nothing"

# 2. up to date.
setup 0.2.0
upd check | grep -q "up to date" || die "up-to-date"
ok "check says up to date"

# 3. successful apply, SHA-256 only (ALLOW_UNSIGNED=1, warns), keeps previous binary and a snapshot.
setup 0.1.0
out="$(upd apply 2>&1)" || die "apply failed: $out"
grep -q "WARNING: ALLOW_UNSIGNED=1" <<<"$out" || die "no sha-only warning"
[ "$("$T/inst/metalbear" --version)" = 0.2.0 ] || die "binary not updated"
[ "$("$T/inst/metalbear.prev" --version)" = 0.1.0 ] || die "previous binary not kept"
[ "$(cat "$T/lex/x.json")" = lex-v0.2.0 ] || die "lexicons not updated"
ls "$T"/bk/data-0.1.0-*.tar >/dev/null || die "no snapshot"
tar -tf "$T"/bk/data-0.1.0-*.tar | grep -q 'repo.sqlite3' || die "snapshot lacks sqlite"
ok "apply updates, keeps previous binary, writes snapshot"

# 4. manual rollback restores binary, lexicons and data.
echo "new-row" >"$T/data/repo.sqlite3"
upd rollback >/dev/null || die "rollback failed"
[ "$("$T/inst/metalbear" --version)" = 0.1.0 ] && [ "$(cat "$T/data/repo.sqlite3")" = old-row ] && [ "$(cat "$T/lex/x.json")" = lex-old ] || die "rollback incomplete"
ok "rollback restores binary, lexicons and data"

# 5. tampered tarball: refused, nothing changed, service still up.
mkrelease v0.2.0 ok corrupt
setup 0.1.0
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "SHA-256 mismatch" <<<"$out" || die "tamper not caught: $out"
[ "$("$T/inst/metalbear" --version)" = 0.1.0 ] || die "tamper changed binary"
ok "corrupt tarball refused"

# 6. signed release verifies; wrong key refuses; missing signature refuses.
mkrelease v0.2.0 ok
setup 0.1.0 "SIGNERS_FILE=\"$T/signers\""
out="$(upd apply 2>&1)" || die "signed apply failed: $out"; grep -q "signature verified" <<<"$out" || die "no verify msg: $out"
setup 0.1.0 "SIGNERS_FILE=\"$T/othersigners\""
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "signature does not verify" <<<"$out" && [ "$("$T/inst/metalbear" --version)" = 0.1.0 ] || die "bad signature accepted: $out"
rm "$T/rel/download/v0.2.0/SHA256SUMS.sig"
setup 0.1.0 "SIGNERS_FILE=\"$T/signers\""
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "no SHA256SUMS.sig" <<<"$out" || die "missing signature accepted: $out"
ok "signature required when configured: good accepted, wrong key and missing refused"

# 7. new binary fails its health check: automatic rollback of binary and data.
mkrelease v0.2.0 bad
setup 0.1.0
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "rolled back to 0.1.0" <<<"$out" || die "no rollback: $out"
[ "$("$T/inst/metalbear" --version)" = 0.1.0 ] && [ "$(cat "$T/lex/x.json")" = lex-old ] || die "rollback left new files"
curl -fsS -o /dev/null "http://127.0.0.1:$HPORT/xrpc/_health" || die "old version not serving after rollback"
ok "failed health check rolls back binary and restarts the old version"

# 8. bad inputs: non-release tag, downgrade.
setup 0.1.0
set +e; out="$(upd apply --to '../evil' 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "not a vX.Y.Z" <<<"$out" || die "bad tag accepted"
setup 0.3.0
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "not newer" <<<"$out" || die "downgrade accepted"
ok "invalid tag and downgrade refused"

# 9. no snapshot, no update: a data dir with no SQLite files is refused after nothing changed.
mkrelease v0.2.0 ok
setup 0.1.0
rm -f "$T/data/repo.sqlite3"
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "no SQLite files" <<<"$out" || die "update proceeded without backup: $out"
[ "$("$T/inst/metalbear" --version)" = 0.1.0 ] || die "binary changed without backup"
curl -fsS -o /dev/null "http://127.0.0.1:$HPORT/xrpc/_health" || die "service left stopped after refused update"
ok "no backup, no update; service restarted"

# 10. the default is strict: with the built-in release key (no SIGNERS_FILE, no
# ALLOW_UNSIGNED) a release signed by any other key is refused, and so is an
# unsigned one. The private half of the built-in key is not available to this
# test, so only refusals can be checked here.
mkrelease v0.2.0 ok
setup 0.1.0 "ALLOW_UNSIGNED=0"
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "signature does not verify" <<<"$out" && [ "$("$T/inst/metalbear" --version)" = 0.1.0 ] || die "release signed by another key accepted by default: $out"
rm "$T/rel/download/v0.2.0/SHA256SUMS.sig"
setup 0.1.0 "ALLOW_UNSIGNED=0"
set +e; out="$(upd apply 2>&1)"; rc=$?; set -e
[ "$rc" != 0 ] && grep -q "unsigned releases are refused" <<<"$out" && [ "$("$T/inst/metalbear" --version)" = 0.1.0 ] || die "unsigned release accepted by default: $out"
ok "default refuses an unsigned release and one signed by another key"

echo "$pass checks passed"

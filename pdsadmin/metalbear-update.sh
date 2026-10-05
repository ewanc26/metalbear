#!/usr/bin/env bash
#
# metalbear-update.sh — update an installed MetalBear from this repo's GitHub
# releases, with integrity checks, a data backup, and automatic rollback.
#
# Usage:
#   metalbear-update.sh check                 report whether a newer release exists (default; changes nothing)
#   metalbear-update.sh apply [--to vX.Y.Z]   install it (needs root, restarts the service)
#   metalbear-update.sh rollback              put back the previous binary and data snapshot
#   metalbear-update.sh --help
#
# Nothing here runs unless an operator (or a timer the operator enabled) runs
# it. `check` is read-only. `apply` is the only command that stops the server.
#
# Configuration: /etc/metalbear/update.conf (override with METALBEAR_UPDATE_CONF),
# a shell fragment. See deploy/systemd/update.conf.example for every setting.
#
# How an update is made safe, in order:
#   1. The release's SHA256SUMS is fetched over HTTPS from github.com only.
#   2. If SIGNERS_FILE is set, SHA256SUMS.sig must verify against it
#      (ssh-keygen -Y verify) or the update is refused. Without it only the
#      SHA-256 is checked, which catches corruption and a swapped asset but not
#      a compromised release; the script says so every time.
#   3. The tarball's SHA-256 must match its line in SHA256SUMS.
#   4. The archive is unpacked into a scratch directory and the new binary must
#      report the release's version before anything is touched.
#   5. The service is stopped and every SQLite file (and the blob salt) in the
#      data directory is copied to BACKUP_DIR, then the copy is verified. If the
#      backup cannot be made there is no update: schema changes made by a newer
#      binary cannot be undone without it, and MetalBear stores no schema
#      version that would let this script tell which releases change the schema.
#   6. The previous binary and lexicons are kept as <name>.prev, the new ones
#      are moved in, the service starts, and HEALTH_URL must answer within
#      HEALTH_TIMEOUT seconds. If it does not, the previous binary and the data
#      snapshot are restored and the service is started again. Writes accepted
#      by the new binary in that window are discarded with the snapshot.
#
# No credentials are read, sent or logged: only public release URLs are fetched
# and the health URL is unauthenticated. Do not put secrets in update.conf.
set -euo pipefail
umask 077

REPO="ewanc26/metalbear"
CONF="${METALBEAR_UPDATE_CONF:-/etc/metalbear/update.conf}"

# Defaults, overridable in CONF.
SERVICE="metalbear"
BIN="/usr/local/bin/metalbear"
LEXICON_DIR=""                      # installed lexicon corpus; empty = leave alone
DATA_DIR="/var/lib/metalbear"
BACKUP_DIR="/var/backups/metalbear"
HEALTH_URL="http://127.0.0.1:2583/xrpc/_health"
HEALTH_TIMEOUT=60
SIGNERS_FILE=""                     # ssh allowed_signers file; empty = SHA-256 only
SIGNER_IDENTITY="metalbear-release"
STOP_CMD=""                         # default: systemctl stop $SERVICE
START_CMD=""                        # default: systemctl start $SERVICE
BASE_URL="https://github.com/${REPO}/releases"
CURL_PROTO="=https"                 # tests point BASE_URL at a local server and widen this
REQUIRE_ROOT=1                      # tests run unprivileged against stub service commands

# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

say() { echo "metalbear-update: $*"; }
fail() { echo "metalbear-update: $*" >&2; exit 1; }

usage() { sed -n '3,12p' "${BASH_SOURCE[0]}"; }

stop_service() { if [ -n "$STOP_CMD" ]; then $STOP_CMD; else systemctl stop "$SERVICE"; fi; }
start_service() { if [ -n "$START_CMD" ]; then $START_CMD; else systemctl start "$SERVICE"; fi; }

need() { command -v "$1" >/dev/null || fail "$1 is required"; }

sha256_of() {
	if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
	else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# vX.Y.Z only; anything else (a branch name, a path, "../x") is refused before
# it can reach a URL or the filesystem.
valid_tag() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# Newer-than comparison on X.Y.Z, without relying on sort -V (absent on BusyBox).
version_gt() {
	local IFS=.
	# shellcheck disable=SC2206
	local a=($1) b=($2) i
	for i in 0 1 2; do
		((${a[i]:-0} > ${b[i]:-0})) && return 0
		((${a[i]:-0} < ${b[i]:-0})) && return 1
	done
	return 1
}

platform() {
	case "$(uname -s)-$(uname -m)" in
	Linux-x86_64) echo linux-x86_64 ;;
	Linux-aarch64 | Linux-arm64) echo linux-aarch64 ;;
	Darwin-arm64) echo macos-arm64 ;;
	*) return 1 ;;
	esac
}

current_version() { "$BIN" --version 2>/dev/null | head -1; }

# Resolves "latest" through the releases/latest redirect: plain HTTPS, no API
# token, no rate-limit surprises.
latest_tag() {
	local url
	url="$(curl -fsS --proto "$CURL_PROTO" -o /dev/null -w '%{redirect_url}' "${BASE_URL}/latest")" ||
		fail "could not reach ${BASE_URL}/latest"
	local tag="${url##*/}"
	valid_tag "$tag" || fail "unexpected latest release '$tag'"
	echo "$tag"
}

fetch() { curl -fsSL --proto "$CURL_PROTO" --tlsv1.2 --max-time 600 -o "$2" "$1" || fail "download failed: $1"; }

cmd_check() {
	need curl
	local cur latest
	cur="$(current_version)" || fail "cannot run $BIN --version"
	latest="$(latest_tag)"
	if platform >/dev/null; then :; else
		say "no prebuilt release for $(uname -s)-$(uname -m); build from source (see README) to update."
	fi
	if version_gt "${latest#v}" "$cur"; then
		say "update available: $cur -> ${latest#v}"
		say "run: metalbear-update.sh apply"
		return 10
	fi
	say "up to date ($cur)"
}

verify_download() { # dir tarball-name
	local dir="$1" asset="$2"
	if [ -n "$SIGNERS_FILE" ]; then
		need ssh-keygen
		[ -f "$dir/SHA256SUMS.sig" ] || fail "SIGNERS_FILE is set but the release has no SHA256SUMS.sig; refusing"
		ssh-keygen -Y verify -f "$SIGNERS_FILE" -I "$SIGNER_IDENTITY" -n file \
			-s "$dir/SHA256SUMS.sig" <"$dir/SHA256SUMS" >/dev/null ||
			fail "SHA256SUMS signature does not verify against $SIGNERS_FILE; refusing"
		say "signature verified"
	else
		say "WARNING: SIGNERS_FILE not set; checking SHA-256 only (no authenticity check)"
	fi
	local want got
	want="$(awk -v f="$asset" '$2 == f || $2 == "*" f {print $1}' "$dir/SHA256SUMS")"
	[ -n "$want" ] && [ "$(wc -l <<<"$want")" -eq 1 ] || fail "$asset is not listed exactly once in SHA256SUMS"
	got="$(sha256_of "$dir/$asset")"
	[ "$want" = "$got" ] || fail "SHA-256 mismatch for $asset (expected $want, got $got)"
	say "sha256 ok: $asset"
}

backup_data() { # outfile
	local out="$1" list
	[ -d "$DATA_DIR" ] || fail "DATA_DIR $DATA_DIR does not exist"
	list="$(mktemp)"
	(cd "$DATA_DIR" && find . -type f \( -name '*.sqlite3' -o -name '*.sqlite3-wal' -o -name '*.sqlite3-shm' -o -name '.blobstore.salt' \) -print) >"$list"
	grep -q '\.sqlite3$' "$list" || { rm -f "$list"; fail "no SQLite files under $DATA_DIR; wrong DATA_DIR? refusing"; }
	local need_kb avail_kb
	need_kb="$(cd "$DATA_DIR" && xargs -a "$list" du -k | awk '{s+=$1} END {print s*2+1024}')"
	avail_kb="$(df -Pk "$BACKUP_DIR" | awk 'NR==2 {print $4}')"
	[ "$avail_kb" -ge "$need_kb" ] || { rm -f "$list"; fail "not enough space in $BACKUP_DIR (need ~${need_kb} KiB, have ${avail_kb} KiB)"; }
	tar -C "$DATA_DIR" -cf "$out" -T "$list"
	rm -f "$list"
	tar -tf "$out" >/dev/null || fail "backup archive $out does not read back"
	say "data snapshot: $out"
}

restore_data() { tar -C "$DATA_DIR" -xf "$1"; }

healthy() {
	local i=0
	while [ "$i" -lt "$HEALTH_TIMEOUT" ]; do
		curl -fsS -o /dev/null --max-time 3 "$HEALTH_URL" 2>/dev/null && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

cmd_apply() {
	local target=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--to) target="${2:-}"; shift 2 ;;
		*) fail "unknown argument $1" ;;
		esac
	done
	[ "$REQUIRE_ROOT" != 1 ] || [ "$(id -u)" -eq 0 ] || fail "apply needs root (it replaces $BIN and restarts $SERVICE)"
	need curl; need tar
	local plat cur
	plat="$(platform)" || fail "no prebuilt release for $(uname -s)-$(uname -m) (ARMv6/ARMv7 included); build from source"
	cur="$(current_version)" || fail "cannot run $BIN --version"
	[ -n "$target" ] || target="$(latest_tag)"
	valid_tag "$target" || fail "'$target' is not a vX.Y.Z release tag"
	version_gt "${target#v}" "$cur" || fail "$target is not newer than installed $cur; nothing to do (use rollback to go back)"

	exec 9>"${TMPDIR:-/tmp}/metalbear-update.lock"
	command -v flock >/dev/null && { flock -n 9 || fail "another update is running"; }

	local asset
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	asset="metalbear-${plat}.tar.gz"
	say "updating $cur -> ${target#v} ($asset)"
	fetch "${BASE_URL}/download/${target}/${asset}" "$work/$asset"
	fetch "${BASE_URL}/download/${target}/SHA256SUMS" "$work/SHA256SUMS"
	# A missing signature is reported by verify_download, not as a bare 404.
	[ -z "$SIGNERS_FILE" ] || curl -fsSL --proto "$CURL_PROTO" --tlsv1.2 --max-time 60 -o "$work/SHA256SUMS.sig" "${BASE_URL}/download/${target}/SHA256SUMS.sig" 2>/dev/null || true
	verify_download "$work" "$asset"

	# Refuse archives that could write outside the scratch directory.
	if tar -tzf "$work/$asset" | grep -q -E '(^/|(^|/)\.\.(/|$))'; then
		fail "archive contains absolute or parent-relative paths; refusing"
	fi
	mkdir "$work/new"
	tar -xzf "$work/$asset" -C "$work/new" --strip-components=1
	[ -x "$work/new/metalbear" ] || fail "archive has no metalbear binary"
	[ "$("$work/new/metalbear" --version | head -1)" = "${target#v}" ] ||
		fail "new binary reports a different version than $target; refusing"

	mkdir -p "$BACKUP_DIR"
	local stamp snap
	stamp="$(date -u +%Y%m%dT%H%M%SZ)"
	snap="$BACKUP_DIR/data-${cur}-${stamp}.tar"

	say "stopping $SERVICE"
	stop_service
	installed=0
	rollback_now() {
		say "rolling back to $cur"
		stop_service || true
		[ -e "$BIN.prev" ] && mv -f "$BIN.prev" "$BIN"
		if [ -n "$LEXICON_DIR" ] && [ -e "$LEXICON_DIR.prev" ]; then rm -rf "$LEXICON_DIR"; mv "$LEXICON_DIR.prev" "$LEXICON_DIR"; fi
		restore_data "$snap"
		start_service
	}
	# A failure after the service stopped must not leave it stopped.
	trap 'rc=$?; if [ $rc -ne 0 ] && [ "${installed:-1}" -eq 0 ]; then start_service || true; fi; rm -rf "$work"' EXIT

	backup_data "$snap"

	cp -p "$BIN" "$BIN.prev"
	if [ -n "$LEXICON_DIR" ] && [ -d "$work/new/lexicons" ]; then
		rm -rf "$LEXICON_DIR.prev"; cp -a "$LEXICON_DIR" "$LEXICON_DIR.prev"
		rm -rf "$LEXICON_DIR"; cp -a "$work/new/lexicons" "$LEXICON_DIR"
	fi
	install -m 0755 "$work/new/metalbear" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	installed=1

	say "starting $SERVICE and waiting up to ${HEALTH_TIMEOUT}s for $HEALTH_URL"
	start_service
	if healthy; then
		say "updated to $(current_version); previous binary kept at $BIN.prev, data snapshot at $snap"
	else
		say "health check failed"
		rollback_now
		healthy && fail "update to $target failed its health check; rolled back to $cur" ||
			fail "update failed AND the rolled-back $cur did not become healthy; inspect $SERVICE (snapshot: $snap)"
	fi
}

cmd_rollback() {
	[ "$REQUIRE_ROOT" != 1 ] || [ "$(id -u)" -eq 0 ] || fail "rollback needs root"
	[ -e "$BIN.prev" ] || fail "no previous binary at $BIN.prev"
	local snap
	snap="$(ls -1t "$BACKUP_DIR"/data-*.tar 2>/dev/null | head -1)" || true
	[ -n "$snap" ] || fail "no data snapshot in $BACKUP_DIR; refusing to roll back the binary alone"
	say "rolling back using $snap (writes since that snapshot are discarded)"
	stop_service
	mv -f "$BIN.prev" "$BIN"
	if [ -n "$LEXICON_DIR" ] && [ -e "$LEXICON_DIR.prev" ]; then rm -rf "$LEXICON_DIR"; mv "$LEXICON_DIR.prev" "$LEXICON_DIR"; fi
	restore_data "$snap"
	start_service
	healthy || fail "service did not become healthy after rollback"
	say "rolled back to $(current_version)"
}

case "${1:-check}" in
check) shift || true; cmd_check "$@" ;;
apply) shift; cmd_apply "$@" ;;
rollback) cmd_rollback ;;
-h | --help | help) usage ;;
*) usage >&2; exit 2 ;;
esac

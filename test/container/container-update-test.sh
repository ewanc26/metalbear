#!/bin/sh
# Regression tests for scripts/container-update.sh, against stub images built
# from test/container/stub. Needs docker and network access for the alpine base.
#
#   sh test/container/container-update-test.sh
#
# Cases:
#   1. A floating tag moved by a pull must not make "the previous image" the new
#      one: a failed upgrade restores the image that was running, by ID.
#   2. Rollback refuses without --yes when there is no terminal, keeps the
#      current data as an archive when it runs, and restores the old image.
#   3. Rollback refuses a target that cannot read the snapshot's schema.

set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="${SCRIPT:-$ROOT/scripts/container-update.sh}"
STUB="$ROOT/test/container/stub"
PORT=2595

CONTAINER=cu-test
VOLUME=cu-test-vol
BACKUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cu-test.XXXXXX")"
export CONTAINER VOLUME BACKUP_DIR
export RUN_OPTS="-p $PORT:2583"
export HEALTH_URL="http://127.0.0.1:$PORT/xrpc/_health"
export HEALTH_TIMEOUT=8
export PULL=0

failures=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }
check() {
    # check "description" <command...>
    desc="$1"
    shift
    if "$@"; then pass "$desc"; else fail "$desc"; fi
}

image_id() { docker image inspect -f '{{.Id}}' "$1"; }
running_image() { docker inspect -f '{{.Image}}' "$CONTAINER" 2>/dev/null; }
# Last build to write /data/marks, read from the volume with a stub image.
last_mark() {
    docker run --rm -v "$VOLUME:/data:ro" --entrypoint /bin/cat cu-stub:a /data/marks | tail -n 1
}
state_value() { sed -n "s/^$1=//p" "$BACKUP_DIR/last-upgrade.env"; }
wait_serving() {
    n=0
    while [ "$n" -lt 20 ]; do
        curl -fsS -o /dev/null --max-time 2 "$HEALTH_URL" 2>/dev/null && return 0
        sleep 1
        n=$((n + 1))
    done
    return 1
}
cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    docker volume rm "$VOLUME" >/dev/null 2>&1
    docker rmi -f cu-stub:a cu-stub:b cu-stub:c cu-stub:cur >/dev/null 2>&1
    find "$BACKUP_DIR" -mindepth 1 -delete 2>/dev/null
    rmdir "$BACKUP_DIR" 2>/dev/null
}
trap cleanup EXIT

docker info >/dev/null 2>&1 || { echo "docker is not running" >&2; exit 2; }
docker rm -f "$CONTAINER" >/dev/null 2>&1
docker volume rm "$VOLUME" >/dev/null 2>&1

docker build -q -t cu-stub:a --build-arg MARK=a "$STUB" >/dev/null || exit 2
docker build -q -t cu-stub:b --build-arg MARK=b --build-arg BROKEN=1 "$STUB" >/dev/null || exit 2
docker build -q -t cu-stub:c --build-arg MARK=c "$STUB" >/dev/null || exit 2

# ---- case 1: floating tag -------------------------------------------------
docker tag cu-stub:a cu-stub:cur
docker run -d --name "$CONTAINER" -p "$PORT:2583" -v "$VOLUME:/data" cu-stub:cur >/dev/null
check "initial container serves" wait_serving
A_ID="$(image_id cu-stub:a)"
check "initial container runs image A" [ "$(running_image)" = "$A_ID" ]

# The floating tag moves to the broken build before the upgrade.
docker tag cu-stub:b cu-stub:cur
if "$SCRIPT" upgrade cu-stub:cur >/dev/null 2>&1; then
    fail "upgrade to a broken build reports failure"
else
    pass "upgrade to a broken build reports failure"
fi
check "failed upgrade restores image A by ID, not the tag" [ "$(running_image)" = "$A_ID" ]
check "failed upgrade records image A as the previous image" \
    [ "$(state_value PREVIOUS_IMAGE)" = "$A_ID" ]
check "failed upgrade leaves the data at the snapshot (last writer A)" \
    [ "$(last_mark)" = "a" ]
check "restored container serves" wait_serving

# ---- case 2: rollback confirmation and archive ----------------------------
if "$SCRIPT" upgrade cu-stub:c >/dev/null 2>&1; then
    pass "healthy upgrade to C succeeds"
else
    fail "healthy upgrade to C succeeds"
fi
C_ID="$(image_id cu-stub:c)"
check "container runs image C after the upgrade" [ "$(running_image)" = "$C_ID" ]
check "previous image is still A after the upgrade to C" \
    [ "$(state_value PREVIOUS_IMAGE)" = "$A_ID" ]

if "$SCRIPT" rollback </dev/null >/dev/null 2>&1; then
    fail "rollback without --yes and without a terminal is refused"
else
    pass "rollback without --yes and without a terminal is refused"
fi
check "refused rollback leaves image C running" [ "$(running_image)" = "$C_ID" ]
set -- "$BACKUP_DIR"/pre-rollback-*.tar
check "refused rollback writes no archive of the current data" [ ! -e "$1" ]

check "rollback --yes succeeds" "$SCRIPT" rollback --yes
check "rollback restores image A by ID" [ "$(running_image)" = "$A_ID" ]
check "rollback restores the snapshot (last writer A)" [ "$(last_mark)" = "a" ]
set -- "$BACKUP_DIR"/pre-rollback-*.tar
PRE="$1"
check "rollback keeps the discarded data as an archive" [ -f "$PRE" ]
check "the archive holds the data that the rollback discarded (last writer C)" \
    [ "$(tar -xOf "$PRE" ./marks 2>/dev/null | tail -n 1)" = "c" ]

# ---- case 3: schema guard -------------------------------------------------
# Make the snapshot claim a schema that image A cannot read, then ask for a
# rollback to A. The guard must refuse and leave the container alone.
sed 's/^SNAPSHOT_SCHEMA=.*/SNAPSHOT_SCHEMA=2/' "$BACKUP_DIR/last-upgrade.env" \
    > "$BACKUP_DIR/last-upgrade.env.tmp" && mv "$BACKUP_DIR/last-upgrade.env.tmp" "$BACKUP_DIR/last-upgrade.env"
if "$SCRIPT" rollback --yes cu-stub:a >/dev/null 2>&1; then
    fail "rollback to a build that cannot read the snapshot is refused"
else
    pass "rollback to a build that cannot read the snapshot is refused"
fi
check "refused schema rollback leaves image A running" [ "$(running_image)" = "$A_ID" ]

echo
if [ "$failures" -eq 0 ]; then
    echo "all container-update checks passed"
    exit 0
fi
echo "$failures check(s) failed"
exit 1

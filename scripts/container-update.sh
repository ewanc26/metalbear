#!/bin/sh
# Snapshot, upgrade and roll back a MetalBear container install.
#
# This is the docker counterpart of pdsadmin/metalbear-update.sh. The systemd
# updater downloads a release; this one pulls an image tag and recreates the
# container on the same data volume. The rules match docs/updating.md: no
# upgrade without a verified snapshot, a health check after the change, a
# restore of the snapshot and the old image if that check fails, and no
# rollback to a build that cannot read the snapshot's schema.
#
#   container-update.sh snapshot
#   container-update.sh upgrade IMAGE          e.g. ghcr.io/ewanc26/metalbear:0.44
#   container-update.sh rollback [IMAGE]       default: the image before the last upgrade
#   container-update.sh status
#
# Configuration comes from the environment, with these defaults:
#   CONTAINER=metalbear          container name
#   VOLUME=metalbear-data        named volume holding /data
#   RUN_OPTS="-p 2583:2583"      extra docker run options (ports, env, mounts)
#   HEALTH_URL=http://127.0.0.1:2583/xrpc/_health
#   HEALTH_TIMEOUT=60            seconds to wait for the health check
#   BACKUP_DIR=$HOME/metalbear-snapshots
#
# Set RUN_OPTS to the same options you used for `docker run`, minus the name,
# the volume and the image: the script recreates the container with them.
# The restore and schema checks run the images themselves, so they need
# nothing installed on the host beyond docker, curl and tar.

set -eu

CONTAINER="${CONTAINER:-metalbear}"
VOLUME="${VOLUME:-metalbear-data}"
RUN_OPTS="${RUN_OPTS:--p 2583:2583}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:2583/xrpc/_health}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/metalbear-snapshots}"
STATE="$BACKUP_DIR/last-upgrade.env"

die() {
    echo "container-update: $*" >&2
    exit 1
}

log() {
    # stderr, because take_snapshot is captured with $(...) and must print only its path.
    echo "container-update: $*" >&2
}

require_docker() {
    docker info >/dev/null 2>&1 || die "docker is not running"
}

# The schema a binary writes, from `metalbear --version` (line 2: "schema N").
image_schema() {
    schema="$(docker run --rm --entrypoint /usr/local/bin/metalbear "$1" --version 2>/dev/null |
        sed -n 's/^schema \([0-9][0-9]*\)$/\1/p' | head -n 1)"
    [ -n "$schema" ] || die "could not read the schema from $1 (is it a MetalBear image?)"
    echo "$schema"
}

current_image() {
    docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null || true
}

# Stop the container so the databases are at rest, then archive /data with the
# image's own tar. The archive is read back before it is trusted.
take_snapshot() {
    image="$1"
    mkdir -p "$BACKUP_DIR"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    archive="$BACKUP_DIR/data-$stamp.tar"
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
        docker stop "$CONTAINER" >/dev/null
    fi
    log "snapshotting volume $VOLUME to $archive"
    docker run --rm --entrypoint /bin/tar \
        -v "$VOLUME:/data:ro" -v "$BACKUP_DIR:/backup" "$image" \
        -C /data -cf "/backup/data-$stamp.tar" . || die "snapshot failed"
    entries="$(tar -tf "$archive" 2>/dev/null | wc -l | tr -d ' ')"
    [ "$entries" -gt 0 ] || die "snapshot $archive is empty or unreadable; nothing changed"
    echo "$archive"
}

restore_snapshot() {
    archive="$1"
    image="$2"
    name="$(basename "$archive")"
    log "restoring $name into volume $VOLUME"
    docker run --rm --entrypoint /bin/sh \
        -v "$VOLUME:/data" -v "$BACKUP_DIR:/backup:ro" "$image" \
        -c "find /data -mindepth 1 -delete && tar -C /data -xf /backup/$name" ||
        die "restore failed; the volume may be partly written, restore $archive by hand"
}

start_container() {
    image="$1"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    docker run -d --name "$CONTAINER" $RUN_OPTS -v "$VOLUME:/data" \
        --restart unless-stopped "$image" >/dev/null
}

# Wait for the health check. Returns non-zero if it never passes.
wait_healthy() {
    waited=0
    while [ "$waited" -lt "$HEALTH_TIMEOUT" ]; do
        if curl -fsS -o /dev/null --max-time 3 "$HEALTH_URL" 2>/dev/null; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}

write_state() {
    mkdir -p "$BACKUP_DIR"
    {
        echo "PREVIOUS_IMAGE=$1"
        echo "SNAPSHOT=$2"
        echo "SNAPSHOT_SCHEMA=$3"
    } >"$STATE"
}

cmd_snapshot() {
    require_docker
    image="$(current_image)"
    [ -n "$image" ] || die "no container named $CONTAINER"
    archive="$(take_snapshot "$image")"
    docker start "$CONTAINER" >/dev/null 2>&1 || true
    log "snapshot kept at $archive"
}

cmd_upgrade() {
    new="${1:-}"
    [ -n "$new" ] || die "usage: upgrade IMAGE"
    require_docker
    old="$(current_image)"
    [ -n "$old" ] || die "no container named $CONTAINER to upgrade"

    if [ "${PULL:-1}" = 1 ]; then
        log "pulling $new"
        docker pull "$new" >/dev/null || die "pull failed; nothing changed"
    fi
    new_schema="$(image_schema "$new")"
    old_schema="$(image_schema "$old")"
    log "schema: $old_schema (current) -> $new_schema (new)"

    archive="$(take_snapshot "$old")"
    write_state "$old" "$archive" "$old_schema"

    log "starting $new"
    start_container "$new"
    if wait_healthy; then
        log "upgraded to $new; health check passed"
        return 0
    fi

    log "health check failed for $new; restoring $old and the snapshot"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    restore_snapshot "$archive" "$old"
    start_container "$old"
    if wait_healthy; then
        die "upgrade to $new failed its health check; $old is running on the snapshot"
    fi
    die "upgrade to $new failed and $old did not come back healthy; investigate before retrying"
}

cmd_rollback() {
    [ -f "$STATE" ] || die "no upgrade recorded in $STATE; nothing to roll back"
    # shellcheck disable=SC1090
    . "$STATE"
    target="${1:-$PREVIOUS_IMAGE}"
    require_docker

    target_schema="$(image_schema "$target")"
    if [ "$target_schema" -lt "$SNAPSHOT_SCHEMA" ]; then
        die "refusing rollback: $target writes schema $target_schema but the snapshot is schema $SNAPSHOT_SCHEMA, and that build cannot read it"
    fi
    [ -f "$SNAPSHOT" ] || die "snapshot $SNAPSHOT is missing; refusing to roll back without it"

    log "rolling back to $target from $SNAPSHOT"
    docker stop "$CONTAINER" >/dev/null 2>&1 || true
    restore_snapshot "$SNAPSHOT" "$target"
    start_container "$target"
    if wait_healthy; then
        log "rolled back to $target; health check passed"
        return 0
    fi
    die "rolled back to $target but the health check failed; investigate"
}

cmd_status() {
    require_docker
    state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null)" || state=absent
    echo "container: $CONTAINER ($state)"
    echo "image:     $(current_image)"
    if [ -f "$STATE" ]; then
        # shellcheck disable=SC1090
        . "$STATE"
        echo "last upgrade: previous image $PREVIOUS_IMAGE, snapshot $SNAPSHOT (schema $SNAPSHOT_SCHEMA)"
    else
        echo "last upgrade: none recorded"
    fi
}

case "${1:-}" in
    snapshot) cmd_snapshot ;;
    upgrade) shift; cmd_upgrade "$@" ;;
    rollback) shift; cmd_rollback "$@" ;;
    status) cmd_status ;;
    *) sed -n '2,20p' "$0" >&2; exit 2 ;;
esac

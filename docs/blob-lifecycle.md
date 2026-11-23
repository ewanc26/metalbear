# Blob lifecycle

Uploaded blobs have two states, tracked per account and CID in the host-wide
`<data>/blob_lifecycle.sqlite3` database (schema version 7):

| State | Meaning |
|---|---|
| temporary | Written by `uploadBlob` but not yet named by a record. `getBlob` returns 404, `listBlobs` omits it, and its bytes do not count against the account's blob quota. |
| durable | A record referenced the blob. It is visible, counted against quota, and stays reachable until no live record revision names it. |

The first record reference promotes a temporary copy to durable; re-uploading
the same CID does not demote it, because a live record may still need the
bytes. References are stored with the commit revision that made them, so a
reference whose revision has since been removed by repo GC is stale and can be
pruned while references to surviving revisions keep the blob alive.

## Configuration

`limits.blob_temp_seconds` in the config file, or
`METALBEAR_BLOB_TEMP_SECONDS`, sets how long an unreferenced temporary upload
may sit on disk. The default is 86400 seconds (one day); zero removes the
grace period and a negative value is rejected at startup. It is a lower bound,
not a timer: nothing is deleted until a sweep runs.

## Sweep and operator CLI

A sweep walks every registered account, opens its `blobs` directory and
`repo.sqlite3`, seeds lifecycle rows for any pre-existing payloads as durable
(the seed is insert-safe, so a live temporary upload keeps its state), then:

1. deletes temporary copies older than `blob_temp_seconds`;
2. drops references whose revision is no longer present in that account's
   repo, keeping the blob if another revision still names it;
3. deletes durable copies with no surviving reference.

Run one from a **stopped** instance with the offline wrapper (see
[operator-commands.md](operator-commands.md)):

```sh
METALBEAR_DATA=/var/lib/metalbear metalbear-maintenance.sh blob-sweep --dry-run
```

`--dry-run` prints the counts without deleting anything and needs no
confirmation. Without it the wrapper asks for confirmation unless `--yes` is
passed. Both forms print one summary line, including the account count, with
`temporary`, `temporary_bytes`, `expiring`, `unreferenced_durable`, `deleted`
and `refs_pruned`. The helper also accepts `metalbear-maint --data-dir DIR
blob-sweep [--dry-run]` directly.

## Metrics

The same counts are read from the lifecycle database at scrape time and
exposed as gauges at `/metrics` (see [monitoring.md](monitoring.md)):
`metalbear_blobs_temporary`, `metalbear_blobs_expiring` and
`metalbear_blobs_unreferenced_durable`. `temporary_bytes` is reported by the
sweep and its dry-run summary. A rising `metalbear_blobs_expiring` means
uploads are being abandoned faster than they are swept; a rising
`metalbear_blobs_unreferenced_durable` means records were deleted or their
revisions collected without their blobs being reclaimed.

## Embedders and imports

Only `metalbear_blob_store_put_temporary` creates a temporary copy. Plain
`put` / `put_file` remain durable for embedders, export and inbound-migration
paths that reference their blobs immediately, and stores used without a
lifecycle database keep their historical "every stored blob is visible"
behaviour.

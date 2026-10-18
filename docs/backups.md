# Scheduled backups

MetalBear can back up its data directory on a timer, and keep only the newest
archives. It is off until you set an interval.

## Settings

| Setting | Environment variable | Config key | Default |
|---|---|---|---|
| Interval in seconds (off when unset or 0) | `METALBEAR_BACKUP_INTERVAL_SECONDS` | `backup.interval_seconds` | off |
| Archives to keep | `METALBEAR_BACKUP_RETAIN` | `backup.retain` | 7 |
| Directory for archives | `METALBEAR_BACKUP_DIR` | `backup.dir` | none: required when the interval is set |

The backup directory is required when backups are on, and it must not be inside
the data directory. The server refuses to run a backup into the data directory,
because each archive would then contain the previous ones. There is no default
location: a default beside the data directory is outside the volume in a
container, and it disappears when the container is recreated. Put the directory
on storage that outlives the container.

## What a run does

1. Copies the data directory into a staging directory inside the backup
   directory. Each SQLite database is copied with `VACUUM INTO`, so the server
   keeps running and a database with uncommitted WAL data is copied whole.
   Other files are copied as they are.
2. Writes `metalbear-<UTC time>.bak` and reads it back to check it.
3. Deletes the oldest archives beyond the retention count.

A run that fails at any step removes its own partial files and leaves every
existing archive in place. Failures are logged as `backup:` lines.

## Restoring

An archive restores with `metalbear_backup_restore` into an empty data
directory. Stop the server before restoring over a running data directory.

## What this does not cover

- Archives are not encrypted, and they are not copied off the host. Keep a copy
  somewhere else if the host can be lost.
- The first run happens one interval after the server starts, not at start-up.
- Writing an archive streams each file, so a large file costs no more memory
  than one buffer. Restoring reads each entry into memory, so restoring a very
  large file needs that much free memory.
- A file over 4 GiB is refused, because the archive stores sizes as 32 bits.

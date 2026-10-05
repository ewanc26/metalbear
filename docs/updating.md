# Updating a MetalBear install

MetalBear can update itself from this repository's GitHub releases, but only
when you ask it to. The tool is `pdsadmin/metalbear-update.sh`, a shell script
outside the server binary, so it costs a Raspberry Pi 1 nothing when it is not
running ([#34](https://github.com/ewanc26/metalbear/issues/34)).

It covers the prebuilt tarball install under systemd. A container install
updates by pulling a newer image tag. A source build updates with `git pull`
and a rebuild. There is no prebuilt ARMv6 or ARMv7 archive, so a Pi 1 builds
from source and the script says so rather than guessing.

## Use

```sh
sudo cp deploy/systemd/update.conf.example /etc/metalbear/update.conf   # then edit
metalbear-update.sh check      # read-only; exit status 10 means "update available"
sudo metalbear-update.sh apply
sudo metalbear-update.sh rollback
```

`check` is the default and changes nothing. `apply` is the only command that
stops the server. The systemd units in `deploy/systemd/` split the two on
purpose: `metalbear-update-check.timer` runs the read-only check daily, and
`metalbear-update-apply.timer` is not enabled by anything. Enable it only once
you have picked a maintenance window, because applying restarts the server.

## What `apply` does

1. Fetches `SHA256SUMS` for the release over HTTPS from github.com.
2. If `SIGNERS_FILE` is set, verifies `SHA256SUMS.sig` with `ssh-keygen -Y
   verify` and refuses on any failure, including a missing signature. If it is
   not set, only the SHA-256 is checked and the script warns each time. That
   catches corruption and a swapped asset, not a compromised release.
3. Checks the tarball against its line in `SHA256SUMS`, rejects archives with
   absolute or `..` paths, and runs the new binary's `--version`, which must
   equal the release.
4. Stops the service and copies every SQLite file (and the blob salt) in
   `DATA_DIR` to `BACKUP_DIR`, then reads the copy back. No backup, no update.
5. Keeps the old binary and lexicons as `.prev`, installs the new ones,
   starts the service, and waits for `HEALTH_URL`.
6. If the health check fails, restores the old binary and the snapshot and
   starts the old version. Anything the new binary wrote in that window is
   discarded with the snapshot.

The script reads no credentials and logs none; it fetches public release URLs
only. It refuses a downgrade and anything that is not a `vX.Y.Z` tag.

## Why a backup is mandatory

Startup applies schema changes in place (`CREATE TABLE IF NOT EXISTS`, `ALTER
TABLE ... ADD COLUMN`), and the databases carry no schema version. The script
therefore cannot tell which releases change the schema, so it treats every
update as one that might, and refuses to run without a snapshot to return to.
Recording a schema version would let it say more; that is tracked in the
issue linked from the pull request that added this.

## Release signing

Releases are published with a `SHA256SUMS` file. `release.yml` signs it with
an OpenSSH ed25519 key when the repository secret `RELEASE_SIGNING_KEY` exists.
That key has to come from the owner and has not been created yet, so current
releases are unsigned. When it exists, put the public half in an
`allowed_signers` file (`metalbear-release ssh-ed25519 AAAA...`) and set
`SIGNERS_FILE`. After a release, `tools/release.sh check-assets vX.Y.Z`
downloads and verifies the published files.

## What has been tested

On a Linux x86-64 host only, against a local release server and a stub binary:
`test/update/test_update.sh`, run in CI as the `updater` job. It covers check,
apply, rollback, a corrupt archive, a good, wrong-key and missing signature, a
failed health check, a bad tag, a downgrade, and a data directory with no
SQLite files. It has not run against a real release, a real systemd unit, or
any Raspberry Pi.

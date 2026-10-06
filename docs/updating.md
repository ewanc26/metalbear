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
2. Verifies `SHA256SUMS.sig` with `ssh-keygen -Y verify` against the release
   key built into the script (or `SIGNERS_FILE`) and refuses on any failure,
   including a missing signature. Only `ALLOW_UNSIGNED=1` falls back to the
   SHA-256 alone, with a warning each time; that catches corruption and a
   swapped asset, not a compromised release.
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
TABLE ... ADD COLUMN`). Every database now records a schema version in
SQLite's `user_version`, and a build refuses to open a database written by a
newer one rather than guess ([#56](https://github.com/ewanc26/metalbear/issues/56)).
That protects a rollback to a build that has this check, and nothing older:
binaries before 0.44 do not look. The updater also cannot yet tell which
release raises the version, so it still treats every update as one that might
change the schema and refuses to run without a snapshot to return to.

## Release signing

Releases are published with a `SHA256SUMS` file and a detached OpenSSH ed25519
signature over it, `SHA256SUMS.sig`, made in `release.yml` with a private key
that exists only as the repository secret `RELEASE_SIGNING_KEY`. The release
workflow fails rather than publish without it, and checks its own signature
against the committed public key before publishing.

The public half is in [`pdsadmin/release-signers`](../pdsadmin/release-signers),
as an `allowed_signers` line, and is built into `metalbear-update.sh`:

```
metalbear-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICvNnkY9ds73BobaJO7nyfkBeqmaEOdzeF/zevg9/4uB
```

The updater refuses a release whose signature does not verify against it, and
refuses one with no signature. Releases up to and including v0.43.0 are
unsigned, so `metalbear-update.sh` will not install them unless the operator sets
`ALLOW_UNSIGNED=1` in `update.conf`, which checks the SHA-256 only and says so.
To trust a different key, set `SIGNERS_FILE` to an `allowed_signers` file.

If the key ever has to be replaced, the new public key goes into
`pdsadmin/metalbear-update.sh` and `pdsadmin/release-signers`, and operators need
the new script, because the updater only trusts the key it has. `tools/release.sh check-assets vX.Y.Z` downloads a release and
verifies the published files.

## What has been tested

On a Linux x86-64 host only, against a local release server and a stub binary:
`test/update/test_update.sh`, run in CI as the `updater` job. It covers check,
apply, rollback, a corrupt archive, a good, wrong-key and missing signature, and the strict default (an unsigned release and one signed by another key are refused), a
failed health check, a bad tag, a downgrade, and a data directory with no
SQLite files. It has not run against a real release, a real systemd unit, or
any Raspberry Pi.

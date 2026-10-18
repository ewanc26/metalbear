# Updating a MetalBear install

MetalBear can update itself from this repository's GitHub releases, but only
when you ask it to. The tool is `pdsadmin/metalbear-update.sh`, a shell script
outside the server binary, so it costs a Raspberry Pi 1 nothing when it is not
running ([#34](https://github.com/ewanc26/metalbear/issues/34)).

It covers the prebuilt tarball install under systemd. A container install has
its own script, `scripts/container-update.sh`, described under
[Container installs](#container-installs). A source build updates with
`git pull` and a rebuild. There is no prebuilt ARMv6 or ARMv7 archive, so a Pi
1 builds from source and the script says so rather than guessing.

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
binaries before 0.44 do not look. `metalbear --version` prints the schema
number on its second line (`schema N`), and `metalbear-update.sh apply` logs
whether a release changes it. The snapshot is still taken for every update,
because a rollback needs one; skipping it when the schema is unchanged is a
separate decision, not yet made.

## Container installs

`scripts/container-update.sh` is the docker counterpart of the systemd updater.
It runs one container, `metalbear` by default, on one named volume, which holds
`/data`. It does the same things in the same order:

- **`snapshot`** stops the container, archives `/data` with the image's own
  `tar`, reads the archive back, and starts the container again. No snapshot,
  no upgrade.
- **`upgrade IMAGE`** takes a snapshot, records the current image and its
  schema, starts `IMAGE`, and waits up to `HEALTH_TIMEOUT` seconds for
  `HEALTH_URL` (`/xrpc/_health`). If the check fails, it empties the volume,
  restores the snapshot, starts the previous image, and checks it again.
- **`rollback [--yes] [IMAGE]`** restores the snapshot taken by the last upgrade
  and starts the previous image, or `IMAGE` if given. **This discards every
  write made since the upgrade.** It asks for confirmation unless `--yes` is
  given, and refuses without `--yes` when there is no terminal to ask on. Before
  it replaces `/data`, it archives the current data as
  `BACKUP_DIR/pre-rollback-<time>.tar` and prints the path, so a rollback that
  was a mistake can be undone by restoring that archive. It refuses when `IMAGE`
  writes an older schema than the snapshot holds, because that build cannot
  read the data.
- **`status`** shows the container's state and the last recorded upgrade.

The script records the previous image by its image ID, not its tag. A tag such
as `:latest` can move when you pull, so a tag cannot say which build the
previous image was. The tag is recorded for display only.

It reads the schema from `metalbear --version` (its second line,
`schema N`), so it needs no database access on the host. It does not stop
the volume from being written by anything else, so stop any other writer
first.

Set `RUN_OPTS` to the options you give `docker run`, minus the name, the volume
and the image, such as `-p 2583:2583` and `-e METALBEAR_SERVICE_DID=…`. The
script recreates the container with them, so a wrong `RUN_OPTS` produces a
container that does not start, and the health check then rolls it back.

The state for `rollback` lives in `BACKUP_DIR/last-upgrade.env`, next to the
archives. Keep both. Losing the state file means `rollback` has nothing to
restore, and the archives are then the only copy.

### What has been tested

On a macOS arm64 host with Docker 29.8.2, against a locally built image and a
throwaway volume, not a published release. The run covered: a snapshot; a
healthy upgrade; an upgrade to an image that listens on the wrong port, which
restored the old image and its data; a status check; a rollback refused by the
schema check (the snapshot's schema was edited to 2 to trigger it, because no
build with schema 2 exists); and a rollback to the recorded image that passed
its health check. It has not run against `ghcr.io` (the script pulls unless
`PULL=0` is set), a real release tag, or bear1. The systemd updater and
`test/update/test_update.sh` are unchanged.

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

# Offline operator commands

Five maintenance commands repair state directly in a stopped MetalBear data
directory: `publish-identity`, `sequencer-recover`, `rebuild-repo`,
`rotate-keys` and `blob-sweep`. They are the shell-era jobs an operator needs
when the daemon is down or when its derived state has drifted; unlike the admin
XRPC endpoints in `metalbear-admin.sh`, none of them talks to a running server.

## Stop first

```sh
sudo systemctl stop metalbear
METALBEAR_DATA=/var/lib/metalbear metalbear-admin sequencer-recover
sudo systemctl start metalbear
```

The wrapper refuses to run if `METALBEAR_HEALTH_URL`
(default `http://127.0.0.1:2583/xrpc/_health`) answers, checks that the data
directory contains `accounts.sqlite3` and `sequencer.sqlite3`, and holds an
exclusive `.maintenance.lock` in that directory for the command's duration.
`rebuild-repo`, `rotate-keys` and a deleting `blob-sweep` also ask for
confirmation unless `--yes` is passed; `blob-sweep --dry-run` does not.
Never remove the lock file while a command is running.

The helper binary `metalbear-maint` is built by CMake and found in `build/` or
any `build-*/` directory. Set `METALBEAR_MAINT_BIN` if it lives elsewhere.
Release tarballs do not ship it yet; build it from a source checkout matching
the running version.

## Commands

### `publish-identity <DID>`

Looks the DID up in the account registry and appends a `#identity` event to the
sequencer. Use it when an account exists on disk and resolves its handle, but
consumers never learned about it because the original event was lost. It does
not contact PLC or publish a DID document.

### `sequencer-recover`

Walks every registered account, heals a missing `#account` tail event, emits a
`#sync` when the repo head is newer than the last event, and sequences an
`#identity` event. It is the offline equivalent of the reconciliation the
server runs at startup, so it is safe to repeat: a no-op run adds nothing.

### `rebuild-repo <DID>`

Verifies the current head commit against the repo's signing key, then rebuilds
the derived record and blob SQL indexes by walking the head's MST. The commit
and its blocks are unchanged. This repairs a corrupted index after a crash or
a direct block-store repair; it does **not** reconstruct a damaged MST from
records. A head that fails verification is refused.

### `rotate-keys <DID...>`

Publishes each account's **existing** repo signing key as the `#atproto`
verification method in its did:plc document, copies every other field of the
last operation forward, and sequences an `#identity` event. This matches the
reference PDS script: it repairs a DID document that advertises the wrong key
without changing the key that signs commits. Minting a new repo key would need
a repo-head rewrite API and is deliberately not attempted here.

`did:web` accounts need no PLC operation. `did:plc` accounts need the host's
rotation key from `<data>/server_keys.sqlite3` and a reachable directory:

```sh
METALBEAR_DATA=/var/lib/metalbear METALBEAR_PLC_URL=https://plc.directory \
  metalbear-admin rotate-keys --yes did:plc:abc123
```

The `--yes` flag is consumed by the wrapper, which forwards `--plc-url` to the
helper. Calling `metalbear-maintenance.sh --yes --plc-url URL rotate-keys
DID...` directly is equivalent.

### `blob-sweep [--dry-run]`

Deletes expired temporary uploads and durable blobs whose last record revision
is gone, across every account in the data directory. Start with `--dry-run`,
which reports what would happen without deleting anything:

```sh
METALBEAR_DATA=/var/lib/metalbear \
  metalbear-maintenance.sh blob-sweep --dry-run
```

The summary line includes the account count, temporary counts and bytes,
expiring copies, unreferenced durables, deletions and pruned references. The
temporary window comes from `limits.blob_temp_seconds` /
`METALBEAR_BLOB_TEMP_SECONDS` (default 86400). See
[blob-lifecycle.md](blob-lifecycle.md) for the state model and the `/metrics`
gauges.

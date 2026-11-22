# Moving an account to another PDS

MetalBear can export a whole account as one portable archive, so moving to
another PDS is a single command instead of hand-assembling a repo CAR, a blob
list and a series of blob downloads.

## Exporting

Use the admin CLI on the PDS that currently holds the account:

```sh
metalbear-admin export-account did:plc:abc123 alice.tar
```

The command writes a plain `ustar` archive. You can list or extract it with
any `tar`:

```sh
tar -tf alice.tar
tar -xf alice.tar
```

The archive contains:

| Entry | What it is |
|---|---|
| `manifest.json` | The account's DID, handle, effective `#atproto` signing key, indexed time, and the blob list |
| `repo.car` | The same CAR that `com.atproto.sync.getRepo` returns |
| `blobs/<cid>` | Each blob, keyed by its CID, with its MIME type recorded in the manifest |

The signing key in the manifest is the one the account's DID document currently
publishes. Keep the archive somewhere safe: it contains the account's posts
and media in full.

The same export is available over XRPC as
`com.atproto.temp.exportAccountBundle` (a query taking `did`), gated by the
same Basic admin credential as the other `com.atproto.admin.*` routes. It
returns `application/x-tar`. The `temp` namespace is deliberate: the wire
format needs no lexicon and is not a proposal to standardise one.

## Importing

The archive is shaped so an importer can use the ordinary AT Protocol repo
routes, with no MetalBear-specific steps:

1. Create the destination account with the same DID from `manifest.json`,
   passing the DID to `com.atproto.server.createAccount`. This is the
   bootstrap case where the DID document still points at the old host's
   signing key; keep that key published until the import completes.
2. Feed `repo.car` to `com.atproto.repo.importRepo` with content type
   `application/vnd.ipld.car`.
3. Re-upload each `blobs/<cid>` with `com.atproto.repo.uploadBlob`, using the
   `mimeType` from the manifest. Blobs are content-addressed, so the CID is
   reproduced and the repo's existing references keep resolving.
4. Once the data is in place, publish the new host's signing key and PDS
   endpoint in the DID document, then complete the move through the usual
   identity flow.

> **Bootstrap caveat:** `com.atproto.server.createAccount` only accepts a
> caller-supplied real DID when the request authenticates as that DID. A fresh
> destination has no account or token for it, so its public route cannot
> complete step 1 by itself; a production import needs an authenticated
> provisioning or entryway step. The test suite uses the `did:example:` seam to
> exercise the archive format without that bootstrap.

The bundle is assembled in memory and the XRPC layer copies it once more when
writing the response, so an account with very large blobs needs roughly twice
the bundle size in free memory on the exporting host. Use the CLI for large
accounts where that matters less; the direct archive write avoids the extra
copy.

# MetalBear as a labeler

Decision, recorded for [#117](https://github.com/ewanc26/metalbear/issues/117): MetalBear
hosts a labeler for its own accounts. It does not run a moderation service and it does
not carry other labelers' labels.

## What it does

- **Stores one label per account takedown.** An account takedown applied through
  `com.atproto.admin.updateSubjectStatus` writes a `!takedown` label, with the account's DID
  as the subject and the server's service DID as the source. Lifting the takedown writes the
  same label with `neg: true`. Record and blob takedowns write nothing, because they are not
  account labels.
- **Serves `com.atproto.label.queryLabels`** from that store. The query is public, as it is
  in the protocol, and it takes the lexicon's filters:
  - `uriPatterns` (required, repeatable): an exact URI or a prefix ending in `*`.
  - `sources` (repeatable): keep only labels from the named labeler DIDs.
  - `limit` (1 to 250, default 50) and `cursor`. A page that has more labels returns the id
    of its last label as `cursor`.
- **Keeps the store in `labels.sqlite3`** beside the other databases in the data directory.
  The store records its schema version like the rest.

The lexicon has no date filter, so the "date" the issue asked for is not in the query. The
store orders by insert order, and `cts` is the time the label was written.

## What it does not do

- **Subscribe to other labelers.** The issue suggested subscribing to `subscribeLabels` for
  labelers the owner trusts. That needs a trusted list the owner has not supplied, so it is
  not built. Until it is, a query returns only this server's own labels.
- **Sign labels.** The store writes labels without a `sig`. The lexicon makes `sig` optional,
  and Wolfram has no label-signing function yet. Clients that verify label signatures will
  not trust these labels. Signing with the service key is the next step, and it needs test
  vectors for the label encoding before it can be claimed.
- **Write labels other than `!takedown`.** There is no label-creation route. The only writer
  is the takedown path.

## Where it lives

- `include/metalbear/label/label_store.h`, `src/label/label_store.c`: the store.
- `include/metalbear/label/labels_routes.h`, `src/label/labels_routes.c`: the query route,
  including the parsing that reads repeated parameters from the raw query string.
- `src/admin/admin_routes.c`: the takedown writer.
- `src/server_auth.c`: `com.atproto.label.queryLabels` is on the public list.

## How it was checked

- `test/test_label_store.c` covers exact and prefix patterns, the source filter (including an
  empty list), pagination with a cursor, negation, a pattern carrying SQL, and a reopen.
- `test/test_takedown.c` checks the label after a takedown and after it is lifted, through
  the real admin route and the real query route.
- `test/test_server.c` checks that an unknown subject returns an empty list with a 200.
- Parameter handling was checked over HTTP against a running server: repeated
  `uriPatterns`, percent-encoded values, and invalid `limit`, `cursor` and empty values
  (each 400 `InvalidRequest`).

No check here covers signing, subscribing to another labeler, or the AppView side.

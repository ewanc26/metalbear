# Account deactivation and deletion

MetalBear distinguishes two steps in account removal, mirroring the reference
PDS: **deactivation** takes the account offline while keeping its repository and
blobs, and **deletion** removes it for good.

## Deactivation

`com.atproto.server.deactivateAccount` sets the account inactive, records a
`deactivated_at` timestamp in the per-account `account.sqlite3`, and emits a
`deactivated` `#account` event. The repository stays on disk, so reactivating
with `com.atproto.server.activateAccount` restores it exactly. The timestamp is
written by the store itself: an operator cannot backdate it through XRPC.

## Scheduled hard deletion

A deactivated account is *not* removed immediately. When
`accounts.deletion_hold_seconds` is set to a positive value, a background sweep
checks the registry on a timer and hard-deletes any account whose deactivation
timestamp is at least that many seconds old. The key maps to
`METALBEAR_DELETION_HOLD_SECONDS` as a runtime override; the environment value
wins over the config file, and negative values are refused at startup.

`0` (the default) leaves the sweep off: deactivated accounts stay on disk until
an operator deletes them by hand. This is deliberate — a mistaken deactivation
is recoverable, a sweep is not.

The hold is measured from `deactivated_at`, never from account creation, and a
clock that jumps backwards cannot shorten it. Accounts whose store has no
deactivation timestamp (for example, one written by an older build that was
deactivated before the field existed) are left alone rather than guessed at.

The deletion itself uses the same code path as `com.atproto.server.deleteAccount`
and `com.atproto.admin.deleteAccount`:

1. a `deleted` `#account` event is sequenced on the host firehose *before* any
   state is removed, so consumers that never saw the account created still
   learn it is gone;
2. the account's earlier history is purged from the sequencer, keeping only that
   final announcement;
3. the registry row and every moderation takedown for the DID are removed;
4. the handle's published DNS record is retracted; and
5. the account's data directory is deleted.

Because the announcement uses the host log rather than a resolved account
context, it is emitted even for accounts nobody has touched since deactivation.

## Visibility

`com.atproto.admin.getSubjectStatus` reports `deactivatedAt` for a deactivated
account. The public `com.atproto.server.checkAccountStatus` lexicon has no field
for a pending-deletion time, so it reports only `activated: false`; clients
should not infer a deletion deadline from it.

## Storage migration

The deactivation columns were added in schema version 4. On open, an older
account database gains `deactivated_at` and `delete_after` columns
idempotently; the binary refuses a database written by a newer schema version.
See `CHANGELOG.md` for the version history.

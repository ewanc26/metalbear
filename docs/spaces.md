# AT Protocol Spaces: where they would land in MetalBear

This is a design note for [#47](https://github.com/ewanc26/metalbear/issues/47),
not a plan of record. Spaces are an alpha upstream: breaking changes
are still landing, the permissioned-data proposal is still a proposal, and
Wolfram has not implemented them ([wolfram#35](https://github.com/ewanc26/wolfram/issues/35)).
Nothing here defines an API, a route or a schema. The note exists so that when
the gate in #47 opens I am not starting from a blank page, and so that nothing
I build in the meantime makes Spaces harder to add.

What I know about the design comes from the sources linked in #47 and
wolfram#35, as summarised there on 2026-09-16: `com.atproto.space.*` routes,
permissioned repositories, space authorities, space credentials over DPoP,
per-space sync, membership with separate read and write policies, and
non-public blobs. It is access control, not end-to-end encryption.

## The rule

Wolfram owns the protocol: lexicons, Space URIs and references, credential and
DPoP verification, CAR and sync framing. MetalBear owns what a PDS has to
decide and remember: who may read and write, where the data lives, and what is
served to whom. If a piece of Spaces logic would be useful to a client, it
belongs in Wolfram, and `tools/check-drift.sh` already refuses new local
copies of Wolfram primitives.

## Where each piece would touch the code today

| Spaces concept | Today's MetalBear code | What changes |
| --- | --- | --- |
| Permissioned repository | One `repo.sqlite3` per account, opened through `src/account/account_context.c` and bounded by the resident-account cache | A space repository is a second kind of repository. It needs its own store and its own place in the cache budget, which matters on a Pi ([#34](https://github.com/ewanc26/metalbear/issues/34)). |
| Membership, read and write policy | Nothing equivalent; access today is "the account owner, or public" | New persistent state and the enforcement point every space route goes through. This is the security-sensitive part and gets tests before anything else. |
| Space credentials, DPoP | OAuth and DPoP live in `src/oauth/`, with Wolfram verifying DPoP proofs | Verification from Wolfram; the decision about what a valid credential allows stays in MetalBear. |
| Scopes | `src/oauth/oauth_scope.c`, which validates NSIDs with Wolfram since #59 | Whatever scope grammar upstream settles on, parsed the same way. |
| Non-public blobs | `com.atproto.sync.getBlob` is in `is_public_route` in `src/server.c`, and the blob store serves by CID | A blob in a space must never be reachable by the public `getBlob` route. That needs a membership check before the store is asked, and a regression test that tries the public path. |
| Per-space sync | One sequencer and one `subscribeRepos` stream for public commits (`src/sequencer.c`) | Space commits must not appear on the public firehose. Per-space sync is a separate stream or endpoint, framed by Wolfram. |
| Repo-host registration | Crawl requests to relays from the sequencer path | Follows whatever the final specification says; upstream's own alpha disagrees with its proposal here (linked from wolfram#35). |
| Migrations | Startup migrations with no schema version ([#56](https://github.com/ewanc26/metalbear/issues/56)) | Spaces will add tables. I want #56 settled first, so an older binary refuses a database that has them instead of misreading it. |

## Before the gate, what is safe to do

- Keep public and private paths separate in new code. A blob or record route
  added now should take its access decision in one place, so a space check can
  slot in front of it later.
- Settle #56, since Spaces will need schema changes that an older binary must
  refuse.
- Keep the minimal profile building (#62), so Spaces can be a module that a
  Pi build leaves out.

Prototyping against the alpha is fine on a branch, and it is thrown away
when it is done.

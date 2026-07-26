# MetalBear agent guidance

MetalBear is a pure C11 AT Protocol PDS built on the sibling Wolfram SDK. It provides a runnable PDS foundation, supporting multi-account hosting.

## Read first and architecture

- `/Volumes/Storage/Developer/Local/atproto` is the protocol and PDS behavior authority. Inspect its lexicons and PDS implementation before changing endpoint semantics.
- `src/server.c` is the central file: server lifecycle, XRPC route registration, auth callback, and all protocol handler functions.
- `src/account.c` manages credential storage, app passwords, email tokens, and account state (active/deactivated) in a per-account SQLite database.
- `src/auth.c` manages session tokens (access/refresh JWTs) with scrypt-hashed refresh tokens and scope-based access control.
- `src/sequencer.c` handles the firehose event stream (commits, identity, account, sync events) with configurable retention.
- `src/account_registry.c` is the multi-account registry, mapping account DIDs to their respective data directory paths.
- `src/email.c` is the optional SMTP email client using libcurl.
- `src/backup.c` implements repository backup/restore with CRC32 checksums.
- `src/oauth.c` handles OAuth 2.0 token endpoints.
- `src/key_rotation.c` manages P-256 signing key rotation.
- `include/metalbear/` contains all public headers.

## Reuse and safety

- Reuse Wolfram primitives and server infrastructure. Do not copy Wolfram code into this repository or hand-roll cryptography.
- Keep authentication, repository ownership, persistence, and protocol errors explicit. Never return fabricated success for an unfinished endpoint.
- Never commit secrets, live credentials, signing keys, or PDS data.

## Endpoint correctness

- Every endpoint's input/output schema must match its lexicon definition from
  `/Volumes/Storage/Developer/Local/atproto`. Use the exact field names, required
  fields, and error codes specified in the lexicon, not ad-hoc alternatives.
- Session responses (`createSession`, `refreshSession`, `createAccount`) must
  include `email` and `emailConfirmed` fields when email is configured.
- Error codes must use lexicon-defined names (e.g. `InvalidHandle`,
  `HandleNotAvailable`, `ExpiredToken`) rather than generic names like
  `InvalidRequest` or `InternalError`. Equally, do not invent names that merely
  sound official: the `com.atproto.repo` write endpoints declare only
  `InvalidSwap`, and the reference reports every other failure as plain
  `InvalidRequest` with a descriptive message. Read the lexicon's `errors`
  array and the reference handler before choosing a name — an invented one is
  as unusable to a client as a generic one, and harder to spot.
- The precision belongs in the message when the name is generic: `Invalid
  record key: <rkey>`, `Invalid $type: expected <x>, got <y>`, `Too many
  writes. Max: 200`.
- Records must be validated against the lexicon corpus on write. A collection
  with no schema is `validationStatus: "unknown"` and still stored; a
  collection with a schema that the record violates is rejected. Never store a
  record that fails a schema you have.
- Auth callback must check `is_public_route` before DID ownership validation,
  since public route bodies may contain DIDs being created/registered, not
  accessed.
- Query-string parameters arrive as JSON **strings**, never numbers or bools —
  there is no lexicon at the HTTP layer to coerce them. Read them with
  `query_param_int` / `query_param_bool`; a bare `cJSON_IsNumber` or
  `cJSON_IsTrue` test silently discards every value a client sends and falls
  back to the default.
- Closed unions in a response (e.g. `applyWrites` results) must carry the
  `$type` that discriminates each member, or a strict client rejects the whole
  payload.

## The firehose is the only thing the network actually sees

Reads can be perfect while a PDS is invisible. Every federation bug found so
far looked healthy from the outside: records stored, getRepo serving, commits
verifying, and nothing reaching a relay. Check the wire, not the API.

- **subscribeRepos is one stream for the host**, not per account. It is served
  from the server's sequencer at the data root. Anything that publishes
  elsewhere is invisible however correctly it is recorded.
- **Every account context must publish into that sequencer.** It is wired in
  `metalbear_account_context_open` so it cannot be forgotten; wiring it at a
  call site once meant only the primary account ever federated.
- **CID links are DAG-CBOR**: tag 42 wrapping a byte string whose first byte is
  `0x00`. Our decoder tolerantly skips leading zeros, so a frame written
  without the prefix round-trips through our own tests perfectly and is
  rejected outright by every strict reader. Assert on encoded bytes, not
  round-trips.
- **Sequence numbers must never restart.** Cursors are per-host and consumers
  persist them; a log that restarts at 1 hands out numbers already used and
  wedges every consumer on FutureCursor. A fresh log is seeded above any value
  the host could have issued.
- **A quiet PDS must announce itself.** Relays are told about new data via
  requestCrawl to `METALBEAR_CRAWLERS`, throttled to 20 minutes.
- When diagnosing, capture a `#commit` from `bsky.network` and one from the PDS
  and compare them field by field. That is what found the missing CID prefix
  after a great deal of guessing did not.
- `tools/firehose_probe.py <host>` subscribes over the public ingress and
  checks the frames a strict reader would reject. Like `verify_repo_car.py` it
  is stdlib-only and shares no code with Wolfram — verifying our encoder with
  our encoder proves nothing. Run it against the live host, not localhost: it
  exercises the whole path a relay uses, TLS and proxy included.

## Multi-account, with no privileged account

The "bootstrap" account is just the one named in configuration. It is not *the*
account, and nothing server-wide should reach through it — that assumption
produced a deleteAccount that destroyed the wrong account, password resets that
only ever worked for one, and a firehose that served one account's log.
Resolve the account a request acts on; never substitute the configured one.

## Identity: the signing key is the interop contract

The single defect that makes a repo unfederatable is a DID document that
advertises a signing key the repo does not sign with. Relays and AppViews
reject such commits outright while the PDS reports success, so nothing surfaces
it locally.

- Whenever this server publishes a DID document (bootstrap minting, PLC
  operations, `createAccount`), the key it publishes must be the key the repo
  store actually holds. Pass it explicitly via
  `metalbear_repo_store_open_with_key` /
  `metalbear_account_context_open_with_key`; never let the repo generate its
  own key after a document naming a different one has been published.
- `didDoc` in any response is a **W3C DID document**: `verificationMethod` is
  an array of Multikey entries keyed `<did>#atproto`. The `verificationMethods`
  object map belongs only to unsigned PLC *operations*. Build documents with
  `metalbear_did_document_build`.
- `checkAccountStatus.validDid` and `describeRepo.handleIsCorrect` are
  answers about the outside world; resolve the published document over the
  network rather than reporting what this server believes.

## Repo writes

- `applyWrites` is atomic and produces exactly ONE signed commit and ONE
  firehose `#commit` event listing every op. Use `wf_repo_apply_writes`; do not
  loop over the single-record functions.
- A record's CID covers its content only, so two records can legitimately share
  one block. Deduplicate the block, never the MST entry.
- Compare-and-swap failures return `WF_ERR_CONFLICT` and must surface as the
  lexicon's `InvalidSwap`, which clients branch on to retry an optimistic
  write. Deleting an absent record is a no-op success, not a 404.

## Validation

- Run `cmake -S . -B build && cmake --build build && ctest --test-dir build
  --output-on-failure` before declaring a slice done.
- Every server route must have an offline end-to-end test in `test/test_server.c`
  or a dedicated test file covering success, auth failure, and schema conformance.
- Test cleanup must remove all SQLite files (repo, auth, account, sequence,
  registry) plus blob directories.
- A green local suite does not prove federation. For identity or repo-format
  changes, verify against the live dev PDS at `/Volumes/Storage/Server/bear`:
  export the repo with `com.atproto.sync.getRepo` and check the commit
  signature against the key published in the PLC directory, using something
  other than Wolfram — verifying wolfram's output with wolfram proves nothing.

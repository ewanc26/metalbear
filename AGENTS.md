# MetalBear agent guidance

MetalBear is a C23-first AT Protocol PDS built on the sibling Wolfram SDK.

The project is implemented primarily in C23. C++ is permitted for complex or sensitive components where C is insufficient — specifically RAII-based resource management (e.g. sqlite3, OpenSSL), performance-critical code, and third-party library integrations that have no C equivalent. All C++ usage must follow strict isolation via `extern "C"` modules. Public headers, exported APIs, protocol handlers, and the core server architecture remain C23. C++ components must expose a C ABI (`extern "C"` where required), and exceptions must never cross the C/C++ boundary. Default to C for new code; introduce C++ only when the complexity, resource management, or performance requirements justify it.

It provides a runnable PDS foundation, supporting multi-account hosting.

## Read first and architecture

- `/Volumes/Storage/Developer/Local/atproto` is the protocol and PDS behavior authority. Inspect its lexicons and PDS implementation before changing endpoint semantics.
- <https://atproto.com> is the normative specification, and says things the
  reference source does not spell out — the sync spec's requirements on `rev`
  ordering, clock-drift rejection, `prevData` chain verification and what a
  consuming relay may reject are stated there and nowhere in the TypeScript.
  Read <https://atproto.com/specs/sync> before touching the firehose, and the
  relevant `specs/` page before any wire-format change. Where the two appear
  to disagree, the lexicons and reference implementation win for behaviour,
  but the spec is what other implementations were written against.
- `src/server.c` is the central file: server lifecycle
  (`metalbear_server_create`/`_start`), XRPC route registration, and the auth
  callback. Most protocol handlers have moved out into per-domain route
  files it registers against — see "File organization" below;
  `src/server_internal.h` is the private header those files and server.c
  share.
- `src/admin/admin_routes.c` — `com.atproto.admin.*` handlers.
- `src/identity/identity_routes.c` — `com.atproto.identity.*` handlers, DID
  document resolution/caching, and the PLC operation flow.
- `src/oauth/oauth_credentials.c` — the `metalbear_oauth_subject_resolver` /
  `metalbear_oauth_credential_verifier` callbacks `/oauth/authorize` uses to
  resolve and verify a `login_hint` against a local account.
- `src/session/session_routes.c` — `com.atproto.server.{create,get,refresh,delete}Session`
  and app-password handlers.
- `src/account/account_routes.c` — `createAccount`, email
  confirmation/update, password reset, invite codes, `checkAccountStatus`,
  `reserveSigningKey`.
- `src/sync/sync_routes.c` — every `com.atproto.sync.*` handler
  (`getRepo`, `getBlocks`, `getRepoStatus`, `listBlobs`, `getRecord`,
  `getBlob`, `listRepos`, `listReposByCollection`, `getHead`, `getCheckout`)
  plus `requestCrawl`.
- `src/appview/appview_routes.c` — the `app.bsky.*`/`chat.bsky.*` AppView
  reverse-proxy plumbing and its ~30 thin per-lexicon wrappers, plus the
  generic fallback proxy for unmatched NSIDs.
- `src/moderation/moderation_routes.c` — `com.atproto.moderation.createReport`.
- `cpp/metalbear/account.cpp` manages credential storage, app passwords, email tokens, and account state (active/deactivated) in a per-account SQLite database. Migrated from C to C++17 with RAII for the sqlite3 handle; the public C ABI is preserved via `extern "C"`.
- `src/oauth/auth.c` manages session tokens (access/refresh JWTs) with scrypt-hashed refresh tokens and scope-based access control.
- `src/sequencer.c` handles the firehose event stream (commits, identity, account, sync events) with configurable retention.
- `cpp/metalbear/account_registry.cpp` manages the multi-account registry, mapping account DIDs to their respective data directory paths. Migrated from C to C++17 with RAII for the sqlite3 handle; the public C ABI is preserved via `extern "C"`.
- `src/email.c` is the optional SMTP email client using libcurl.
- `src/repo/backup.c` implements repository backup/restore with CRC32 checksums.
- `src/oauth/oauth.c` handles OAuth 2.0 token endpoints.
- `src/oauth/oauth_scope.c` implements OAuth auth scope parsing and matching for AT Protocol granular permissions. Parses static scopes (`atproto`, `transition:*`) and dynamic repo scopes (`repo:<collection>?action=<action>`). Integrated with the authentication callback in `server.c` to enforce scope-based access control on repo write operations.
- `src/repo/repo_store.c` is the durable, writable repo storage engine
  (CBOR<->JSON, MST/commit persistence, the `metalbear_repo_store_*` public
  CRUD API). `src/repo/repo_routes.c` is its `com.atproto.repo.*` XRPC
  handlers (`createRecord`, `putRecord`, `applyWrites`, `importRepo`, etc.) —
  these reach into the engine's internals as directly as the engine itself
  does (`h_import_repo` manipulates the CAR/head/signing key while replaying
  an import), sharing `src/repo/repo_store_internal.h`. `src/repo/did_document.c`
  builds W3C DID documents and is fully self-contained. `src/repo/blob_store.c`
  / `src/repo/blob_store_server.c` are the blob persistence layer and its routes.
- `src/account/account_context.c` / `src/account/account_cache.c` resolve and cache the per-request account context (DID, repo, auth) route handlers share.
- `src/dns/handle_dns.c` / `src/dns/handle_dns_rfc2136.c` publish the `_atproto` handle-resolution TXT records (static zone file and RFC 2136 dynamic update, respectively).
- `src/moderation/report.c` is the SQLite-backed report store; `src/moderation/moderation_routes.c` is its `createReport` handler.
- `src/ops/metrics.c` / `src/ops/update_watcher.c` back `GET /metrics` and the self-update checker.
- `cpp/metalbear/key_rotation.cpp` manages P-256 signing key rotation. Migrated from C to C++17 with RAII for the sqlite3 handle; the public C ABI is preserved via `extern "C"`.
- `include/metalbear/` contains all public headers.

## File organization

Every file deals with one part of a scope — one XRPC lexicon domain, one
subsystem, one storage engine. `server.c` at 8619 lines used to hold nearly
every protocol handler in the codebase; it and `repo_store.c` were split
along these lines, and the same standard applies to new code and to the
next oversized file found, not just the ones already done.

- **Domain-scoped route files**: XRPC handlers for one lexicon namespace
  (or one clearly-bounded cluster within a namespace, e.g. `sync_routes.c`
  covering `com.atproto.sync.*`) live in their own `src/<domain>/<domain>_routes.c`,
  declared via a matching `.h` in the same directory. `server.c` includes
  that header and registers the handlers; it does not define them.
- **Internal headers share what the public API must not expose.** A struct
  that is opaque in `include/metalbear/*.h` for external consumers (e.g.
  `metalbear_server`, `metalbear_repo_store`) sometimes has fields several
  files within the module need directly — route handlers reading
  `server->public_url`, `h_import_repo` manipulating the repo store's CAR
  and head directly. The real definition and any cross-cutting helper
  functions those files call go in a private `<module>_internal.h`
  (`server_internal.h`, `repo_store_internal.h`) next to the files that
  share it — never duplicated per file, never added to the public header.
  A function only needs exposing here if something outside its own file
  calls it; keep everything else `static`.
- **The public header doesn't move.** Splitting an implementation file does
  not change `include/metalbear/*.h` — every function declared there keeps
  its existing declaration, so external callers (including cross-file calls
  within this same repo, like `server.c` calling
  `metalbear_xrpc_server_register_pds_repo_resolver_ex`) need no changes.
- **A cluster carved out of a larger block stays in its own domain even
  when its neighbors don't.** `resolve_oauth_subject`/`verify_oauth_credential`
  sat inside what was otherwise the identity cluster in `server.c`, but they
  are OAuth login-credential callbacks (`metalbear_oauth_subject_resolver` /
  `_credential_verifier`), not DID/identity XRPC handlers — they moved to
  `src/oauth/` instead of riding along with `src/identity/`. Physical
  proximity in the original file is not a reason to keep unrelated things
  together; check what a function's callers actually are before deciding
  where it belongs.
- **One extraction, one commit, verified before the next.** Each split is
  its own `refactor:` commit: full clean rebuild, full `ctest` run,
  `clang-format` on the touched files (re-run build + tests after
  formatting — a reflow can shift a multi-line signature's continuation
  indent without changing behavior, but confirm it didn't), push, and a
  green CI run before starting the next file. Don't stack unverified splits.
- **Size alone doesn't mandate a split.** A large file that genuinely deals
  with one scope — one lexicon namespace with a lot of surface area, one
  cohesive subsystem — is not automatically a violation. Look for actual
  domain mixing (a session handler and a moderation handler in the same
  file) before deciding a file needs dividing, not just a line count.

## Commits

- **Atomic conventional commits**: one logical change per commit, scoped by
  module — `feat(server)`, `fix(sequencer)`, `docs(agents)`. Never mix
  unrelated changes; in particular do not combine a code change with a docs
  update. Split into sequential commits instead.
- **No AI co-authors**: do not add a `Co-authored-by:` trailer crediting an AI
  agent. AI assistance is welcome; credit for committed work goes to human
  authors only. Omit the trailer entirely.

Matches the sibling Wolfram repository's convention, so the two histories read
the same way.

## Versioning

- **Tag every version bump**: a commit that changes `VERSION` in
  `CMakeLists.txt` must also create a signed annotated git tag on that commit:
  `git tag -s v<major>.<minor>.<patch> -m "v<major>.<minor>.<patch>"` (use `-s`
  when a signing key is available, otherwise `-a`). Push tags with
  `git push --tags`.
- **Bump in the same commit**: the version change and the tag must refer to the
  same commit — no separate bump commit without a tag.
- **Create a GitHub release for every version bump**: after tagging, create a
  release via `gh release create v<major>.<minor>.<patch> --title "v<major>.<minor>.<patch>" --generate-notes` (the tag is named by that single positional; a second positional would be treated as an upload file). The release must be created in the same commit as the tag — no separate release without a tag.
- **Version independently**: MetalBear and Wolfram are sibling projects, not a
  single release unit. Bump each on its own history and let their versions
  drift; there is no requirement that they share a version string or release
  together.
- **No version jumps**: bump from the immediately previous released version.
  Never skip a patch, minor, or major number; do not backfill gaps with
  phantom tags or releases.
- **Attach binaries starting at 1.0.0**: releases before 1.0.0 are source-only
  (`gh release create` with no upload). From the 1.0.0 release onward, every
  release must also attach built binaries as release assets (e.g. `gh release
  upload v<major>.<minor>.<patch> <path>...`) — built via the same flow as
  local verification (`cmake --build build`), for each platform the project
  ships prebuilt artifacts for.

## Release and redeploy

A shipped feature runs one flow end to end. Skipping a step is how a page
stays stale or a daemon rebuilds the same state twice.

1. **Verify locally**: `cmake -S . -B build && cmake --build build && ctest
   --test-dir build --output-on-failure`. When the landing page or another
   `frontend/` surface changed, also rebuild the frontend with `npm run build`
   in `frontend/`.
2. **Commit and version**: land the feature as its own atomic conventional
   commit, then a `version: bump to x.y.z` commit changing `VERSION` in
   `CMakeLists.txt`. Tag that commit (`git tag -s vx.y.z -m "vx.y.z"`), push
   `main` and the tag, and create the GitHub release in the same commit as the
   tag — no bump without a tag, no release without one.
3. **Deploy to bear1.croft.click**: `docker compose build bear-pds && docker
   compose up -d bear-pds` in `/Volumes/Storage/Server/bear`. When the
   frontend changed, copy the fresh `frontend/build/` over
   `/Volumes/Storage/Server/stack/nginx/bear1-site` (nginx serves it read-only
   from a bind mount, so no restart is needed). Finally write the deployed
   commit pair to `.last-build-commit` as `<metalbear HEAD>:<wolfram HEAD>` —
   the daemon at `/Volumes/Storage/Server/stack/server-daemon.sh` rebuilds
   whenever that marker differs from the checkouts' current HEADs, so syncing
   it is what stops a duplicate build. Verify on the public ingress, not
   localhost: `curl https://bear1.croft.click/xrpc/_health` for the version,
   `/_debug/health` (admin-gated) for the debug dump.

## The landing page is two pages

`GET /` on the PDS port serves `landing_handler`'s static HTML and is almost
never seen. The public page at bear1.croft.click is the SvelteKit frontend in
`frontend/`, prerendered to `build/` and copied to
`/Volumes/Storage/Server/stack/nginx/bear1-site`; nginx serves only
`index.html`, `_app/` and `robots.txt` statically and falls every other path
through to the PDS. The page reads what it displays from the server at request
time, so anything it shows must come from a public endpoint a browser can
fetch — `operator.json` carries `software.version` and `software.wolframVersion`
for exactly that reason. A version added only to `landing_handler` is invisible
on the public site, and a rebuilt frontend is not a redeployed container: the
server still has to be rebuilt with the matching `operator.json` change.

## Reuse and safety

- Reuse Wolfram primitives and server infrastructure. Do not copy Wolfram code into this repository or hand-roll cryptography.
- **Libraries first, hand-rolling last**: before writing any algorithm, encoding, hash, or cryptographic operation from scratch, prefer an established, maintained library — reuse Wolfram primitives first, then third-party libraries (SQLite, OpenSSL, libcurl, libmicrohttpd, cJSON). This is a strict policy: hand-rolling is the last resort, used only where no suitable library exists, and then isolated behind a single wrapper with a comment recording what was considered and why. Never hand-roll cryptography, hashing, base64url, canonical DAG-CBOR, JWT, or TLS. Verify a candidate library actually exists and links on the target (pkg-config, CMake `find_package`) before designing around it; never assume a library is available.
- **Prefer C++ where it is beneficial**: RAII-based resource management (e.g. sqlite3, OpenSSL), performance-critical code, and third-party library integrations with no C equivalent. Use C++ rather than error-prone manual-cleanup C where it is clearly safer; default to C otherwise. Always use `extern "C"` for any wrapper so the rest of the codebase can consume it without C++ headers or types. Where a C library equivalent exists, prefer the C one.
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
  call site once meant only one account ever federated.
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
- **Account lifecycle events belong on the host log, not a context.** Opening
  an account context without the server's sequencer gives it a private log
  that nothing reads, so creation events vanish and the network's first sight
  of a DID is a bare `#commit`. Sequence lifecycle events against
  `server->sequencer` directly: resolving a context first also means the event
  is skipped whenever the account is not cached, which is how deleteAccount
  came to announce nothing.
- **`#sync` carries the commit block, not the repo.** The lexicon caps
  `blocks` at 10000 bytes. Use `metalbear_repo_store_export_commit`; the
  full-repo export grows with the account and silently passes the limit, so a
  validating relay drops the event on exactly the accounts big enough to need
  it.
- **Frames must be canonical DAG-CBOR.** Three defects of this kind each made
  the PDS unfederatable while every test passed, because our decoder tolerates
  exactly what the encoder got wrong: CID links missing the `0x00` multibase
  prefix, map keys out of canonical order, and integers encoded wider than
  necessary. The last blocked federation for days — every integer was built at
  64 bits, so the frame header's `op: 1` took eight bytes where one is
  canonical, and a strict consumer failed on the header and dropped the
  connection before reading a single event. From outside that is
  indistinguishable from a relay refusing to talk to you.
- When diagnosing, capture a `#commit` from `bsky.network` and one from the PDS
  and compare them field by field **and byte by byte**. That is what found all
  three, after a great deal of guessing did not.
- **A relay that connects and leaves is not a relay that never came.** indigo
  logs a validation failure and advances its cursor anyway, so a cursor stuck
  at `-1` means the frame never decoded — not that it decoded and was
  rejected. That distinction rules out every semantic check at once and points
  straight at the encoding. Read the consumer's source before theorising.
- Measurements need checking before conclusions do. "No requests from the
  relay" was drawn from a log grep that could never have matched, because
  traffic arrives through a tunnel and nginx logs the tunnel's address.
- `tools/firehose_probe.cpp <host>` subscribes over the public ingress and
  checks the frames a strict reader would reject. Like `verify_repo_car.cpp` it
  is stdlib-only and shares no code with Wolfram — verifying our encoder with
  our encoder proves nothing. Run it against the live host, not localhost: it
  exercises the whole path a relay uses, TLS and proxy included.

## Multi-account, with no privileged account

There is no bootstrap account, and configuration names no account at all. A
host exists before its first user; accounts arrive through
`com.atproto.server.createAccount`, gated by invite codes unless
`METALBEAR_INVITE_REQUIRED=false`. Admin endpoints authenticate with HTTP Basic
against `METALBEAR_ADMIN_PASSWORD` and belong to no account.

Anything server-wide belongs to the server, not to an account:

- **PLC rotation key** — `server->plc_rotation` at `server_keys.sqlite3`,
  seeded from `METALBEAR_PLC_ROTATION_KEY` when set and generated once
  otherwise. It signs the genesis operation for every DID this host mints. A
  configured key that cannot be adopted is fatal at startup: silently
  substituting a generated one makes every DID minted afterwards
  unrecoverable with the operator's real key.
- **OAuth store** — `server->oauth` at `server_oauth.sqlite3`, one signing key
  for the host. The account a token speaks for is recorded on the grant and
  carried in the token's `sub`, never bound into the store. `login_hint`
  names the account being authorized and is required, because with no default
  identity a missing hint would otherwise hand the client somebody else's
  session.
- **The firehose log** — one per host at the data root.

Resolve the account a request acts on, every time. Reaching through a
configured account produced a deleteAccount that destroyed the wrong account,
password resets that only ever worked for one, a firehose that served one
account's log, public reads gated on an unrelated account's active flag, and
`/.well-known/atproto-did` answering every unknown hostname with one account's
identity — a wrong answer rather than a missing one.

## Identity: the signing key is the interop contract

The single defect that makes a repo unfederatable is a DID document that
advertises a signing key the repo does not sign with. Relays and AppViews
reject such commits outright while the PDS reports success, so nothing surfaces
it locally.

- Whenever this server publishes a DID document (PLC operations,
  `createAccount`), the key it publishes must be the key the repo store
  actually holds. Pass it explicitly via
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
- Every create/put/delete/applyWrites handler tracks which blobs a record
  references (`metalbear_blob_store_associate`/`_dissociate`, driven by
  `metalbear_blob_walk_refs`), deleting a blob outright the moment no record
  references it — mirrors the reference PDS's `record_blob` bookkeeping. A
  record may reference a blob that has not been uploaded yet (the
  `listMissingBlobs` migration flow depends on this); association is
  best-effort and never rejects the write. When a record is replaced but
  keeps referencing the SAME blob CID, dissociating the old value must skip
  any CID the new value still names — the (cid, uri) pair does not change,
  so an unconditional dissociate would delete a blob the record still uses.
  `untrack_superseded_blobs` is the one function that gets this right; do
  not reintroduce a separate unconditional dissociate helper.

## Validation

- Run `cmake -S . -B build && cmake --build build && ctest --test-dir build
  --output-on-failure` before declaring a slice done.
- Test configs name no account: set `invite_required = false` and create every
  account the test needs through `com.atproto.server.createAccount`, which is
  the same path a real client takes.
- Every server route must have an offline end-to-end test in `test/test_server.c`
  or a dedicated test file covering success, auth failure, and schema conformance.
- Test cleanup must remove all SQLite files (repo, auth, account, sequence,
  registry) plus blob directories.
- A green local suite does not prove federation. For identity or repo-format
  changes, verify against the live dev PDS at `/Volumes/Storage/Server/bear`:
  export the repo with `com.atproto.sync.getRepo` and check the commit
  signature against the key published in the PLC directory, using something
  other than Wolfram — verifying wolfram's output with wolfram proves nothing.

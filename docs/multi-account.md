# Multi-account support for MetalBear

Status: **design plan — partially implemented.** Steps 1–3 are complete
(account context + per-account directory encoding, bootstrap wiring, and
`createAccount` provisioning a real isolated account). Steps 4–7
(per-request resolver, switching authenticated/repo/sync handlers, and
`listRepos`/`updateHandle`) remain. Code changes continue incrementally on
feature branches and are merged to `main` with `--no-ff`.

## Goal

MetalBear currently starts with a single account baked in at startup: one
`repo.sqlite3`, one `account.sqlite3`, one `auth.sqlite3`, one `blobs/`
directory, one `sequencer.sqlite3`, one `oauth.sqlite3`, and one `keys.sqlite3`,
all under a single `data_directory`, and every handler reads the server's one
open account context (`server->account_did`, `server->repo`, `server->account`,
`server->auth`, `server->blobs`, `server->sequencer`, `server->oauth`,
`server->key_rotation`).

The aim is to behave like any other PDS: `createAccount` provisions a real,
isolated account; authenticated requests act on the caller's own account; public
reads are scoped by the `did`/`repo`/`handle` in the request.

## Current facts that make this tractable

- `metalbear_account_registry` already stores per-DID metadata:
  `did`, `handle`, `password_hash`, `data_directory`, `active`. It has
  `find_by_did`, `find_by_handle`, `add`, `update_handle`, `remove`, `list`.
- `metalbear_account_registry_add(registry, did, handle, password_hash,
  data_directory)` already exists; today `createAccount` calls it but passes a
  *relative fragment* (`user_domain/handle`) and never opens a separate store
  for the new account, so second accounts are metadata-only.
- Every per-account store already opens from a path:
  - `metalbear_account_store_open(path, bootstrap_password, **out)`
  - `metalbear_auth_store_open(path, service_did, account_did, **out)`
  - `metalbear_sequencer_open(path, did, handle, **out)`
  - `metalbear_oauth_store_open(path, issuer, account_did, **out)`
  - `metalbear_key_rotation_open(path, **out)`
  - `wf_repo_store_open(path, did, handle, **out)` and
    `wf_blob_store_new(dir)` (file-backed).
- `authenticate()` already sets `req->authed_subject` to the caller's DID for
  authed requests.

So the missing piece is **per-request account resolution + open/close of that
account's stores**, plus fixing `createAccount` to actually provision them.

## Data layout

A single PDS data root (`config->data_directory`) contains one subdirectory per
account, keyed by DID (safe, unique, filesystem-friendly enough after encoding):

```
<data_directory>/
  registry.sqlite3          # shared account registry (already: accounts.sqlite3)
  <enc(did)>/
    repo.sqlite3
    blobs/
    auth.sqlite3
    account.sqlite3
    sequencer.sqlite3
    oauth.sqlite3
    keys.sqlite3
```

- DID → directory name is a deterministic, reversible encoding (e.g. replace
  `:` with `_` and `%`/`:` escaping) so lookups are filesystem-safe and
  collision-free. Helper `account_dir_for_did(root, did)`.
- The bootstrap/primary account from `config` lives at
  `root/<enc(config->account_did)>/`; `createAccount` creates
  `root/<enc(new_did)>/`.

## Core abstraction: `metalbear_account_context`

Introduce a per-request handle bundling one account's open stores:

```c
typedef struct metalbear_account_context {
    char *did;
    char *handle;
    wf_repo_store *repo;
    wf_blob_store *blobs;
    metalbear_auth_store *auth;
    metalbear_account_store *account;
    metalbear_sequencer *sequencer;
    metalbear_oauth_store *oauth;
    metalbear_key_rotation *key_rotation;
    bool owned;          /* false for the long-lived bootstrap context */
} metalbear_account_context;
```

Lifecycle:
- `metalbear_account_context_open(root, entry, service_did, public_url,
  issuer, *out)` opens all seven stores for the account named by `entry`
  (creating them on first use, mirroring current startup behavior).
- `metalbear_account_context_close(ctx)` closes them. For the long-lived
  bootstrap context `owned=false` means "don't close" (or the server owns it
  separately as today).
- A small LRU/reference-counted cache of open contexts avoids re-opening the
  same SQLite files on every request. Initial implementation: open per request
  and close when the handler returns (simple, correct, no concurrency bugs);
  add caching only if profiling shows a need. Wolfram's stores are
  thread-safe-ish (mutexes), and the server runs with a thread pool, so a cache
  must be guarded by a mutex — per-request open/close sidesteps that entirely.

## Resolution rules (who is "the account"?)

1. **Authenticated request** (`req->authed_subject` set): look up that DID in the
   registry; open its context. If absent → `WF_ERR_PERMISSION`.
2. **Request carrying `did` or `repo` param** (public repo reads,
   `com.atproto.sync.*`, `com.atproto.repo.*`): resolve the param to a registry
   entry; open that context. Unknown DID → `RepoNotFound` / `AccountNotFound`.
3. **Handle-based** (`resolveHandle`, `createSession` identifier): registry
   `find_by_handle`.
4. **Account-creation / service endpoints** (`createAccount`,
   `describeServer`, `reserveSigningKey`, well-known docs): use the shared/
   bootstrap context, not a specific user.

A helper `resolve_account_context(server, request, *out_ctx, *out_static)`
returns either a freshly opened context (caller closes) or points at the
server's bootstrap context for service-level endpoints.

## Handler changes (mechanical, large)

Replace `server->account_did` / `server->repo` / `server->account` /
`server->auth` / `server->blobs` / `server->sequencer` / `server->oauth` /
`server->key_rotation` reads with the resolved `ctx`. Concretely:

- `authenticate()` already validates the DID is known; keep that, but remember
  the resolved registry entry on the request so handlers don't re-lookup.
- `createSession` / `refreshSession` / `getSession`: operate on the caller's
  context (the DID from credentials).
- `createAccount`: provision `root/<enc(new_did)>/`, open that context, store the
  scrypt password hash in `account.sqlite3` (not just the registry), create the
  repo with the new DID/handle, register in the registry with the real absolute
  `data_directory`, and return a session. Honors invite codes if we later gate
  sign-ups (out of scope for v1; today sign-ups are open like the reference dev
  PDS).
- `com.atproto.repo.*` / `com.atproto.sync.*`: scope to the `repo`/`did` param's
  account context.
- `com.atproto.server.*` self endpoints (`getSession`, `updateEmail`,
  `createAppPassword`, `deactivateAccount`, `checkAccountStatus`,
  `requestAccountDelete`, `deleteAccount`, identity ops): act on the caller's
  context.
- `listRepos`: enumerate registry entries (instead of the single open repo).
- `updateHandle`: update registry + that account's context handle; also rewrite
  the repo store's handle (add a `wf_repo_store_set_handle` or reopen with new
  handle — confirm Wolfram supports renames; otherwise store handle in registry
  and pass at open time).

## The server struct after the change

- Keep `service_did`, `public_url`, `user_domain` (service-level config).
- Keep a `registry` (shared) and a bootstrap `account_context` used for
  service-level endpoints.
- Remove the single per-account fields from the hot path; handlers get the
  right context via resolution.

## Public-route / auth interplay

No behavior change to `is_public_route` or `authenticate`'s DID-ownership gate;
they already distinguish public (repo/sync) routes from authed ones. The only
new rule: public routes that take a `did`/`repo` must resolve that DID to a
registered account before opening its context.

## Migration

- Existing single-account deployments have all stores flat under
  `data_directory`. On first start in multi-account mode, if
  `registry.sqlite3` is absent but `repo.sqlite3` exists at the root, move the
  flat files into `root/<enc(bootstrap_did)>/` and create the registry entry
  from `config->account_did`/`account_handle`. Idempotent and one-way; back up
  first (the backup tool already covers this).

## Testing

- Unit: `account_registry` directory encoding round-trip; `createAccount`
  provisions an isolated, reopenable context; two accounts are fully isolated
  (record in A not visible from B).
- `test_server.c` end-to-end: create two accounts, log in as each, assert
  `getSession`/`checkAccountStatus`/`listRepos` reflect the correct DID; assert
  a repo write by account A is not readable via account B's DID; assert
  `resolveHandle` for both; assert unknown-DID reads return `RepoNotFound`.
- Keep the existing single-account test path working (the bootstrap account).

## Suggested implementation order (incremental, each committed + tested)

1. `account_dir_for_did()` + registry `data_directory` stored as absolute path;
   migration of the bootstrap account. Tests for encoding + migration.
2. `metalbear_account_context` open/close + resolver helper. Tests.
3. `createAccount` provisions a real isolated account (stores + registry +
   session). Tests.
4. Switch authenticated self-endpoints to resolved context. Tests.
5. Switch `com.atproto.repo.*` / `com.atproto.sync.*` to `did`/`repo`-scoped
   context. Tests.
6. `listRepos` enumerates registry. `updateHandle` rewrites handle. Tests.
7. Remove single-account fields from the hot path; final cleanup + full suite.

## Out of scope (v1)

- Invite-code-gated signups, email verification on `createAccount`, PLC
  directory publication, admin endpoints (`com.atproto.admin.*`), OAuth
  per-account issuer differences. These are additive after the core resolution
  lands.

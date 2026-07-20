# MetalBear agent guidance

MetalBear is a pure C11 AT Protocol PDS built on the sibling Wolfram SDK.

## Read first and architecture

- `/Volumes/Storage/Developer/Local/atproto` is the protocol and PDS behavior
  authority. Inspect its lexicons and PDS implementation before changing
  endpoint semantics.
- `src/server.c` is the central file: server lifecycle, XRPC route
  registration, auth callback, and all protocol handler functions.
- `src/account.c` manages credential storage, app passwords, email tokens,
  and account state (active/deactivated) in a per-account SQLite database.
- `src/auth.c` manages session tokens (access/refresh JWTs) with scrypt-hashed
  refresh tokens and scope-based access control.
- `src/sequencer.c` handles the firehose event stream (commits, identity,
  account, sync events) with configurable retention.
- `src/account_registry.c` is the multi-account registry for future per-account
  routing; currently used for DID-to-metadata lookup and `createAccount`.
- `src/email.c` is the optional SMTP email client using libcurl.
- `src/backup.c` implements repository backup/restore with CRC32 checksums.
- `src/oauth.c` handles OAuth 2.0 token endpoints.
- `src/key_rotation.c` manages P-256 signing key rotation.
- `include/metalbear/` contains all public headers.

## Reuse and safety

- Reuse Wolfram primitives and server infrastructure. Do not copy Wolfram code
  into this repository or hand-roll cryptography.
- Keep authentication, repository ownership, persistence, and protocol errors
  explicit. Never return fabricated success for an unfinished endpoint.
- Never commit secrets, live credentials, signing keys, or PDS data.

## Endpoint correctness

- Every endpoint's input/output schema must match its lexicon definition from
  `/Volumes/Storage/Developer/Local/atproto`. Use the exact field names, required
  fields, and error codes specified in the lexicon, not ad-hoc alternatives.
- Session responses (`createSession`, `refreshSession`, `createAccount`) must
  include `email` and `emailConfirmed` fields when email is configured.
- Error codes must use lexicon-defined names (e.g. `InvalidHandle`,
  `HandleNotAvailable`, `ExpiredToken`) rather than generic names like
  `InvalidRequest` or `InternalError`.
- Auth callback must check `is_public_route` before DID ownership validation,
  since public route bodies may contain DIDs being created/registered, not
  accessed.

## Validation

- Run `cmake -S . -B build && cmake --build build && ctest --test-dir build
  --output-on-failure` before declaring a slice done.
- Every server route must have an offline end-to-end test in `test/test_server.c`
  or a dedicated test file covering success, auth failure, and schema conformance.
- Test cleanup must remove all SQLite files (repo, auth, account, sequence,
  registry) plus blob directories.

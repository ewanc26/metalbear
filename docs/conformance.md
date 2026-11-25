# Conformance self-check

`tools/conformance.sh` points a small client at a running PDS and checks that
the core AT Protocol surface behaves as a client expects. It is a client-side
check only: it changes no server configuration and needs no credentials.

## Run it

```sh
cmake -S . -B build && cmake --build build --target test_metalbear_conformance
tools/conformance.sh                       # starts a local MetalBear
tools/conformance.sh http://127.0.0.1:3001 # checks a running instance
```

With no argument the checker starts a MetalBear on an ephemeral loopback port,
runs the checks, and tears it down. This is also `ctest -R metalbear_conformance`,
which is part of the normal test suite. With a base URL it checks that host
instead; the same binary, no special build.

The live mode creates one throwaway account (`conform.example.com`) to exercise
the authenticated flows. Only run it against an instance you own or are allowed
to test against. It reads no credentials and prints none.

## Single-user hosts

Local conformance in single-user mode is supported. The harness starts with a
fresh data directory, so its one `createAccount` is the permitted bootstrap and
the remaining checks use that account's session. It never needs a second
account, which is all the mode allows.

On a seeded single-user host — one already provisioned by
`scripts/setup.sh --single-user` — the single bootstrap account is the account
under test; there is no throwaway second signup. A second `createAccount`
correctly answers 404, so the live-mode setup step cannot mint another one
there. Treat the bootstrap account as the account the checks exercise, not a
host to create an additional throwaway account on.

## Checks

Each check is reported on its own line as `PASS` or `FAIL`, and the checker
exits non-zero if any failed:

| Check | What it asserts |
|---|---|
| `describeServer` | `did` and `availableUserDomains` are present |
| `createAccount` | signup returns a session token and a DID |
| `createSession` | login issues a fresh access token |
| `repo write/read round-trip` | a record written with `createRecord` reads back with `getRecord` |
| `blob upload/get` | an uploaded blob downloads byte-identically at its CID |
| `sync.getLatestCommit` | the head reports both `cid` and `rev` |
| `identity.resolveHandle` | the account's handle resolves to its DID |
| `subscribeRepos frame` | the firehose upgrade succeeds and one frame decodes |

The `subscribeRepos` check needs a loopback port, so it is skipped (reported as
a failure with a clear reason) when a live URL has no numeric port. The local
harness always provides one.

## CI

`conformance.yml` is a manually dispatched, advisory workflow for pointing the
same checker at the dev instance. It is not part of the `CI gate`, so a failure
there never blocks a merge.

## Community compatibility

`community-compat.yml` runs nightly and is also manually dispatchable. It is
advisory for the same reason: it drives the public `bsky.app` UI, so an upstream
page change can fail the run without saying anything about MetalBear. It builds
the current tree, boots a throwaway loopback instance with the same identity
semantics as `scripts/setup.sh --local` (no PLC writes), creates two accounts
with generated passwords, and runs a pinned checkout of
[`atproto-smoke`](https://github.com/aliceisjustplaying/atproto-smoke) against
it. `tools/community-compat.sh` is the shared runner; `SUITE_DIR` points it at
the external checkout. The summary, browser screenshots and server log are
published as the `community-compat` artifact and in the job summary.

The suite is pinned to `6669808cedbcf624c5e849ac05cf336c12e22953` so a failing
nightly can be compared against a known checkout. Its current login flow depends
on the live `bsky.app` page, so a green run also needs network access and an
unchanged upstream login dialog. It does not create accounts itself and receives
no credentials from the repository.

`happyproto/pds-test` is deliberately not a matrix leg. It builds nightly
container images of several PDS implementations; it is not a runnable suite, has
no target-PDS argument or account scenarios, and has no licence file. Treating
its Cocoon image as a MetalBear test would only assert that a different server
starts.

### Triage

Every community-suite failure is recorded here as a bug, deferred, or a
documented divergence; none is silently skipped.

| Date | Failure | Classification | Reason |
|---|---|---|---|
| 2026-11-23 | `login` times out waiting for the `Bluesky Social` dialog text | Deferred (upstream UI drift) | The pinned suite's browser selector no longer matches the current public `bsky.app` login dialog. The local MetalBear started, served `/xrpc/_health`, and created both throwaway accounts with `did:key` identities before the browser step failed; no MetalBear assertion failed. |

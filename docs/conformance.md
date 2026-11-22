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

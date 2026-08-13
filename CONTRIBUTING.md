# Contributing to MetalBear

Thanks for your interest. MetalBear is a C23 AT Protocol PDS built on the
sibling Wolfram SDK. C is the default language for all new code; C++ is permitted for complex or sensitive components where C is insufficient — RAII-based resource management, performance-critical code, and third-party library integrations with no C equivalent. All C++ must expose a C ABI via `extern "C"` and never leak C++ types across the boundary. A few ground rules help keep the codebase coherent.

## Core philosophy

1. **Protocol parity**: cross-reference [bluesky-social/atproto](https://github.com/bluesky-social/atproto) and the sibling [wolfram](https://github.com/ewanc26/wolfram) repository when implementing anything protocol-level, rather than guessing at wire formats.
2. **Reuse Wolfram primitives**: do not copy Wolfram code into this repository or hand-roll cryptography. Wolfram owns transport, identity, repo, crypto, and XRPC infrastructure.
3. **Stubs are honest**: unimplemented functions return an error and carry a `TODO` explaining what's missing and why — never a silent no-op or a fabricated success.
4. **Ownership is explicit**: every heap-allocated output has a matching `_free` function documented next to it. No hidden allocations, no implicit ownership transfer.

## Code style

- Follow the surrounding file's indentation and brace style.
- Atomic conventional commits: every commit must contain exactly one logical change. Scope by module — `feat(server)`, `fix(auth)`, `docs(readme)`, etc.
- No AI co-authors: commits must not add a `Co-authored-by:` trailer crediting an AI agent.

## Development workflow

- **Build**: `make build` or `cmake -S . -B build && cmake --build build`
- **Test**: `make test` or `ctest --test-dir build --output-on-failure`
- **Clean**: `make clean`

CMake defaults to the sibling `../wolfram` checkout. Set
`-DWOLFRAM_SOURCE_DIR=/path/to/wolfram` to use another checkout.

### Running a local instance

`scripts/setup.sh --local` builds MetalBear and starts it on
`http://localhost:2583` with no hostname, TLS, DNS, or federation required:

```sh
scripts/setup.sh --local
```

This is a real running PDS, not a mock: `createAccount`, repo writes, OAuth,
and the firehose all work the same as a production instance. What's
different is the identity:

- `service_did` is `did:web:localhost%3A2583` — did:web's port is
  percent-encoded (`%3A`), and Wolfram's did:web resolver special-cases a
  `localhost`/`localhost:<port>` host to resolve over plain HTTP instead of
  HTTPS, so no reverse proxy or certificate is needed.
- No `identity.plc_url` is set, so accounts mint a self-certifying `did:key`
  instead of a `did:plc` (`account_routes.c` falls back to `did:key`
  precisely when `plc_url` is unset). This matters beyond convenience: a
  `did:plc` genesis operation is a permanent, public write to the live PLC
  directory, and a throwaway dev account has no business making one. Set
  `--dns-token`/`--dns-zone` and rerun without `--local` against a real
  hostname when you actually need to test `did:plc` or federation.
- `firehose.crawlers` is empty, so the instance never announces itself to a
  relay.

Handle and DID resolution for accounts on the instance stay entirely local —
`com.atproto.identity.resolveHandle` checks the account registry before ever
reaching for the network — so a client that insists on resolving over the
open internet rather than asking the PDS directly won't find them. Point
your client's PDS URL at `http://localhost:2583` directly.

`--local` implies `--dev` (the landing page says plainly that this is a
testing instance). Combine it with the usual flags — `--port`, `--data`,
`--config`, `--open` — as needed; see `scripts/setup.sh --help` for the full
list.

## Validation

- Run `ctest --test-dir build --output-on-failure` before declaring a slice done.
- Every server route must have an offline end-to-end test in `test/test_server.c`
  or a dedicated test file covering success, auth failure, and schema conformance.
- Test cleanup must remove all SQLite files (repo, auth, account, sequence,
  registry) plus blob directories.

## References

- [bluesky-social/atproto](https://github.com/bluesky-social/atproto) — the canonical lexicons live under `lexicons/`.
- [wolfram](https://github.com/ewanc26/wolfram) (C) — the sibling SDK providing transport, identity, repo, and crypto primitives.
- [rsky](https://github.com/blacksky-algorithms/rsky) (Rust) — used for behavioural parity on identity, lexicon, repo, moderation, and OAuth flows.

## Security

- Never commit secrets, live credentials, signing keys, or PDS data.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
  Do not open a public issue for a security defect.

## Support the project

Code is the most useful contribution, but not the only one. If you would rather
fund the work than write it, MetalBear and Wolfram are both supported through
[github.com/sponsors/ewanc26](https://github.com/sponsors/ewanc26).

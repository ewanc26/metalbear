# Contributing to MetalBear

Thanks for your interest. MetalBear is a C11 AT Protocol PDS built on the
sibling Wolfram SDK. A few ground rules help keep the codebase coherent.

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

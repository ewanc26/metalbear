# Contributing to MetalBear

MetalBear is an AT Protocol Personal Data Server written in C23 and built on [Wolfram](https://github.com/ewanc26/wolfram). Thanks for helping!

A PDS holds people's accounts and data, so correctness and durability outrank features. Every contribution that touches auth, storage, or sync should come with evidence it was tested against real client traffic.

## Getting started

Build per the [README](README.md); CI runs on every push. A container image is published to ghcr.io, so you can exercise a built server end to end.

## Notes for this project

- **This is server software people trustingly point their identity at.** Favour conservative, spec-faithful changes; link the relevant `com.atproto.*` lexicon in the PR when behaviour is protocol-visible.
- Sessions are restart-persistent: anything you change around JWTs, refresh rotation, revocation, or app passwords must survive a restart and revoke cleanly.
- `com.atproto.sync.subscribeRepos` sequencing has cursor replay across restarts; changes there need a replay test, not just a fresh-boot test.
- Benchmark-sensitive paths (CAR export, blob store) should come with before/after numbers in the PR.

## Before opening a PR

- CI green; tests for anything new.
- Conventional commits (`feat:`, `fix:`, `docs:`, …), focused PRs, verification described in plain words.
- AI-assisted PRs welcome; stand behind every line and run the checks yourself.

## Licence

See [LICENSE](LICENSE). Contributions are accepted under the same terms.
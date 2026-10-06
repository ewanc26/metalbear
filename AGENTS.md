# AGENTS.md

Guidance for AI coding agents working in **metalbear**.

## Project overview

an AT Protocol Personal Data Server written primarily in C and C++

- Language: C
- Default branch: main

## Wolfram is the protocol layer

Wolfram is Ewan's C AT Protocol SDK and is the protocol implementation for MetalBear. It is fetched via CMake FetchContent and is a hard dependency of the MetalBear build. If the fetch fails, the build fails — there is no silent fallback.

## Build numbers and version stamping

Every MetalBear build carries stamped values from CMake. A release must never ship without build identifiers present. If commit SHAs are not being recorded in CI, the 6-character short SHA is the fallback identifier.

## Working rules

- Inspect the README, manifests, CI workflows, and nearby code before editing.
- Preserve existing architecture, naming, formatting, and error-handling conventions.
- Use project scripts for validation; never claim checks you did not run.
- Keep changes scoped and update tests or documentation when behavior changes.
- Use feature branches and pull requests.
- Treat generated files, credentials, deployment configuration, and release metadata as sensitive.

<!-- flow:begin -->
## Unified flow (canonical: ewanc26/wolfram, docs/flow.md)

This block is byte-identical in every repo of the stack and is drift-checked by CI. Do not edit a copy; change it by PR to wolfram, then copy it out.

- Branch from main as `<type>/<slug>`. Types: feat fix docs ci chore refactor test perf build ui release (titles and commits also allow revert). Slug: lowercase `a-z 0-9 . _ -`.
- Commit subjects and PR titles are Conventional Commits: `type(scope): summary`. Keep commits focused. Never push an empty commit.
- Agent commits end with the `Co-Authored-By:` and `Claude-Session:` trailers the session supplies. PR descriptions use `.github/PULL_REQUEST_TEMPLATE.md` (What this changes, Verification, Docs) and end with the session link.
- Nothing goes straight to main. Branch, open a PR, wait for green CI, merge the PR with a rebase merge (never squash, never a merge commit). Required checks: `CI gate` and `flow / conventions`.
- A rebase merge lands every commit on main as written, so each commit stands alone: a conventional subject, builds, passes tests. Write review fixes as real conventional commits (`fix(scope): ...`), never "address review".
- Never force-push, so a PR branch is never rebased locally, and never merge main into a PR branch (a merge commit breaks the rebase merge; the flow check fails it). If a PR is behind or conflicted and GitHub can still rebase-merge it cleanly, merge it once CI is green on the current head. Otherwise cut a fresh branch from main, cherry-pick the commits, open a new PR linking the old one, and close the old one with a comment.
- Never merge red. Never force-push. Never skip, disable or delete a test to get green: read the job log, reproduce, fix the root cause, wait, repeat. A red main is fixed before anything else.
- Update AGENTS.md, README and docs/ in the same PR as the change. AGENTS.md is imperative and exact; README and docs are user-facing prose.
- Label every issue: exactly one kind (bug, enhancement, documentation, refactor, test, chore, question) and at least one `area: <x>`. The taxonomy is `.github/labels.yml` (canonical in wolfram, drift-checked as `flow / labels and metadata`); add a label there, never ad hoc. Repository description, homepage, topics and features are `.github/repo-metadata.yml`; the owner applies it with `tools/apply-repo-metadata.sh`, because agents cannot write repository metadata.
- State exactly what was verified and where (host, emulator, hardware). Never claim hardware you did not use.
- Releases go through the repo's own release script only, and only after every consumer in the stack has been verified against the change.
- Anything only the owner can supply (credentials, hardware results, money, irreversible actions): file an issue labelled `needs-owner` and move on.
- READMEs and logos follow `docs/house-style.md` (wolfram), checked by `flow / style`.
- No secrets in the repo or its CI. No Vercel. No registry publishing.
<!-- flow:end -->

## MetalBear specifics

Rules on top of the flow above.

- Required status checks: `CI gate` and `flow / conventions`. Required status check: `CI gate`
- `CI gate` aggregates every non-informational job in `ci.yml`. Add new jobs to its `needs`; `tools/check-drift.sh` fails if you forget.
- Adopt a new Wolfram by bumping the tag in `CMakeLists.txt`, `README.md` and `Dockerfile.devsibling` together, after building and running ctest against it. Wolfram changes land first.
- Release only with `tools/release.sh` (`prepare`, merge the bump PR, then `tag`), only from a green, merged `main`. Never hand-tag. `release.yml`'s `verify` job refuses a tag that is not `vX.Y.Z`, differs from the CMake VERSION, is not on `main`, or lacks a green `CI gate`.
- The self-updater is `pdsadmin/metalbear-update.sh`; its inputs are `release.yml`'s archives and `SHA256SUMS[.sig]`. Keep it, `docs/updating.md`, `deploy/systemd/` and `test/update/test_update.sh` in step with any change to release asset names or data layout. It must stay opt-in (check-only by default), refuse to update without a verified backup, roll back on a failed health check, and never read, print or store credentials. Never generate or commit a signing key: it is the repository secret `RELEASE_SIGNING_KEY`, supplied by the owner.
- `docs/logo.svg` is the single source of the bear. `frontend/` SVGs must contain all of its rects (drift check). After changing it, run `python3 tools/gen_icons.py` to regenerate `admin-mobile/assets/*.png` (needs Pillow) and commit the result.
- Issues and issue comments are written in the owner's first person (plain British English, dry, specific: "I've found", "I want") and end with the exact line `_Written by Claude on my behalf._`. PR descriptions keep the session link instead.
- Do not reimplement Wolfram primitives; `tools/check-drift.sh` fails on known local copies.
- `tools/check-drift.sh` (CI job `drift`) is metalbear's own drift check: Wolfram pin, DNS provider count, the required check named above, release gating, updater platforms, the bear, no local Wolfram primitives. The canonical flow files are checked separately by Wolfram's `flow / drift`.
- Branch protection (require `CI gate` and `flow / conventions`, no force-push, no direct push to `main`, rebase merging only) must be set by the repository owner and is tracked in a `needs-owner` issue; the API refuses it to agents.

## Recent history

Sync AGENTS.md from zincfox; Sync AGENTS.md from zincfox; Sync CONTRIBUTING.md from zincfox; Sync CONTRIBUTING.md from zincfox; test(server): cover mod-service auth for getPreferences
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

## Flow

Follow this for every change. Rules first, rationale after.

1. Never commit or push to `main`. Branch from `main`, named `<type>/<slug>` (type: feat, fix, chore, docs, test, ci, refactor, perf, build, revert, style, audit, release; slug lowercase `a-z0-9._-`).
2. Commit subjects and the PR title are `<type>(<scope>): <summary>`. Commits are atomic. Never push an empty commit. Never force-push.
3. End agent commits with the `Co-Authored-By:` and `Claude-Session:` trailers for the session; end agent PR descriptions with the generated-with line and session link.
4. Open a PR using `.github/PULL_REQUEST_TEMPLATE.md`. Keep it small. State exactly what was verified and where (host, emulator, hardware); never claim hardware you did not use.
5. Update AGENTS.md, README and `docs/` in the same PR as the change.
6. Merge with rebase only (`merge_method: rebase`), never squash and never a merge commit, and only when the `ci gate` check is green. Every commit lands on `main` as written, so each must be a standalone conventional commit that builds and passes tests; write review fixes as real `fix(scope): ...` commits. Never merge `main` into a PR branch. If a PR cannot be rebased cleanly, cut a fresh branch from `main`, cherry-pick, open a new PR linking the old one, and close the old one with a comment. A red check is never an end state: read the job log, reproduce, root-cause, fix, push, repeat. Never skip, disable or delete a test to get green. A red `main` is fixed before anything else.
7. Wolfram changes land first; adopt a new Wolfram by bumping the tag in `CMakeLists.txt`, `README.md` and `Dockerfile.devsibling` together, after building and running ctest against it.
8. Release only with `tools/release.sh` (`prepare`, merge the bump PR, then `tag`), only from a green, merged `main`. Never hand-tag. `release.yml`'s `verify` job refuses a tag that is not `vX.Y.Z`, differs from the CMake VERSION, is not on `main`, or lacks a green `ci gate`.
9. The self-updater is `pdsadmin/metalbear-update.sh`; its inputs are `release.yml`'s archives and `SHA256SUMS[.sig]`. Keep it, `docs/updating.md`, `deploy/systemd/` and `test/update/test_update.sh` in step with any change to release asset names or data layout. It must stay opt-in (check-only by default), refuse to update without a verified backup, roll back on a failed health check, and never read, print or store credentials. Never generate or commit a signing key: it is the repository secret `RELEASE_SIGNING_KEY`, supplied by the owner.
10. Do not commit secrets. Do not publish to registries or Vercel from here.

Required status check: `ci gate`

Enforcement:

- `tools/flow-check.sh` (CI job `flow`) checks rule 1 (branch name), 2 (title, commit subjects, empty commits, no merge commits) and the template sections of rule 4.
- `tools/check-drift.sh` (CI job `drift`) checks that the Wolfram pin, the DNS provider count, the required check named above, and the PR template agree with the code. Change both sides together.
- `ci gate` aggregates every non-informational job. Add new jobs to its `needs`.
- Branch protection (require `ci gate`, no force-push, no direct push to `main`, rebase merging only) must be set by the repository owner; the API refuses it to agents. Until it is, `ci gate` is advisory to GitHub but binding on agents under rule 6.

Why: the stack (wolfram, metalbear, cobalt, indigo, platinum) is changed by several agents at once. Small PRs, a single gate and mechanical checks keep any one agent from breaking another's base.

## Recent history

Sync AGENTS.md from zincfox; Sync AGENTS.md from zincfox; Sync CONTRIBUTING.md from zincfox; Sync CONTRIBUTING.md from zincfox; test(server): cover mod-service auth for getPreferences
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

## Recent history

Sync AGENTS.md from zincfox; Sync AGENTS.md from zincfox; Sync CONTRIBUTING.md from zincfox; Sync CONTRIBUTING.md from zincfox; test(server): cover mod-service auth for getPreferences
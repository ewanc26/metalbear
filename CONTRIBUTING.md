# Contributing to metalbear

an AT Protocol Personal Data Server written primarily in C and C++

## Project context

- Primary language: C
- Default branch: main

## Before submitting changes

- Read the README, manifests, and CI workflows before choosing commands.
- Run the documented formatter, linter, build, and test checks relevant to your change.
- Keep commits focused and explain compatibility or operational impact.
- Open changes through a pull request with verification results.

## How a change goes in

The full rules are in [AGENTS.md](AGENTS.md); the short version is a
branch named `<type>/<slug>`, conventional commit subjects, a pull request
filled in from the template, and a green `CI gate` before it merges. Nothing
goes straight to `main`, and pull requests are merged with rebase, so every
commit on a branch lands as written: keep each one standalone, and fix review
comments with new `fix(scope): ...` commits rather than merging `main` in.
`tools/check-drift.sh` checks the facts the docs and code both state; the flow
checks themselves are Wolfram's (`flow / conventions`).

Releases go through `tools/release.sh`, never by hand-tagging.

## Recent direction

Recent commits: Sync AGENTS.md from zincfox; Sync AGENTS.md from zincfox; Sync CONTRIBUTING.md from zincfox; Sync CONTRIBUTING.md from zincfox; test(server): cover mod-service auth for getPreferences
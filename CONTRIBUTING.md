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

The full rules are in [AGENTS.md](AGENTS.md#flow); the short version is a
branch named `<type>/<slug>`, conventional commit subjects, a pull request
filled in from the template, and a green `ci gate` before it merges. Nothing
goes straight to `main`. Two scripts check this for you and can be run before
pushing: `tools/flow-check.sh` (see its header for the environment it reads)
and `tools/check-drift.sh`.

## Recent direction

Recent commits: Sync AGENTS.md from zincfox; Sync AGENTS.md from zincfox; Sync CONTRIBUTING.md from zincfox; Sync CONTRIBUTING.md from zincfox; test(server): cover mod-service auth for getPreferences
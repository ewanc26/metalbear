# Changelog

Every pull request that changes something a user or operator would notice adds
a line under `[Unreleased]`, and `tools/release.sh prepare` turns that section
into the next version's. Releases made before it existed are described only by their
[GitHub release notes](https://github.com/ewanc26/metalbear/releases).

## [Unreleased]

### Added

- I can update a prebuilt install from these releases with `pdsadmin/metalbear-update.sh`: it checks the SHA-256 (and a signature, once I have a signing key), snapshots the databases, installs, and rolls back if the health check fails. It does nothing unless asked. See [docs/updating.md](docs/updating.md). ([#57](https://github.com/ewanc26/metalbear/pull/57))
- Releases now carry a `SHA256SUMS` file, which is what the updater reads. ([#57](https://github.com/ewanc26/metalbear/pull/57))

### Changed

- Container images are tagged with the exact version, the minor and, for the newest stable release only, `latest`. A published version tag is never moved, and each release's notes list the image digests and lead with its CHANGELOG section. The README says how to upgrade a container. ([#63](https://github.com/ewanc26/metalbear/pull/63))
- Wolfram is pinned to v0.26.0. ([#49](https://github.com/ewanc26/metalbear/pull/49))
- OAuth scopes are stricter: an `rpc:` method or a `repo:` collection has to be a real NSID now, checked by Wolfram's validator, so `rpc:foo.bar` no longer parses. AT-URIs given to the admin takedown routes are parsed by Wolfram too. ([#59](https://github.com/ewanc26/metalbear/pull/59))
- A release tag is refused unless it matches the version in `CMakeLists.txt`, sits on `main` and passed CI. Releases are cut with `tools/release.sh`. ([#52](https://github.com/ewanc26/metalbear/pull/52))

### Fixed

- The minimal build profile, the one meant for a Raspberry Pi 1B or Zero, did not compile. It does now, and CI builds it, runs the Pi checklist's tests against it and checks that the 64-bit atomics compile for ARMv6Z without libatomic. None of that has run on a Pi yet. ([#66](https://github.com/ewanc26/metalbear/pull/66))
- The README said there were four DNS providers in one place and three in another. There are four. ([#50](https://github.com/ewanc26/metalbear/pull/50))

## [0.42.3] - 2026-10-04

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.42.3).

## [0.42.2] - 2026-09-23

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.42.2).

## [0.42.1] - 2026-08-28

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.42.1).

## [0.42.0] - 2026-08-28

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.42.0).

## [0.41.0] - 2026-08-26

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.41.0).

## [0.40.0] - 2026-08-24

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.40.0).

## [0.39.1] - 2026-08-13

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.39.1).

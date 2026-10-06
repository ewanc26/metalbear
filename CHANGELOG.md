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

- The admin app's icons were Expo's placeholder. They are the bear now, drawn from `docs/logo.svg` by `tools/gen_icons.py` in the house green, and the web favicon uses the same green. ([#65](https://github.com/ewanc26/metalbear/pull/67))
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

## [0.39.0] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.39.0).

## [0.38.2] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.38.2).

## [0.38.1] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.38.1).

## [0.38.0] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.38.0).

## [0.37.0] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.37.0).

## [0.36.0] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.36.0).

## [0.35.1] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.35.1).

## [0.35.0] - 2026-08-12

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.35.0).

## [0.34.0] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.34.0).

## [0.33.0] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.33.0).

## [0.32.1] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.32.1).

## [0.32.0] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.32.0).

## [0.31.1] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.31.1).

## [0.31.0] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.31.0).

## [0.30.0] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.30.0).

## [0.29.0] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.29.0).

## [0.28.2] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.28.2).

## [0.28.1] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.28.1).

## [0.28.0] - 2026-08-11

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.28.0).

## [0.27.5] - 2026-08-10

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.27.5).

## [0.27.4] - 2026-08-10

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.27.4).

## [0.27.3] - 2026-08-10

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.27.3).

## [0.27.2] - 2026-08-10

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.27.2).

## [0.27.1] - 2026-08-10

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.27.1).

## [0.27.0] - 2026-08-10

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.27.0).

## [0.26.2] - 2026-08-09

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.26.2).

## [0.26.1] - 2026-08-09

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.26.1).

## [0.26.0] - 2026-08-09

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.26.0).

## [0.25.2] - 2026-08-09

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.25.2).

## [0.25.1] - 2026-08-09

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.25.1).

## [0.25.0] - 2026-08-08

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.25.0).

## [0.24.1] - 2026-08-08

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.24.1).

## [0.24.0] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.24.0).

## [0.23.0] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.23.0).

## [0.22.0] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.22.0).

## [0.21.1] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.21.1).

## [0.21.0] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.21.0).

## [0.20.14] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.14).

## [0.20.13] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.13).

## [0.20.12] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.12).

## [0.20.11] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.11).

## [0.20.10] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.10).

## [0.20.9] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.9).

## [0.20.8] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.8).

## [0.20.7] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.7).

## [0.20.6] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.6).

## [0.20.5] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.5).

## [0.20.4] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.4).

## [0.20.3] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.3).

## [0.20.2] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.2).

## [0.20.1] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.1).

## [0.20.0] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.20.0).

## [0.19.0] - 2026-08-07

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.19.0).

## [0.18.1] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.18.1).

## [0.18.0] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.18.0).

## [0.17.1] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.17.1).

## [0.17.0] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.17.0).

## [0.16.0] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.16.0).

## [0.15.0] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.15.0).

## [0.14.2] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.14.2).

## [0.14.1] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.14.1).

## [0.14.0] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.14.0).

## [0.13.26] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.26).

## [0.13.25] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.25).

## [0.13.24] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.24).

## [0.13.23] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.23).

## [0.13.22] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.22).

## [0.13.21] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.21).

## [0.13.20] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.20).

## [0.13.19] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.19).

## [0.13.18] - 2026-08-06

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.18).

## [0.13.17] - 2026-08-05

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.17).

## [0.13.16] - 2026-08-05

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.16).

## [0.13.15] - 2026-08-05

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.15).

## [0.13.14] - 2026-08-05

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.14).

## [0.13.13] - 2026-08-05

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.13).

## [0.13.12] - 2026-08-05

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.12).

## [0.13.11] - 2026-08-05

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.11).

## [0.13.10] - 2026-08-04

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.10).

## [0.13.9] - 2026-08-04

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.9).

## [0.13.8] - 2026-08-04

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.8).

## [0.13.7] - 2026-08-04

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.7).

## [0.13.6] - 2026-08-04

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.6).

## [0.13.5] - 2026-08-04

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.5).

## [0.13.4] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.4).

## [0.13.3] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.3).

## [0.13.2] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.2).

## [0.13.1] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.1).

## [0.13.0] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.13.0).

## [0.12.0] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.12.0).

## [0.11.0] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.11.0).

## [0.10.0] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.10.0).

## [0.9.0] - 2026-08-01

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.9.0).

## [0.8.3] - 2026-07-31

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.8.3).

## [0.8.2] - 2026-07-31

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.8.2).

## [0.8.1] - 2026-07-31

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.8.1).

## [0.8.0] - 2026-07-31

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.8.0).

## [0.7.0] - 2026-07-28

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.7.0).

## [0.6.1] - 2026-07-27

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.6.1).

## [0.6.0] - 2026-07-27

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.6.0).

## [0.5.0] - 2026-07-27

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.5.0).

## [0.4.1] - 2026-07-27

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.4.1).

## [0.4.0] - 2026-07-27

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.4.0).

## [0.3.1] - 2026-07-27

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.3.1).

## [0.3.0] - 2026-07-26

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.3.0).

## [0.2.7] - 2026-07-25

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.7).

## [0.2.6] - 2026-07-23

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.6).

## [0.2.5] - 2026-07-23

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.5).

## [0.2.4] - 2026-07-23

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.4).

## [0.2.3] - 2026-07-23

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.3).

## [0.2.2] - 2026-07-23

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.2).

## [0.2.1] - 2026-07-23

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.1).

## [0.2.0] - 2026-07-22

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.2.0).

## [0.1.0] - 2026-07-21

Released before this changelog existed. The notes are on the [release page](https://github.com/ewanc26/metalbear/releases/tag/v0.1.0).

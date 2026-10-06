# Changelog

Every pull request that changes something a user or operator would notice adds
a line under `[Unreleased]`, and `tools/release.sh prepare` turns that section
into the next version's. Releases before 0.42.3 are described only by their
[GitHub release notes](https://github.com/ewanc26/metalbear/releases).

## [Unreleased]

### Added

- I can update a prebuilt install from these releases with
  `pdsadmin/metalbear-update.sh`: it checks the SHA-256 (and a signature, once I
  have a signing key), snapshots the databases, installs, and rolls back if the
  health check fails. It does nothing unless asked. See
  [docs/updating.md](docs/updating.md). ([#57](https://github.com/ewanc26/metalbear/pull/57))
- Releases now carry a `SHA256SUMS` file, which is what the updater reads.
  ([#57](https://github.com/ewanc26/metalbear/pull/57))

### Changed

- Container images are tagged with the exact version, the minor and, for the
  newest stable release only, `latest`. A published version tag is never moved,
  and each release's notes list the image digests and lead with its CHANGELOG
  section. The README says how to upgrade a container.
  ([#63](https://github.com/ewanc26/metalbear/pull/63))
- Wolfram is pinned to v0.26.0. ([#49](https://github.com/ewanc26/metalbear/pull/49))
- OAuth scopes are stricter: an `rpc:` method or a `repo:` collection has to be
  a real NSID now, checked by Wolfram's validator, so `rpc:foo.bar` no longer
  parses. AT-URIs given to the admin takedown routes are parsed by Wolfram too.
  ([#59](https://github.com/ewanc26/metalbear/pull/59))
- A release tag is refused unless it matches the version in `CMakeLists.txt`,
  sits on `main` and passed CI. Releases are cut with `tools/release.sh`.
  ([#52](https://github.com/ewanc26/metalbear/pull/52))

### Fixed

- The README said there were four DNS providers in one place and three in
  another. There are four. ([#50](https://github.com/ewanc26/metalbear/pull/50))

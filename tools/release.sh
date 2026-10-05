#!/usr/bin/env bash
#
# release.sh — cut a MetalBear release without touching main directly.
#
# Usage:
#   tools/release.sh [--dry-run] prepare <major|minor|patch|x.y.z>
#   tools/release.sh [--dry-run] tag
#
# A release is two steps with a merge between them, because main only changes
# through a green pull request:
#
#   prepare  From an up-to-date main: bump VERSION in project() on a new
#            release/vX.Y.Z branch, build and run ctest against it, commit
#            "chore(version): bump to X.Y.Z". You then push the branch and open
#            a pull request for it as for any other change.
#   tag      After that PR has merged, from an up-to-date main: confirm the
#            version has no tag yet and that `ci gate` is green on HEAD, then
#            push the annotated tag vX.Y.Z. release.yml does the rest and
#            refuses a tag that disagrees with the CMake version or is not on
#            main (its `verify` job).
#
# Requires: git, cmake, a C/C++ toolchain; `gh` (authenticated) for `tag`.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

dry_run=0
if [ "${1:-}" = "--dry-run" ]; then
	dry_run=1
	shift
fi
mode="${1:-}"
arg="${2:-}"

fail() {
	echo "release: $*" >&2
	exit 1
}
usage() {
	sed -n '3,9p' "${BASH_SOURCE[0]}" >&2
	exit 2
}

# Read VERSION out of the project() block. cmake_minimum_required(VERSION 3.20)
# also contains the word, so a plain grep would match the wrong line.
read_version() {
	awk '/^project\(/,/\)[[:space:]]*$/' CMakeLists.txt |
		sed -n 's/.*VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' |
		head -1
}

require_synced_main() {
	[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || fail "must be on main"
	[ -z "$(git status --porcelain)" ] || fail "working tree is not clean"
	git fetch origin --tags --prune --quiet
	[ "$(git rev-parse main)" = "$(git rev-parse origin/main)" ] ||
		fail "local main differs from origin/main; sync first"
}

case "$mode" in
prepare)
	[ -n "$arg" ] || usage
	require_synced_main
	current="$(read_version)"
	[ -n "$current" ] || fail "could not read VERSION from project() in CMakeLists.txt"
	case "$arg" in
	major | minor | patch)
		IFS=. read -r ma mi pa <<<"$current"
		case "$arg" in
		major) new="$((ma + 1)).0.0" ;;
		minor) new="$ma.$((mi + 1)).0" ;;
		patch) new="$ma.$mi.$((pa + 1))" ;;
		esac
		;;
	*) new="$arg" ;;
	esac
	[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "bad version: $new"
	[ "$new" != "$current" ] || fail "version is already $current"
	git ls-remote --exit-code --tags origin "refs/tags/v$new" >/dev/null 2>&1 &&
		fail "tag v$new already exists on origin"
	echo ">> $current -> $new on branch release/v$new"
	if ((dry_run)); then
		echo ">> Dry run: nothing changed."
		exit 0
	fi
	git checkout -q -b "release/v$new"
	trap 'git checkout -q -- CMakeLists.txt; git checkout -q main; git branch -q -D "release/v$new" 2>/dev/null || true' ERR
	python3 - "$new" <<-'PY'
	import re, sys
	want = sys.argv[1]
	lines = open("CMakeLists.txt").read().split("\n")
	start = next(i for i, l in enumerate(lines) if l.startswith("project("))
	end = next(i for i in range(start, len(lines)) if lines[i].rstrip().endswith(")"))
	for i in range(start, end + 1):
	    new, n = re.subn(r"(VERSION\s+)[0-9][0-9.]*", r"\g<1>" + want, lines[i])
	    if n:
	        lines[i] = new
	        break
	else:
	    sys.exit("no VERSION line inside project()")
	open("CMakeLists.txt", "w").write("\n".join(lines))
	PY
	[ "$(read_version)" = "$new" ] || fail "bump did not take effect"
	jobs="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
	cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Debug >/dev/null
	cmake --build build-release -j"$jobs"
	ctest --test-dir build-release --output-on-failure -j"$jobs"
	git add CMakeLists.txt
	git commit -q -m "chore(version): bump to $new"
	trap - ERR
	echo ">> Committed on release/v$new. Next: push it, open a PR titled"
	echo "   'chore(version): bump to $new', merge it when green, then run"
	echo "   tools/release.sh tag from main."
	;;
tag)
	require_synced_main
	version="$(read_version)"
	[ -n "$version" ] || fail "could not read VERSION from project() in CMakeLists.txt"
	tag="v$version"
	git rev-parse -q --verify "refs/tags/$tag" >/dev/null && fail "tag $tag already exists"
	command -v gh >/dev/null || fail "gh not found"
	sha="$(git rev-parse HEAD)"
	state="$(gh api "repos/{owner}/{repo}/commits/$sha/check-runs" \
		--jq '[.check_runs[] | select(.name == "ci gate")] | map(.conclusion) | .[0] // "missing"')"
	[ "$state" = success ] || fail "'ci gate' on $sha is '$state', not 'success'; not releasing"
	echo ">> $tag at $sha: ci gate green"
	if ((dry_run)); then
		echo ">> Dry run: nothing tagged."
		exit 0
	fi
	git tag -a "$tag" -m "$tag" "$sha"
	git push origin "$tag"
	echo ">> Pushed $tag; release.yml will verify and publish."
	;;
*) usage ;;
esac

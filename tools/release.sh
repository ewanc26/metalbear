#!/usr/bin/env bash
#
# release.sh — cut a MetalBear release without touching main directly.
#
# Usage:
#   tools/release.sh [--dry-run] prepare <major|minor|patch|x.y.z>
#   tools/release.sh [--dry-run] tag
#   tools/release.sh check-assets vX.Y.Z
#
# A release is two steps with a merge between them, because main only changes
# through a green pull request:
#
#   prepare  From an up-to-date main: bump VERSION in project() on a new
#            release/vX.Y.Z branch, move CHANGELOG.md's Unreleased entries
#            under the new version, build and run ctest against it, commit
#            "chore(version): bump to X.Y.Z". You then push the branch and open
#            a pull request for it as for any other change.
#   tag      After that PR has merged, from an up-to-date main: confirm the
#            version has no tag yet and that `CI gate` is green on HEAD, then
#            push the annotated tag vX.Y.Z. release.yml does the rest and
#            refuses a tag that disagrees with the CMake version or is not on
#            main (its `verify` job).
#
#   check-assets  After release.yml has finished: download SHA256SUMS and every
#            archive it lists from the published release and verify them, the
#            same inputs pdsadmin/metalbear-update.sh consumes. Read-only.
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
	trap 'git checkout -q -- CMakeLists.txt CHANGELOG.md; git checkout -q main; git branch -q -D "release/v$new" 2>/dev/null || true' ERR
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
	# CHANGELOG.md: the Unreleased section becomes this version's, and a fresh
	# empty Unreleased goes on top. An empty Unreleased means there is nothing
	# to release.
	python3 - "$new" "$(date -u +%Y-%m-%d)" <<-'PY'
	import re, sys
	new, day = sys.argv[1], sys.argv[2]
	text = open("CHANGELOG.md").read()
	m = re.search(r"^## \[Unreleased\]\n(.*?)(?=^## \[|\Z)", text, re.S | re.M)
	if not m or not re.search(r"^- ", m.group(1), re.M):
	    sys.exit("CHANGELOG.md has no entries under [Unreleased]; nothing to release")
	text = text[:m.start()] + f"## [Unreleased]\n\n## [{new}] - {day}\n" + m.group(1) + text[m.end():]
	open("CHANGELOG.md", "w").write(text)
	PY
	git add CMakeLists.txt CHANGELOG.md
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
		--jq '[.check_runs[] | select(.name == "CI gate")] | map(.conclusion) | .[0] // "missing"')"
	[ "$state" = success ] || fail "'CI gate' on $sha is '$state', not 'success'; not releasing"
	echo ">> $tag at $sha: CI gate green"
	if ((dry_run)); then
		echo ">> Dry run: nothing tagged."
		exit 0
	fi
	git tag -a "$tag" -m "$tag" "$sha"
	if ! git push origin "$tag"; then
		# Some environments refuse `git push` of a tag. Try the same annotated
		# tag through the REST API; the push event it raises is what starts
		# release.yml either way. (The agents' sandbox proxy refuses this too,
		# in which case the owner pushes the tag: see the needs-owner issue.)
		echo ">> git push of $tag refused; creating it through the REST API"
		git tag -d "$tag" >/dev/null
		# gh repo view uses GraphQL, which some sandboxes block; read the remote.
		slug="$(git remote get-url origin | sed -E 's#^(git@[^:]+:|https?://[^/]+/)##; s#\.git$##')"
		obj="$(gh api -X POST "repos/$slug/git/tags" -f tag="$tag" -f message="$tag" \
			-f object="$sha" -f type=commit --jq .sha)"
		gh api -X POST "repos/$slug/git/refs" -f ref="refs/tags/$tag" -f sha="$obj" >/dev/null
	fi
	echo ">> Pushed $tag; release.yml will verify and publish."
	;;
check-assets)
	valid="^v[0-9]+\.[0-9]+\.[0-9]+$"
	[[ "$arg" =~ $valid ]] || usage
	command -v curl >/dev/null || fail "curl not found"
	url="https://github.com/ewanc26/metalbear/releases/download/$arg"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	curl -fsSL -o "$tmp/SHA256SUMS" "$url/SHA256SUMS" || fail "release $arg has no SHA256SUMS"
	[ -s "$tmp/SHA256SUMS" ] || fail "SHA256SUMS is empty"
	for p in linux-x86_64 linux-aarch64 macos-arm64; do
		grep -q " metalbear-$p.tar.gz$" "$tmp/SHA256SUMS" || fail "SHA256SUMS does not list metalbear-$p.tar.gz"
	done
	while read -r _ name; do
		curl -fsSL -o "$tmp/$name" "$url/$name" || fail "cannot download $name"
	done <"$tmp/SHA256SUMS"
	(cd "$tmp" && if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi) ||
		fail "checksum verification failed"
	if curl -fsSL -o "$tmp/SHA256SUMS.sig" "$url/SHA256SUMS.sig" 2>/dev/null; then
		echo ">> SHA256SUMS.sig present (verify it with ssh-keygen -Y verify and the release key)"
	else
		echo ">> WARNING: release is unsigned"
	fi
	echo ">> $arg assets verified"
	;;
*) usage ;;
esac

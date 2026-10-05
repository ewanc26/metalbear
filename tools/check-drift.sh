#!/usr/bin/env bash
#
# check-drift.sh — fail when a fact stated in two places disagrees.
#
# Each check here exists because the pair really did drift once or could
# plausibly do so. Run from the repo root; CI runs it as the `drift` job.
#
#   1. The Wolfram pin is the same in CMakeLists.txt, README.md and
#      Dockerfile.devsibling, and that tag exists on the Wolfram remote
#      (skipped with DRIFT_OFFLINE=1).
#   2. The README's "<N> providers" matches the DNS provider table in code.
#   3. The status check AGENTS.md says is required exists in ci.yml and
#      depends on every job there that is not informational.
#   5. release.yml gates its build jobs on `verify`.
#   6. The updater's platform names and SHA256SUMS exist in release.yml.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
err() {
	echo "drift: $*" >&2
	echo "::error::drift: $*" 2>/dev/null || true
	fail=1
}

# 1. Wolfram pin ------------------------------------------------------------
cmake_pin="$(sed -n 's/^[[:space:]]*GIT_TAG[[:space:]]\{1,\}\(v[0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1)"
[ -n "$cmake_pin" ] || err "no 'GIT_TAG vX.Y.Z' Wolfram pin found in CMakeLists.txt"
readme_pin="$(sed -n 's/.*pinned to the released `\(v[0-9][0-9.]*\)` tag.*/\1/p' README.md | head -1)"
docker_pin="$(sed -n 's/.*fetches Wolfram pinned to \(v[0-9][0-9.]*\).*/\1/p' Dockerfile.devsibling | head -1)"
[ "$readme_pin" = "$cmake_pin" ] || err "README.md pins Wolfram '${readme_pin:-?}' but CMakeLists.txt pins '$cmake_pin'"
[ "$docker_pin" = "$cmake_pin" ] || err "Dockerfile.devsibling says Wolfram '${docker_pin:-?}' but CMakeLists.txt pins '$cmake_pin'"
if [ -n "$cmake_pin" ] && [ "${DRIFT_OFFLINE:-0}" != 1 ]; then
	git ls-remote --exit-code --tags https://github.com/ewanc26/wolfram.git "refs/tags/$cmake_pin" >/dev/null 2>&1 ||
		err "Wolfram tag $cmake_pin does not exist on ewanc26/wolfram"
fi

# 2. DNS provider count -----------------------------------------------------
code_n="$(awk '/^static const dns_provider providers\[\]/,/^};/' src/dns/handle_dns.c | grep -c '^[[:space:]]*{"')"
word="$(sed -n 's/^\([A-Z][a-z]*\) providers are supported.*/\1/p' README.md | head -1)"
case "$word" in
	One) doc_n=1 ;; Two) doc_n=2 ;; Three) doc_n=3 ;; Four) doc_n=4 ;;
	Five) doc_n=5 ;; Six) doc_n=6 ;; *) doc_n=0 ;;
esac
[ "$code_n" -gt 0 ] || err "found no providers[] entries in src/dns/handle_dns.c"
[ "$doc_n" -eq "$code_n" ] || err "README.md says '${word:-?} providers' but handle_dns.c has $code_n"
if grep -n -E 'one of the (two|three|five|six)\b' README.md >/dev/null; then
	err "README.md has a stale 'one of the <n>' provider count"
fi

# 3. Required status check --------------------------------------------------
python3 - <<'PY' || fail=1
import re, sys, yaml
agents = open("AGENTS.md").read()
m = re.search(r"Required status check: `([^`]+)`", agents)
if not m:
    sys.exit("drift: AGENTS.md does not name the required status check ('Required status check: `...`')")
name = m.group(1)
jobs = yaml.safe_load(open(".github/workflows/ci.yml"))["jobs"]
gate = next((j for j in jobs.values() if j.get("name") == name), None)
if gate is None:
    sys.exit(f"drift: AGENTS.md requires '{name}' but ci.yml has no job with that name")
needs = set(gate.get("needs", []))
missing = [k for k, j in jobs.items()
           if j is not gate and not j.get("continue-on-error") and k not in needs]
if missing:
    sys.exit(f"drift: gate job '{name}' does not depend on: {', '.join(missing)}")
PY

# 5. Release gating ---------------------------------------------------------
python3 - <<'PY' || fail=1
import sys, yaml
jobs = yaml.safe_load(open(".github/workflows/release.yml"))["jobs"]
if "verify" not in jobs:
    sys.exit("drift: release.yml has no 'verify' job")
for k in ("binaries", "image"):
    n = jobs[k].get("needs", [])
    n = [n] if isinstance(n, str) else n
    if "verify" not in n:
        sys.exit(f"drift: release.yml job '{k}' does not need 'verify'")
PY

# 6. Updater platforms vs release matrix -----------------------------------
for p in $(grep -o 'echo \(linux\|macos\)-[a-z0-9_]*' pdsadmin/metalbear-update.sh | cut -d' ' -f2 | sort -u); do
	grep -q "name: $p\$" .github/workflows/release.yml ||
		err "pdsadmin/metalbear-update.sh expects platform '$p' but release.yml builds no such archive"
done
grep -q 'SHA256SUMS' .github/workflows/release.yml || err "release.yml does not publish SHA256SUMS, which the updater needs"

[ "$fail" -eq 0 ] || { echo "drift: FAILED" >&2; exit 1; }
echo "drift: ok"

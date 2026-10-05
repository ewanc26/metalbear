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
#   4. The PR template carries the sections flow-check.sh demands.
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

# 4. PR template vs flow-check.sh -------------------------------------------
sections="$(sed -n 's/^REQUIRED_SECTIONS=(\(.*\))$/\1/p' tools/flow-check.sh)"
while IFS= read -r s; do
	[ -n "$s" ] || continue
	grep -qxF "$s" .github/PULL_REQUEST_TEMPLATE.md ||
		err "PULL_REQUEST_TEMPLATE.md lacks '$s', which tools/flow-check.sh requires"
done < <(grep -o '"[^"]*"' <<<"$sections" | tr -d '"')

[ "$fail" -eq 0 ] || { echo "drift: FAILED" >&2; exit 1; }
echo "drift: ok"

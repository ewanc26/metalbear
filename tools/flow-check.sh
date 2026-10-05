#!/usr/bin/env bash
#
# flow-check.sh — enforce the pull-request flow written in AGENTS.md.
#
# Reads the pull request from the environment so it can be run locally and
# from CI with the same code:
#
#   PR_TITLE   the pull request title
#   PR_BODY    the pull request description
#   HEAD_REF   the source branch name
#   BASE_SHA   the base commit the PR merges into
#   HEAD_SHA   the PR head commit (default HEAD)
#
# Checks: branch name, conventional title, template sections present in the
# body, conventional commit subjects, no empty commits, no merge commits. Everything it reports
# is a rule from AGENTS.md; change them together (tools/check-drift.sh keeps
# the template and this file in step).
#
# This file and .github/workflows/flow-checks.yml are written to be hosted
# unchanged by Wolfram and copied or called by the other repos in the stack.
# Nothing here is MetalBear-specific.
set -euo pipefail

TYPES='feat|fix|chore|docs|test|ci|refactor|perf|build|revert|style'
# Sections the PR body must contain. Keep in step with
# .github/PULL_REQUEST_TEMPLATE.md.
REQUIRED_SECTIONS=("## What this changes" "## Why")

fail=0
err() {
	echo "flow-check: $*" >&2
	echo "::error::flow-check: $*" 2>/dev/null || true
	fail=1
}

: "${PR_TITLE:?PR_TITLE is required}"
: "${HEAD_REF:?HEAD_REF is required}"
: "${BASE_SHA:?BASE_SHA is required}"
HEAD_SHA="${HEAD_SHA:-HEAD}"
PR_BODY="${PR_BODY:-}"

# Branch: <type>/<slug>.
if ! [[ "$HEAD_REF" =~ ^($TYPES|audit|release)/[a-z0-9][a-z0-9._-]*$ ]]; then
	err "branch '$HEAD_REF' must look like <type>/<slug> (type: ${TYPES//|/, }, audit, release; slug lowercase a-z0-9._-)"
fi

# Title: conventional commit.
if ! [[ "$PR_TITLE" =~ ^($TYPES)(\([a-z0-9._-]+\))?\!?:\ .+ ]]; then
	err "PR title '$PR_TITLE' must be '<type>(<scope>): <summary>' (type: ${TYPES//|/, })"
fi

# Body: template sections.
for s in "${REQUIRED_SECTIONS[@]}"; do
	if ! grep -qxF "$s" <<<"$PR_BODY"; then
		err "PR body is missing the section '$s' from .github/PULL_REQUEST_TEMPLATE.md"
	fi
done

# Merge commits: PRs are rebase-merged, so a merge commit on the branch would
# be rewritten or refused. Rebase or cherry-pick onto a fresh branch instead.
for m in $(git rev-list --merges "$BASE_SHA..$HEAD_SHA"); do
	err "commit ${m:0:9} is a merge commit; rebase instead (PRs are rebase-merged)"
done

# Commits: conventional subjects, none empty. Merge commits are skipped.
while read -r sha; do
	[ -n "$sha" ] || continue
	subject="$(git log -1 --format=%s "$sha")"
	short="${sha:0:9}"
	if ! [[ "$subject" =~ ^($TYPES)(\([a-z0-9._-]+\))?\!?:\ .+ ]]; then
		err "commit $short subject '$subject' is not conventional"
	fi
	if [ -z "$(git diff-tree --no-commit-id --name-only -r "$sha")" ]; then
		err "commit $short ('$subject') changes no files; empty commits are not allowed"
	fi
done < <(git rev-list --no-merges "$BASE_SHA..$HEAD_SHA")

if [ "$fail" -ne 0 ]; then
	echo "flow-check: FAILED (rules are in AGENTS.md, 'Flow')" >&2
	exit 1
fi
echo "flow-check: ok"

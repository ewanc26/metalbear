## What this changes
A short description of the change and the problem it solves.

## Why
Context a reviewer would not get from the diff — the failure it fixes, the spec it
follows, or the deployment it unblocks. Link the issue if there is one.

## Checklist
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] New or changed routes have an end-to-end test covering success, auth failure,
      and schema conformance
- [ ] Tests clean up every SQLite file and blob directory they create
- [ ] Commits are atomic and conventional (`feat(server)`, `fix(auth)`, `docs(readme)`)
- [ ] No `Co-authored-by:` trailer crediting an AI agent
- [ ] No secrets, live credentials, signing keys, or PDS data in the diff
- [ ] Docs updated if behaviour or configuration changed

## Protocol parity
If this touches protocol surface, note what you checked it against
([atproto](https://github.com/bluesky-social/atproto),
[rsky](https://github.com/blacksky-algorithms/rsky), or a live PDS) — or say N/A.

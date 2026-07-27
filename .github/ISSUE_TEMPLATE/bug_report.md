---
name: Bug report
about: Report a defect in MetalBear (crash, wrong response, federation failure, build failure)
title: "[bug]: "
labels: ["bug"]
assignees: []
---

## Affected area
Which part of MetalBear? e.g. `server`/routes, `auth`/sessions, `oauth`, `repo_store`,
`blob_store`, `sequencer`/firehose, `account_registry`, `handle_dns`, `email`,
`backup`, `key_rotation`, the admin CLI, the container images, or the frontend.

## Describe the bug
A clear and concise description of what the bug is.

## To reproduce
Steps, plus the request that triggers it:
```sh
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{...}' http://127.0.0.1:2583/xrpc/com.atproto...
```
- Expected behaviour:
- Actual behaviour (include the response body and status code):
- Relevant server log lines:

## Environment
- MetalBear version / commit: (`metalbear --version`, or `git rev-parse HEAD`)
- Install method: source build, prebuilt release archive, or container (state the tag)
- OS / compiler / CMake version:
- Wolfram commit, if built from source:
- Reverse proxy in front, if any (and whether it forwards WebSocket upgrades):

## Protocol context (if applicable)
- Lexicon / NSID involved:
- Reference: does [bluesky-social/atproto](https://github.com/bluesky-social/atproto)'s
  PDS or [rsky](https://github.com/blacksky-algorithms/rsky) behave differently?
  Link the relevant lexicon or source.

## Secrets
Redact DIDs you do not want public, admin passwords, PLC rotation keys, DNS API
tokens, and SMTP credentials before pasting logs or configuration.

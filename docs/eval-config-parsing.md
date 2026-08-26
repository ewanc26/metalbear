# Evaluation: Config Parsing Libraries for MetalBear

**Issue:** [#44](https://github.com/ewanc26/metalbear/issues/44)
**Date:** 2026-08-26

## Current State

MetalBear hand-rolls TOML and YAML parsers in `cpp/metalbear/config_file.cpp`
(713 lines). An X-macro field table defines ~40 config fields, and both loaders
expand the same table so adding a field to one dialect auto-adds it to the other.

The header comment at `include/metalbear/config_file.h:34-38` states this is
deliberate: "keeping it in-tree avoids adding a parser dependency to a project
whose point is that it is plain C with few of them."

### Pain Points

1. **Hard cap of 64 owned strings** (`config_file.cpp:20`) — silently returns
   NULL if exceeded, risking undefined behavior downstream.
2. **Restricted TOML/YAML subset** — no nested tables, inline tables,
   multi-line strings, block sequences, anchors, or arbitrary indentation.
   Operators hitting edge cases get opaque errors.
3. **Env var overrides are inconsistent** — some use `ENV_STR`/`ENV_I64`
   macros, others do manual `getenv()` + `strtol()` with varying validation.
   Several overrides live in unrelated files (`server.c:2292`,
   `handle_dns.c:720`).
4. **No semantic validation** — types are checked but values (DID format, PLC
   URLs) are not.

## Candidates Evaluated

### TOML

| Library | Stars | License | Spec | Language | Dependencies | Verdict |
|---------|-------|---------|------|----------|-------------|---------|
| **tomlc17** | 157 | MIT | TOML v1.1 | C17 (C99 compat) | **None** | **Recommended** |
| tomlc99 | 652 | MIT | TOML v1.0 | C99 | None | Obsolete (author-deprecated, stack overflow vulns) |
| toml11 | 1,278 | MIT | TOML v1.1 | **C++11** | None | Fails C constraint |
| tinytoml | — | — | TOML v0.4 | **C++** | None | Fails C constraint, ancient spec |
| toml-c (arp242) | — | MIT | TOML v1.1 | C | None | Viable but less maintained than tomlc17 |

**tomlc17** is the clear winner: same author as tomlc99, fixes the stack
overflow vulnerability, passes the full `toml-test` suite (214 valid + 466
invalid cases), zero dependencies, drop-in two-file integration (`tomlc17.h` +
`tomlc17.c`). The `toml_seek()` API maps directly to nested section access:

```c
toml_result_t r = toml_parse_file_ex("config.toml");
if (!r.ok) { fprintf(stderr, "%s\n", r.errmsg); return 1; }
toml_datum_t host = toml_seek(r.toptab, "server.host");
toml_datum_t port = toml_seek(r.toptab, "server.port");
// ~15 lines to parse and extract all fields
toml_free(r);
```

### YAML

| Library | Stars | License | Spec | Language | Dependencies | Verdict |
|---------|-------|---------|------|----------|-------------|---------|
| **libyaml** | 1,149 | MIT | YAML 1.1/1.2 | C | **None** | **Recommended** |
| tlsa/libcyaml | 327 | ISC | YAML 1.1/1.2 | C | Requires libyaml | Good but v2 breaking changes in progress |
| andrewmd5/cyaml | 11 | MIT | YAML 1.2 | C | None | Too new (created Dec 2025) |
| tinyyaml | 9 | — | Partial | **C++** | None | Fails C constraint |

**libyaml** is the de facto standard C YAML parser (used by PyYAML, Ruby,
libsass). Event-based API requires ~80 lines of state machine code to build a
nested config struct — more boilerplate than tomlc17, but well-proven and
zero-dependency.

**tlsa/libcyaml** adds schema-driven struct mapping on top of libyaml (~40
lines instead of ~80), but its v2 branch has breaking changes and should be
avoided until stable.

## Recommendation

1. **TOML:** Replace the hand-rolled TOML parser with **tomlc17**. Drop in
   `tomlc17.h` + `tomlc17.c` (both files, MIT licensed), expand the X-macro
   field table into `toml_seek()` calls with typed accessors. Estimated
   replacement: ~80 lines vs the current ~170-line TOML loader.

2. **YAML:** Replace the hand-rolled YAML parser with **libyaml**. Write a
   ~80-line event processor that maps YAML events to the same config struct.
   The X-macro field table can drive both loaders.

3. **Keep the X-macro field table** — it's the right abstraction for the
   env-var override layer and ensures both dialects stay in sync.

4. **Centralize env var overrides** — after the parser swap, unify the
   inconsistent `getenv()` sites into a single pass using the field table.

### What This Does NOT Fix

- The env var override scatter (separate concern, should be its own cleanup)
- The 64-string cap (eliminated by tomlc17/libyaml which own their strings)
- Semantic validation (DID format, URL reachability — separate concern)
- The restricted-subset limitation becomes moot (tomlc17 handles full TOML 1.1)

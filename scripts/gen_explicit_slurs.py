#!/usr/bin/env python3
"""gen_explicit_slurs.py -- regenerate src/repo/explicit_slurs_patterns.c.

Extracts the regex pattern literals from the reference's
packages/pds/src/handle/explicit-slurs.ts and emits them as PCRE2 pattern
strings in a generated C source file. Extraction is mechanical (splitting
on the array literal's own line structure and slicing off the '/' regex
delimiters) rather than a hand transcription, since the source patterns are
long, Unicode-heavy character classes where a manual retype risks silently
dropping or mangling a combining character.

Usage:
    python3 scripts/gen_explicit_slurs.py <path-to-atproto-reference-clone>

Writes src/repo/explicit_slurs_patterns.c relative to the repo root (this
script's parent directory's parent).
"""

import json
import sys
from pathlib import Path


def extract_patterns(ts_source: str) -> list[str]:
    start = ts_source.index("[", ts_source.index("explicitSlurRegexes"))
    depth = 0
    end = None
    for i in range(start, len(ts_source)):
        c = ts_source[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        raise ValueError("unbalanced brackets while locating explicitSlurRegexes array")
    body = ts_source[start + 1 : end]

    patterns = []
    for line in body.splitlines():
        s = line.strip()
        if not s.startswith("/"):
            continue
        if s.endswith(","):
            s = s[:-1]
        if not (s.startswith("/") and s.endswith("/")):
            raise ValueError(f"unexpected regex literal line: {s[:60]!r}...")
        patterns.append(s[1:-1])
    return patterns


def c_escape(s: str) -> str:
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        else:
            out.append(ch)
    return "".join(out)


def render_c(patterns: list[str]) -> str:
    lines = [
        "/**",
        " * explicit_slurs_patterns.c -- generated from the reference's",
        " * explicit-slurs.ts (packages/pds/src/handle/explicit-slurs.ts, itself",
        " * sourced from https://github.com/Blank-Cheque/Slurs).",
        " *",
        " * Regenerate with scripts/gen_explicit_slurs.py rather than hand-editing:",
        " * the pattern strings are extracted programmatically from the .ts source",
        " * to avoid transcription errors in the Unicode-heavy character classes.",
        " *",
        " * DO NOT EDIT BY HAND.",
        " */",
        "",
        '#include "explicit_slurs_internal.h"',
        "",
        f"#define WF_EXPLICIT_SLUR_PATTERN_COUNT {len(patterns)}",
        "",
        "const char *const metalbear_explicit_slur_patterns"
        "[WF_EXPLICIT_SLUR_PATTERN_COUNT] = {",
    ]
    for p in patterns:
        lines.append(f'    "{c_escape(p)}",')
    lines.append("};")
    lines.append("")
    lines.append(
        "const size_t metalbear_explicit_slur_pattern_count = "
        "WF_EXPLICIT_SLUR_PATTERN_COUNT;"
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 1
    reference_root = Path(sys.argv[1])
    src = reference_root / "packages" / "pds" / "src" / "handle" / "explicit-slurs.ts"
    if not src.is_file():
        print(f"not found: {src}", file=sys.stderr)
        return 1

    ts_source = src.read_text(encoding="utf-8")
    patterns = extract_patterns(ts_source)

    repo_root = Path(__file__).resolve().parent.parent
    out_path = repo_root / "src" / "repo" / "explicit_slurs_patterns.c"
    out_path.write_text(render_c(patterns), encoding="utf-8")

    print(f"Extracted {len(patterns)} patterns from {src}")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

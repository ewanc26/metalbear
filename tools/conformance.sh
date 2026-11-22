#!/usr/bin/env bash
# Run the conformance self-check (issue #161).
#
#   tools/conformance.sh                 # start a local MetalBear and check it
#   tools/conformance.sh http://host:port # check a running instance instead
#
# No credentials are read, printed or stored. When given a live URL the check
# creates one throwaway account on that instance; only point it at a host you
# own or are allowed to test against.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary="${CONFORMANCE_BINARY:-${repo_root}/build/test_metalbear_conformance}"

if [ ! -x "$binary" ]; then
    # Fall back to any other build directory that has been configured.
    for candidate in "$repo_root"/build-*/test_metalbear_conformance; do
        if [ -x "$candidate" ]; then
            binary=$candidate
            break
        fi
    done
fi

if [ ! -x "$binary" ]; then
    printf 'conformance checker not built; run:\n' >&2
    printf '  cmake -S . -B build && cmake --build build --target test_metalbear_conformance\n' >&2
    exit 2
fi

exec "$binary" "$@"

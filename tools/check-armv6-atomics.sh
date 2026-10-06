#!/usr/bin/env bash
#
# check-armv6-atomics.sh — compile every MetalBear source that uses C11
# atomics for the Raspberry Pi 1B/Zero CPU and check what came out.
#
# Usage: tools/check-armv6-atomics.sh <configured-build-dir>
#
# Uses Debian's arm-linux-gnueabihf-gcc with the flags from Wolfram's
# .devdeps/rpi1.cmake (-march=armv6zk -mfpu=vfp -mfloat-abi=hard) plus -marm,
# because that compiler defaults to Thumb-2, which ARMv6 does not have. For
# each object it checks:
#   - Tag_CPU_arch is v6KZ and Tag_FP_arch VFPv2 (nothing ARMv7 leaked in);
#   - no undefined __atomic_* symbol, i.e. the 64-bit atomics were lowered to
#     inline LDREXD/STREXD and the link will not need libatomic.
# Compile-only, against host headers: it proves what the compiler emits for
# these files, not that the program links or runs on a Pi. That needs the
# hardware run in docs/pi1-hardware-validation.md (#34).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
build="${1:?usage: check-armv6-atomics.sh <configured-build-dir>}"
CC="${ARMV6_CC:-arm-linux-gnueabihf-gcc}"
command -v "$CC" >/dev/null || { echo "armv6: $CC not found" >&2; exit 1; }
READELF="${CC%gcc}readelf"
NM="${CC%gcc}nm"
OBJDUMP="${CC%gcc}objdump"

inc=(-Iinclude -Isrc -I"$build/_deps/wolfram-src/include" -I"$build/_deps/cjson-src")
flags=(-std=gnu2x -O2 -marm -march=armv6zk -mfpu=vfp -mfloat-abi=hard -mtune=arm1176jzf-s)
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

mapfile -t files < <(grep -rlE '_Atomic|<stdatomic\.h>' src --include='*.c' | sort)
[ "${#files[@]}" -gt 0 ] || { echo "armv6: no sources use atomics?" >&2; exit 1; }

fail=0
for f in "${files[@]}"; do
	o="$out/$(echo "$f" | tr / _).o"
	if ! "$CC" "${flags[@]}" "${inc[@]}" -c "$f" -o "$o" 2>"$o.err"; then
		echo "armv6: $f does not compile for ARMv6:" >&2; cat "$o.err" >&2; fail=1; continue
	fi
	arch="$("$READELF" -A "$o" | sed -n 's/.*Tag_CPU_arch: //p')"
	fp="$("$READELF" -A "$o" | sed -n 's/.*Tag_FP_arch: //p')"
	libcalls="$("$NM" "$o" | awk '$1 == "U" && $2 ~ /^__atomic_/ {print $2}' | sort -u | tr '\n' ' ')"
	ldrexd="$("$OBJDUMP" -d "$o" | grep -c ldrexd || true)"
	echo "armv6: $f arch=$arch fp=${fp:-none} ldrexd=$ldrexd libatomic=[${libcalls% }]"
	[ "$arch" = v6KZ ] || { echo "armv6: $f targets $arch, not v6KZ" >&2; fail=1; }
	[ -z "$fp" ] || [ "$fp" = VFPv2 ] || { echo "armv6: $f uses FP arch $fp, not VFPv2" >&2; fail=1; }
	[ -z "$libcalls" ] || { echo "armv6: $f calls libatomic ($libcalls)" >&2; fail=1; }
done
[ "$fail" -eq 0 ] && echo "armv6: ok (${#files[@]} files)"
exit "$fail"

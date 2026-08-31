# Raspberry Pi 1B / Zero hardware validation

This is the on-device evidence checklist for [#34].  It validates the
ARM1176JZF-S (ARMv6Z, VFPv2, hard-float) deployment path after #31 changed
file-backed blob residency from O(total blob payload bytes) to metadata plus
the one blob currently being served.

Run it on a real Raspberry Pi 1B or Zero, not QEMU.  Cross-compilation proves
that the linker accepted the target; it cannot prove that an ARMv6 CPU will
execute the output or establish its memory envelope.

## Evidence to record

Put the following in the #34 closing comment (or a dated attachment):

- MetalBear and Wolfram commit IDs, `uname -a`, `/proc/cpuinfo`, `MemTotal`,
  OS release, compiler version, linker version, and the exact sysroot source.
- The complete configure command, `METALBEAR_PROFILE`, configured thread
  count, resident-account limit, and blob-upload limit.
- `readelf -A`, `readelf -d`, and the result of the atomic probe below.
- startup time; idle and peak RSS; thread count; open-FD count; and latency
  samples, both before and after the large blob corpus is present.

Do not publish passwords, access tokens, private DIDs, or a production data
directory.

## 1. Build the actual target

Use a Pi-compatible hard-float rootfs.  Debian/Ubuntu's generic `armhf`
cross-toolchains target ARMv7 and are not valid for the Pi 1B/Zero.

```sh
export RPI1_CC=/path/to/arm-linux-gnueabihf-gcc
export RPI1_CXX=/path/to/arm-linux-gnueabihf-g++
export RPI1_ROOTFS=/path/to/raspbian-armv6-rootfs

cmake -S . -B build-rpi1 \
  -DCMAKE_TOOLCHAIN_FILE=../wolfram/.devdeps/rpi1.cmake \
  -DWOLFRAM_SOURCE_DIR=../wolfram \
  -DMETALBEAR_PROFILE=minimal \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-rpi1 -j"$(getconf _NPROCESSORS_ONLN)"
```

Copy `build-rpi1/metalbear` and the matching source/build test tree to the Pi.
Run the tests **on the Pi**, never through the host cross-build's `ctest`.

On the Pi, verify that the binary is ARMv6 and is not carrying an unresolved
libatomic dependency.  `armv6zk` is essential: it lets GCC lower the
project's 64-bit atomic metrics and DID-cache operations to the CPU's inline
LDREXD/STREXD instructions.

```sh
file ./metalbear
readelf -A ./metalbear | tee readelf-attributes.txt
readelf -d ./metalbear | tee readelf-dynamic.txt
if readelf -d ./metalbear | grep -q 'libatomic'; then
  echo 'FAIL: unexpected libatomic dependency'; exit 1
fi
./metalbear --version
./metalbear --help >/dev/null
```

**Pass:** `file` reports 32-bit ARM hard-float, the attributes identify an
ARMv6 target, no `SIGILL` occurs, and no `libatomic` dependency is present.

## 2. Run the smallest representative functional set

The selected tests cover account creation/session handling, record write/read,
blob upload/read and persistent file-backed blobs, sync/firehose operations,
and the atomic-backed metrics counters.  They use local stubs where the
protocol would otherwise contact the public network.

```sh
ctest --test-dir build-rpi1 --output-on-failure -j1 \
  -R 'metalbear_(server|blob_store|audit_sync|metrics|repo_parallel)$' \
  | tee ctest-pi1.txt
```

Then start the real binary with a fresh, disposable data directory.  Use one
server worker on this one-core target and an intentionally low resident account
budget; the config file can set the same values if preferred.

```sh
export METALBEAR_LISTEN=127.0.0.1 METALBEAR_PORT=2583
export METALBEAR_DATA="$PWD/pi1-data"
export METALBEAR_SERVICE_DID='did:web:pi1-validation.invalid'
export METALBEAR_USER_DOMAIN='.pi1-validation.invalid'
export METALBEAR_ADMIN_PASSWORD='use-a-temporary-local-password'
export METALBEAR_MAX_RESIDENT_ACCOUNTS=16
mkdir -p "$METALBEAR_DATA"
printf '[server]\nthreads = 1\n' >pi1-validation.toml
export METALBEAR_CONFIG="$PWD/pi1-validation.toml"

start_ns=$(date +%s%N)
./metalbear >metalbear.log 2>&1 &
pid=$!
until curl -fsS http://127.0.0.1:2583/xrpc/_health >/dev/null; do sleep 0.1; done
printf 'startup_elapsed_s=%.3f\n' \
  "$(awk -v n="$(date +%s%N)" -v s="$start_ns" 'BEGIN { print (n-s)/1e9 }')" \
  | tee -a pi1-measurements.txt
```

Run one disposable account through `createAccount`, `createSession`,
`createRecord`, `getRecord`, `uploadBlob`, `getBlob`, and `getRepo`.  Open a
`subscribeRepos` connection before the record write and confirm it receives
the commit.  Finally configure a controlled relay/crawler endpoint, write one
more record, and retain its `requestCrawl` receipt plus the receiver's log.
Do not count a best-effort public-relay crawl as a reproducible test.

## 3. Measure a corpus larger than RAM

This is the regression test for #31.  Use a disposable filesystem with at
least `RAM + 128 MiB` free.  Create a corpus of 4 MiB blobs totalling at least
384 MiB on a 256 MiB Pi, or 640 MiB on a 512 MiB Pi; upload sequentially using
the authenticated `com.atproto.repo.uploadBlob` endpoint.  Keep the response
CID for a first, middle, and last blob.

1. Record the measurements below with an empty blob store.
2. Upload the corpus, stop the server cleanly, then restart it from the same
   data directory.  This makes startup scan real on-disk blob metadata.
3. Record the same measurements after the restart, then fetch the three saved
   CIDs.  During one fetch, sample RSS every 100 ms to capture the bounded
   per-request allocation.

```sh
rss_kib() { awk '/VmRSS:/ {print $2}' /proc/"$pid"/status; }
threads() { awk '/Threads:/ {print $2}' /proc/"$pid"/status; }
fds() { find /proc/"$pid"/fd -mindepth 1 -maxdepth 1 | wc -l; }
printf 'rss_kib=%s threads=%s open_fds=%s\n' \
  "$(rss_kib)" "$(threads)" "$(fds)" | tee -a pi1-measurements.txt
curl -fsS -u "admin:$METALBEAR_ADMIN_PASSWORD" \
  http://127.0.0.1:2583/metrics | tee metrics.txt
```

For latency, record 30 sequential loopback samples for the health endpoint
and the representative read/write requests.  `curl`'s `time_total` is enough;
report p50 and p99, plus the raw samples so the calculation is auditable.

```sh
for n in $(seq 1 30); do
  curl -sS -o /dev/null -w '%{time_total}\n' \
    http://127.0.0.1:2583/xrpc/_health
done | sort -n | tee health-latency-seconds.txt
```

## Acceptance gates

These are deliberately conservative deployment gates, not performance claims
for a modern host.  A result that misses one is still useful: publish it and
open a follow-up for the limiting component.

| Check | Pass condition |
| --- | --- |
| Executability / atomics | ARMv6Z hard-float binary starts on-device without `SIGILL`; no `libatomic` dependency; `metalbear_metrics` and `metalbear_repo_parallel` pass. |
| Core behaviour | All five selected CTest executables pass; manual account/session/record/blob/sync flow and controlled `requestCrawl` succeed. |
| Startup | Fresh and corpus-restart health checks each complete within 15 s. |
| Memory, 256 MiB model | Idle RSS <= 64 MiB; sampled peak RSS <= 128 MiB; no OOM or swap thrashing.  A 512 MiB-only board must be labelled as such, not presented as 256 MiB validation. |
| Corpus scaling | Restart RSS after the >RAM corpus is no more than 16 MiB above the empty-store baseline; the three fetched blobs are byte-correct. |
| Process footprint | At the one-worker configuration, <= 4 threads and <= 64 open FDs at idle; corpus restart may add no more than 16 FDs over baseline. |
| Responsiveness | Loopback health p50 <= 250 ms and p99 <= 1 s, with no failed requests during the representative flow. |

When every gate passes on a 256 MiB Pi 1B, close #34 with the evidence.  If
only a 512 MiB revision is available, check every applicable box but leave
the 256 MiB criterion explicitly open.

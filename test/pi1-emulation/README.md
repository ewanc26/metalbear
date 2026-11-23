# Pi 1B/Zero resource-budget emulation

Runs MetalBear in Docker under the resource budgets the real hardware
validation demands, so the memory, thread, file-descriptor and startup
gates from
[docs/pi1-hardware-validation.md](../../docs/pi1-hardware-validation.md)
can be exercised before a Raspberry Pi 1B or Zero is in reach.

It is not hardware validation, and is never reported as such: an
ARM1176's execution and timing behaviour is not emulated here, and
nothing in this directory satisfies or closes [#34][]. What it does catch,
early and on any machine:

- RSS regressions against the 256 MiB model. The runbook gates are idle
  RSS <= 64 MiB and sampled peak <= 128 MiB; this harness enforces the
  256 MiB board total as a hard cgroup ceiling, so a breach comes back as
  a loud OOM kill rather than a silent number.
- Thread and open-FD ceilings (runbook gates: <= 4 threads, <= 64 open
  FDs), enforced as process and FD caps on the container.
- Startup-time blowups once the store grows (the 15 s health gate, with
  whatever the host itself contributes called out as such).
- The blob-corpus-larger-than-RAM regression ([#31][]) in a disposable
  data directory that no real deployment ever has to see.

## Prerequisites

- Docker with Compose v2.20 or newer (the arm profile uses `profiles:`).
- Optional, `emulate-arm` profile only, one-time QEMU binfmt registration:

  ```sh
  docker run --privileged --rm tonistiigi/binfmt --install arm
  ```

## Run

```sh
docker compose up -d                # native architecture under Pi1 caps
docker compose --profile emulate-arm up   # additionally arm/v7 under QEMU
```

Both services bind loopback only: `127.0.0.1:25830` (native) and
`127.0.0.1:25831` (arm). Identity values are `.invalid` placeholders, so
nothing here can resolve or federate even if it reaches a network. There
is no restart policy: a crash stops the container visibly.

## Measure against the gates

```sh
# Memory and threads against the <= 64 MiB idle and <= 4 threads gates
docker exec pi1-metalbear sh -c \
  'grep -E "VmRSS|Threads" /proc/"$(pidof metalbear)"/status'

# Open FDs against the <= 64 gate
docker exec pi1-metalbear sh -c 'ls /proc/"$(pidof metalbear)"/fd | wc -l'

# cgroup accounting, and the admin-gated Prometheus metrics
docker stats --no-stream pi1-metalbear
curl -fsS -u admin:pi1-emulation-only http://127.0.0.1:25830/metrics

# Rough health-gate timing; not the runbook's latency evidence
time curl -fsS http://127.0.0.1:25830/xrpc/_health >/dev/null
```

Keep `docker stats` running in another terminal while exercising the
representative flows from the runbook; RSS between samples is what needs
watching, so the `VmRSS` grep matters more than either endpoint alone.

## Corpus larger than RAM

Follow step 3 of the hardware runbook (4 MiB blobs, at least 384 MiB of
them at this 256 MiB cap, thousands of rows is fine) but upload through
the emulated instance: `http://127.0.0.1:25830`, an account on the
`.pi1-emulation.invalid` user domain, sequential authenticated
`com.atproto.repo.uploadBlob` calls. Restart the container once the
corpus is up, then sample `VmRSS` every 100 ms during a fetch of a saved
blob to capture the bounded per-request allocation that [#31][] fixed.
The corpus lives in the named volume; `down -v` discards it with
everything else.

## Clean up

```sh
docker compose down -v --profile emulate-arm
```

[#34]: https://github.com/ewanc26/metalbear/issues/34
[#31]: https://github.com/ewanc26/metalbear/issues/31

# MetalBear — an AT Protocol Personal Data Server in C23.
#
# The build context is the parent directory holding both the MetalBear and
# Wolfram source trees, so the image always builds the SDK from the same commit
# rather than against whatever a registry happens to have. The release workflow
# assembles that layout; locally it is the parent of the two checkouts.
#
#   docker build -f MetalBear/Dockerfile -t metalbear .
#
# Configuration comes from a config.toml (mount it and set METALBEAR_CONFIG) or
# from environment variables, which override the file. Nothing is baked in, so
# one image serves every deployment.

FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        gcc \
        g++ \
        make \
        pkg-config \
        git \
        libsqlite3-dev \
        libcurl4-openssl-dev \
        libssl-dev \
        libsecp256k1-dev \
        libmicrohttpd-dev \
        libzstd-dev \
        libidn2-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Debian bookworm ships libc-ares 1.18.1; Wolfram requires >= 1.28 for the
# DNS record API. Build from the c-ares main branch so pkg-config finds a
# version that satisfies the check and the runtime stage carries the matching
# shared library.
RUN git clone --depth 1 https://github.com/c-ares/c-ares.git /tmp/c-ares \
    && cmake -B /tmp/c-ares/build -S /tmp/c-ares \
            -DCMAKE_BUILD_TYPE=Release \
            -DCARES_SHARED=ON \
            -DCARES_STATIC=OFF \
    && cmake --build /tmp/c-ares/build --parallel \
    && cmake --install /tmp/c-ares/build \
    && rm -rf /tmp/c-ares

WORKDIR /src
# The POSIX feature-test macros glibc needs are set by Wolfram's CMake target
# and inherited here, so no global CFLAGS override is required. Setting it here
# only masked the problem for this image while CI and every other consumer
# still broke.
COPY MetalBear ./MetalBear
COPY wolfram ./wolfram

# The build context excludes .git (see the repo root's .dockerignore), so
# CMake's own git-detection for METALBEAR_BUILD_COMMIT can never find one from
# in here. Accept it as a build arg instead, computed on the host where .git
# is available -- docker-compose.yaml passes it from METALBEAR_BUILD_COMMIT in
# the shell environment at `docker compose build` time. Defaults to "unknown"
# so a plain `docker build` with no arg still degrades the same way CMake's
# own fallback does, rather than failing.
ARG METALBEAR_BUILD_COMMIT=unknown

# Where this image sits on the software release life cycle (see README.md's
# "Release stage" section) -- defaults to CMakeLists.txt's own default, but a
# deployment building its own image (a stable self-host, say) can override it
# with --build-arg or docker-compose.yaml's build.args, same pattern as
# METALBEAR_BUILD_COMMIT above.
ARG METALBEAR_RELEASE_STAGE=alpha

# Static internal libraries: the project's own objects link into the binary, so
# the runtime stage carries one file instead of four shared libraries that have
# to be kept in step with it.
RUN cmake -S MetalBear -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DMETALBEAR_BUILD_TESTS=OFF \
        -DWOLFRAM_SOURCE_DIR=/src/wolfram \
        -DMETALBEAR_BUILD_COMMIT="${METALBEAR_BUILD_COMMIT}" \
        -DMETALBEAR_RELEASE_STAGE="${METALBEAR_RELEASE_STAGE}" \
    && cmake --build build --parallel "$(nproc 2>/dev/null || echo 4)"

# A toolchain image with the sources and the test suite, for poking at the
# server without setting up a build host:
#
#   docker build -f MetalBear/Dockerfile --target dev -t metalbear:dev .
#   docker run --rm -it metalbear:dev            # a shell in the source tree
#   docker run --rm metalbear:dev ctest --test-dir build --output-on-failure
#
# Built Debug with tests, unlike the runtime image, because that is the point
# of it. Nothing here reaches the shipped image.
FROM build AS dev
RUN cmake -S MetalBear -B MetalBear/build \
        -DCMAKE_BUILD_TYPE=Debug \
        -DMETALBEAR_BUILD_TESTS=ON \
        -DWOLFRAM_SOURCE_DIR=/src/wolfram \
    && cmake --build MetalBear/build --parallel "$(nproc 2>/dev/null || echo 4)"
WORKDIR /src/MetalBear
ENV METALBEAR_LEXICON_DIR=/src/wolfram/lexicons
CMD ["/bin/bash"]

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="MetalBear" \
      org.opencontainers.image.description="An AT Protocol Personal Data Server written in C23" \
      org.opencontainers.image.source="https://github.com/ewanc26/metalbear" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
RUN apt-get update     && apt-get install -y --no-install-recommends \
        ca-certificates \
        libsqlite3-0 \
        libcurl4 \
        libssl3 \
        libsecp256k1-1 \
        libmicrohttpd12 \
        libzstd1 \
        libidn2-0 \
        zlib1g \
        wget \
    && rm -rf /var/lib/apt/lists/*

# The build stage compiled against a newer c-ares than bookworm ships; carry
# the matching shared library into the runtime image.
COPY --from=build /usr/local/lib/libcares.so* /usr/local/lib/
RUN ldconfig

COPY --from=build /src/build/metalbear /usr/local/bin/metalbear

# The lexicon corpus records are validated against on write. Without it every
# write is stored unchecked and reported as validationStatus "unknown".
COPY --from=build /src/wolfram/lexicons /usr/local/share/metalbear/lexicons

# Materialise /data in the image itself. It is normally a bind mount, but
# without it in the image `docker exec` cannot even start a process (it chdirs
# to WORKDIR first), which is exactly when you need a shell to diagnose a
# broken mount.
RUN mkdir -p /data
WORKDIR /data
# Bind to 0.0.0.0: the loopback default is right on a host with a reverse proxy
# beside it, but inside a container it makes the server unreachable from
# outside, which looks like a crash rather than a binding choice.
ENV METALBEAR_DATA=/data \
    METALBEAR_LISTEN=0.0.0.0 \
    METALBEAR_LEXICON_DIR=/usr/local/share/metalbear/lexicons
EXPOSE 2583

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO- http://127.0.0.1:${METALBEAR_PORT:-2583}/xrpc/_health || exit 1

ENTRYPOINT ["/usr/local/bin/metalbear"]

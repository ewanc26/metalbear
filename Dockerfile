# MetalBear dev/test PDS image.
#
# Build context is the parent directory that contains both the MetalBear and
# Wolfram source trees (see bear/docker-compose.yaml in the server stack). This
# images compiles MetalBear (C11) and the Wolfram server SDK it depends on,
# then runs the resulting `metalbear` binary.
#
# Runtime configuration (DID, handle, password, public URL) is supplied through
# environment variables at container start, so this image is reusable across
# deployments.

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
        libc-ares-dev \
        libidn2-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The POSIX feature-test macros glibc needs are set by Wolfram's CMake target
# and inherited here, so no global CFLAGS override is required. Setting it here
# only masked the problem for this image while CI and every other consumer
# still broke.
COPY MetalBear ./MetalBear
COPY wolfram ./wolfram

RUN cmake -S MetalBear -B build \
        -DCMAKE_BUILD_TYPE=Debug \
        -DMETALBEAR_BUILD_TESTS=OFF \
        -DWOLFRAM_SOURCE_DIR=/src/wolfram \
    && cmake --build build --parallel "$(nproc 2>/dev/null || echo 4)"

FROM debian:bookworm-slim AS runtime
RUN apt-get update     && apt-get install -y --no-install-recommends \
        ca-certificates \
        libsqlite3-0 \
        libcurl4 \
        libssl3 \
        libsecp256k1-1 \
        libmicrohttpd12 \
        libzstd1 \
        libc-ares2 \
        libidn2-0 \
        zlib1g \
        wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/metalbear /usr/local/bin/metalbear
# The core/wolfram/cjson/libcbor libraries are built as shared objects; ship
# them all alongside the binary so it loads at runtime.
COPY --from=build /src/build/libmetalbear_core.so /usr/local/lib/
COPY --from=build /src/build/wolfram/libwolfram.so /usr/local/lib/
COPY --from=build /src/build/_deps/cjson-build/libcjson.so* /usr/local/lib/
COPY --from=build /src/build/_deps/libcbor-build/src/libcbor.so* /usr/local/lib/
RUN ldconfig

# The lexicon corpus records are validated against on write. Without it every
# write is stored unchecked and reported as validationStatus "unknown".
COPY --from=build /src/wolfram/lexicons /usr/local/share/metalbear/lexicons

# Materialise /data in the image itself. It is normally a bind mount, but
# without it in the image `docker exec` cannot even start a process (it chdirs
# to WORKDIR first), which is exactly when you need a shell to diagnose a
# broken mount.
RUN mkdir -p /data
WORKDIR /data
ENV METALBEAR_DATA=/data
EXPOSE 2583
ENTRYPOINT ["/usr/local/bin/metalbear"]

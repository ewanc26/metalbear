# Stub image for test/container/container-update-test.sh. Not a MetalBear build:
# it has the same entrypoint, `--version` output and health path, so the update
# script can be exercised without a release.
FROM python:3.12-alpine
ARG MARK=a
ARG SCHEMA=1
ARG BROKEN=0
RUN mkdir -p /srv/xrpc && echo '{}' > /srv/xrpc/_health
COPY metalbear /usr/local/bin/metalbear
RUN chmod 0755 /usr/local/bin/metalbear
ENV STUB_MARK=$MARK STUB_SCHEMA=$SCHEMA STUB_BROKEN=$BROKEN
ENTRYPOINT ["/usr/local/bin/metalbear"]

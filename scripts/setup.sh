#!/usr/bin/env bash
#
# setup.sh — build and provision a MetalBear PDS from a clean machine.
#
# Installs build dependencies, builds MetalBear and its Wolfram dependency,
# generates the secrets a host needs, writes a config.toml, and starts the
# daemon. It does not terminate TLS or configure a reverse proxy: put nginx,
# Caddy or a tunnel in front and point it at the configured port.
#
# Usage:
#   scripts/setup.sh --hostname pds.example.com [options]
#
#   --hostname <host>   public hostname; the service DID becomes did:web:<host>
#   --data <dir>        data directory (default ./data)
#   --port <port>       listen port (default 2583)
#   --open              allow registration without invite codes
#   --dev               mark as a testing instance (says so on the landing page)
#   --operator <name>   operator name shown on the landing page
#   --email <addr>      admin contact, published via describeServer
#   --operator-url <u>  operator's own page
#   --support-url <u>   where to support the operator
#   --description <s>   one line about this instance
#   --no-start          provision only, do not launch
#
# Re-running is safe: existing secrets are carried over, so a rebuild never
# changes the identity authority that signed DIDs already minted.

set -euo pipefail

HOSTNAME_ARG=""
DATA_DIR="data"
PORT="2583"
INVITE_REQUIRED="true"
DEVELOPMENT="false"
OPERATOR_NAME=""
OPERATOR_EMAIL=""
OPERATOR_URL=""
SUPPORT_URL=""
INSTANCE_DESC="A personal AT Protocol server."
START=1

while [ $# -gt 0 ]; do
	case "$1" in
		--hostname) HOSTNAME_ARG="${2:-}"; shift 2 ;;
		--data)     DATA_DIR="${2:-}"; shift 2 ;;
		--port)     PORT="${2:-}"; shift 2 ;;
		--open)     INVITE_REQUIRED="false"; shift ;;
		--dev)      DEVELOPMENT="true"; shift ;;
		--operator) OPERATOR_NAME="${2:-}"; shift 2 ;;
		--email)    OPERATOR_EMAIL="${2:-}"; shift 2 ;;
		--operator-url) OPERATOR_URL="${2:-}"; shift 2 ;;
		--support-url)  SUPPORT_URL="${2:-}"; shift 2 ;;
		--description)  INSTANCE_DESC="${2:-}"; shift 2 ;;
		--no-start) START=0; shift ;;
		-h|--help)  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

if [ -z "$HOSTNAME_ARG" ]; then
	echo "error: --hostname is required (e.g. --hostname pds.example.com)" >&2
	exit 2
fi

say() { printf '\033[32m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m==>\033[0m %s\n' "$1" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------- dependencies

say "Checking build dependencies"
MISSING=""
for tool in cmake git curl; do
	command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done

if [ -n "$MISSING" ]; then
	if command -v apt-get >/dev/null 2>&1; then
		say "Installing:$MISSING and libraries (apt)"
		sudo apt-get update -qq
		sudo apt-get install -y -qq \
			build-essential cmake git curl pkg-config \
			libcurl4-openssl-dev libssl-dev libsqlite3-dev \
			libmicrohttpd-dev libsecp256k1-dev zlib1g-dev
	elif command -v brew >/dev/null 2>&1; then
		say "Installing:$MISSING and libraries (brew)"
		brew install cmake git curl openssl sqlite libmicrohttpd secp256k1
	else
		echo "error: missing$MISSING and no apt-get or brew to install them" >&2
		exit 1
	fi
fi

# Wolfram is a sibling checkout by default; fetch it if absent.
if [ ! -d "../wolfram" ] && [ -z "${WOLFRAM_SOURCE_DIR:-}" ]; then
	say "Cloning Wolfram (the SDK MetalBear is built on)"
	git clone --depth 1 https://github.com/ewanc26/wolfram.git ../wolfram
fi

# ---------------------------------------------------------------------- build

say "Building"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" >/dev/null
say "Built $(./build/metalbear --version 2>/dev/null || echo 'build/metalbear')"

# --------------------------------------------------------------------- secrets

CONFIG_FILE="${CONFIG_FILE:-config.toml}"
ENV_FILE="${ENV_FILE:-metalbear.env}"

# Keep any secret that already exists. Regenerating the PLC rotation key would
# orphan every DID this host has already minted: the operations were signed
# with the old key and cannot be updated without it.
keep() {
	local name="$1" toml="$2"
	if [ -f "$ENV_FILE" ] && grep -q "^${name}=" "$ENV_FILE"; then
		grep -m1 "^${name}=" "$ENV_FILE" | cut -d= -f2-
	elif [ -f "$CONFIG_FILE" ] && grep -qE "^[[:space:]]*${toml}[[:space:]]*=" "$CONFIG_FILE"; then
		grep -m1 -E "^[[:space:]]*${toml}[[:space:]]*=" "$CONFIG_FILE" \
			| sed -E 's/.*=[[:space:]]*"([^"]*)".*/\1/'
	fi
}

random_hex() { openssl rand -hex "$1"; }
random_pw()  { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }

PLC_KEY="$(keep METALBEAR_PLC_ROTATION_KEY plc_rotation_key)"
ADMIN_PW="$(keep METALBEAR_ADMIN_PASSWORD admin_password)"
[ -n "$PLC_KEY" ] || { PLC_KEY="$(random_hex 32)"; NEW_PLC=1; }
[ -n "$ADMIN_PW" ] || { ADMIN_PW="$(random_pw)"; NEW_ADMIN=1; }

say "Writing $CONFIG_FILE"
umask 077
cat > "$CONFIG_FILE" <<EOF
# MetalBear configuration, generated by scripts/setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
#
# Contains secrets: keep it out of version control. Every value can also be set
# as an environment variable, and the environment wins, so a per-deployment
# override needs no edit here. See config.example.toml for the full set.

[server]
listen      = "127.0.0.1"
port        = ${PORT}
threads     = 4
data        = "${DATA_DIR}"
service_did = "did:web:${HOSTNAME_ARG}"
public_url  = "https://${HOSTNAME_ARG}"
user_domain = ".${HOSTNAME_ARG}"

[operator]
# Shown on the landing page and, where the protocol defines a field for it,
# published through com.atproto.server.describeServer.
name        = "${OPERATOR_NAME}"
email       = "${OPERATOR_EMAIL}"
url         = "${OPERATOR_URL}"
support_url = "${SUPPORT_URL}"
description = "${INSTANCE_DESC}"

# Marks a testing instance; the landing page says so plainly.
development = ${DEVELOPMENT}

[identity]
plc_url = "https://plc.directory"

# Signs the genesis PLC operation for every DID this host mints. Losing it
# orphans those DIDs: their operations cannot be updated without it.
plc_rotation_key = "${PLC_KEY}"

did_cache_ttl_seconds = 300
did_cache_entries     = 64

[accounts]
# HTTP Basic 'admin:<password>' for admin endpoints, including invite codes.
admin_password  = "${ADMIN_PW}"
invite_required = ${INVITE_REQUIRED}

[limits]
# 100/60 is under two requests a second, which one AppView or a backfilling
# relay exceeds without being abusive.
rate_limit                = 3000
rate_limit_window_seconds = 60
blob_upload_bytes         = 5242880

[firehose]
# Without a crawler a quiet host is never crawled and never federates.
crawlers             = ["https://bsky.network"]
crawl_notify_seconds = 1200
ping_seconds         = 20
retention_max_age_seconds = 2592000
retention_min_events      = 1000

[appview]
url = "https://api.bsky.app"
did = "did:web:api.bsky.app"
EOF

[ "${NEW_PLC:-0}" = 1 ] && warn "Generated a new PLC rotation key. Back up $CONFIG_FILE."
[ "${NEW_ADMIN:-0}" = 1 ] && say "Admin password: $ADMIN_PW"

mkdir -p "$DATA_DIR"

# ----------------------------------------------------------------------- start

if [ "$START" = 0 ]; then
	say "Provisioned. Start with: METALBEAR_CONFIG=$CONFIG_FILE ./build/metalbear"
	exit 0
fi

say "Starting MetalBear on 127.0.0.1:${PORT}"
METALBEAR_CONFIG="$CONFIG_FILE" ./build/metalbear &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
	sleep 1
	curl -sf "http://127.0.0.1:${PORT}/xrpc/_health" >/dev/null 2>&1 && break
done

if ! curl -sf "http://127.0.0.1:${PORT}/xrpc/_health" >/dev/null 2>&1; then
	echo "error: server did not become healthy" >&2
	exit 1
fi

say "Healthy: $(curl -s "http://127.0.0.1:${PORT}/xrpc/_health")"
cat <<EOF

Next steps
  1. Point a TLS reverse proxy at 127.0.0.1:${PORT} for ${HOSTNAME_ARG}.
     WebSocket upgrades must be forwarded, or the firehose will not serve.
  2. Create the first account:

     CODE=\$(curl -sS -u "admin:${ADMIN_PW}" -X POST \\
       -H 'Content-Type: application/json' --data '{"useCount":1}' \\
       https://${HOSTNAME_ARG}/xrpc/com.atproto.server.createInviteCode \\
       | sed -E 's/.*"code":"([^"]+)".*/\\1/')

     curl -sS -X POST -H 'Content-Type: application/json' --data \\
       "{\\"handle\\":\\"you.${HOSTNAME_ARG}\\",\\"email\\":\\"you@example.com\\",
         \\"password\\":\\"...\\",\\"inviteCode\\":\\"\$CODE\\"}" \\
       https://${HOSTNAME_ARG}/xrpc/com.atproto.server.createAccount

  3. Handles under .${HOSTNAME_ARG} need a DNS TXT record to resolve:
       _atproto.you.${HOSTNAME_ARG}  TXT  "did=did:plc:..."

  4. Confirm a relay is consuming the host:
       curl -s "https://bsky.network/xrpc/com.atproto.sync.getHostStatus?hostname=${HOSTNAME_ARG}"
     seq -1 means registered but never consumed; a rising seq means federating.

EOF

wait $PID

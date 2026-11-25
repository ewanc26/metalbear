#!/usr/bin/env bash
#
# setup.sh — build and provision a MetalBear PDS from a clean machine.
#
# Installs build dependencies, builds MetalBear and its Wolfram dependency,
# generates the secrets a host needs, writes a config file, and starts the
# daemon. It does not terminate TLS or configure a reverse proxy: put nginx,
# Caddy or a tunnel in front and point it at the configured port.
#
# Usage:
#   scripts/setup.sh --hostname pds.example.com [options]
#
#   --hostname <host>   public hostname; the service DID becomes did:web:<host>
#   --data <dir>        data directory (default ./data)
#   --port <port>       listen port (default 2583)
#   --format <fmt>      config file dialect: yaml (default) or toml
#   --config <path>     config file path (default config.yaml / config.toml,
#                       matching --format; a name like bear.yml also selects
#                       the dialect, since the loader dispatches on extension)
#   --open              allow registration without invite codes
#   --single-user       one-account host: generate a single_user config and
#                       prompt for the one bootstrap account after the health
#                       check; incompatible with --open and --no-start
#   --dev               mark as a testing instance (says so on the landing page)
#   --local             development instance on http://localhost:<port>: no
#                       --hostname needed, did:web resolves over plain HTTP
#                       (Wolfram special-cases the "localhost" host for this),
#                       no crawler is announced to, and --dev is implied
#   --operator <name>   operator name shown on the landing page
#   --email <addr>      admin contact, published via describeServer
#   --operator-url <u>  operator's own page
#   --support-url <u>   where to support the operator
#   --description <s>   one line about this instance
#   --dns-token <t>     Cloudflare API token with Zone.DNS:Edit
#   --dns-zone <id>     Cloudflare zone ID; with a token, MetalBear writes the
#                       _atproto TXT records that make minted handles resolve
#   --no-start          provision only, do not launch (not with --single-user)
#
# Re-running is safe: existing secrets are carried over, so a rebuild never
# changes the identity authority that signed DIDs already minted. With
# --single-user an existing account is verified through public reads rather
# than created twice.

set -euo pipefail

HOSTNAME_ARG=""
DATA_DIR="data"
PORT="2583"
FORMAT="yaml"
CONFIG_FILE_ARG=""
INVITE_REQUIRED="true"
SINGLE_USER="false"
DEVELOPMENT="false"
LOCAL_DEV="false"
OPERATOR_NAME=""
OPERATOR_EMAIL=""
OPERATOR_URL=""
SUPPORT_URL=""
INSTANCE_DESC="A personal AT Protocol server."
DNS_TOKEN=""
DNS_ZONE=""
START=1
PID=""
TMP_DIR=""

while [ $# -gt 0 ]; do
	case "$1" in
		--hostname) HOSTNAME_ARG="${2:-}"; shift 2 ;;
		--data)     DATA_DIR="${2:-}"; shift 2 ;;
		--port)     PORT="${2:-}"; shift 2 ;;
		--format)   FORMAT="${2:-}"; shift 2 ;;
		--config)   CONFIG_FILE_ARG="${2:-}"; shift 2 ;;
		--open)     INVITE_REQUIRED="false"; shift ;;
		--single-user) SINGLE_USER="true"; shift ;;
		--dev)      DEVELOPMENT="true"; shift ;;
		--local)    LOCAL_DEV="true"; DEVELOPMENT="true"; shift ;;
		--operator) OPERATOR_NAME="${2:-}"; shift 2 ;;
		--email)    OPERATOR_EMAIL="${2:-}"; shift 2 ;;
		--operator-url) OPERATOR_URL="${2:-}"; shift 2 ;;
		--support-url)  SUPPORT_URL="${2:-}"; shift 2 ;;
		--description)  INSTANCE_DESC="${2:-}"; shift 2 ;;
		--dns-token)    DNS_TOKEN="${2:-}"; shift 2 ;;
		--dns-zone)     DNS_ZONE="${2:-}"; shift 2 ;;
		--no-start) START=0; shift ;;
		-h|--help)  sed -n '2,/^set -euo pipefail$/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; exit 0 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

case "$FORMAT" in
	yaml|toml) ;;
	*) echo "error: --format must be 'yaml' or 'toml', got '$FORMAT'" >&2; exit 2 ;;
esac

if [ "$SINGLE_USER" = "true" ]; then
	if [ "$INVITE_REQUIRED" = "false" ]; then
		echo "error: --open is incompatible with --single-user: the one bootstrap account bypasses admission and every later createAccount returns 404" >&2
		exit 2
	fi
	if [ "$START" = 0 ]; then
		echo "error: --no-start is incompatible with --single-user: the one account must be provisioned while the server is running" >&2
		exit 2
	fi
fi

say() { printf '\033[32m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m==>\033[0m %s\n' "$1" >&2; }

if [ -z "$HOSTNAME_ARG" ]; then
	if [ "$LOCAL_DEV" = "true" ]; then
		HOSTNAME_ARG="localhost"
	else
		echo "error: --hostname is required (e.g. --hostname pds.example.com)" >&2
		exit 2
	fi
fi

# did:web's http fallback (Wolfram's did_web_build_url) only triggers for a
# host that is exactly "localhost" or "localhost:<port>" -- a subdomain like
# "pds.localhost" still resolves over https and needs its own TLS.
if [ "$LOCAL_DEV" = "true" ] && [ "$HOSTNAME_ARG" != "localhost" ]; then
	warn "--local with --hostname $HOSTNAME_ARG: did:web resolution stays https unless the hostname is exactly 'localhost'."
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------- dependencies

say "Checking build dependencies"
MISSING=""
for tool in cmake git curl jq; do
	command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done

if [ -n "$MISSING" ]; then
	if command -v apt-get >/dev/null 2>&1; then
		say "Installing:$MISSING and libraries (apt)"
		sudo apt-get update -qq
		sudo apt-get install -y -qq \
			build-essential cmake git curl jq pkg-config \
			libcurl4-openssl-dev libssl-dev libsqlite3-dev \
			libmicrohttpd-dev libsecp256k1-dev zlib1g-dev
	elif command -v brew >/dev/null 2>&1; then
		say "Installing:$MISSING and libraries (brew)"
		brew install cmake git curl jq openssl sqlite libmicrohttpd secp256k1
	else
		echo "error: missing$MISSING and no apt-get or brew to install them" >&2
		exit 1
	fi
fi

# Wolfram is fetched pinned to a released tag by CMake's FetchContent during
# the configure step below -- no sibling checkout required.

# ---------------------------------------------------------------------- build

say "Building"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" >/dev/null
say "Built $(./build/metalbear --version 2>/dev/null || echo 'build/metalbear')"

# --------------------------------------------------------------------- secrets

if [ -n "$CONFIG_FILE_ARG" ]; then
	CONFIG_FILE="$CONFIG_FILE_ARG"
elif [ "$FORMAT" = "yaml" ]; then
	CONFIG_FILE="${CONFIG_FILE:-config.yaml}"
else
	CONFIG_FILE="${CONFIG_FILE:-config.toml}"
fi
ENV_FILE="${ENV_FILE:-metalbear.env}"

# Keep any secret that already exists. Regenerating the PLC rotation key would
# orphan every DID this host has already minted: the operations were signed
# with the old key and cannot be updated without it. Tries both dialects'
# `key = "value"` (TOML) and `key: "value"` (YAML) syntax against whatever is
# on disk, since a re-run can switch --format from what wrote it last time.
keep() {
	local name="$1" key="$2"
	if [ -f "$ENV_FILE" ] && grep -q "^${name}=" "$ENV_FILE"; then
		grep -m1 "^${name}=" "$ENV_FILE" | cut -d= -f2-
	elif [ -f "$CONFIG_FILE" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*[=:]" "$CONFIG_FILE"; then
		grep -m1 -E "^[[:space:]]*${key}[[:space:]]*[=:]" "$CONFIG_FILE" \
			| sed -E 's/.*[=:][[:space:]]*"?([^"]*[^" ])"?[[:space:]]*(#.*)?$/\1/'
	fi
}

random_hex() { openssl rand -hex "$1"; }
random_pw()  { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }

[ -n "$DNS_TOKEN" ] || DNS_TOKEN="$(keep METALBEAR_DNS_API_TOKEN api_token)"
[ -n "$DNS_ZONE" ]  || DNS_ZONE="$(keep METALBEAR_DNS_ZONE_ID zone_id)"

ADMIN_PW="$(keep METALBEAR_ADMIN_PASSWORD admin_password)"
[ -n "$ADMIN_PW" ] || { ADMIN_PW="$(random_pw)"; NEW_ADMIN=1; }

# A local dev instance has no identity.plc_url, so createAccount mints a
# self-certifying did:key instead of a did:plc (account_routes.c falls back
# to did:key precisely when plc_url is unset) -- no PLC rotation key is ever
# used, and generating one would just be a secret to lose track of. Skipping
# plc_url here is also what keeps account creation from reaching the live
# PLC directory at all: a did:plc genesis operation is a permanent, public
# write to a production registry that a throwaway dev account has no
# business making.
if [ "$LOCAL_DEV" != "true" ]; then
	PLC_KEY="$(keep METALBEAR_PLC_ROTATION_KEY plc_rotation_key)"
	[ -n "$PLC_KEY" ] || { PLC_KEY="$(random_hex 32)"; NEW_PLC=1; }
fi

# Single-user leaves the DID-cache and firehose-retention keys out of the
# generated config so the daemon's one-account defaults apply. A rerun must
# not carry the generic multi-account values forward from an older config:
# setup rewrites the file instead of editing it in place.
if [ "$SINGLE_USER" = "true" ]; then
	GENERATED_DID_CACHE_YAML=''
	GENERATED_DID_CACHE_TOML=''
	GENERATED_RETENTION_MIN_YAML=''
	GENERATED_RETENTION_MIN_TOML=''
else
	GENERATED_DID_CACHE_YAML='  did_cache_entries: 64'
	GENERATED_DID_CACHE_TOML='did_cache_entries     = 64'
	GENERATED_RETENTION_MIN_YAML='  retention_min_events: 1000'
	GENERATED_RETENTION_MIN_TOML='retention_min_events      = 1000'
fi

# A local dev instance is addressed directly at http://<host>:<port> --
# there's no reverse proxy terminating TLS in front of it -- so the DID and
# public URL must say so explicitly rather than deriving the usual
# https://<host> shape. did:web percent-encodes the port as %3A.
if [ "$LOCAL_DEV" = "true" ]; then
	SERVICE_DID="did:web:${HOSTNAME_ARG}%3A${PORT}"
	PUBLIC_URL="http://${HOSTNAME_ARG}:${PORT}"
	IDENTITY_YAML='identity:
  # No plc_url: accounts mint a self-certifying did:key instead of a
  # did:plc, so account creation never reaches the live PLC directory. Set
  # plc_url (and rerun without --local) to test did:plc for real.
  did_cache_ttl_seconds: 300
  did_cache_entries: 64'
	IDENTITY_TOML='[identity]
# No plc_url: accounts mint a self-certifying did:key instead of a
# did:plc, so account creation never reaches the live PLC directory. Set
# plc_url (and rerun without --local) to test did:plc for real.
did_cache_ttl_seconds = 300
did_cache_entries     = 64'
	FIREHOSE_YAML='firehose:
  # A local dev instance is not meant to federate, so no crawler is announced
  # to. Add one back (e.g. crawlers: ["https://bsky.network"]) if this host
  # needs to reach a real relay.
  crawl_notify_seconds: 1200
  ping_seconds: 20
  retention_max_age_seconds: 2592000
  retention_min_events: 1000'
	FIREHOSE_TOML='[firehose]
# A local dev instance is not meant to federate, so no crawler is announced
# to. Add one back (e.g. crawlers = ["https://bsky.network"]) if this host
# needs to reach a real relay.
crawl_notify_seconds = 1200
ping_seconds         = 20
retention_max_age_seconds = 2592000
retention_min_events      = 1000'
else
	SERVICE_DID="did:web:${HOSTNAME_ARG}"
	PUBLIC_URL="https://${HOSTNAME_ARG}"
	IDENTITY_YAML='identity:
  plc_url: "https://plc.directory"

  # Signs the genesis PLC operation for every DID this host mints. Losing it
  # orphans those DIDs: their operations cannot be updated without it.
  plc_rotation_key: "'"${PLC_KEY}"'"

  did_cache_ttl_seconds: 300
  did_cache_entries: 64'
	IDENTITY_TOML='[identity]
plc_url = "https://plc.directory"

# Signs the genesis PLC operation for every DID this host mints. Losing it
# orphans those DIDs: their operations cannot be updated without it.
plc_rotation_key = "'"${PLC_KEY}"'"

did_cache_ttl_seconds = 300
did_cache_entries     = 64'
	FIREHOSE_YAML='firehose:
  # Without a crawler a quiet host is never crawled and never federates.
  crawlers: ["https://bsky.network"]
  crawl_notify_seconds: 1200
  ping_seconds: 20
  retention_max_age_seconds: 2592000
  retention_min_events: 1000'
	FIREHOSE_TOML='[firehose]
# Without a crawler a quiet host is never crawled and never federates.
crawlers             = ["https://bsky.network"]
crawl_notify_seconds = 1200
ping_seconds         = 20
retention_max_age_seconds = 2592000
retention_min_events      = 1000'
fi

# Drop the generic multi-account values for a one-account host so the daemon's
# smaller defaults take effect. The replacement is empty in single-user mode
# and restores the original lines otherwise.
IDENTITY_YAML="${IDENTITY_YAML/  did_cache_entries: 64/${GENERATED_DID_CACHE_YAML}}"
IDENTITY_TOML="${IDENTITY_TOML/did_cache_entries     = 64/${GENERATED_DID_CACHE_TOML}}"
FIREHOSE_YAML="${FIREHOSE_YAML/  retention_min_events: 1000/${GENERATED_RETENTION_MIN_YAML}}"
FIREHOSE_TOML="${FIREHOSE_TOML/retention_min_events      = 1000/${GENERATED_RETENTION_MIN_TOML}}"

# Single-user emits only keys the strict loader knows: one worker and the
# restriction flag. The daemon supplies the remaining lightweight defaults
# (resident accounts, DID cache, firehose floor) when they are unset.
if [ "$SINGLE_USER" = "true" ]; then
	THREADS=1
	SERVER_SINGLE_USER_YAML='  single_user: true'
	SERVER_SINGLE_USER_TOML='single_user = true'
else
	THREADS=4
	SERVER_SINGLE_USER_YAML=''
	SERVER_SINGLE_USER_TOML=''
fi

say "Writing $CONFIG_FILE ($FORMAT)"
umask 077
if [ "$FORMAT" = "yaml" ]; then
cat > "$CONFIG_FILE" <<EOF
# MetalBear configuration, generated by scripts/setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
#
# Contains secrets: keep it out of version control. Every value can also be set
# as an environment variable, and the environment wins, so a per-deployment
# override needs no edit here. See config.example.yaml for the full set.

server:
  listen: "127.0.0.1"
  port: ${PORT}
  threads: ${THREADS}
${SERVER_SINGLE_USER_YAML}
  data: "${DATA_DIR}"
  service_did: "${SERVICE_DID}"
  public_url: "${PUBLIC_URL}"
  user_domain: ".${HOSTNAME_ARG}"

operator:
  # Shown on the landing page and, where the protocol defines a field for it,
  # published through com.atproto.server.describeServer.
  name: "${OPERATOR_NAME}"
  email: "${OPERATOR_EMAIL}"
  url: "${OPERATOR_URL}"
  support_url: "${SUPPORT_URL}"
  description: "${INSTANCE_DESC}"

  # Marks a testing instance; the landing page says so plainly.
  development: ${DEVELOPMENT}

${IDENTITY_YAML}

accounts:
  # HTTP Basic 'admin:<password>' for admin endpoints, including invite codes.
  admin_password: "${ADMIN_PW}"
  invite_required: ${INVITE_REQUIRED}

limits:
  # 100/60 is under two requests a second, which one AppView or a backfilling
  # relay exceeds without being abusive.
  rate_limit: 3000
  rate_limit_window_seconds: 60
  blob_upload_bytes: 5242880

${FIREHOSE_YAML}

appview:
  url: "https://api.bsky.app"
  did: "did:web:api.bsky.app"
EOF
else
cat > "$CONFIG_FILE" <<EOF
# MetalBear configuration, generated by scripts/setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
#
# Contains secrets: keep it out of version control. Every value can also be set
# as an environment variable, and the environment wins, so a per-deployment
# override needs no edit here. See config.example.toml for the full set.

[server]
listen      = "127.0.0.1"
port        = ${PORT}
threads     = ${THREADS}
${SERVER_SINGLE_USER_TOML}
data        = "${DATA_DIR}"
service_did = "${SERVICE_DID}"
public_url  = "${PUBLIC_URL}"
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

${IDENTITY_TOML}

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
repo_bytes                = 0
blob_bytes                = 0

${FIREHOSE_TOML}

[appview]
url = "https://api.bsky.app"
did = "did:web:api.bsky.app"
EOF
fi

# Drop optional fields left empty (not every deployment sets an operator
# email, url or support url). An empty quoted string is invalid input to the
# loader -- "absent" and "empty" are different states, and this config only
# has a way to say the former -- so a line that says nothing is better left
# out entirely, matching "a setting left out keeps its default".
sed -i.bak -E '/=[[:space:]]*""[[:space:]]*$/d; /:[[:space:]]*""[[:space:]]*$/d' \
	"$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"

# Only with both halves: a provider named without credentials is refused at
# startup, on purpose, so a half-written section would leave the host unable to
# boot rather than merely unable to write records.
if [ -n "$DNS_TOKEN" ] && [ -n "$DNS_ZONE" ] && [ "$FORMAT" = "yaml" ]; then
	cat >> "$CONFIG_FILE" <<EOF

dns:
  # Writes _atproto.<handle> TXT records on account creation, so handles
  # minted under .${HOSTNAME_ARG} resolve without a record per account by hand.
  provider: "cloudflare"
  api_token: "${DNS_TOKEN}"
  zone_id: "${DNS_ZONE}"
  ttl: 300
EOF
	say "Handle DNS records will be published via Cloudflare"
elif [ -n "$DNS_TOKEN" ] && [ -n "$DNS_ZONE" ]; then
	cat >> "$CONFIG_FILE" <<EOF

[dns]
# Writes _atproto.<handle> TXT records on account creation, so handles minted
# under .${HOSTNAME_ARG} resolve without a record per account by hand.
provider  = "cloudflare"
api_token = "${DNS_TOKEN}"
zone_id   = "${DNS_ZONE}"
ttl       = 300
EOF
	say "Handle DNS records will be published via Cloudflare"
elif [ -n "$DNS_TOKEN" ] || [ -n "$DNS_ZONE" ]; then
	warn "Ignoring the DNS credential: --dns-token and --dns-zone are both needed."
fi

[ "${NEW_PLC:-0}" = 1 ] && warn "Generated a new PLC rotation key. Back up $CONFIG_FILE."

# Never print the admin password: terminal output gets copied into issues and
# CI logs. The admin CLI sources this 0600 file instead. Keep any other
# settings the operator already put in it; only the two we own are rewritten.
write_env_file() {
	local env_tmp line
	env_tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
	chmod 600 "$env_tmp"
	if [ -f "$ENV_FILE" ]; then
		while IFS= read -r line || [ -n "$line" ]; do
			case "$line" in
				METALBEAR_ADMIN_PASSWORD=*|METALBEAR_HOSTNAME=*) continue ;;
			esac
			printf '%s\n' "$line" >> "$env_tmp"
		done < "$ENV_FILE"
	fi
	{
		printf 'METALBEAR_HOSTNAME=%s\n' "$HOSTNAME_ARG"
		printf 'METALBEAR_ADMIN_PASSWORD=%s\n' "$ADMIN_PW"
	} >> "$env_tmp"
	mv -f "$env_tmp" "$ENV_FILE"
	chmod 600 "$ENV_FILE"
	say "Admin password written to $ENV_FILE (0600) for the admin CLI"
}
write_env_file

# One account only. The server flag bypasses admission for the first
# createAccount and makes every later one return 404, so no invite code and no
# admin call is involved here. listRepos has no handle field in this lexicon,
# so it establishes which DID owns the host and resolveHandle checks the
# handle the operator typed against that DID.
provision_single_user_account() {
	local handle="" email="" password="" confirmation=""
	local existing_count existing_did resolved_did http_code did
	local repos_file handle_file password_file request_file response_file

	printf 'Handle for the one account (e.g. alice.%s): ' "$HOSTNAME_ARG"
	IFS= read -r handle || { echo "error: a handle is required" >&2; exit 1; }
	[ -n "$handle" ] || { echo "error: a handle is required" >&2; exit 1; }

	TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/metalbear-single-user.XXXXXX")"
	chmod 700 "$TMP_DIR"
	repos_file="$TMP_DIR/repos.json"
	handle_file="$TMP_DIR/handle.json"

	# resolveHandle is the authoritative public read for "does this handle
	# already exist here?" A fresh account has no repo head, so listRepos may
	# legitimately be empty until its first post. Never use it alone to decide
	# whether to create the one account.
	http_code="$(curl -sS -G --data-urlencode "handle=$handle" \
		-o "$handle_file" -w '%{http_code}' \
		"http://127.0.0.1:${PORT}/xrpc/com.atproto.identity.resolveHandle")" || {
			echo "error: could not resolve $handle on this host" >&2
			exit 1
		}
	case "$http_code" in
		2??) resolved_did="$(jq -r '.did // empty' "$handle_file")"
			[ -n "$resolved_did" ] || {
				echo "error: resolveHandle returned no DID for $handle" >&2
				exit 1
			} ;;
		4??) resolved_did="" ;;
		*) echo "error: resolveHandle returned HTTP $http_code for $handle" >&2
			exit 1 ;;
	esac

	if ! curl -sf "http://127.0.0.1:${PORT}/xrpc/com.atproto.sync.listRepos?limit=2" \
		-o "$repos_file"; then
		echo "error: could not read the account list from this host" >&2
		exit 1
	fi
	if ! jq -e '.repos | type == "array"' "$repos_file" >/dev/null 2>&1; then
		echo "error: com.atproto.sync.listRepos returned an unexpected response" >&2
		exit 1
	fi

	existing_count="$(jq -r '.repos | length' "$repos_file")"
	if [ "$existing_count" -gt 1 ] || [ -n "$(jq -r '.cursor // empty' "$repos_file")" ]; then
		echo "error: single-user mode needs an empty or one-account data directory; found more than one repo" >&2
		exit 1
	fi
	if [ "$existing_count" -eq 1 ]; then
		existing_did="$(jq -r '.repos[0].did // empty' "$repos_file")"
		if [ "$resolved_did" != "$existing_did" ]; then
			echo "error: this host already has account $existing_did, not $handle" >&2
			echo "       rerun with the handle of the existing account" >&2
			exit 1
		fi
	fi
	if [ -n "$resolved_did" ]; then
		say "Account $handle ($resolved_did) is already provisioned; skipping account creation."
		return 0
	fi

	if [ ! -t 0 ]; then
		echo "error: --single-user needs an interactive terminal to read the account password" >&2
		exit 1
	fi
	IFS= read -r -p "Email for $handle: " email || {
		echo "error: an email address is required" >&2; exit 1; }
	[ -n "$email" ] || { echo "error: an email address is required" >&2; exit 1; }
	IFS= read -r -s -p "Password: " password || {
		echo "error: a password is required" >&2; exit 1; }
	printf '\n'
	[ -n "$password" ] || { echo "error: a password is required" >&2; exit 1; }
	IFS= read -r -s -p "Confirm password: " confirmation || {
		echo "error: a password is required" >&2; exit 1; }
	printf '\n'
	if [ "$password" != "$confirmation" ]; then
		echo "error: passwords do not match" >&2
		exit 1
	fi
	unset confirmation

	password_file="$TMP_DIR/password"
	request_file="$TMP_DIR/create-account.json"
	response_file="$TMP_DIR/create-account-response.json"
	for file in "$password_file" "$request_file" "$response_file"; do
		: > "$file"
		chmod 600 "$file"
	done
	printf '%s' "$password" > "$password_file"
	unset password
	jq -n --arg handle "$handle" --arg email "$email" --rawfile password "$password_file" \
		'{handle: $handle, email: $email, password: $password}' > "$request_file"
	unset email

	http_code="$(curl -sS -o "$response_file" -w '%{http_code}' -X POST \
		-H 'Content-Type: application/json' --data-binary @"$request_file" \
		"http://127.0.0.1:${PORT}/xrpc/com.atproto.server.createAccount")" || {
			echo "error: createAccount request failed" >&2; exit 1; }
	case "$http_code" in
		2??) ;;
		*) echo "error: createAccount returned HTTP $http_code: $(jq -r '.message // .error // "unknown error"' "$response_file" 2>/dev/null)" >&2
			exit 1 ;;
	esac
	did="$(jq -r '.did // empty' "$response_file")"
	[ -n "$did" ] || { echo "error: createAccount did not return a DID" >&2; exit 1; }
	say "Provisioned $handle ($did)"
}

cleanup() {
	if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; fi
	if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi
}
trap cleanup EXIT

mkdir -p "$DATA_DIR"

# ----------------------------------------------------------------------- start

if [ "$START" = 0 ]; then
	say "Provisioned. Start with: METALBEAR_CONFIG=$CONFIG_FILE ./build/metalbear"
	exit 0
fi

say "Starting MetalBear on 127.0.0.1:${PORT}"
METALBEAR_CONFIG="$CONFIG_FILE" ./build/metalbear &
PID=$!

for _ in $(seq 1 30); do
	sleep 1
	curl -sf "http://127.0.0.1:${PORT}/xrpc/_health" >/dev/null 2>&1 && break
done

if ! curl -sf "http://127.0.0.1:${PORT}/xrpc/_health" >/dev/null 2>&1; then
	echo "error: server did not become healthy" >&2
	exit 1
fi

say "Healthy: $(curl -s "http://127.0.0.1:${PORT}/xrpc/_health")"

if [ "$SINGLE_USER" = "true" ]; then
	provision_single_user_account

	if [ "$LOCAL_DEV" = "true" ]; then
		SU_URL="$PUBLIC_URL"
		SU_HOST_NOTE="This is a local dev instance: no TLS, no DNS, no crawler. Talk to it directly at ${PUBLIC_URL}."
		SU_DNS_NOTE="Handle and DID resolution for the one account stay local -- no DNS or plc.directory lookup leaves the machine -- so an app that insists on resolving over the open network will not find it."
		SU_RELAY_NOTE=""
	else
		SU_URL="https://${HOSTNAME_ARG}"
		SU_HOST_NOTE="Point a TLS reverse proxy at 127.0.0.1:${PORT} for ${HOSTNAME_ARG}. WebSocket upgrades must be forwarded, or the firehose will not serve."
		if [ -n "$DNS_TOKEN" ] && [ -n "$DNS_ZONE" ]; then
			SU_DNS_NOTE="Handle TXT records are written automatically on account creation."
		else
			SU_DNS_NOTE="The one handle under .${HOSTNAME_ARG} needs a DNS TXT record to resolve. Pass --dns-token and --dns-zone to have MetalBear write it."
		fi
		SU_RELAY_NOTE="  4. Confirm a relay is consuming the host:
       curl -s \"https://bsky.network/xrpc/com.atproto.sync.getHostStatus?hostname=${HOSTNAME_ARG}\"
     seq -1 means registered but never consumed; a rising seq means federating."
	fi

	cat <<EOF

Next steps (single-user)
  1. ${SU_HOST_NOTE}
  2. Sign in at ${SU_URL} with the handle you entered above. That is the only
     account: a second createAccount returns 404, as do invite codes, the
     com.atproto.admin.* endpoints and the bundled /admin and /signup pages.
     The admin password is in ${ENV_FILE} (0600) for the admin CLI, but there
     are no admin endpoints to drive in this mode.
  3. Federation is unchanged: crawlers, the firehose, blobs and OAuth behave as
     on a multi-account host. ${SU_DNS_NOTE}

${SU_RELAY_NOTE}
EOF
elif [ "$LOCAL_DEV" = "true" ]; then
cat <<EOF

Next steps
  1. This is a local dev instance: no TLS, no DNS, no crawler. Talk to it
     directly at ${PUBLIC_URL}.
  2. Create the first account:

     . "${ENV_FILE}"   # 0600; defines METALBEAR_ADMIN_PASSWORD
     CODE=\$(curl -sS -u "admin:\${METALBEAR_ADMIN_PASSWORD}" -X POST \\
       -H 'Content-Type: application/json' --data '{"useCount":1}' \\
       ${PUBLIC_URL}/xrpc/com.atproto.server.createInviteCode \\
       | sed -E 's/.*"code":"([^"]+)".*/\\1/')

     curl -sS -X POST -H 'Content-Type: application/json' --data \\
       "{\\"handle\\":\\"you.${HOSTNAME_ARG}\\",\\"email\\":\\"you@example.com\\",
         \\"password\\":\\"...\\",\\"inviteCode\\":\\"\$CODE\\"}" \\
       ${PUBLIC_URL}/xrpc/com.atproto.server.createAccount

  3. Point your client's PDS URL at ${PUBLIC_URL}. Handle and DID resolution
     for accounts on this host stay local -- no DNS or plc.directory lookup
     leaves the machine -- so an app that insists on resolving over the open
     network (rather than asking this PDS directly) will not find them.

EOF
else
	if [ -n "$DNS_TOKEN" ] && [ -n "$DNS_ZONE" ]; then
		DNS_NOTE="Handle TXT records are written automatically on account creation."
	else
		DNS_NOTE="Handles under .${HOSTNAME_ARG} need a DNS TXT record to resolve:
       _atproto.you.${HOSTNAME_ARG}  TXT  \"did=did:plc:...\"
     Pass --dns-token and --dns-zone to have MetalBear write them."
	fi

cat <<EOF

Next steps
  1. Point a TLS reverse proxy at 127.0.0.1:${PORT} for ${HOSTNAME_ARG}.
     WebSocket upgrades must be forwarded, or the firehose will not serve.
  2. Create the first account:

     . "${ENV_FILE}"   # 0600; defines METALBEAR_ADMIN_PASSWORD
     CODE=\$(curl -sS -u "admin:\${METALBEAR_ADMIN_PASSWORD}" -X POST \\
       -H 'Content-Type: application/json' --data '{"useCount":1}' \\
       https://${HOSTNAME_ARG}/xrpc/com.atproto.server.createInviteCode \\
       | sed -E 's/.*"code":"([^"]+)".*/\\1/')

     curl -sS -X POST -H 'Content-Type: application/json' --data \\
       "{\\"handle\\":\\"you.${HOSTNAME_ARG}\\",\\"email\\":\\"you@example.com\\",
         \\"password\\":\\"...\\",\\"inviteCode\\":\\"\$CODE\\"}" \\
       https://${HOSTNAME_ARG}/xrpc/com.atproto.server.createAccount

  3. ${DNS_NOTE}

  4. Confirm a relay is consuming the host:
       curl -s "https://bsky.network/xrpc/com.atproto.sync.getHostStatus?hostname=${HOSTNAME_ARG}"
     seq -1 means registered but never consumed; a rising seq means federating.

EOF
fi

wait $PID

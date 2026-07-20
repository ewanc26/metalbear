#!/usr/bin/env bash
#
# metalbear-admin — MetalBear PDS admin CLI (mirrors refpds `pdsadmin`).
#
# Drives MetalBear's XRPC admin endpoints with curl, exactly like the
# reference PDS admin scripts. Reads configuration from a `metalbear.env`
# file (override with METALBEAR_ENV_FILE) or from METALBEAR_* env vars.
#
# Unlike refpds this script does NOT require root.
#
# Subcommands:
#   account list                       List hosted accounts
#   account create <EMAIL> <HANDLE>   Create a new account
#   create-invite-code [useCount]    Mint an invite code (admin)
#   request-crawl [HOST,...]           Ask crawlers/relays to crawl this PDS
#
set -o errexit
set -o nounset
set -o pipefail

# ---- config loading -------------------------------------------------------
METALBEAR_ENV_FILE="${METALBEAR_ENV_FILE:-./metalbear.env}"
if [[ -f "${METALBEAR_ENV_FILE}" ]]; then
  # shellcheck source=./metalbear.env
  source "${METALBEAR_ENV_FILE}"
fi

# ---- curl helpers (mirror refpds) ----------------------------------------
function curl_cmd_get {
  curl --fail --silent --show-error "$@"
}

function curl_cmd_post {
  curl --fail --silent --show-error --request POST \
       --header "Content-Type: application/json" "$@"
}

function curl_cmd_post_nofail {
  curl --silent --show-error --request POST \
       --header "Content-Type: application/json" "$@"
}

# ---- subcommand dispatch --------------------------------------------------
COMMAND="${1:-help}"
shift || true

if [[ "${COMMAND}" == "account" ]]; then
  SUBCOMMAND="${1:-}"
  shift || true

  # ---- account list ----
  if [[ "${SUBCOMMAND}" == "list" ]]; then
    if [[ -z "${METALBEAR_HOSTNAME:-}" ]]; then
      echo "ERROR: METALBEAR_HOSTNAME is not set" >/dev/stderr
      exit 1
    fi
    DIDS="$(curl_cmd_get \
      "https://${METALBEAR_HOSTNAME}/xrpc/com.atproto.sync.listRepos?limit=100" \
      | jq --raw-output '.repos[].did')"
    OUTPUT='[{"handle":"Handle","email":"Email","did":"DID"}'
    for did in ${DIDS}; do
      ITEM="$(curl_cmd_get \
        --user "admin:${METALBEAR_ADMIN_PASSWORD}" \
        "https://${METALBEAR_HOSTNAME}/xrpc/com.atproto.admin.getAccountInfo?did=${did}" \
        | jq --arg did "${did}" \
              '{ handle: .handle, email: (.email // ""), did: $did }')"
      OUTPUT="${OUTPUT},${ITEM}"
    done
    OUTPUT="${OUTPUT}]"
    echo "${OUTPUT}" \
      | jq --raw-output '.[] | [.handle, .email, .did] | @tsv' \
      | column --table

  # ---- account create ----
  elif [[ "${SUBCOMMAND}" == "create" ]]; then
    EMAIL="${1:-}"
    HANDLE="${2:-}"

    if [[ -z "${EMAIL}" ]]; then
      read -r -p "Enter an email address (e.g. alice@${METALBEAR_HOSTNAME}): " EMAIL
    fi
    if [[ -z "${HANDLE}" ]]; then
      read -r -p "Enter a handle (e.g. alice.${METALBEAR_HOSTNAME}): " HANDLE
    fi

    if [[ -z "${EMAIL}" || -z "${HANDLE}" ]]; then
      echo "ERROR: missing EMAIL and/or HANDLE parameters." >/dev/stderr
      echo "Usage: $0 account create <EMAIL> <HANDLE>" >/dev/stderr
      exit 1
    fi

    PASSWORD="$(openssl rand -base64 30 | tr -d "=+/" | cut -c1-24)"
    INVITE_CODE="$(curl_cmd_post \
      --user "admin:${METALBEAR_ADMIN_PASSWORD}" \
      --data '{"useCount": 1}' \
      "https://${METALBEAR_HOSTNAME}/xrpc/com.atproto.server.createInviteCode" \
      | jq --raw-output '.code')"
    RESULT="$(curl_cmd_post_nofail \
      --data "{\"email\":\"${EMAIL}\", \"handle\":\"${HANDLE}\", \"password\":\"${PASSWORD}\", \"inviteCode\":\"${INVITE_CODE}\"}" \
      "https://${METALBEAR_HOSTNAME}/xrpc/com.atproto.server.createAccount")"

    DID="$(echo "${RESULT}" | jq --raw-output '.did')"
    if [[ "${DID}" != did:* ]]; then
      ERR="$(echo "${RESULT}" | jq --raw-output '.message')"
      echo "ERROR: ${ERR}" >/dev/stderr
      echo "Usage: $0 account create <EMAIL> <HANDLE>" >/dev/stderr
      exit 1
    fi

    echo
    echo "Account created successfully!"
    echo "-----------------------------"
    echo "Handle   : ${HANDLE}"
    echo "DID      : ${DID}"
    echo "Password : ${PASSWORD}"
    echo "-----------------------------"
    echo "Save this password, it will not be displayed again."
    echo

  else
    echo "Unknown subcommand: account ${SUBCOMMAND}" >/dev/stderr
    exit 1
  fi

elif [[ "${COMMAND}" == "create-invite-code" ]]; then
  USE_COUNT="${1:-1}"
  if [[ -z "${METALBEAR_HOSTNAME:-}" ]]; then
    echo "ERROR: METALBEAR_HOSTNAME is not set" >/dev/stderr
    exit 1
  fi
  curl_cmd_post \
    --user "admin:${METALBEAR_ADMIN_PASSWORD}" \
    --data "{\"useCount\": ${USE_COUNT}}" \
    "https://${METALBEAR_HOSTNAME}/xrpc/com.atproto.server.createInviteCode" \
    | jq --raw-output '.code'

elif [[ "${COMMAND}" == "request-crawl" ]]; then
  RELAY_HOSTS="${1:-}"
  if [[ -z "${RELAY_HOSTS}" ]]; then
    RELAY_HOSTS="${METALBEAR_CRAWLERS:-}"
  fi
  if [[ -z "${RELAY_HOSTS}" ]]; then
    echo "ERROR: missing RELAY HOST parameter." >/dev/stderr
    echo "Usage: $0 request-crawl <RELAY HOST>[,<RELAY HOST>,...]" >/dev/stderr
    exit 1
  fi
  if [[ -z "${METALBEAR_HOSTNAME:-}" ]]; then
    echo "ERROR: METALBEAR_HOSTNAME is not set" >/dev/stderr
    exit 1
  fi

  for host in ${RELAY_HOSTS//,/ }; do
    echo "Requesting crawl from ${host}"
    if [[ "${host}" != https:* && "${host}" != http:* ]]; then
      host="https://${host}"
    fi
    curl \
      --fail \
      --silent \
      --show-error \
      --request POST \
      --header "Content-Type: application/json" \
      --data "{\"hostname\": \"${METALBEAR_HOSTNAME}\"}" \
      "${host}/xrpc/com.atproto.sync.requestCrawl" >/dev/null
  done
  echo "done"

else
  cat <<'EOF'
MetalBear admin CLI (mirrors refpds `pdsadmin`)

Usage:
  metalbear-admin account list
  metalbear-admin account create <EMAIL> <HANDLE>
  metalbear-admin create-invite-code [useCount]
  metalbear-admin request-crawl [RELAY HOST,...]

Configuration: sourced from METALBEAR_ENV_FILE (default ./metalbear.env)
or the METALBEAR_* environment variables (METALBEAR_HOSTNAME,
METALBEAR_ADMIN_PASSWORD, METALBEAR_CRAWLERS).
EOF
  exit 1
fi

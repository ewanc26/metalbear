<p align="center">
  <img src="docs/logo.svg" alt="MetalBear" width="420">
</p>

# MetalBear

MetalBear is an AT Protocol Personal Data Server written in C11 and built on
[Wolfram](https://github.com/ewanc26/wolfram). It hosts multiple accounts, mints
`did:plc` identities, serves the firehose, and federates: as of 0.4.1 a
MetalBear instance is consumed by Bluesky's relays and its posts are indexed by
the Bluesky AppView.

**Version:** 0.5.0

## Core Features

- `com.atproto.server.describeServer`, `createSession`, `getSession`,
  `refreshSession`, and `deleteSession`
- restart-persistent, HS256-signed AT Protocol access/refresh JWTs with refresh
  rotation, a bounded reuse grace period, and revocation
- durable standard and privileged app passwords with one-time password display,
  scope-preserving sessions, listing, and revocation of associated refresh chains
- repository-key-signed `com.atproto.server.getServiceAuth` JWT issuance with
  audience, method, protected-method, and expiration validation
- authenticated `com.atproto.repo` record creation, update, deletion, batch
  writes, and CAR import
- public record reads, collection listing, repo description, and latest commit
- full or revision-filtered CAR repository export and CID-selected block export
- public repository status, single-account repository enumeration, and
  `com.atproto.sync.listBlobs` enumeration (backed by Wolfram's
  `wf_blob_store_list`, with limit/cursor pagination)
- durable `com.atproto.sync.subscribeRepos` sequencing with live commit events,
  cursor replay across restarts, import sync events, and `FutureCursor` errors
- `com.atproto.identity.resolveHandle`, `/.well-known/atproto-did` handle
  resolution, and a `did:web` service document
- `com.atproto.identity.updateHandle` (constrained to the configured user
  domain) and
  `com.atproto.identity.getRecommendedDidCredentials` exposing the account's
  signing key, rotation keys, alsoKnownAs, and PDS service endpoint
- durable account deactivation/reactivation with repository availability,
  session/status reporting, and account/identity/sync firehose events
- `com.atproto.server.checkAccountStatus` with activation, DID validity, and
  repository head reporting
- `com.atproto.server.reserveSigningKey` returning a fresh `did:key` without
  disrupting the active repository signing key
- `com.atproto.server.createInviteCode` and `createInviteCodes` generating real
  single-account invite codes
- session/account responses carrying the lexicon `emailAuthFactor` flag
- durable SQLite-backed signed repositories and file-backed blob upload/serving

## Admin Endpoints

Admin-gated `com.atproto.admin.*` procedures require HTTP Basic auth with the
configured admin password:

- `com.atproto.admin.getAccountInfo` — resolve DID to handle/email/active state
- `com.atproto.admin.sendEmail` — send templated email to an account
- `com.atproto.admin.getInviteCodes` — list invite codes with account/use metadata
- `com.atproto.admin.disableInviteCodes` — disable invite codes by exact code or
  by account
- `com.atproto.admin.deleteAccount` — permanently remove an account, its data
  directory, and its registry entry
- `com.atproto.admin.updateSubjectStatus` — apply takedown, deactivation, or
  reactivation status to a repo, record, or blob subject
- `com.atproto.admin.updateAccountPassword` — reset an account password (admin)
- `com.atproto.admin.enableAccountInvites` / `disableAccountInvites` — toggle
  whether an account may create invite codes

## OAuth Authorization Server

Full OAuth 2.0 authorization server endpoints for AT Protocol OAuth flows:

- `GET /.well-known/oauth-authorization-server` - RFC 8414 server metadata
  with AT Protocol-specific extensions (DPoP, PKCE S256, PAR required)
- `GET /.well-known/oauth-protected-resource` - RFC 9728 resource metadata
- `GET /oauth/jwks` - ES256 public JSON Web Key Set
- `POST /oauth/par` - Pushed Authorization Request (RFC 9126)
- `GET /oauth/authorize` - Authorization endpoint with auto-approval
- `POST /oauth/token` - Token endpoint (authorization code + refresh grants)
- `POST /oauth/revoke` - Token revocation (RFC 7009)

## Account Management

- `com.atproto.server.requestAccountDelete` - Request account deletion with
  email confirmation (when SMTP configured)
- `com.atproto.server.deleteAccount` - Delete account: revokes all sessions,
  removes credentials, deactivates account, emits firehose deletion event
- Account registry for multi-account hosting (database-backed)

## Email Integration

SMTP-based email delivery for account operations:

- Account deletion confirmation emails
- Password reset emails (when configured)
- Email verification emails (when configured)
- Configurable SMTP host, port, authentication, and STARTTLS

## Backups

Repository backup and restore tooling:

- Create compressed backups of all SQLite databases and blob storage
- Verify backup integrity with CRC32 checksums
- Restore from backup to a new data directory
- Automatic directory creation during restore

## Firehose Retention

Automatic pruning of old firehose events:

- Configurable maximum event age (default: 30 days)
- Minimum event count guarantee (default: 1000 events)
- Retention applied on server startup

## Key Rotation

- Persistent signing key store with P-256 key generation
- `metalbear_key_rotation_rotate()` for safe key rotation
- Keys survive daemon restarts

## Admin CLI

The `pdsadmin/metalbear-admin.sh` script mirrors the reference PDS admin tooling:

```sh
./pdsadmin/metalbear-admin.sh account list
./pdsadmin/metalbear-admin.sh account create alice@example.com alice.example.com
./pdsadmin/metalbear-admin.sh account delete did:plc:...
./pdsadmin/metalbear-admin.sh account takedown did:plc:...
./pdsadmin/metalbear-admin.sh account untakedown did:plc:...
./pdsadmin/metalbear-admin.sh account reset-password did:plc:...
./pdsadmin/metalbear-admin.sh create-invite-code [useCount]
./pdsadmin/metalbear-admin.sh request-crawl [RELAY HOST,...]
```

## Operational

- Per-IP token-bucket rate limiting (100 requests/60 seconds default)
- Configurable listen address and port
- Optional email notifications for account operations
- Automatic firehose event retention
- Dynamic landing page at `/` listing hosted accounts and version

## Install

### Container

```sh
docker run -d --name metalbear -p 2583:2583 -v metalbear-data:/data \
  -e METALBEAR_SERVICE_DID=did:web:pds.example.com \
  -e METALBEAR_USER_DOMAIN=.pds.example.com \
  ghcr.io/ewanc26/metalbear:latest
```

Built for `linux/amd64` and `linux/arm64`. Mount a `config.toml` and set
`METALBEAR_CONFIG` to configure it as a file instead; environment variables
override whatever the file says.

### Prebuilt binaries

Each [release](https://github.com/ewanc26/metalbear/releases) carries archives
for Linux (x86_64, aarch64) and macOS (arm64, x86_64), containing the binary,
the lexicon corpus, and an example configuration. They link the system's TLS,
HTTP, SQLite and crypto libraries, so those must be installed:

```sh
apt install libsqlite3-0 libcurl4 libssl3 libsecp256k1-1 libmicrohttpd12 \
            libzstd1 zlib1g                                    # Debian/Ubuntu
brew install openssl@3 sqlite libmicrohttpd secp256k1 zstd     # macOS
```

MetalBear does not terminate TLS. Bind it to loopback and put a reverse proxy
in front, forwarding WebSocket upgrades — without those the firehose will not
serve and the host will never federate.

## Build and test

Wolfram's server dependencies are required (`libmicrohttpd`, SQLite,
libsecp256k1, OpenSSL, and libcurl).

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

By default CMake uses the sibling `../wolfram` checkout. Set
`-DWOLFRAM_SOURCE_DIR=/path/to/wolfram` to use another checkout.

Or provision a host end to end — dependencies, build, secrets, `config.toml`,
and a running daemon:

```sh
scripts/setup.sh --hostname pds.example.com
```

Re-running is safe: existing secrets are carried over, so a rebuild never
changes the identity authority that signed DIDs already minted.

## Configuration

Settings live in a `config.toml`, read from `./config.toml` or the path in
`METALBEAR_CONFIG`. Every value can also be given as an environment variable,
and **the environment overrides the file**, so a checked-in config can describe
the shape of a deployment while secrets and per-host overrides stay outside it.

```toml
[server]
service_did = "did:web:pds.example.com"
user_domain = ".pds.example.com"
port        = 2583

[accounts]
admin_password  = "..."
invite_required = true

[limits]
rate_limit                = 3000   # per client, per window
rate_limit_window_seconds = 60

[firehose]
crawlers     = ["https://bsky.network"]
ping_seconds = 20                  # keepalive; must beat the proxy idle timeout
```

`config.example.toml` documents every setting. Unknown keys are an error with a
line number rather than a silent no-op — a configuration file that is half-read
is worse than one that refuses to load.

## Run

No account is configured. A host exists before its first user, and accounts
arrive through `com.atproto.server.createAccount`.

```sh
export METALBEAR_SERVICE_DID='did:web:pds.example.com'
export METALBEAR_USER_DOMAIN='.example.com'
export METALBEAR_ADMIN_PASSWORD='replace-with-a-strong-password'
./build/metalbear
```

Optional variables are `METALBEAR_LISTEN` (default `127.0.0.1`),
`METALBEAR_PORT` (default `2583`), `METALBEAR_DATA` (default `data`), and
`METALBEAR_PUBLIC_URL`. The public URL is derived from a `did:web` service DID
when omitted and is published as the DID document's PDS service endpoint.

`METALBEAR_PLC_ROTATION_KEY` is a hex-encoded secp256k1 private key that signs
the genesis PLC operation for every DID this host mints. It is generated and
persisted on first start when unset; supply it to keep the same identity
authority across rebuilds. A configured key that cannot be parsed is fatal
rather than silently replaced, because every DID minted with a substitute key
would be unrecoverable.

`METALBEAR_INVITE_REQUIRED` defaults to true. Mint a code with admin HTTP Basic
auth, then create the first account with it:

```sh
curl -sS -u "admin:$METALBEAR_ADMIN_PASSWORD" -X POST \
  -H 'Content-Type: application/json' --data '{"useCount":1}' \
  http://127.0.0.1:2583/xrpc/com.atproto.server.createInviteCode

curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"handle":"alice.example.com","email":"alice@example.com",
           "password":"...","inviteCode":"..."}' \
  http://127.0.0.1:2583/xrpc/com.atproto.server.createAccount
```

Set `METALBEAR_CRAWLERS='https://bsky.network'` to announce new data to a relay;
the PDS sends `requestCrawl` on write, throttled to once every 20 minutes.

### Email Configuration (Optional)

```sh
export METALBEAR_SMTP_HOST='smtp.example.com'
export METALBEAR_SMTP_PORT=587
export METALBEAR_SMTP_USERNAME='user@example.com'
export METALBEAR_SMTP_PASSWORD='your-smtp-password'
export METALBEAR_FROM_ADDRESS='pds@example.com'
export METALBEAR_FROM_NAME='My PDS'
export METALBEAR_ACCOUNT_EMAIL='alice@example.com'
```

MetalBear generates its session-signing secret on first start and stores it in
`auth.sqlite3` with the refresh-token registry. Tokens therefore survive daemon
restarts and are returned only by the session endpoints. Firehose frames and
their monotonic sequence numbers are stored separately in `sequencer.sqlite3`.
Account availability is persisted in `account.sqlite3`.
Account passwords are stored only as random-salted scrypt verifiers, as are app
passwords.

Login through XRPC and use the returned access token for writes:

```sh
curl -sS http://127.0.0.1:2583/xrpc/com.atproto.server.describeServer
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"identifier":"alice.example.com","password":"..."}' \
  http://127.0.0.1:2583/xrpc/com.atproto.server.createSession
```

## Performance

Measured on the development host (Apple M-series, 10 cores, Docker), one
account, reads over loopback at 8 concurrent connections:

| | |
|---|---|
| sustained reads | ~1,000 req/s over 30s (`listRecords`, limit 50) |
| write throughput | ~200 signed commits/s at 4 concurrent |
| write latency | p50 19 ms, p99 27 ms |
| CPU under sustained read load | ~1 core of 10 (94% peak of one core) |
| RSS under load | 29.5 MiB peak, 21 MiB mean |
| RSS idle | 12.7 MiB |
| binary | 79 KB |
| container image | 176 MB |
| disk, 1 account with ~30 records and media | ~1 MB |

Writes are bounded by secp256k1 commit signing and the SQLite transaction, not
by request handling, which is why they sit two orders of magnitude below reads.

The default per-client budget of 100 requests per 60 seconds is under two a
second; a single AppView or a relay backfilling with `getRepo` exceeds it
without being abusive, so raise `limits.rate_limit` on a host serving real
traffic. These numbers were taken with it raised.

## Security boundary

Session JWTs match the upstream legacy PDS claim structure and are signed with
a per-installation HS256 secret. MetalBear does not terminate TLS: bind it to
loopback and put a reverse proxy in front.

## Status

MetalBear federates. A running instance is consumed by Bluesky's relays and by
several third-party ones, its commits verify against the key published in the
PLC directory, and its posts, profile and media appear on the Bluesky AppView.

Still missing or unproven for production use:

- no takedown model, so only `deactivated` and `deleted` account statuses are
  ever reported
- `listRepos` paginates on an integer offset rather than a keyset, so concurrent
  account creation can skip or repeat an entry across pages
- account deletion does not purge that DID's earlier firehose events
- no metrics or structured operational logging
- accounts minted under the host's own subdomain need a `_atproto` DNS TXT
  record for their handles to resolve; see issue #8

## Frontend

`frontend/` holds the landing page: SvelteKit, prerendered to static files, and
the only non-C part of this repository. It reads the server's own XRPC endpoints
in the browser, so it reports live state rather than build-time state.

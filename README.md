# MetalBear

MetalBear is an AT Protocol Personal Data Server written in C and built on
[Wolfram](../wolfram). It provides a runnable single-account PDS foundation:

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
- public repository status and single-account repository enumeration
- durable `com.atproto.sync.subscribeRepos` sequencing with live commit events,
  cursor replay across restarts, import sync events, and `FutureCursor` errors
- `com.atproto.identity.resolveHandle`, `/.well-known/atproto-did` handle
  resolution, and a `did:web` service document
- durable account deactivation/reactivation with repository availability,
  session/status reporting, and account/identity/sync firehose events
- durable SQLite-backed signed repositories and file-backed blob upload/serving

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

## Operational

- Per-IP token-bucket rate limiting (100 requests/60 seconds default)
- Configurable listen address and port
- Optional email notifications for account operations
- Automatic firehose event retention

This is not yet a production-complete PDS. DID document publication via PLC,
TLS termination, and operational hardening (logging, metrics, monitoring)
remain to be implemented.

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

## Run

Configure the account and start the daemon:

```sh
export METALBEAR_SERVICE_DID='did:web:pds.example.com'
export METALBEAR_ACCOUNT_DID='did:plc:replace-with-your-account-did'
export METALBEAR_HANDLE='alice.example.com'
export METALBEAR_USER_DOMAIN='.example.com'
export METALBEAR_PASSWORD='replace-with-a-strong-password'
./build/metalbear
```

Optional variables are `METALBEAR_LISTEN` (default `127.0.0.1`),
`METALBEAR_PORT` (default `2583`), `METALBEAR_DATA` (default `data`), and
`METALBEAR_PUBLIC_URL`. The public URL is derived from a `did:web` service DID
when omitted and is published as the DID document's PDS service endpoint.

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
On first start the configured password is converted to a random-salted scrypt
verifier in that database; later environment changes do not overwrite it. App
passwords are also stored there only as random-salted scrypt verifiers.

Login through XRPC and use the returned access token for writes:

```sh
curl -sS http://127.0.0.1:2583/xrpc/com.atproto.server.describeServer
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"identifier":"alice.example.com","password":"replace-with-a-strong-password"}' \
  http://127.0.0.1:2583/xrpc/com.atproto.server.createSession
```

## Security boundary

Session JWTs match the upstream legacy PDS claim structure and are signed with
a per-installation HS256 secret. The configured account password is only used
to bootstrap the durable scrypt verifier. Bind to loopback or place MetalBear
behind a TLS reverse proxy; do not expose this milestone directly to the public
internet.

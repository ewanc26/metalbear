#ifndef METALBEAR_SERVER_H
#define METALBEAR_SERVER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_server metalbear_server;

typedef struct metalbear_config {
    const char *listen_address;
    uint16_t port;
    unsigned int thread_count;
    const char *data_directory;
    const char *service_did;
    const char *public_url; /* optional; derived from did:web when omitted */
    const char *user_domain;
    /*
     * Hex-encoded secp256k1 private key used to sign PLC operations
     * (refpds PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX).
     *
     * This is the server's identity authority, not an account's. MetalBear
     * used to take the rotation key from a configured "bootstrap" account,
     * which made one account structurally privileged and meant a host could
     * not exist before its first user. The reference PDS has no such account:
     * it holds a rotation key and mints DIDs on demand. When unset, the key
     * is generated once and persisted under the data directory.
     */
    const char *plc_rotation_key;
    /* Email configuration (optional) */
    const char *smtp_host;
    uint16_t smtp_port;
    const char *smtp_username;
    const char *smtp_password;
    const char *from_address;
    const char *from_name;
    bool smtp_starttls;
    /* Account email for notifications */
    const char *account_email;
    /* Firehose retention (optional, defaults: max_age=30d, min_events=1000) */
    int64_t retention_max_age_seconds;
    int64_t retention_min_events;
    /* Admin password (refpds PDS_ADMIN_PASSWORD). When set, admin
     * endpoints require HTTP Basic `admin:<password>` auth. When unset,
     * admin endpoints return 401 honestly. */
    const char *admin_password;
    /* Comma-separated crawler/relay hostnames (refpds PDS_CRAWLERS).
     * Each is POSTed a com.atproto.sync.requestCrawl when a new PDS
     * instance declares itself. Empty => requestCrawl returns an honest
     * NoCrawlersConfigured error. */
    const char *crawlers;
    /* When true, createAccount requires a valid invite code (refpds
     * PDS_INVITE_REQUIRED). Honest minimum: reject when absent. */
    bool invite_required;
    /* Maximum blob upload size in bytes (refpds PDS_BLOB_UPLOAD_LIMIT).
     * 0 => no limit. Enforced in the blob upload path. */
    int64_t blob_upload_limit;
    /*
     * Per-client request budget: `rate_limit` requests per `rate_limit_window`
     * seconds. Both default to the historical 100/60 when zero.
     *
     * 100 per minute is under two requests a second, which a single AppView or
     * a relay backfilling with getRepo will exceed without being abusive, so an
     * operator serving real traffic needs to be able to raise it.
     */
    int64_t rate_limit;
    int64_t rate_limit_window;
    /* Resolved DID documents are cached for `did_cache_ttl_seconds` across
     * `did_cache_entries` slots. Zero uses the defaults (300s, 64). Without a
     * cache every describeRepo becomes an outbound request to the PLC
     * directory, which a federating host cannot sustain. */
    int64_t did_cache_ttl_seconds;
    int64_t did_cache_entries;
    /* Throttle between requestCrawl announcements (default 20 minutes) and
     * firehose keepalive ping interval (default 20 seconds; must stay well
     * under the tightest idle timeout in the proxy path). Zero uses these. */
    int64_t crawl_notify_seconds;
    int64_t firehose_ping_seconds;
    /*
     * Who runs this instance, and what to say about it.
     *
     * `contact_email` and the two policy links are the fields
     * com.atproto.server.describeServer already defines, so they go on the
     * wire where any client can read them. The rest has no standard home and
     * is served from /operator.json, which is MetalBear's own and named so it
     * cannot be mistaken for a protocol route.
     */
    const char *operator_name;
    const char *operator_url;
    const char *support_url;
    const char *instance_description;
    const char *privacy_policy_url;
    const char *terms_of_service_url;
    /* Marks a testing instance, so the landing page can say plainly that the
     * accounts on it are not people. */
    bool development;
    /* PLC directory URL for did:plc account creation. NULL/empty => accounts
     * default to did:key instead of did:plc. */
    const char *plc_url;
    /* Upstream AppView URL and DID for app.bsky.* proxying. When set, unmatched
     * app.bsky.* XRPC NSIDs are forwarded to the AppView with a short-lived
     * service-auth JWT minted from the PDS's repo key. */
    const char *appview_url;
    const char *appview_did;
    /* Directory of lexicon JSON documents used to validate records on write.
     * NULL falls back to the install/source locations; when no corpus is
     * found, writes are stored unvalidated and report "unknown". */
    const char *lexicon_dir;
    /*
     * DNS provider for publishing the `_atproto` TXT records that make handles
     * resolve.
     *
     * A wildcard certificate covers one label, so a host minting
     * `alice.pds.example.com` under `*.example.com` has no certificate for the
     * handle and the HTTPS resolution route cannot work for it at all. The DNS
     * route always can, but writing a record per account by hand does not scale
     * past the operator's own account.
     *
     * `dns_provider` is "cloudflare" or empty. Empty leaves handle resolution
     * to the operator, which is what every deployment did before this existed.
     */
    const char *dns_provider;
    const char *dns_api_token;
    const char *dns_zone_id;
    int64_t dns_record_ttl;
} metalbear_config;

/* Start a single-account AT Protocol PDS. All strings are copied. */
metalbear_server *metalbear_server_start(const metalbear_config *config);

/* The actual bound port, useful when config.port was zero. */
uint16_t metalbear_server_port(const metalbear_server *server);

/* Stop and free the server. Durable repository and blob data remain on disk. */
void metalbear_server_free(metalbear_server *server);

#ifdef __cplusplus
}
#endif

#endif

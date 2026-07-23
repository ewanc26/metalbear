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
    const char *account_did;
    const char *account_handle;
    const char *user_domain;
    const char *password;
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
    /* PLC directory URL for did:plc account creation. NULL/empty => accounts
     * default to did:key instead of did:plc. */
    const char *plc_url;
    /* Upstream AppView URL and DID for app.bsky.* proxying. When set, unmatched
     * app.bsky.* XRPC NSIDs are forwarded to the AppView with a short-lived
     * service-auth JWT minted from the PDS's repo key. */
    const char *appview_url;
    const char *appview_did;
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

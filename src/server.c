#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "server_internal.h"

#include "admin/admin_routes.h"
#include "identity/identity_routes.h"
#include "oauth/oauth_credentials.h"
#include "session/session_routes.h"
#include "account/account_routes.h"
#include "account/preferences_routes.h"
#include "sync/sync_routes.h"
#ifdef METALBEAR_MODULE_APPVIEW
#include "appview/appview_routes.h"
#endif
#include "moderation/moderation_routes.h"
#ifdef METALBEAR_MODULE_VIDEO
#include "video/video_routes.h"
#endif
#include "ops/status.h"
#include "ops/ops_routes.h"
#include "repo/blob_store_server.h"

#include "metalbear/server.h"
#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/account/account_context.h"
#include "metalbear/account/account_cache.h"
#include "metalbear/oauth/auth.h"
#include "metalbear/repo/backup.h"
#ifdef METALBEAR_MODULE_EMAIL
#include "metalbear/email.h"
#endif
#ifdef METALBEAR_MODULE_DNS
#include "metalbear/dns/handle_dns.h"
#endif
#include "metalbear/repo/key_rotation.h"
#include "metalbear/oauth/oauth.h"
#include "metalbear/oauth/oauth_account_routes.h"
#include "metalbear/oauth/oauth_scope.h"
#include "metalbear/moderation/report.h"
#include "metalbear/oauth/oauth_routes.h"
#include "metalbear/sequencer.h"

#include "metalbear/repo/blob_store.h"
#ifdef METALBEAR_MODULE_UPDATE_WATCHER
#include "metalbear/ops/update_watcher.h"
#endif
#include "wolfram/crypto.h"
#include "wolfram/plc.h"
#include "metalbear/repo/repo_store.h"
#include "wolfram/repo/cid.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ftw.h>
#include <curl/curl.h>

/* Logging lives in log.c so the daemon shares it: see metalbear/log.h. */

/* ---- admin / refpds config (mirrors refpds PDS_* env) ---- */

/* struct metalbear_server is defined in server_internal.h, shared with the
 * route-handler modules this file delegates to (src/admin/, etc.). */

static bool make_directory(const char *path) {
    if (mkdir(path, 0700) == 0) return true;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

char *join_path(const char *directory, const char *name) {
    size_t dn = strlen(directory), nn = strlen(name);
    bool slash = dn > 0 && directory[dn - 1] == '/';
    char *path = malloc(dn + nn + (slash ? 1 : 2));
    if (!path) return NULL;
    snprintf(path, dn + nn + (slash ? 1 : 2), "%s%s%s", directory,
             slash ? "" : "/", name);
    return path;
}

/*
 * Load the lexicon corpus used to validate records on write.
 *
 * A missing corpus is not fatal: without one every write reports
 * validationStatus "unknown", which is the honest answer and what the
 * reference reports for a collection it has no schema for. It is logged
 * loudly, though, because silently accepting malformed records is a much
 * worse failure than refusing to start.
 */
static void load_lexicons(metalbear_server *server, const char *configured) {
    static const char *const fallbacks[] = {
        "/usr/local/share/metalbear/lexicons",
#ifdef METALBEAR_SOURCE_WOLFRAM_LEXICON_DIR
        METALBEAR_SOURCE_WOLFRAM_LEXICON_DIR,
#endif
        "../wolfram/lexicons",
        "lexicons",
    };
    const char *candidates[1 + sizeof(fallbacks) / sizeof(fallbacks[0])];
    size_t n = 0;
    if (configured && configured[0]) candidates[n++] = configured;
    for (size_t i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); i++)
        candidates[n++] = fallbacks[i];

    for (size_t i = 0; i < n; i++) {
        wf_lexicon_registry *registry = wf_lexicon_registry_new();
        if (!registry) return;
        if (wf_lexicon_registry_load_dir(registry, candidates[i]) == WF_OK) {
            server->lexicons = registry;
            LOG_INFO("loaded lexicons from %s; records will be validated",
                     candidates[i]);
            return;
        }
        wf_lexicon_registry_free(registry);
    }
    LOG_WARN("no lexicon corpus found (set METALBEAR_LEXICON_DIR); records "
             "will be stored without validation and reported as "
             "validationStatus \"unknown\"");
}

static bool copy_config(metalbear_server *server,
                        const metalbear_config *config) {
    server->service_did = strdup(config->service_did);
    if (config->public_url) server->public_url = strdup(config->public_url);
    server->user_domain = strdup(config->user_domain);
    server->data_directory = strdup(config->data_directory);
    if (config->admin_password && config->admin_password[0])
        server->admin_password = strdup(config->admin_password);
    if (config->crawlers && config->crawlers[0])
        server->crawlers = strdup(config->crawlers);
    server->invite_required = config->invite_required;
    server->blob_upload_limit = config->blob_upload_limit;
    server->accepting_imports = config->accepting_imports;
    server->max_import_size = config->max_import_size;
    if (config->plc_url && config->plc_url[0])
        server->plc_url = strdup(config->plc_url);
    if (config->appview_url && config->appview_url[0])
        server->appview_url = strdup(config->appview_url);
    if (config->appview_did && config->appview_did[0])
        server->appview_did = strdup(config->appview_did);
    if (config->mod_service_did && config->mod_service_did[0])
        server->mod_service_did = strdup(config->mod_service_did);
    load_lexicons(server, config->lexicon_dir);
    return server->service_did && (!config->public_url || server->public_url) &&
           server->user_domain && server->data_directory;
}

/*
 * Parse a 64-character hex secp256k1 private key into a signing key.
 *
 * The env var carries hex (refpds PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX);
 * metalbear_key_rotation_import wants the decoded scalar. Returns false on
 * anything that is not exactly 32 bytes of hex, so a truncated or mistyped
 * key is refused rather than padded into a different key.
 */
static bool parse_secp256k1_hex(const char *hex, wf_signing_key *out) {
    if (!hex || !out) return false;
    size_t len = strlen(hex);
    if (len != 64) return false;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < 32; i++) {
        unsigned int byte = 0;
        for (int nibble = 0; nibble < 2; nibble++) {
            char c = hex[i * 2 + nibble];
            unsigned int value;
            if (c >= '0' && c <= '9')
                value = (unsigned int)(c - '0');
            else if (c >= 'a' && c <= 'f')
                value = (unsigned int)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                value = (unsigned int)(c - 'A' + 10);
            else
                return false;
            byte = (byte << 4) | value;
        }
        out->bytes[i] = (unsigned char)byte;
    }
    out->type = WF_KEY_TYPE_SECP256K1;
    return true;
}

static bool valid_config(const metalbear_config *config) {
    /* No account is required to start: a host exists before its first user,
     * and accounts arrive through createAccount. */
    return config && config->listen_address && config->data_directory &&
           config->service_did && config->user_domain;
}

metalbear_server *metalbear_server_start(const metalbear_config *config) {
    metalbear_log_configure();
    if (!valid_config(config)) {
        LOG_ERROR("invalid server configuration");
        return NULL;
    }
    if (!make_directory(config->data_directory)) {
        LOG_ERROR("cannot create data directory: %s", config->data_directory);
        return NULL;
    }

    metalbear_server *server = calloc(1, sizeof(*server));
    if (server) server->started_at = time(NULL);
    if (!server || !copy_config(server, config)) {
        LOG_ERROR("cannot initialise server");
        goto fail;
    }

    /* Derive the public URL before anything needs it: the OAuth store below
     * uses it as its token issuer, and it was previously computed late, during
     * route registration. */
    if (!server->public_url)
        server->public_url =
            metalbear_public_url_from_service_did(server->service_did);
    if (!server->public_url) {
        LOG_ERROR("cannot determine public URL from service DID");
        goto fail;
    }

    /* One event log for the host, at the data root — not inside any account's
     * directory. A relay subscribes to the server, not to an account. */
    char *seq_path = NULL;
    if (asprintf(&seq_path, "%s/sequencer.sqlite3", config->data_directory) <
            0 ||
        !seq_path) {
        LOG_ERROR("cannot compute sequencer path");
        goto fail;
    }
    if (metalbear_sequencer_open(seq_path, &server->sequencer) != WF_OK) {
        LOG_ERROR("cannot open sequencer at %s", seq_path);
        free(seq_path);
        goto fail;
    }
    free(seq_path);

    /*
     * The server's PLC rotation key: the authority that signs DID operations
     * for every account this host mints. Kept at the data root because it
     * belongs to the host — taking it from a configured account made that
     * account impossible to delete and impossible to do without.
     */
    char *rotation_path =
        join_path(config->data_directory, "server_keys.sqlite3");
    if (!rotation_path || metalbear_key_rotation_open(
                              rotation_path, &server->plc_rotation) != WF_OK) {
        LOG_ERROR("cannot open server key store");
        free(rotation_path);
        goto fail;
    }
    free(rotation_path);
    if (config->plc_rotation_key && config->plc_rotation_key[0]) {
        wf_signing_key configured;
        memset(&configured, 0, sizeof(configured));
        /* A configured key that cannot be adopted must not be quietly replaced
         * by a generated one: every DID minted with the wrong key is
         * unrecoverable without the operator's real key. */
        if (!parse_secp256k1_hex(config->plc_rotation_key, &configured) ||
            metalbear_key_rotation_import(server->plc_rotation, &configured) !=
                WF_OK) {
            LOG_ERROR("METALBEAR_PLC_ROTATION_KEY is not a usable secp256k1 "
                      "key (expected 64 hex characters)");
            goto fail;
        }
    }

    /* One OAuth store for the host. Its signing key is the server's; the
     * account a token speaks for is carried in the token, not in the store. */
    char *oauth_path =
        join_path(config->data_directory, "server_oauth.sqlite3");
    if (!oauth_path ||
        metalbear_oauth_store_open(oauth_path, server->public_url,
                                   &server->oauth) != WF_OK) {
        LOG_ERROR("cannot open server OAuth store");
        free(oauth_path);
        goto fail;
    }
    free(oauth_path);

    /* Open account registry */
    char *registry_path = join_path(config->data_directory, "accounts.sqlite3");
    if (!registry_path || metalbear_account_registry_open(
                              registry_path, &server->registry) != WF_OK) {
        LOG_ERROR("cannot open account registry");
        free(registry_path);
        goto fail;
    }
    free(registry_path);
    /* The registry starts empty. There is no account to seed: every account,
     * including the first, is created through com.atproto.server.createAccount
     * and registers itself there. */

    identity_configure_did_doc_cache(
        (time_t)config->did_cache_ttl_seconds,
        config->did_cache_entries > 0 ? (size_t)config->did_cache_entries : 0);
    sync_configure_crawler_notify((time_t)config->crawl_notify_seconds);
    if (config->firehose_ping_seconds > 0)
        metalbear_sequencer_set_ping_seconds(config->firehose_ping_seconds);

    /* Per-client (IP-keyed) request budget, configurable; matches the
     * reference's "global-ip" bucket by default (rate-limits.ts: 3000/5min).
     * A route-specific limiter (wf_xrpc_server_set_route_rate_limiter)
     * replaces this one for that route rather than stacking with it -- see
     * wf_server_find_route_rate_limiter in xrpc_server.c -- which is exactly
     * how the reference excludes sync.getRepo from its global-ip bucket
     * (rl_get_repo_5min below covers that route on its own budget). */
    {
        int64_t budget = config->rate_limit > 0 ? config->rate_limit : 3000;
        int64_t window =
            config->rate_limit_window > 0 ? config->rate_limit_window : 300;
        server->rate_limiter =
            wf_rate_limiter_new((size_t)budget, (size_t)window, 0);
        server->rate_limit_budget = budget;
        server->rate_limit_window = window;
    }

    /* Endpoint-specific budgets, matching the reference PDS's values exactly
     * (see the metalbear_server struct's rl_* fields for the source files).
     * Not configurable — these protect account security, not general API
     * capacity, so they should not silently loosen with METALBEAR_RATE_LIMIT.
     */
    server->rl_create_session_day = wf_rate_limiter_new(300, 86400, 0);
    server->rl_create_session_5min = wf_rate_limiter_new(30, 300, 0);
    server->rl_request_password_reset_day = wf_rate_limiter_new(50, 86400, 0);
    server->rl_request_password_reset_hour = wf_rate_limiter_new(15, 3600, 0);
    server->rl_request_account_delete_day = wf_rate_limiter_new(15, 86400, 0);
    server->rl_request_account_delete_hour = wf_rate_limiter_new(5, 3600, 0);
    server->rl_request_email_confirmation_day =
        wf_rate_limiter_new(15, 86400, 0);
    server->rl_request_email_confirmation_hour =
        wf_rate_limiter_new(5, 3600, 0);
    server->rl_request_email_update_day = wf_rate_limiter_new(15, 86400, 0);
    server->rl_request_email_update_hour = wf_rate_limiter_new(5, 3600, 0);
    server->rl_repo_write_hour = wf_rate_limiter_new(5000, 3600, 0);
    server->rl_repo_write_day = wf_rate_limiter_new(35000, 86400, 0);
    server->rl_update_handle_5min = wf_rate_limiter_new(10, 300, 0);
    server->rl_update_handle_day = wf_rate_limiter_new(50, 86400, 0);
    server->rl_get_repo_5min = wf_rate_limiter_new(6000, 300, 0);

    /* Open moderation report store */
    char *reports_path = join_path(config->data_directory, "reports.sqlite3");
    if (!reports_path ||
        metalbear_report_store_open(reports_path, &server->reports) != WF_OK) {
        LOG_ERROR("cannot open report store");
        free(reports_path);
        goto fail;
    }
    free(reports_path);
    /* Announce new data to configured relays, throttled. */
    metalbear_sequencer_set_notify(server->sequencer, notify_crawlers, server);

    server->xrpc = wf_xrpc_server_start(config->listen_address, config->port,
                                        config->thread_count);
    if (!server->xrpc) {
        LOG_ERROR("cannot start XRPC listener");
        goto fail;
    }
    if (metalbear_register_identity_documents(server) != WF_OK) {
        LOG_ERROR("cannot register identity documents");
        goto fail;
    }

    /* Cache of open per-account store bundles, keyed by DID. Every account
     * resolves through this cache — there is no account held open beside it. */
    server->account_cache = metalbear_account_cache_new(
        server->service_did, server->public_url, server->data_directory);
    /* Every account the cache opens publishes into the one stream
     * subscribeRepos serves; without this their commits go to a log nothing
     * reads. */
    metalbear_account_cache_set_sequencer(server->account_cache,
                                          server->sequencer);
    /* Bound the resident account set for small hosts (e.g. a 256 MB Pi 1B).
     * The config file sets the deployment default; METALBEAR_MAX_RESIDENT_
     * ACCOUNTS overrides it at runtime. */
    if (config->max_resident_accounts > 0)
        metalbear_account_cache_set_max_resident(
            server->account_cache, (size_t)config->max_resident_accounts);
    {
        const char *max_res = getenv("METALBEAR_MAX_RESIDENT_ACCOUNTS");
        if (max_res && max_res[0]) {
            char *end = NULL;
            long v = strtol(max_res, &end, 10);
            if (end != max_res && v > 0)
                metalbear_account_cache_set_max_resident(server->account_cache,
                                                         (size_t)v);
        }
    }
    if (!server->account_cache) {
        LOG_ERROR("cannot create account cache");
        goto fail;
    }

    /* Reconcile every account in the registry against the host-wide
     * sequencer.  This was bootstrap-only, so secondary accounts lost their
     * #identity/#account events on restart and relays saw a bare #commit for
     * DIDs they had never been introduced to. */
    {
        metalbear_account_entry *entries = NULL;
        size_t count = 0;
        if (metalbear_account_registry_list(server->registry, &entries,
                                            &count) == WF_OK) {
            for (size_t i = 0; i < count; i++) {
                metalbear_account_context *acct = metalbear_account_cache_get(
                    server->account_cache, server->registry, entries[i].did);
                if (!acct) continue;
                metalbear_sequencer_reconcile_account(
                    server->sequencer, entries[i].did,
                    metalbear_account_is_active(acct->account));
                if (acct->repo)
                    metalbear_sequencer_reconcile_repo(server->sequencer,
                                                       acct->repo);
                /* This context was opened solely for reconciliation during
                 * startup; release it so it becomes evictable under the
                 * resident budget rather than pinned for the process lifetime.
                 * Request-path acquisitions are released by the request
                 * observer instead. */
                metalbear_account_cache_release(server->account_cache, acct);
            }
            metalbear_account_entries_free(entries, count);
        }
    }

    if (wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.server.describeServer",
                                      describe_server, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "_health", health,
                                      server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.createAccount",
                                          create_account, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.identity.resolveHandle",
                                      resolve_handle, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.identity.resolveDid",
                                      resolve_did_identity, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.identity.resolveIdentity",
                                      resolve_identity, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.identity.refreshIdentity",
            refresh_identity, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.identity.getRecommendedDidCredentials",
            get_recommended_did_credentials, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.identity.updateHandle",
                                          update_handle, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.identity.requestPlcOperationSignature",
            request_plc_operation_signature, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.identity.signPlcOperation",
            sign_plc_operation, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.identity.submitPlcOperation",
            submit_plc_operation, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.createSession",
                                          create_session, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.server.getSession",
                                      get_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.refreshSession",
                                          refresh_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.deleteSession",
                                          delete_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.createAppPassword",
            create_app_password, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.server.listAppPasswords",
                                      list_app_passwords, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.revokeAppPassword",
            revoke_app_password, server) != WF_OK ||
        /* Not part of the AT Protocol lexicon -- account-management
         * listings for OAuth state (connected apps, active devices),
         * registered under a project-scoped nsid the same way "_health"
         * is, so they still go through the standard authenticate()
         * callback and resolve_request_context rather than needing their
         * own auth. */
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.metalbear.oauth.listDevices",
                                      oauth_list_devices, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.metalbear.oauth.revokeDevice",
            oauth_revoke_device, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.metalbear.oauth.listGrants",
                                      oauth_list_grants, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.metalbear.oauth.revokeGrant", oauth_revoke_grant,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.deactivateAccount",
            deactivate_account, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.activateAccount",
                                          activate_account, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.server.getServiceAuth",
            metalbear_get_service_auth, server) != WF_OK ||
        metalbear_xrpc_server_register_pds_repo_resolver_ex(
            server->xrpc, metalbear_repo_resolver, server, server->service_did,
            server->public_url, resolve_did_doc_json, server, server->lexicons,
            metalbear_repo_access_guard, server, server->accepting_imports,
            server->max_import_size) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.repo.uploadBlob",
                                          upload_blob, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.repo.listMissingBlobs",
                                      list_missing_blobs, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "com.atproto.sync.getBlob",
                                      get_blob, server) != WF_OK) {
        LOG_ERROR("cannot register XRPC routes");
        goto fail;
    }
    if (wf_xrpc_server_register_query(server->xrpc, "com.atproto.sync.getRepo",
                                      get_repo, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.sync.getBlocks", get_blocks,
                                      server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.sync.getRepoStatus",
                                      get_repo_status, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.sync.listBlobs", list_blobs,
                                      server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.sync.listRepos", list_repos,
                                      server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.sync.listReposByCollection",
            list_repos_by_collection, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.sync.getRecord", get_record,
                                      server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "com.atproto.sync.getHead",
                                      get_head, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.sync.getCheckout",
                                      get_checkout, server) != WF_OK ||
        metalbear_sequencer_register(server->sequencer, server->xrpc) !=
            WF_OK) {
        LOG_ERROR("cannot register sync export routes");
        goto fail;
    }

#ifdef METALBEAR_MODULE_APPVIEW
    if (server->appview_url && server->appview_url[0]) {
        wf_xrpc_server_set_fallback(server->xrpc, proxy_fallback, server);
    }
#endif

    wf_xrpc_server_set_auth_callback(server->xrpc, metalbear_authenticate,
                                     server);

    /* Release every account context acquired on the request path once the
     * handler has returned, so the bounded cache can evict idle accounts.
     * See account_cache_request_observer. */
    wf_xrpc_server_set_request_observer(
        server->xrpc, metalbear_account_cache_request_observer, server);

    /* Register OAuth HTTP routes (bypass XRPC auth) */
    /* One OAuth store for the host. The account a token speaks for comes from
     * the token itself, so no account DID is bound in at registration. */
    if (metalbear_oauth_routes_register(
            server->xrpc, server->oauth, server->public_url,
            server->service_did, resolve_oauth_subject, verify_oauth_credential,
            server) != WF_OK) {
        LOG_ERROR("cannot register OAuth routes");
        goto fail;
    }

    /* Register account deletion routes */
    if (wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.requestAccountDelete",
            request_account_delete, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.deleteAccount",
                                          delete_account, server) != WF_OK) {
        LOG_ERROR("cannot register deletion routes");
        goto fail;
    }

    /* Register email flow routes */
    if (wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.requestEmailConfirmation",
            request_email_confirmation, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.confirmEmail",
                                          confirm_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.requestEmailUpdate",
            request_email_update, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.updateEmail",
                                          update_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.requestPasswordReset",
            request_password_reset, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.server.resetPassword",
                                          reset_password, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.server.getAccountInviteCodes",
            get_account_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.server.checkAccountStatus",
                                      check_account_status, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.reserveSigningKey",
            reserve_signing_key, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.createInviteCode",
            create_invite_code, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.server.createInviteCodes",
            create_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "app.bsky.actor.getPreferences",
                                      get_actor_preferences, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "app.bsky.actor.putPreferences",
            put_actor_preferences, server) != WF_OK ||
#ifdef METALBEAR_MODULE_APPVIEW
        /* AppView-proxied app.bsky.* endpoints (rsky-pds/ref-pds pattern).
         * Auth runs first, so handlers see req->authed_subject and can mint
         * requester-scoped service-auth JWTs for the upstream AppView. */
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.feed.getFeed",
                                      appview_get_feed, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.feed.getFeedSkeleton",
            appview_get_feed_skeleton, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.feed.getAuthorFeed",
            appview_get_author_feed, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.feed.getActorFeeds",
            appview_get_actor_feeds, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.feed.getFeedGenerators",
            appview_get_feed_generators, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.feed.getFeedGenerator",
            appview_get_feed_generator, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.feed.getPosts",
                                      appview_get_posts, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.actor.getProfile",
                                      appview_get_profile, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "app.bsky.actor.getProfiles",
                                      appview_get_profiles, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.feed.getActorLikes",
            appview_get_actor_likes, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.feed.getTimeline",
                                      appview_get_timeline, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.feed.getPostThread",
            appview_get_post_thread, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "app.bsky.notification.registerPush",
            appview_register_push, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "app.bsky.notification.unregisterPush",
            appview_unregister_push, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.actor.getActorStatistics",
            appview_get_actor_statistics, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.actor.getActorRankings",
            appview_get_actor_rankings, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.graph.getFollows",
                                      appview_get_follows, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "app.bsky.graph.getFollowers",
                                      appview_get_followers, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.graph.getBlocks",
                                      appview_get_blocks, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.graph.getList",
                                      appview_get_list, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "app.bsky.graph.getLists",
                                      appview_get_lists, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.graph.getListItems", appview_get_list_items,
            server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.graph.getStarterPack",
            appview_get_starter_pack, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.graph.getStarterPacks",
            appview_get_starter_packs, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.notification.getUnreadCount",
            appview_get_unread_notifications, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.notification.listNotifications",
            appview_get_notifications, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "chat.bsky.convo.getConvo",
                                      appview_get_convo, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc, "chat.bsky.convo.getConvos",
                                      appview_get_convos, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "chat.bsky.convo.getMessages",
                                      appview_get_messages, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.labeler.getServices",
            appview_get_labeler_info, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.unspecced.getAgeAssuranceState",
            appview_unspecced_get_age_assurance_state, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.unspecced.getAgeAssuranceConfig",
            appview_unspecced_get_age_assurance_config, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.unspecced.getAgeAssurance",
            appview_unspecced_get_age_assurance, server) != WF_OK ||
#endif /* METALBEAR_MODULE_APPVIEW */
        /* Admin endpoints (refpds PDS_ADMIN_PASSWORD, Basic auth) */
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.admin.getAccountInfo",
            admin_get_account_info, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.admin.getSubjectStatus",
            admin_get_subject_status, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.updateSubjectStatus",
            admin_update_subject_status, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.admin.sendEmail",
                                          admin_send_email, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.admin.getAccountInfos",
            admin_get_account_infos, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.updateAccountHandle",
            admin_update_account_handle, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.updateAccountEmail",
            admin_update_account_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.updateAccountPassword",
            admin_update_account_password, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.enableAccountInvites",
            admin_enable_account_invites, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.disableAccountInvites",
            admin_disable_account_invites, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "com.atproto.admin.getInviteCodes",
            admin_get_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.disableInviteCodes",
            admin_disable_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "com.atproto.admin.deleteAccount",
            admin_delete_account, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.moderation.createReport",
                                          create_report, server) != WF_OK ||
        /* Public crawl declaration (refpds PDS_CRAWLERS) */
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "com.atproto.sync.requestCrawl",
                                          request_crawl, server) != WF_OK ||
        /* Temporary unspecced route — always returns { activated: true } */
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.temp.checkSignupQueue",
                                      check_signup_queue, server) != WF_OK ||
#ifdef METALBEAR_MODULE_VIDEO
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "app.bsky.video.uploadVideo",
                                          video_upload, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
                                      "app.bsky.video.getJobStatus",
                                      video_get_job_status, server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.video.getUploadLimits",
            video_get_upload_limits, server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "app.bsky.video.startUpload", video_start_upload,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "app.bsky.video.finishUpload", video_finish_upload,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(
            server->xrpc, "app.bsky.video.abortUpload", video_abort_upload,
            server) != WF_OK ||
        wf_xrpc_server_register_query(
            server->xrpc, "app.bsky.video.getUploadStatus",
            video_get_upload_status, server) != WF_OK ||
#ifdef WF_XRPC_SERVER_HAS_STREAMING_PROCEDURES
        wf_xrpc_server_register_streaming_procedure(
            server->xrpc, "app.bsky.video.uploadPart",
            &video_upload_part_handler, server) != WF_OK)
#else
        wf_xrpc_server_register_procedure(server->xrpc,
                                          "app.bsky.video.uploadPart",
                                          video_upload_part, server) != WF_OK)
#endif
#else
        /* Without the video module the chain above ends in `||`; close it. */
        false)
#endif /* METALBEAR_MODULE_VIDEO */
    {
        LOG_ERROR("cannot register email/invite/video routes");
        goto fail;
    }

    /* Apply rate limiting */
    if (server->rate_limiter)
        wf_xrpc_server_set_rate_limiter(server->xrpc, server->rate_limiter);

    /* Single-tier, IP-keyed endpoint budgets that the framework enforces on
     * its own once attached — no handler-side code needed. Ownership of each
     * limiter transfers to server->xrpc; freed on wf_xrpc_server_free. Values
     * match the reference PDS exactly (createAccount.ts, deleteAccount.ts,
     * resetPassword.ts, uploadBlob.ts). */
    wf_xrpc_server_set_route_rate_limiter(
        server->xrpc, "POST", "/xrpc/com.atproto.server.createAccount",
        wf_rate_limiter_new(100, 300, 0));
    wf_xrpc_server_set_route_rate_limiter(
        server->xrpc, "POST", "/xrpc/com.atproto.server.deleteAccount",
        wf_rate_limiter_new(50, 300, 0));
    wf_xrpc_server_set_route_rate_limiter(
        server->xrpc, "POST", "/xrpc/com.atproto.server.resetPassword",
        wf_rate_limiter_new(50, 300, 0));
    /* uploadBlob had no rate limit at all -- unbounded upload attempts are a
     * storage/bandwidth exhaustion vector a single-tier, IP-keyed budget
     * closes off, matching the reference exactly (1000/day). */
    wf_xrpc_server_set_route_rate_limiter(server->xrpc, "POST",
                                          "/xrpc/com.atproto.repo.uploadBlob",
                                          wf_rate_limiter_new(1000, 86400, 0));
    /* Passkey authentication had no route-specific limit, only the generous
     * global-ip budget above (3000/5min default) -- unlike createSession,
     * which gets its own 30/5min tier. Forging a valid assertion without the
     * private key stays infeasible regardless of request volume, so this
     * isn't closing an auth bypass; it bounds the compute cost (base64
     * decode, DB lookup, ECDSA verify per attempt) of hammering the one
     * pre-auth passkey endpoint that does real crypto work. IP-only (not
     * identifier+IP like createSession): unlike a password/username,
     * credential_id isn't something a client chooses or types, so there's no
     * "attacker hammers one victim's identifier from many IPs" case to guard
     * against separately. */
    wf_xrpc_server_set_route_rate_limiter(server->xrpc, "POST",
                                          "/oauth/passkey/authenticate/verify",
                                          wf_rate_limiter_new(30, 300, 0));

#ifdef METALBEAR_MODULE_EMAIL
    /* Initialize email module if configured */
    if (config->smtp_host && config->smtp_host[0] && config->from_address &&
        config->from_address[0]) {
        metalbear_email_config email_cfg = {
            .smtp_host = config->smtp_host,
            .smtp_port = config->smtp_port ? config->smtp_port : 587,
            .smtp_username = config->smtp_username,
            .smtp_password = config->smtp_password,
            .from_address = config->from_address,
            .from_name = config->from_name,
            .smtp_starttls = config->smtp_starttls,
        };
        metalbear_email_open(&email_cfg, &server->email);
    }
#endif

#ifdef METALBEAR_MODULE_DNS
    /*
     * Open the handle DNS publisher, if one is configured.
     *
     * A misconfigured provider is fatal on purpose. The alternative is a host
     * that starts, mints accounts, and writes no records — and the operator
     * only finds out when every handle shows as handle.invalid on an AppView,
     * long after the accounts exist.
     */
    if (config->dns_provider && config->dns_provider[0]) {
        if (metalbear_handle_dns_open_ex(
                config->dns_provider, config->dns_api_token,
                config->dns_zone_id, config->dns_server,
                (int)config->dns_record_ttl, &server->handle_dns) != WF_OK) {
            LOG_ERROR("dns: provider '%s' is configured but unusable. It needs "
                      "an api_token and a zone_id; 'rfc2136' additionally "
                      "needs a server, and its api_token is the TSIG key as "
                      "'<name>:<base64 secret>'. Known providers are "
                      "cloudflare, digitalocean, desec and rfc2136",
                      config->dns_provider);
            metalbear_server_free(server);
            return NULL;
        }
        LOG_INFO("dns: publishing _atproto records via %s",
                 config->dns_provider);
    }
#endif

#ifdef METALBEAR_MODULE_UPDATE_WATCHER
    /* Start the update watcher if enabled */
    if (config->update_check_enabled) {
        metalbear_update_watcher_config uc = {
            .enabled = true,
            .interval_seconds = config->update_check_interval > 0
                                    ? config->update_check_interval
                                    : 86400,
            .metalbear_repo = config->update_metalbear_repo
                                  ? config->update_metalbear_repo
                                  : "ewanc26/metalbear",
            .wolfram_repo = config->update_wolfram_repo
                                ? config->update_wolfram_repo
                                : "ewanc26/wolfram",
            .current_metalbear_version = METALBEAR_VERSION,
            .current_wolfram_version = WOLFRAM_VERSION_STRING,
        };
        if (metalbear_update_watcher_open(&uc, &server->update_watcher) !=
            WF_OK) {
            LOG_WARN("update-watcher: could not start (releases unreachable?)");
        } else {
            LOG_INFO("update-watcher: checking every %ld seconds",
                     (long)uc.interval_seconds);
        }
    }
#endif

    if (config->account_email && config->account_email[0])
        server->account_email = strdup(config->account_email);
#define COPY_OPT(field)                                                        \
    if (config->field && config->field[0]) server->field = strdup(config->field)
    COPY_OPT(operator_name);
    COPY_OPT(operator_email);
    COPY_OPT(operator_url);
    COPY_OPT(support_url);
    COPY_OPT(instance_description);
    COPY_OPT(privacy_policy_url);
    COPY_OPT(terms_of_service_url);
#undef COPY_OPT
    server->development = config->development;

    /* Configure firehose retention */
    server->retention_max_age = config->retention_max_age_seconds > 0
                                    ? config->retention_max_age_seconds
                                    : 30 * 24 * 60 * 60; /* 30 days */
    server->retention_min_events =
        config->retention_min_events > 0 ? config->retention_min_events : 1000;

    /* Apply initial retention */
    metalbear_sequencer_retain(server->sequencer, server->retention_max_age,
                               server->retention_min_events);

    return server;

fail:
    metalbear_server_free(server);
    return NULL;
}

uint16_t metalbear_server_port(const metalbear_server *server) {
    return server ? wf_xrpc_server_port(server->xrpc) : 0;
}

void metalbear_server_free(metalbear_server *server) {
    if (!server) return;
    wf_xrpc_server_free(server->xrpc);
    metalbear_account_cache_free(server->account_cache);
    metalbear_oauth_store_free(server->oauth);
    metalbear_key_rotation_free(server->plc_rotation);
    /* Freed after the account contexts, which borrow it. */
    metalbear_sequencer_free(server->sequencer);
    metalbear_account_registry_free(server->registry);
#ifdef METALBEAR_MODULE_EMAIL
    metalbear_email_free(server->email);
#endif
#ifdef METALBEAR_MODULE_DNS
    metalbear_handle_dns_free(server->handle_dns);
#endif
#ifdef METALBEAR_MODULE_UPDATE_WATCHER
    metalbear_update_watcher_free(server->update_watcher);
#endif
    metalbear_report_store_free(server->reports);
    wf_rate_limiter_free(server->rate_limiter);
    wf_rate_limiter_free(server->rl_create_session_day);
    wf_rate_limiter_free(server->rl_create_session_5min);
    wf_rate_limiter_free(server->rl_request_password_reset_day);
    wf_rate_limiter_free(server->rl_request_password_reset_hour);
    wf_rate_limiter_free(server->rl_request_account_delete_day);
    wf_rate_limiter_free(server->rl_request_account_delete_hour);
    wf_rate_limiter_free(server->rl_request_email_confirmation_day);
    wf_rate_limiter_free(server->rl_request_email_confirmation_hour);
    wf_rate_limiter_free(server->rl_request_email_update_day);
    wf_rate_limiter_free(server->rl_request_email_update_hour);
    wf_rate_limiter_free(server->rl_repo_write_hour);
    wf_rate_limiter_free(server->rl_repo_write_day);
    wf_rate_limiter_free(server->rl_update_handle_5min);
    wf_rate_limiter_free(server->rl_update_handle_day);
    wf_rate_limiter_free(server->rl_get_repo_5min);
    metalbear_log_close();
    free(server->service_did);
    free(server->public_url);
    free(server->user_domain);
    free(server->data_directory);
    free(server->account_email);
    free(server->operator_email);
    free(server->admin_password);
    free(server->crawlers);
    free(server->plc_url);
    free(server->appview_url);
    free(server->appview_did);
    free(server->mod_service_did);
    wf_lexicon_registry_free(server->lexicons);
    free(server);
}

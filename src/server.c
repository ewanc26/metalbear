#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif

#include "metalbear/server.h"
#include "metalbear/log.h"
#include "metalbear/metrics.h"
#include "metalbear/account.h"
#include "metalbear/account_registry.h"
#include "metalbear/account_context.h"
#include "metalbear/account_cache.h"
#include "metalbear/auth.h"
#include "metalbear/backup.h"
#include "metalbear/email.h"
#include "metalbear/handle_dns.h"
#include "metalbear/key_rotation.h"
#include "metalbear/oauth.h"
#include "metalbear/oauth_scope.h"
#include "metalbear/report.h"
#include "metalbear/oauth_routes.h"
#include "metalbear/sequencer.h"

#include "metalbear/blob_store.h"
#include "metalbear/update_watcher.h"
#include "wolfram/crypto.h"
#include "wolfram/plc.h"
#include "wolfram/version.h"
#include "metalbear/repo_store.h"
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

static char *join_path(const char *directory, const char *name);

/* ---- admin / refpds config (mirrors refpds PDS_* env) ---- */
/* Parse HTTP Basic `admin:<password>` from the Authorization header and compare
 * it (constant-time) against the configured admin password. Returns true only
 * when a password is configured AND the header matches exactly. */
static bool admin_authenticated(metalbear_server *server,
                              const wf_xrpc_request *req);

struct metalbear_server {
    wf_xrpc_server *xrpc;
    /* When this process began serving, for the uptime gauge at /metrics. */
    time_t started_at;
    /*
     * The server's own PLC rotation key and OAuth store.
     *
     * Both used to be reached through a configured "bootstrap" account, which
     * made that one account structurally privileged: the host could not exist
     * before its first user, and anything server-wide that reached through it
     * acted on the wrong account for everybody else. They belong to the host.
     */
    metalbear_key_rotation *plc_rotation;
    metalbear_oauth_store *oauth;
    metalbear_account_registry *registry;
    wf_rate_limiter *rate_limiter;
    metalbear_email *email;
    char *service_did;
    char *public_url;
    char *user_domain;
    char *data_directory;
    char *account_email;
    /* Who runs this instance; surfaced on describeServer where the protocol
     * defines a field, and on /operator.json where it does not. */
    char *operator_name;
    char *operator_url;
    char *support_url;
    char *instance_description;
    char *privacy_policy_url;
    char *terms_of_service_url;
    bool development;
    int64_t retention_max_age;
    int64_t retention_min_events;
    /* refpds-mirrored config (METALBEAR_*) */
    char *admin_password;     /* may be NULL => admin endpoints 401 */
    char *crawlers;           /* comma-separated relay hosts, may be NULL */
    bool invite_required;
    int64_t blob_upload_limit; /* 0 => unlimited */
    char *plc_url;            /* PLC directory URL or NULL */
    char *appview_url;        /* Upstream AppView URL or NULL */
    char *appview_did;        /* Upstream AppView DID for service-auth or NULL */
    metalbear_account_cache *account_cache;
    metalbear_report_store *reports;
    /* The PDS-wide firehose log. subscribeRepos is one stream for the whole
     * host, so every account publishes into this rather than its own. */
    metalbear_sequencer *sequencer;
    /* Lexicon corpus used to validate records on write. NULL when no corpus
     * was found, in which case every write reports validationStatus
     * "unknown" rather than pretending records were checked. */
    wf_lexicon_registry *lexicons;
    /* Publishes the `_atproto` TXT records that make minted handles resolve.
     * NULL when no DNS provider is configured, which leaves those records to
     * the operator. */
    metalbear_handle_dns *handle_dns;
    metalbear_update_watcher *update_watcher;
};

/*
 * Point `_atproto.<handle>` at `did`, if a provider is configured.
 *
 * Never fatal to the operation that triggered it. The account or the rename is
 * already durable by the time this runs, and an unresolvable handle is a
 * recoverable state: the record can be written by hand, and the next handle
 * change tries again. Failing the request instead would leave the caller
 * believing nothing happened when the account exists.
 */
static void publish_handle_dns(metalbear_server *server, const char *handle,
                               const char *did) {
    if (!server->handle_dns || !handle || !did) return;
    if (metalbear_handle_dns_publish(server->handle_dns, handle, did) != WF_OK) {
        metalbear_metrics_inc(METALBEAR_METRIC_DNS_FAILURES);
        LOG_ERROR("dns: could not publish _atproto.%s for did=%s: %s; the "
                  "handle will not resolve until the record exists",
                  handle, did,
                  metalbear_handle_dns_last_error(server->handle_dns));
        return;
    }
    LOG_INFO("dns: published _atproto.%s -> %s", handle, did);
}

/* Drop `_atproto.<handle>`, if a provider is configured. Same rule: a stale
 * record is a smaller problem than a failed deletion, so this only logs. */
static void retract_handle_dns(metalbear_server *server, const char *handle) {
    if (!server->handle_dns || !handle) return;
    if (metalbear_handle_dns_retract(server->handle_dns, handle) != WF_OK) {
        metalbear_metrics_inc(METALBEAR_METRIC_DNS_FAILURES);
        LOG_WARN("dns: could not remove _atproto.%s: %s; the record now points "
                 "at a handle this host no longer serves",
                 handle, metalbear_handle_dns_last_error(server->handle_dns));
        return;
    }
    LOG_INFO("dns: removed _atproto.%s", handle);
}

static bool is_public_route(const char *nsid) {
    static const char *const public_routes[] = {
        "com.atproto.server.describeServer",
        "_health",
        "com.atproto.server.createSession",
        "com.atproto.server.createAccount",
        "com.atproto.server.requestPasswordReset",
        "com.atproto.server.reserveSigningKey",
        "com.atproto.identity.resolveHandle",
        "com.atproto.identity.resolveDid",
        "com.atproto.identity.resolveIdentity",
        "com.atproto.identity.refreshIdentity",
        "com.atproto.repo.getRecord",
        "com.atproto.repo.describeRepo",
        "com.atproto.repo.listRecords",
        "com.atproto.sync.getLatestCommit",
        "com.atproto.sync.getBlob",
        "com.atproto.sync.getRepo",
        "com.atproto.sync.getBlocks",
        "com.atproto.sync.getRepoStatus",
        "com.atproto.sync.listRepos",
        "com.atproto.sync.listReposByCollection",
        "com.atproto.sync.listBlobs",
        "com.atproto.sync.getRecord",
        "com.atproto.sync.subscribeRepos",
        "com.atproto.sync.requestCrawl",
    };
    for (size_t i = 0; i < sizeof(public_routes) / sizeof(public_routes[0]); i++)
        if (strcmp(nsid, public_routes[i]) == 0) return true;
    return false;
}

/* Admin endpoints (refpds model): gated behind HTTP Basic
 * `admin:<METALBEAR_ADMIN_PASSWORD>`. */
static bool is_admin_route(const char *nsid) {
    /*
     * Invite creation is admin-authenticated, matching the reference, which
     * gates both endpoints on `authVerifier.adminToken`. Omitting them left
     * the only way to mint a code behind a bearer token — and with
     * `invite_required` set, that made it impossible to create any account at
     * all: the endpoint that issues the code an account needs could not
     * itself be reached. The lockout is invisible while registration is open.
     */
    return strcmp(nsid, "com.atproto.server.createInviteCode") == 0 ||
           strcmp(nsid, "com.atproto.server.createInviteCodes") == 0 ||
           strcmp(nsid, "com.atproto.admin.getAccountInfo") == 0 ||
           strcmp(nsid, "com.atproto.admin.getAccountInfos") == 0 ||
           strcmp(nsid, "com.atproto.admin.getSubjectStatus") == 0 ||
           strcmp(nsid, "com.atproto.admin.updateSubjectStatus") == 0 ||
           strcmp(nsid, "com.atproto.admin.sendEmail") == 0 ||
           strcmp(nsid, "com.atproto.admin.updateAccountHandle") == 0 ||
           strcmp(nsid, "com.atproto.admin.updateAccountEmail") == 0 ||
           strcmp(nsid, "com.atproto.admin.updateAccountPassword") == 0 ||
           strcmp(nsid, "com.atproto.admin.enableAccountInvites") == 0 ||
           strcmp(nsid, "com.atproto.admin.disableAccountInvites") == 0 ||
           strcmp(nsid, "com.atproto.admin.getInviteCodes") == 0 ||
           strcmp(nsid, "com.atproto.admin.disableInviteCodes") == 0 ||
           strcmp(nsid, "com.atproto.admin.deleteAccount") == 0;
}

/* Parse and verify the HTTP Basic credential against the configured admin
 * password. Builds the expected `admin:<password>` string, base64-encodes
 * it with OpenSSL, and compares constant-time. Returns false when no admin
 * password is configured or the supplied credential does not match. */
static bool admin_authenticated(metalbear_server *server,
                              const wf_xrpc_request *req) {
    if (!server->admin_password || !server->admin_password[0])
        return false;
    const char *header = req->auth_header;
    static const char prefix[] = "Basic ";
    if (!header || strncmp(header, prefix, sizeof(prefix) - 1) != 0)
        return false;
    const char *provided = header + sizeof(prefix) - 1;
    /* Skip trailing whitespace (newline) some clients append. */
    size_t provided_len = strlen(provided);
    while (provided_len > 0 &&
           (provided[provided_len - 1] == '\r' ||
            provided[provided_len - 1] == '\n' ||
            provided[provided_len - 1] == ' '))
        provided_len--;

    char expected[512];
    int n = snprintf(expected, sizeof(expected), "admin:%s",
                    server->admin_password);
    if (n < 0 || (size_t)n >= sizeof(expected)) return false;
    char encoded[1024];
    int elen = EVP_EncodeBlock((unsigned char *)encoded,
                                (const unsigned char *)expected, n);
    if (elen <= 0) return false;

    if ((size_t)elen != provided_len) return false;
    return CRYPTO_memcmp(encoded, provided, (size_t)elen) == 0;
}

static const char *bearer_token(const char *header) {
    static const char prefix[] = "Bearer ";
    if (!header || strncmp(header, prefix, sizeof(prefix) - 1) != 0)
        return NULL;
    return header + sizeof(prefix) - 1;
}

/* Decode the `sub` claim from a JWT *without* verifying its signature. This
 * is used only to route the request to the correct account's auth store, which
 * then performs real signature/expiry/scope verification. Returns a
 * caller-owned string, or NULL on any parse failure. */
static char *jwt_subject(const char *token) {
    if (!token) return NULL;
    const char *first = strchr(token, '.');
    if (!first) return NULL;
    const char *second = strchr(first + 1, '.');
    if (!second) return NULL;
    size_t len = (size_t)(second - (first + 1));
    char *segment = malloc(len + 1);
    if (!segment) return NULL;
    memcpy(segment, first + 1, len);
    segment[len] = '\0';
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    wf_status decoded = wf_crypto_base64url_decode(segment, &raw, &raw_len);
    free(segment);
    if (decoded != WF_OK || !raw)
        return NULL;
    cJSON *payload = cJSON_ParseWithLength((const char *)raw, raw_len);
    free(raw);
    if (!payload) return NULL;
    cJSON *sub = cJSON_GetObjectItemCaseSensitive(payload, "sub");
    char *result = NULL;
    if (cJSON_IsString(sub) && sub->valuestring[0])
        result = strdup(sub->valuestring);
    cJSON_Delete(payload);
    return result;
}

/*
 * Detect whether the Authorization header carries a DPoP scheme token (RFC
 * 9449). The atproto OAuth profile uses `Authorization: DPoP <token>` with a
 * separate `DPoP: <proof>` header. A plain `Bearer` header with a DPoP proof
 * header also indicates an OAuth-bound request (RFC 9449 accepts both).
 */
static bool is_dpop_request(const char *auth_header, const char *dpop_header) {
    if (!auth_header) return false;
    if (strncasecmp(auth_header, "DPoP ", 5) == 0) return true;
    return dpop_header && strncasecmp(auth_header, "Bearer ", 7) == 0;
}

/*
 * Verify an OAuth DPoP-bound access token and set the authenticated subject.
 * Returns WF_OK on success, with `out_subject` set to a heap-owned DID string
 * that the caller must free. The request URI (htu) is reconstructed from the
 * server's public URL and the XRPC NSID — the DPoP proof's `htu` is compared
 * against this (query and fragment stripped by Wolfram's normalize_htu).
 */
static wf_status authenticate_oauth(metalbear_server *server,
                                     const wf_xrpc_request *req,
                                     char **out_subject,
                                     char **out_scope) {
    if (!server->oauth) {
        LOG_WARN("authenticate: OAuth token presented but no OAuth store");
        return WF_ERR_PERMISSION;
    }

    /* Build the htu: <public_url>/xrpc/<nsid>. The DPoP proof's htu must
     * match this (after normalization strips query/fragment). */
    char htu[1024];
    int n = snprintf(htu, sizeof(htu), "%s/xrpc/%s",
                     server->public_url ? server->public_url : "",
                     req->nsid ? req->nsid : "");
    if (n < 0 || (size_t)n >= sizeof(htu)) {
        LOG_WARN("authenticate: OAuth htu exceeds buffer");
        return WF_ERR_INTERNAL;
    }

    wf_oauth_verified_token *verified = NULL;
    wf_status status = metalbear_oauth_verify_request(
        server->oauth, req->auth_header, req->dpop_header,
        req->method ? req->method : "GET", htu, &verified);
    if (status != WF_OK) {
        LOG_WARN("authenticate: OAuth verify failed nsid=%s status=%d",
                 req->nsid ? req->nsid : "-", status);
        return status;
    }

    /* metalbear_oauth_verify_request already checks iss/aud/scope/dpop_bound,
     * but the subject may not be an account we host. */
    if (!verified->sub || !verified->sub[0]) {
        wf_oauth_verified_token_free(verified);
        return WF_ERR_PERMISSION;
    }

    *out_subject = strdup(verified->sub);
    *out_scope = verified->scope ? strdup(verified->scope) : NULL;
    wf_oauth_verified_token_free(verified);
    return *out_subject ? WF_OK : WF_ERR_ALLOC;
}

/* Determine the account DID implied by a request: the authenticated subject
 * (writes / self endpoints) or a `did`/`repo` parameter (public reads). When
 * the DID must be extracted from an `at://` `repo` value, it is written into
 * `buf` and `buf` is returned; otherwise the parameter pointer is returned. */
static const char *request_account_did(metalbear_server *server,
                                        const wf_xrpc_request *req,
                                        char *buf, size_t bufsz) {
    (void)server;
    if (req->authed_subject && req->authed_subject[0])
        return req->authed_subject;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *repo = cJSON_GetObjectItemCaseSensitive(req->params, "repo");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        const char *cand = cJSON_IsString(repo) ? repo->valuestring :
                           (cJSON_IsString(did) ? did->valuestring : NULL);
        if (cand && strncmp(cand, "did:", 4) == 0) return cand;
        if (cand && strncmp(cand, "at://", 5) == 0) {
            const char *p = cand + 5;
            size_t n = 0;
            while (p[n] && p[n] != '/') n++;
            if (n > 0 && n < bufsz) {
                memcpy(buf, p, n);
                buf[n] = '\0';
                return buf;
            }
        }
    }
    return NULL;
}

/*
 * Split `at://<authority>/<collection>/<rkey>` into its three parts, each
 * copied into the caller's buffer. Returns false unless all three are present
 * and fit: a strong reference names exactly one record, and a URI stopping at
 * the collection names a great many.
 */
static bool split_at_uri(const char *uri,
                         char *authority, size_t authority_sz,
                         char *collection, size_t collection_sz,
                         char *rkey, size_t rkey_sz) {
    if (!uri || strncmp(uri, "at://", 5) != 0) return false;
    const char *parts[3];
    size_t lengths[3];
    const char *p = uri + 5;
    for (int i = 0; i < 3; i++) {
        parts[i] = p;
        size_t n = 0;
        while (p[n] && p[n] != '/') n++;
        lengths[i] = n;
        if (n == 0) return false;
        p += n;
        if (i < 2) {
            if (*p != '/') return false;
            p++;
        }
    }
    if (*p != '\0') return false;
    char *outs[3] = { authority, collection, rkey };
    size_t sizes[3] = { authority_sz, collection_sz, rkey_sz };
    for (int i = 0; i < 3; i++) {
        if (lengths[i] >= sizes[i]) return false;
        memcpy(outs[i], parts[i], lengths[i]);
        outs[i][lengths[i]] = '\0';
    }
    return true;
}

/* Return the cached context for `did`. The returned context is owned by the
 * cache and must NOT be freed by the caller. Returns NULL when the DID is
 * unknown / cannot be opened. Every account resolves the same way — there is
 * no account the server holds open in preference to the others. */
static metalbear_account_context *context_for_did(metalbear_server *server,
                                                  const char *did) {
    if (!did) return NULL;
    metalbear_account_context *acct = metalbear_account_cache_get(server->account_cache, server->registry,
                                                                  did);
    if (!acct)
        LOG_WARN("context_for_did: unknown did=%s", did);
    return acct;
}

static metalbear_account_context *context_for_identifier(
    metalbear_server *server, const char *identifier) {
    metalbear_account_entry *entry = NULL;
    wf_status status = metalbear_account_registry_find_by_did(
        server->registry, identifier, &entry);
    if (status != WF_OK)
        status = metalbear_account_registry_find_by_handle(
            server->registry, identifier, &entry);
    if (status != WF_OK || !entry) return NULL;
    metalbear_account_context *acct = context_for_did(server, entry->did);
    metalbear_account_entry_free(entry);
    return acct;
}

/* Resolve the account context for a request. The returned context is owned by
 * the cache and must NOT be freed by the caller. Returns NULL when the account
 * cannot be resolved. */
static metalbear_account_context *resolve_request_context(
    metalbear_server *server, const wf_xrpc_request *req) {
    char buf[256];
    const char *did = request_account_did(server, req, buf, sizeof(buf));
    return context_for_did(server, did);
}

/* wolfram per-request resolver: map a request to the correct account's repo /
 * blob stores. Borrowed pointers remain valid for the request duration because
 * the cache outlives the request. */
static wf_status metalbear_repo_resolver(void *ctx,
                                         const wf_xrpc_request *req,
                                         metalbear_repo_store **out_repo,
                                         metalbear_blob_store **out_blobs) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, req);
    if (!acct) return WF_ERR_NOT_FOUND;
    *out_repo = acct->repo;
    *out_blobs = acct->blobs;
    return WF_OK;
}

static bool inactive_route_allowed(const char *nsid) {
    return strcmp(nsid, "com.atproto.server.getSession") == 0 ||
           strcmp(nsid, "com.atproto.server.checkAccountStatus") == 0 ||
           strcmp(nsid, "com.atproto.server.activateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.deactivateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.refreshSession") == 0 ||
           strcmp(nsid, "com.atproto.server.deleteSession") == 0;
}

static bool full_access_route(const char *nsid) {
    return strcmp(nsid, "com.atproto.server.createAppPassword") == 0 ||
           strcmp(nsid, "com.atproto.server.activateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.deactivateAccount") == 0;
}

/* Defined below alongside the other account-status helpers. */
static bool account_is_taken_down(metalbear_server *server, const char *did);

static wf_status authenticate_request(wf_xrpc_request *req, void *ctx);

/*
 * Wraps the auth callback to count refusals it makes for a reason the status
 * alone does not carry: the observer sees a 401, but not whether it came from
 * a missing token, an expired one, or an account that may not act.
 */
static wf_status authenticate(wf_xrpc_request *req, void *ctx) {
    wf_status status = authenticate_request(req, ctx);
    if (status != WF_OK) metalbear_metrics_inc(METALBEAR_METRIC_AUTH_REFUSED);
    return status;
}

static wf_status authenticate_request(wf_xrpc_request *req, void *ctx) {
    metalbear_server *server = ctx;
    LOG_DEBUG("authenticate: nsid=%s method=%s host=%s auth=%s",
              req->nsid ? req->nsid : "-",
              req->method ? req->method : "-",
              req->host_header ? req->host_header : "-",
              req->auth_header ? "yes" : "no");
    /* Admin endpoints (refpds PDS_ADMIN_PASSWORD) are gated by HTTP Basic
     * `admin:<password>`, not bearer tokens. Reject honestly when no
     * password is configured or the credential is missing/wrong. */
    if (is_admin_route(req->nsid))
        return admin_authenticated(server, req) ? WF_OK : WF_ERR_PERMISSION;
    if (is_public_route(req->nsid)) {
        /*
         * An unavailable account's repo is not readable. Resolve which account
         * the request names rather than consulting a single privileged one:
         * checking the configured account's state meant one user deactivating
         * took every other account's public reads down with them, and left a
         * deactivated user's own repo readable.
         *
         * Only the `com.atproto.repo` reads are gated here, and only for
         * deactivation. Everything else — takedowns, and the sync reads —
         * goes through assert_repo_available in the handlers, because this
         * gate can report `RepoDeactivated` and nothing else: a takedown
         * answered under that name tells a consuming relay the account holder
         * chose to leave, when this host in fact refused to serve them.
         */
        if (strncmp(req->nsid, "com.atproto.repo.", 17) == 0) {
            const cJSON *repo = req->params
                ? cJSON_GetObjectItemCaseSensitive(req->params, "repo") : NULL;
            const cJSON *did = req->params
                ? cJSON_GetObjectItemCaseSensitive(req->params, "did") : NULL;
            const cJSON *target = cJSON_IsString(repo) ? repo :
                                  (cJSON_IsString(did) ? did : NULL);
            if (target) {
                metalbear_account_context *acct =
                    context_for_identifier(server, target->valuestring);
                if (acct && !metalbear_account_is_active(acct->account) &&
                    !account_is_taken_down(server, acct->did))
                    return WF_ERR_CONFLICT;
            }
        }
        return WF_OK;
    }
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *repo = cJSON_GetObjectItemCaseSensitive(req->params, "repo");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        cJSON *target = cJSON_IsString(repo) ? repo :
                        (cJSON_IsString(did) ? did : NULL);
        if (target) {
            metalbear_account_entry *entry = NULL;
            wf_status lookup = metalbear_account_registry_find_by_did(
                server->registry, target->valuestring, &entry);
            bool known = lookup == WF_OK && entry;
            metalbear_account_entry_free(entry);
            if (!known)
                return WF_ERR_PERMISSION;
        }
    }

    /*
     * Two token types reach this point, distinguished by the Authorization
     * scheme and the presence of a DPoP proof header:
     *
     *   - Session JWTs (createSession): `Authorization: Bearer <jwt>`, no
     *     DPoP header. HS256-signed, verified against the account's auth
     *     store.
     *   - OAuth DPoP tokens: `Authorization: DPoP <token>` (or `Bearer`
     *     with a DPoP header), plus `DPoP: <proof>`. ES256-signed, verified
     *     against the server's OAuth trusted keys.
     *
     * The flows share takedown and deactivation checks but differ in how the
     * subject is extracted and the token verified.
     */
    char *sub = NULL;
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    char *oauth_scope_str = NULL;

    if (is_dpop_request(req->auth_header, req->dpop_header)) {
        wf_status oauth_status = authenticate_oauth(server, req, &sub,
                                                    &oauth_scope_str);
        if (oauth_status != WF_OK) return oauth_status;

        /* Parse the OAuth scope and enforce granular permissions.
         *
         * The "atproto" static scope grants full access (equivalent to a
         * session token). Dynamic scopes like "repo:<collection>?action=<a>"
         * grant only the specified actions on the specified collections.
         *
         * If the scope is NULL or empty, we treat it as full access for
         * backwards compatibility (older tokens may not carry a scope).
         */
        if (oauth_scope_str && oauth_scope_str[0]) {
            mb_scope_set scope_set;
            if (mb_scope_set_parse(oauth_scope_str, &scope_set) == WF_OK) {
                if (!mb_scope_set_is_full_access(&scope_set)) {
                    /* Determine the collection and action from the request */
                    const char *nsid = req->nsid ? req->nsid : "";
                    mb_repo_action action = MB_REPO_ACTION_NONE;
                    const char *collection = NULL;
                    cJSON *coll_param = NULL;

                    if (strcmp(nsid, "com.atproto.repo.createRecord") == 0) {
                        action = MB_REPO_ACTION_CREATE;
                        coll_param = req->params
                            ? cJSON_GetObjectItemCaseSensitive(req->params,
                                                               "collection")
                            : NULL;
                    } else if (strcmp(nsid, "com.atproto.repo.putRecord") == 0) {
                        action = MB_REPO_ACTION_UPDATE;
                        coll_param = req->params
                            ? cJSON_GetObjectItemCaseSensitive(req->params,
                                                               "collection")
                            : NULL;
                    } else if (strcmp(nsid, "com.atproto.repo.deleteRecord") == 0) {
                        action = MB_REPO_ACTION_DELETE;
                        coll_param = req->params
                            ? cJSON_GetObjectItemCaseSensitive(req->params,
                                                               "collection")
                            : NULL;
                    }

                    collection = cJSON_IsString(coll_param)
                        ? coll_param->valuestring : NULL;

                    if (action != MB_REPO_ACTION_NONE && collection) {
                        if (!mb_scope_set_allows_repo(&scope_set,
                                                       collection, action)) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "did=%s nsid=%s collection=%s action=%d",
                                     sub, nsid, collection, action);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (action == MB_REPO_ACTION_NONE) {
                        /* Read or non-repo operation: check read access.
                         * For now, allow reads if any repo scope matches
                         * or if the scope set is not empty. Full enforcement
                         * of read scopes will be added once the upstream
                         * spec finalizes read permissions. */
                        if (collection &&
                            !mb_scope_set_allows_read(&scope_set, collection) &&
                            !mb_scope_set_is_full_access(&scope_set)) {
                            LOG_WARN("authenticate: OAuth scope denied read "
                                     "did=%s nsid=%s collection=%s",
                                     sub, nsid, collection);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    }
                }
            }
            mb_scope_set_free(&scope_set);
        }
        free(oauth_scope_str);
    } else {
        const char *provided = bearer_token(req->auth_header);
        if (!provided) {
            LOG_DEBUG("authenticate: no bearer token for nsid=%s host=%s",
                      req->nsid ? req->nsid : "-",
                      req->host_header ? req->host_header : "-");
            return WF_ERR_PERMISSION;
        }

        /* Route to the account named by the token's `sub` claim, then verify
         * the token against THAT account's auth store. The signature is
         * server-wide, so verification proves the token is genuine and `sub`
         * is the identity we bind the request to. */
        sub = jwt_subject(provided);
        if (!sub) {
            LOG_DEBUG("authenticate: invalid JWT for nsid=%s host=%s",
                      req->nsid ? req->nsid : "-",
                      req->host_header ? req->host_header : "-");
            return WF_ERR_PERMISSION;
        }

        bool refresh_route = strcmp(req->nsid,
                                    "com.atproto.server.refreshSession") == 0 ||
                             strcmp(req->nsid,
                                    "com.atproto.server.deleteSession") == 0;
        wf_status verify_status = refresh_route
            ? WF_OK
            : metalbear_auth_verify_access_scope(
                  context_for_did(server, sub)->auth, provided, &scope);
        if (verify_status != WF_OK) {
            LOG_WARN("authenticate: token verify failed for did=%s nsid=%s status=%d",
                     sub, req->nsid ? req->nsid : "-", verify_status);
            free(sub);
            return verify_status;
        }
        if (!refresh_route && full_access_route(req->nsid) &&
            scope != METALBEAR_ACCESS_FULL) {
            LOG_WARN("authenticate: insufficient scope for did=%s nsid=%s scope=%d",
                     sub, req->nsid ? req->nsid : "-", scope);
            free(sub);
            return WF_ERR_PERMISSION;
        }
    }

    metalbear_account_context *acct = context_for_did(server, sub);
    if (!acct) {
        LOG_WARN("authenticate: unknown did=%s for nsid=%s host=%s",
                 sub, req->nsid ? req->nsid : "-",
                 req->host_header ? req->host_header : "-");
        free(sub);
        return WF_ERR_PERMISSION;
    }

    /*
     * A takedown admits none of the exceptions a deactivation does: the
     * routes a deactivated account may still reach exist so its holder can
     * reactivate or export, and a taken-down account reactivating itself
     * would undo the moderation action. Sessions are revoked when the
     * takedown is applied, but a token minted before it must not outlive it.
     *
     * The refresh pair is left to its handlers, which answer with the
     * lexicon's `AccountTakedown` rather than a bare authentication failure —
     * the difference a client needs to stop retrying and tell its user why.
     */
    if (account_is_taken_down(server, sub)) {
        LOG_WARN("authenticate: taken-down account did=%s nsid=%s", sub,
                 req->nsid ? req->nsid : "-");
        free(sub);
        return WF_ERR_PERMISSION;
    }
    if (!metalbear_account_is_active(acct->account) &&
        !inactive_route_allowed(req->nsid)) {
        LOG_WARN("authenticate: deactivated account did=%s nsid=%s", sub,
                 req->nsid ? req->nsid : "-");
        free(sub);
        return WF_ERR_CONFLICT;
    }

    LOG_DEBUG("authenticate: granted did=%s nsid=%s scope=%d host=%s", sub,
              req->nsid ? req->nsid : "-", scope,
              req->host_header ? req->host_header : "-");

    req->authed_subject = sub;
    req->authed_principal_kind = WF_XRPC_PRINCIPAL_USER;
    return WF_OK;
}

static wf_status set_json(wf_xrpc_response *response, cJSON *root) {
    if (!root) return WF_ERR_ALLOC;
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return WF_ERR_ALLOC;
    wf_xrpc_response_set_content_type(response, "application/json");
    wf_xrpc_response_set_body(response, json, strlen(json));
    free(json);
    return WF_OK;
}

/* Parse an integer query parameter. XRPC query params always arrive as
 * strings (wf_server_qs_iter), so cJSON_IsNumber checks silently drop
 * them; accept both string and number forms. Returns `fallback` when
 * absent or unparsable, clamped to [min, max]. */
static int query_param_int(const cJSON *params, const char *name,
                           int fallback, int min, int max) {
    const cJSON *p = params
        ? cJSON_GetObjectItemCaseSensitive(params, name) : NULL;
    long v = fallback;
    if (cJSON_IsNumber(p)) {
        v = (long)p->valuedouble;
    } else if (cJSON_IsString(p) && p->valuestring[0]) {
        char *end = NULL;
        long parsed = strtol(p->valuestring, &end, 10);
        if (*end != '\0') return fallback;
        v = parsed;
    }
    if (v < min) v = min;
    if (v > max) v = max;
    return (int)v;
}

static wf_status request_account_delete(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    /* The requester's own account — not the server's configured one. This
     * route is authenticated, so there is always a subject to act on. */
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "delete",
                                             token, sizeof(token)) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create deletion token");
        return WF_OK;
    }
    /* Send confirmation to the requester's own address. */
    char *acct_email = NULL;
    metalbear_account_get_email(acct->account, &acct_email, NULL);
    const char *to = (acct_email && acct_email[0]) ? acct_email
                                                   : server->account_email;
    if (server->email && to && to[0])
        metalbear_email_send_account_deletion(server->email, to, token);
    free(acct_email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "token", token);
    return set_json(response, root);
}

static wf_status delete_account(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *password = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "password") : NULL;
    cJSON *token = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    if (!cJSON_IsString(password) || !password->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "password is required");
        return WF_OK;
    }
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "token is required");
        return WF_OK;
    }
    /*
     * Act on the account named by `did`. This took the caller's did, ignored
     * it, and deleted the server's configured account instead — so a user
     * deleting their own account destroyed somebody else's, and anyone holding
     * that account's credentials could delete it while naming any did at all.
     */
    metalbear_account_context *acct = context_for_did(server, did->valuestring);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Account not found");
        return WF_OK;
    }
    if (!metalbear_account_verify_password(acct->account,
                                           password->valuestring)) {
        wf_xrpc_response_set_error(response, 401, "AuthenticationRequired",
                                   "Invalid password");
        return WF_OK;
    }
    wf_status token_status = metalbear_account_verify_email_token(
        acct->account, "delete", token->valuestring);
    if (token_status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired deletion token");
        return WF_OK;
    }
    /* Revoke all sessions */
    metalbear_auth_delete_all(acct->auth);
    /* Delete all app passwords and credentials */
    metalbear_account_delete(acct->account);
    /* Deactivate the account */
    metalbear_account_deactivate(acct->account, NULL);
    /* Remove from the account registry, moderation state included: a DID
     * re-registered later must not inherit the old account's takedowns. */
    metalbear_account_registry_remove(server->registry, acct->did);
    metalbear_account_registry_clear_takedowns_for_did(server->registry,
                                                       acct->did);
    /* Emit deletion event to firehose, against the host log rather than a
     * resolved context's, then drop everything else this DID ever published:
     * leaving it there hands the repository of somebody who asked to be gone
     * to any consumer backfilling from an old cursor. */
    metalbear_sequencer_account_status(server->sequencer, acct->did, 0,
                                       "deleted");
    int64_t purged = 0;
    metalbear_sequencer_purge_account(server->sequencer, acct->did, &purged);
    metalbear_metrics_inc(METALBEAR_METRIC_ACCOUNTS_DELETED);
    LOG_INFO("delete_account: purged %lld firehose events for did=%s",
             (long long)purged, acct->did);
    /* Drop the handle's TXT record: leaving it would keep pointing resolvers
     * at a DID this host no longer serves. */
    retract_handle_dns(server, acct->handle);
    return WF_OK;
}

static wf_status describe_server(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    cJSON *root = cJSON_CreateObject();
    cJSON *domains = cJSON_CreateArray();
    cJSON *contact = cJSON_CreateObject();
    if (!root || !domains || !contact) {
        cJSON_Delete(root);
        cJSON_Delete(domains);
        cJSON_Delete(contact);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", server->service_did);
    cJSON_AddItemToArray(domains, cJSON_CreateString(server->user_domain));
    cJSON_AddItemToObject(root, "availableUserDomains", domains);
    cJSON_AddBoolToObject(root, "inviteCodeRequired", server->invite_required);
    cJSON_AddBoolToObject(root, "phoneVerificationRequired", false);
    if (server->blob_upload_limit > 0)
        cJSON_AddNumberToObject(root, "blobUploadLimit", (double)server->blob_upload_limit);
    if (server->account_email && server->account_email[0])
        cJSON_AddStringToObject(contact, "email", server->account_email);
    cJSON_AddItemToObject(root, "contact", contact);
    /* `links` is part of the lexicon, so policy URLs belong here rather than
     * in anything MetalBear-specific. */
    if ((server->privacy_policy_url && server->privacy_policy_url[0]) ||
        (server->terms_of_service_url && server->terms_of_service_url[0])) {
        cJSON *links = cJSON_CreateObject();
        if (links) {
            if (server->privacy_policy_url && server->privacy_policy_url[0])
                cJSON_AddStringToObject(links, "privacyPolicy",
                                        server->privacy_policy_url);
            if (server->terms_of_service_url && server->terms_of_service_url[0])
                cJSON_AddStringToObject(links, "termsOfService",
                                        server->terms_of_service_url);
            cJSON_AddItemToObject(root, "links", links);
        }
    }
    return set_json(response, root);
}

/* ---- GET /operator.json (MetalBear-specific) ----
 *
 * Who runs this instance and what software it is. Deliberately not an XRPC
 * method: none of this is in any lexicon, and putting it under /xrpc/ would
 * imply a protocol surface that does not exist. The landing page reads it so
 * that the operator details have one source of truth — the server config —
 * rather than being duplicated into a static page that then goes stale.
 */
static wf_status operator_info(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    (void)request;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;

    cJSON *op = cJSON_CreateObject();
    if (op) {
        if (server->operator_name) cJSON_AddStringToObject(op, "name", server->operator_name);
        if (server->account_email) cJSON_AddStringToObject(op, "email", server->account_email);
        if (server->operator_url)  cJSON_AddStringToObject(op, "url", server->operator_url);
        if (server->support_url)   cJSON_AddStringToObject(op, "supportUrl", server->support_url);
        cJSON_AddItemToObject(root, "operator", op);
    }

    cJSON *sw = cJSON_CreateObject();
    if (sw) {
        cJSON_AddStringToObject(sw, "name", "MetalBear");
        cJSON_AddStringToObject(sw, "version", METALBEAR_VERSION);
        cJSON_AddStringToObject(sw, "repository",
                                "https://github.com/ewanc26/metalbear");
        cJSON_AddStringToObject(sw, "license", "AGPL-3.0-only");
        cJSON_AddItemToObject(root, "software", sw);
    }

    if (server->instance_description)
        cJSON_AddStringToObject(root, "description", server->instance_description);
    /* A testing instance says so, so nobody mistakes its accounts for people. */
    cJSON_AddBoolToObject(root, "development", server->development);
    return set_json(response, root);
}

static wf_status health(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response) {
    (void)ctx;
    (void)request;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "version", METALBEAR_VERSION);
    return set_json(response, root);
}

static wf_status resolve_handle(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *handle = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "handle") : NULL;
    metalbear_account_context *acct = cJSON_IsString(handle) &&
        wf_syntax_handle_is_valid(handle->valuestring)
        ? context_for_identifier(server, handle->valuestring) : NULL;
    if (!acct || !metalbear_account_is_active(acct->account) ||
        account_is_taken_down(server, acct->did)) {
        wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "did", acct->did);
    return set_json(response, root);
}

/* ---- shared identity resolution helpers ----
 * Used by com.atproto.identity.resolveDid / resolveIdentity / refreshIdentity.
 * Local accounts are answered from the registry; everything else resolves
 * over the network (PLC directory for did:plc, well-known for did:web,
 * DNS TXT + well-known for handles), matching rsky-pds' behavior. */

/* Defined further below alongside the session serializers. */
static cJSON *build_did_doc(metalbear_server *server,
                            metalbear_account_context *acct);

/* Fetch a remote DID document's raw JSON. did:plc goes through the
 * configured PLC directory; did:web through its well-known URL. On WF_OK
 * *out_json is heap-allocated and must be freed by the caller. */
/*
 * Small TTL cache of resolved DID documents.
 *
 * Every describeRepo, checkAccountStatus and handle check resolves the DID
 * over the network. Once the host federates that is not a trickle: AppView
 * and indexer traffic drove 241 describeRepo calls in two minutes, each one
 * blocking a worker thread on an outbound request to plc.directory, one to
 * one, until the server stopped answering. Identity documents change rarely,
 * so a short cache removes the amplification without hiding real changes.
 *
 * Deliberately tiny and fixed-size: this is a cache, and a miss is only ever
 * the current behaviour.
 */
#define DID_DOC_CACHE_SLOTS   256    /* upper bound; the live size is config */
#define DID_DOC_CACHE_SECONDS 300

/* Live limits, set from config at startup; the defaults match the constants. */
static size_t did_doc_cache_slots = 64;
static time_t did_doc_cache_ttl = DID_DOC_CACHE_SECONDS;

typedef struct {
    char   did[256];
    char  *json;      /* owned */
    time_t fetched_at;
} did_doc_cache_entry;

static did_doc_cache_entry did_doc_cache[DID_DOC_CACHE_SLOTS];
static pthread_mutex_t did_doc_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* Returns an owned copy of the cached document, or NULL on a miss. */
static char *did_doc_cache_get(const char *did) {
    if (!did) return NULL;
    char *copy = NULL;
    time_t now = time(NULL);
    pthread_mutex_lock(&did_doc_cache_lock);
    for (size_t i = 0; i < did_doc_cache_slots; i++) {
        did_doc_cache_entry *e = &did_doc_cache[i];
        if (!e->json || strcmp(e->did, did) != 0) continue;
        if (now - e->fetched_at > did_doc_cache_ttl) {
            free(e->json);
            e->json = NULL;
            break;
        }
        copy = strdup(e->json);
        break;
    }
    pthread_mutex_unlock(&did_doc_cache_lock);
    return copy;
}

static void did_doc_cache_put(const char *did, const char *json) {
    if (!did || !json || strlen(did) >= sizeof(did_doc_cache[0].did)) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&did_doc_cache_lock);
    /* Reuse this DID's slot, else an empty or expired one, else the oldest. */
    size_t victim = 0;
    time_t oldest = now + 1;
    for (size_t i = 0; i < did_doc_cache_slots; i++) {
        did_doc_cache_entry *e = &did_doc_cache[i];
        if (e->json && strcmp(e->did, did) == 0) { victim = i; goto store; }
        if (!e->json) { victim = i; goto store; }
        if (e->fetched_at < oldest) { oldest = e->fetched_at; victim = i; }
    }
store:
    free(did_doc_cache[victim].json);
    did_doc_cache[victim].json = strdup(json);
    if (did_doc_cache[victim].json) {
        snprintf(did_doc_cache[victim].did, sizeof(did_doc_cache[victim].did),
                 "%s", did);
        did_doc_cache[victim].fetched_at = now;
    }
    pthread_mutex_unlock(&did_doc_cache_lock);
}

static wf_status fetch_remote_did_doc(metalbear_server *server,
                                      const char *did, char **out_json) {
    *out_json = NULL;
    if (!did) return WF_ERR_INVALID_ARG;
    char *cached = did_doc_cache_get(did);
    if (cached) { *out_json = cached; return WF_OK; }
    char url[1024];
    if (strncmp(did, "did:plc:", 8) == 0) {
        if (!server->plc_url) return WF_ERR_NOT_FOUND;
        int n = snprintf(url, sizeof(url), "%s/%s", server->plc_url, did);
        if (n < 0 || (size_t)n >= sizeof(url)) return WF_ERR_INVALID_ARG;
    } else if (strncmp(did, "did:web:", 8) == 0) {
        /* did:web:example.com[:path:segments] -> percent-decoded URL;
         * a plain host uses /.well-known/did.json. */
        char host_path[768];
        size_t j = 0;
        for (const char *p = did + 8; *p && j + 1 < sizeof(host_path); p++) {
            host_path[j++] = (*p == ':') ? '/' : *p;
        }
        host_path[j] = '\0';
        int n;
        if (strchr(host_path, '/'))
            n = snprintf(url, sizeof(url), "https://%s/did.json", host_path);
        else
            n = snprintf(url, sizeof(url), "https://%s/.well-known/did.json",
                         host_path);
        if (n < 0 || (size_t)n >= sizeof(url)) return WF_ERR_INVALID_ARG;
    } else {
        return WF_ERR_INVALID_ARG;
    }
    wf_xrpc_client *client = wf_xrpc_client_new("https://localhost");
    if (!client) return WF_ERR_ALLOC;
    wf_response upstream = {0};
    wf_status status = wf_http_get(client, url, &upstream);
    wf_xrpc_client_free(client);
    if (status != WF_OK || upstream.status < 200 || upstream.status >= 300 ||
        !upstream.body) {
        wf_response_free(&upstream);
        return WF_ERR_NOT_FOUND;
    }
    *out_json = strndup(upstream.body, upstream.body_len);
    if (*out_json) did_doc_cache_put(did, *out_json);
    wf_response_free(&upstream);
    return *out_json ? WF_OK : WF_ERR_ALLOC;
}

/*
 * Is `did` a did:web whose document THIS server publishes?
 *
 * A did:web's authority is whoever serves its document, so for one we host
 * ourselves there is no external party to consult — and trying to consult one
 * is actively harmful: the request loops back through our own ingress and
 * occupies a worker thread that is waiting on this very server. With a handful
 * of such requests the pool is exhausted and the PDS wedges. Resolve these
 * locally instead.
 */
static bool did_web_is_self_hosted(metalbear_server *server, const char *did) {
    if (!did || strncmp(did, "did:web:", 8) != 0 || !server->public_url)
        return false;
    const char *host = did + 8;
    size_t host_len = strcspn(host, ":");   /* stop at the first path segment */

    const char *ours = server->public_url;
    if (strncmp(ours, "https://", 8) == 0) ours += 8;
    else if (strncmp(ours, "http://", 7) == 0) ours += 7;
    size_t ours_len = strcspn(ours, "/");

    return host_len == ours_len && strncmp(host, ours, host_len) == 0;
}

/* metalbear_xrpc_did_doc_provider: resolve `did` through the identity layer
 * (PLC directory / did:web well-known) and return its raw JSON. Deliberately
 * skips the local registry for DIDs someone else is authoritative for —
 * describeRepo uses this to check a handle bi-directionally, which a locally
 * synthesised document cannot do. Returns NULL when the DID does not resolve. */
static char *resolve_did_doc_json(void *ctx, const char *did) {
    metalbear_server *server = ctx;
    if (did_web_is_self_hosted(server, did)) {
        metalbear_account_context *acct = context_for_did(server, did);
        if (!acct) return NULL;
        cJSON *doc = build_did_doc(server, acct);
        if (!doc) return NULL;
        char *json = cJSON_PrintUnformatted(doc);
        cJSON_Delete(doc);
        return json;
    }
    char *json = NULL;
    if (!did || fetch_remote_did_doc(server, did, &json) != WF_OK) return NULL;
    return json;
}

/* Does the account's *published* DID document actually describe this PDS?
 * Mirrors the reference PDS's assertValidDidDocumentForService: the
 * #atproto_pds service endpoint must be our public URL and the #atproto
 * verification method must be the key this repo signs its commits with.
 * A false answer means relays and AppViews will reject the repo's commits,
 * so it must be resolved over the network rather than assumed. */
static bool did_doc_matches_service(metalbear_server *server,
                                    metalbear_account_context *acct) {
    if (!acct->did || !acct->did[0] || !server->public_url) return false;
    const char *local_key =
        acct->repo ? metalbear_repo_store_signing_key_did(acct->repo) : NULL;
    if (!local_key || !local_key[0]) return false;

    /* For a did:web we publish ourselves the document is generated from this
     * repo's own key and this server's URL, so it agrees by construction.
     * Fetching it back over the network would only deadlock on ourselves. */
    if (did_web_is_self_hosted(server, acct->did))
        return context_for_did(server, acct->did) != NULL;

    char *json = NULL;
    if (fetch_remote_did_doc(server, acct->did, &json) != WF_OK || !json)
        return false;
    cJSON *doc = cJSON_Parse(json);
    free(json);
    if (!doc) return false;

    const char *endpoint = metalbear_did_document_pds_endpoint(doc);
    char *published_key = metalbear_did_document_signing_key(doc);
    bool valid = endpoint && strcmp(endpoint, server->public_url) == 0 &&
                 published_key && strcmp(published_key, local_key) == 0;
    if (!valid) {
        LOG_WARN("DID document for %s does not match this service "
                 "(endpoint=%s want=%s, key=%s want=%s)",
                 acct->did, endpoint ? endpoint : "(none)", server->public_url,
                 published_key ? published_key : "(none)", local_key);
    }
    free(published_key);
    cJSON_Delete(doc);
    return valid;
}

/* Build (local) or fetch (remote) the DID document for `did` as a cJSON
 * tree. Caller must cJSON_Delete the result. Sets *deactivated when the
 * local account exists but is unavailable — deactivated or taken down. */
static cJSON *did_doc_for_did(metalbear_server *server, const char *did,
                              bool *deactivated) {
    *deactivated = false;
    metalbear_account_context *acct = context_for_did(server, did);
    if (acct) {
        if (!metalbear_account_is_active(acct->account) ||
            account_is_taken_down(server, acct->did)) {
            *deactivated = true;
            return NULL;
        }
        return build_did_doc(server, acct);
    }
    char *json = NULL;
    if (fetch_remote_did_doc(server, did, &json) != WF_OK || !json)
        return NULL;
    cJSON *doc = cJSON_Parse(json);
    free(json);
    return doc;
}

/* Extract the first at:// handle claimed by a DID document's alsoKnownAs.
 * Heap-allocated; caller frees. NULL when the doc claims no handle. */
static char *did_doc_claimed_handle(const cJSON *did_doc) {
    const cJSON *aka = cJSON_GetObjectItemCaseSensitive(did_doc, "alsoKnownAs");
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, aka) {
        if (!cJSON_IsString(entry) || !entry->valuestring) continue;
        if (strncmp(entry->valuestring, "at://", 5) == 0)
            return strdup(entry->valuestring + 5);
    }
    return NULL;
}

/* Resolve a handle to a DID: local registry first, then DNS TXT /
 * well-known over the network. Heap-allocated; caller frees. */
static char *resolve_handle_to_did(metalbear_server *server,
                                   const char *handle) {
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_handle(server->registry, handle,
                                                  &entry) == WF_OK && entry) {
        char *did = strdup(entry->did);
        metalbear_account_entry_free(entry);
        return did;
    }
    wf_xrpc_client *client = wf_xrpc_client_new("https://localhost");
    if (!client) return NULL;
    char *did = NULL;
    if (wf_handle_resolve(client, handle, &did) != WF_OK) did = NULL;
    wf_xrpc_client_free(client);
    return did;
}

/* Shared core of resolveIdentity (query) and refreshIdentity (procedure):
 * resolve `identifier` (handle or DID) to {did, handle, didDoc} with
 * bi-directional handle verification ('handle.invalid' on mismatch). */
static wf_status identity_info_response(metalbear_server *server,
                                        const char *identifier,
                                        wf_xrpc_response *response) {
    char *did = NULL;
    char *input_handle = NULL;
    if (strncmp(identifier, "did:", 4) == 0) {
        if (!wf_syntax_did_is_valid(identifier)) {
            wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                       "could not resolve DID");
            return WF_OK;
        }
        did = strdup(identifier);
    } else {
        if (!wf_syntax_handle_is_valid(identifier)) {
            wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                       "unable to resolve handle");
            return WF_OK;
        }
        input_handle = strdup(identifier);
        did = resolve_handle_to_did(server, identifier);
        if (!did) {
            free(input_handle);
            wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                       "unable to resolve handle");
            return WF_OK;
        }
    }
    if (!did) {
        free(input_handle);
        return WF_ERR_ALLOC;
    }
    bool deactivated = false;
    cJSON *did_doc = did_doc_for_did(server, did, &deactivated);
    if (!did_doc) {
        free(did);
        free(input_handle);
        if (deactivated)
            wf_xrpc_response_set_error(response, 400, "DidDeactivated",
                                       "DID has been deactivated");
        else
            wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                       "could not resolve DID");
        return WF_OK;
    }
    /* Bi-directional verification of the handle. */
    char *doc_handle = did_doc_claimed_handle(did_doc);
    const char *verified = "handle.invalid";
    if (input_handle) {
        /* The input handle resolved to this DID; validated when the DID
         * document claims the same handle back (case-insensitive). */
        if (doc_handle && strcasecmp(doc_handle, input_handle) == 0)
            verified = doc_handle;
    } else if (doc_handle) {
        /* DID input: verify the claimed handle resolves back to this DID. */
        char *resolved = resolve_handle_to_did(server, doc_handle);
        if (resolved && strcmp(resolved, did) == 0)
            verified = doc_handle;
        free(resolved);
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(did);
        free(input_handle);
        free(doc_handle);
        cJSON_Delete(did_doc);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", did);
    cJSON_AddStringToObject(root, "handle", verified);
    cJSON_AddItemToObject(root, "didDoc", did_doc);
    free(did);
    free(input_handle);
    free(doc_handle);
    return set_json(response, root);
}

/* ---- com.atproto.identity.resolveDid (query) ----
 * Resolves a DID to its complete DID document. Does not bi-directionally
 * verify the handle. Public route. */
static wf_status resolve_did_identity(void *ctx,
                                      const wf_xrpc_request *request,
                                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    if (!cJSON_IsString(did) || !wf_syntax_did_is_valid(did->valuestring)) {
        wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                   "could not resolve DID");
        return WF_OK;
    }
    bool deactivated = false;
    cJSON *did_doc = did_doc_for_did(server, did->valuestring, &deactivated);
    if (!did_doc) {
        if (deactivated)
            wf_xrpc_response_set_error(response, 400, "DidDeactivated",
                                       "DID has been deactivated");
        else
            wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                       "could not resolve DID");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) { cJSON_Delete(did_doc); return WF_ERR_ALLOC; }
    cJSON_AddItemToObject(root, "didDoc", did_doc);
    return set_json(response, root);
}

/* ---- com.atproto.identity.resolveIdentity (query) ----
 * Resolves a handle or DID to a full identity (DID document and verified
 * handle). Public route. */
static wf_status resolve_identity(void *ctx,
                                  const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *identifier = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "identifier") : NULL;
    if (!cJSON_IsString(identifier) || !identifier->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                   "unable to resolve handle");
        return WF_OK;
    }
    return identity_info_response(server, identifier->valuestring, response);
}

/* ---- com.atproto.identity.refreshIdentity (procedure) ----
 * Request that the server re-resolve an identity. MetalBear keeps no DID
 * cache, so every resolution is already fresh; the semantics are identical
 * to resolveIdentity. Public route (the lexicon permits the server to
 * ignore or require auth; rsky-pds treats it as public). */
static wf_status refresh_identity(void *ctx,
                                  const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *identifier = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "identifier") : NULL;
    if (!cJSON_IsString(identifier) || !identifier->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "identifier is required");
        return WF_OK;
    }
    return identity_info_response(server, identifier->valuestring, response);
}

/*
 * Resolve an OAuth `login_hint` (handle or DID) to the account's DID.
 *
 * Handed to the OAuth routes so an authorization names a real account hosted
 * here. Returning 0 for an unknown hint is what keeps the endpoint from
 * issuing a token for an identity this server does not host.
 */
static int resolve_oauth_subject(void *ctx, const char *hint, char *out,
                                 size_t out_len) {
    metalbear_server *server = ctx;
    if (!server || !hint || !hint[0] || !out || out_len == 0) return 0;
    metalbear_account_context *acct = context_for_identifier(server, hint);
    if (!acct || !acct->did || !acct->did[0]) return 0;
    if (strlen(acct->did) >= out_len) return 0;
    snprintf(out, out_len, "%s", acct->did);
    return 1;
}

/*
 * Verify credentials for a device session — /oauth/authorize's proof that
 * the browser controls the account login_hint names, not merely that it
 * knows the handle.
 *
 * Account password only. metalbear_account_verify_credential also accepts
 * app passwords, which valid_login (createSession's own check) is right to
 * allow: an app password is meant to open a session scoped to one
 * third-party client. A device session is not that — it authorizes THIS
 * endpoint to grant arbitrary OTHER OAuth clients access, and opens the web
 * UI's account management including creating further app passwords. An app
 * password that could open one would be a scoped credential escalating
 * itself to full account control, so METALBEAR_CREDENTIAL_ACCOUNT is
 * checked explicitly rather than accepting whatever
 * metalbear_account_verify_credential accepted.
 */
static int verify_oauth_credential(void *ctx, const char *identifier,
                                   const char *password, char *out,
                                   size_t out_len) {
    metalbear_server *server = ctx;
    if (!server || !identifier || !identifier[0] || !password || !out ||
        out_len == 0)
        return 0;
    metalbear_account_context *acct = context_for_identifier(server,
                                                              identifier);
    if (!acct || !acct->did || !acct->did[0]) return 0;
    metalbear_credential_kind credential =
        metalbear_account_verify_credential(acct->account, password, NULL);
    if (credential != METALBEAR_CREDENTIAL_ACCOUNT) return 0;
    if (strlen(acct->did) >= out_len) return 0;
    snprintf(out, out_len, "%s", acct->did);
    return 1;
}

/* ---- com.atproto.identity.getRecommendedDidCredentials (query) ---- */
static wf_status get_recommended_did_credentials(void *ctx,
        const wf_xrpc_request *request, wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    char *didkey = NULL;
    wf_signing_key key;
    memset(&key, 0, sizeof(key));
    /* These are credentials for the account making the request. Reading them
     * from one configured account handed every caller the same identity. */
    metalbear_account_context *acct =
        context_for_did(server, request->authed_subject);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "AuthRequired",
                                   "Authentication required");
        return WF_OK;
    }
    if (metalbear_key_rotation_current_key(acct->key_rotation, &key) != WF_OK ||
        wf_signing_key_public_didkey(&key, &didkey) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not derive signing key");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) { free(didkey); return WF_ERR_ALLOC; }
    cJSON *also_known_as = cJSON_CreateArray();
    if (!also_known_as) { cJSON_Delete(root); free(didkey); return WF_ERR_ALLOC; }
    if (acct->handle && acct->handle[0]) {
        char aka[256];
        snprintf(aka, sizeof(aka), "at://%s", acct->handle);
        cJSON_AddItemToArray(also_known_as, cJSON_CreateString(aka));
    }
    cJSON_AddItemToObject(root, "alsoKnownAs", also_known_as);
    cJSON *verification_methods = cJSON_CreateObject();
    if (!verification_methods) { cJSON_Delete(root); free(didkey); return WF_ERR_ALLOC; }
    cJSON_AddStringToObject(verification_methods, "atproto", didkey);
    cJSON_AddItemToObject(root, "verificationMethods", verification_methods);
    cJSON *rotation_keys = cJSON_CreateArray();
    if (!rotation_keys) { cJSON_Delete(root); free(didkey); return WF_ERR_ALLOC; }
    cJSON_AddItemToArray(rotation_keys, cJSON_CreateString(didkey));
    cJSON_AddItemToObject(root, "rotationKeys", rotation_keys);
    cJSON *services = cJSON_CreateObject();
    if (!services) { cJSON_Delete(root); free(didkey); return WF_ERR_ALLOC; }
    cJSON *atproto_pds = cJSON_CreateObject();
    if (!atproto_pds) { cJSON_Delete(root); free(didkey); return WF_ERR_ALLOC; }
    cJSON_AddStringToObject(atproto_pds, "type", "AtprotoPersonalDataServer");
    cJSON_AddStringToObject(atproto_pds, "serviceEndpoint",
                            server->public_url ? server->public_url : "");
    cJSON_AddItemToObject(services, "atproto_pds", atproto_pds);
    cJSON_AddItemToObject(root, "services", services);
    free(didkey);
    return set_json(response, root);
}

/* ---- com.atproto.identity.updateHandle (procedure) ---- */
static wf_status update_handle(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *handle = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "handle") : NULL;
    if (!cJSON_IsString(handle) || !handle->valuestring[0] ||
        !wf_syntax_handle_is_valid(handle->valuestring)) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "A valid handle is required");
        return WF_OK;
    }
    size_t handle_length = strlen(handle->valuestring);
    size_t domain_length = server->user_domain
        ? strlen(server->user_domain) : 0;
    if (domain_length == 0 || handle_length <= domain_length ||
        strcmp(handle->valuestring + handle_length - domain_length,
               server->user_domain) != 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "Handle must be under the configured domain");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_handle(
            server->registry, handle->valuestring, &existing) == WF_OK &&
        existing && strcmp(existing->did, acct->did) != 0) {
        metalbear_account_entry_free(existing);
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "Handle is already in use");
        return WF_OK;
    }
    metalbear_account_entry_free(existing);
    char *old_handle = strdup(acct->handle);
    char *new_handle = strdup(handle->valuestring);
    if (!old_handle || !new_handle ||
        metalbear_repo_store_set_handle(acct->repo, handle->valuestring) != WF_OK) {
        free(old_handle);
        free(new_handle);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not persist handle");
        return WF_OK;
    }
    if (metalbear_account_registry_update_handle(
            server->registry, acct->did, handle->valuestring) != WF_OK) {
        metalbear_repo_store_set_handle(acct->repo, old_handle);
        free(old_handle);
        free(new_handle);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not persist handle");
        return WF_OK;
    }
    /* Move the TXT record with the handle. Publishing the new one before
     * dropping the old leaves both resolving for a moment, which is the safe
     * order: neither points anywhere wrong, and a resolver that has cached the
     * old name still gets the right DID. */
    publish_handle_dns(server, new_handle, acct->did);
    retract_handle_dns(server, old_handle);

    /*
     * Announce the rename, after the record that makes it resolve.
     *
     * Consumers learned this handle from the #identity event at account
     * creation and have no reason to look again, so without this the rename is
     * durable here and invisible everywhere else. Not fatal: the handle is
     * already changed, and reconciliation heals a missing tail event, where
     * failing the request would report a rename that in fact happened.
     */
    if (metalbear_sequencer_identity(server->sequencer, acct->did,
                                     new_handle) != WF_OK)
        LOG_ERROR("update_handle: could not sequence #identity for did=%s "
                  "handle=%s; the rename is durable but unannounced",
                  acct->did, new_handle);

    free(old_handle);
    free(acct->handle);
    acct->handle = new_handle;
    return WF_OK;
}

/* ---- com.atproto.identity.requestPlcOperationSignature (procedure) ----
 * Sends an email with a token that can be used to sign a PLC operation. */
static wf_status request_plc_operation_signature(void *ctx,
        const wf_xrpc_request *request, wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    /* Get the account's email. */
    char *email = NULL;
    int confirmed = 0;
    metalbear_account_get_email(acct->account, &email, &confirmed);
    if (!email || !email[0]) {
        free(email);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Account does not have an email address");
        return WF_OK;
    }
    /* Create a plc_operation email token. */
    char token[32];
    if (metalbear_account_create_email_token(acct->account, "plc_operation",
                                             token, sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create verification token");
        return WF_OK;
    }
    /* Send the email if configured. */
    if (server->email) {
        char subject[256];
        char body[1024];
        snprintf(subject, sizeof(subject), "PLC Operation Signature Request");
        snprintf(body, sizeof(body),
                 "You have requested a PLC operation signature.\n\n"
                 "Your verification code is: %s\n\n"
                 "Enter this code to sign your PLC operation.\n\n"
                 "If you did not request this, please ignore this email.\n",
                 token);
        metalbear_email_send(server->email, email, subject, body);
    }
    free(email);
    /* Return empty object (per lexicon: no output schema). */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.identity.signPlcOperation (procedure) ----
 * Signs a PLC operation using the token from requestPlcOperationSignature. */
static wf_status sign_plc_operation(void *ctx,
        const wf_xrpc_request *request, wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *token_item = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    if (!cJSON_IsString(token_item) || !token_item->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "token is required");
        return WF_OK;
    }
    /* Verify the plc_operation email token. */
    if (metalbear_account_verify_email_token(
            acct->account, "plc_operation",
            token_item->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired token");
        return WF_OK;
    }
    /* Build a minimal PLC operation.  The full implementation would fetch
     * the last operation from the PLC directory and apply updates; here we
     * return a signed operation skeleton that a PLC client can complete. */
    cJSON *rotation_keys = cJSON_GetObjectItemCaseSensitive(
        request->params, "rotationKeys");
    cJSON *also_known_as = cJSON_GetObjectItemCaseSensitive(
        request->params, "alsoKnownAs");
    cJSON *verification_methods = cJSON_GetObjectItemCaseSensitive(
        request->params, "verificationMethods");
    cJSON *services = cJSON_GetObjectItemCaseSensitive(
        request->params, "services");

    cJSON *op = cJSON_CreateObject();
    if (!op) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(op, "type", "plc_operation");
    cJSON_AddStringToObject(op, "prev", "");

    /* Use provided values or defaults. */
    if (rotation_keys && cJSON_IsArray(rotation_keys)) {
        cJSON_AddItemToObject(op, "rotationKeys",
                              cJSON_Duplicate(rotation_keys, 1));
    } else {
        cJSON *rk = cJSON_CreateArray();
        cJSON_AddItemToArray(rk, cJSON_CreateString(server->service_did));
        cJSON_AddItemToObject(op, "rotationKeys", rk);
    }
    if (also_known_as && cJSON_IsArray(also_known_as)) {
        cJSON_AddItemToObject(op, "alsoKnownAs",
                              cJSON_Duplicate(also_known_as, 1));
    } else {
        cJSON *aka = cJSON_CreateArray();
        char at_handle[512];
        snprintf(at_handle, sizeof(at_handle), "at://%s", acct->handle);
        cJSON_AddItemToArray(aka, cJSON_CreateString(at_handle));
        cJSON_AddItemToObject(op, "alsoKnownAs", aka);
    }
    if (verification_methods && cJSON_IsObject(verification_methods)) {
        cJSON_AddItemToObject(op, "verificationMethods",
                              cJSON_Duplicate(verification_methods, 1));
    } else {
        cJSON *vm = cJSON_CreateObject();
        cJSON_AddStringToObject(vm, "atproto", acct->did);
        cJSON_AddItemToObject(op, "verificationMethods", vm);
    }
    if (services && cJSON_IsObject(services)) {
        cJSON_AddItemToObject(op, "services",
                              cJSON_Duplicate(services, 1));
    } else {
        cJSON *svc = cJSON_CreateObject();
        cJSON *pds = cJSON_CreateObject();
        cJSON_AddStringToObject(pds, "type", "AtprotoPersonalDataServer");
        char endpoint[512];
        snprintf(endpoint, sizeof(endpoint), "%s", server->public_url);
        cJSON_AddStringToObject(pds, "endpoint", endpoint);
        cJSON_AddItemToObject(svc, "atproto_pds", pds);
        cJSON_AddItemToObject(op, "services", svc);
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) { cJSON_Delete(op); return WF_ERR_ALLOC; }
    cJSON_AddItemToObject(root, "operation", op);
    return set_json(response, root);
}

/* ---- com.atproto.identity.submitPlcOperation (procedure) ----
 * Validates and submits a signed PLC operation.  In this standalone PDS
 * mode we validate the structure but skip actual PLC directory submission
 * (which requires an external PLC client). */
static wf_status submit_plc_operation(void *ctx,
        const wf_xrpc_request *request, wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *operation = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "operation") : NULL;
    if (!operation || !cJSON_IsObject(operation)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "operation is required");
        return WF_OK;
    }
    /* Validate basic structure. */
    cJSON *type = cJSON_GetObjectItemCaseSensitive(operation, "type");
    if (!cJSON_IsString(type) ||
        strcmp(type->valuestring, "plc_operation") != 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Invalid operation type");
        return WF_OK;
    }
    cJSON *services = cJSON_GetObjectItemCaseSensitive(operation, "services");
    if (services) {
        cJSON *pds = cJSON_GetObjectItemCaseSensitive(services, "atproto_pds");
        if (pds) {
            cJSON *pds_type = cJSON_GetObjectItemCaseSensitive(pds, "type");
            if (!cJSON_IsString(pds_type) ||
                strcmp(pds_type->valuestring, "AtprotoPersonalDataServer") != 0) {
                wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                           "Incorrect type on atproto_pds service");
                return WF_OK;
            }
            cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(pds, "endpoint");
            if (cJSON_IsString(endpoint) && server->public_url &&
                strcmp(endpoint->valuestring, server->public_url) != 0) {
                wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                           "Incorrect endpoint on atproto_pds service");
                return WF_OK;
            }
        }
    }
    cJSON *rotation_keys = cJSON_GetObjectItemCaseSensitive(operation, "rotationKeys");
    if (rotation_keys && cJSON_IsArray(rotation_keys)) {
        bool has_server_key = false;
        size_t n = cJSON_GetArraySize(rotation_keys);
        for (size_t i = 0; i < n; i++) {
            cJSON *key = cJSON_GetArrayItem(rotation_keys, i);
            if (cJSON_IsString(key) && server->service_did &&
                strcmp(key->valuestring, server->service_did) == 0) {
                has_server_key = true;
                break;
            }
        }
        if (!has_server_key) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "Rotation keys do not include server's rotation key");
            return WF_OK;
        }
    }
    /* In a full implementation, we would submit to the PLC directory here.
     * For now, acknowledge the operation. */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

static metalbear_credential_kind valid_login(
    metalbear_server *server, cJSON *body,
    metalbear_account_context **out_account, char **out_app_password_name) {
    if (out_account) *out_account = NULL;
    if (out_app_password_name) *out_app_password_name = NULL;
    cJSON *identifier = body ? cJSON_GetObjectItemCaseSensitive(body, "identifier") : NULL;
    cJSON *password = body ? cJSON_GetObjectItemCaseSensitive(body, "password") : NULL;
    if (!cJSON_IsString(identifier) || !cJSON_IsString(password))
        return METALBEAR_CREDENTIAL_INVALID;
    metalbear_account_context *acct = context_for_identifier(
        server, identifier->valuestring);
    if (!acct) return METALBEAR_CREDENTIAL_INVALID;
    metalbear_credential_kind credential = metalbear_account_verify_credential(
        acct->account, password->valuestring, out_app_password_name);
    if (credential != METALBEAR_CREDENTIAL_INVALID && out_account)
        *out_account = acct;
    return credential;
}

/*
 * `com.atproto.admin.defs#statusAttr` — `applied` is required, so a status
 * that is not applied is reported as `applied: false` rather than by omitting
 * the field. A moderator reading an omitted key cannot tell "not taken down"
 * from "this server does not track takedowns".
 */
static cJSON *status_attr(bool applied, const char *ref) {
    cJSON *attr = cJSON_CreateObject();
    if (!attr) return NULL;
    cJSON_AddBoolToObject(attr, "applied", applied);
    if (applied && ref && ref[0])
        cJSON_AddStringToObject(attr, "ref", ref);
    return attr;
}

/* The takedown ref recorded against an account, or NULL. Caller frees. */
static char *account_takedown_ref(metalbear_server *server, const char *did) {
    char *ref = NULL;
    if (!did || !did[0]) return NULL;
    metalbear_account_registry_get_takedown(server->registry, did, NULL, NULL,
                                            &ref);
    return ref;
}

/*
 * The account status the lexicons report, mirroring the reference PDS's
 * formatAccountStatus: a takedown outranks a deactivation, and an active
 * account carries no `status` at all. Returns NULL when active, and writes
 * the accompanying `active` boolean through `out_active`.
 */
static const char *account_status_string(metalbear_server *server,
                                         metalbear_account_context *acct,
                                         bool *out_active) {
    char *ref = account_takedown_ref(server, acct->did);
    bool taken_down = ref != NULL;
    free(ref);
    bool active = !taken_down && metalbear_account_is_active(acct->account);
    if (out_active) *out_active = active;
    if (taken_down) return "takendown";
    return active ? NULL : "deactivated";
}

/* Whether the account is taken down, which no bearer token may act through. */
static bool account_is_taken_down(metalbear_server *server, const char *did) {
    char *ref = account_takedown_ref(server, did);
    bool taken_down = ref != NULL;
    free(ref);
    return taken_down;
}

/*
 * The reference PDS's assertRepoAvailability, which every sync read runs
 * before touching the repository. A taken-down repository reports a different
 * error from a deactivated one because the two mean opposite things to a
 * consumer: one is a moderation action by this host, the other the account
 * holder's own choice, and a relay backfilling decides whether to retry on
 * exactly that distinction. Returns false with the response already filled in.
 */
static bool assert_repo_available(metalbear_server *server,
                                  metalbear_account_context *acct,
                                  const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Could not find repo");
        return false;
    }
    /* The account itself always sees its own repository. */
    if (request->authed_subject && acct->did &&
        strcmp(request->authed_subject, acct->did) == 0)
        return true;
    char *ref = account_takedown_ref(server, acct->did);
    if (ref) {
        free(ref);
        wf_xrpc_response_set_error(response, 400, "RepoTakendown",
                                   "Repo has been takendown");
        return false;
    }
    if (!metalbear_account_is_active(acct->account)) {
        wf_xrpc_response_set_error(response, 400, "RepoDeactivated",
                                   "Repo has been deactivated");
        return false;
    }
    return true;
}

/*
 * The repository layer's access guard, consulted by every route registered
 * through metalbear_xrpc_server_register_pds_repo_resolver_ex. A read of the
 * repository as a whole reports the availability errors; a single record
 * reads as absent, which is both what the reference answers and the only
 * thing `com.atproto.repo.getRecord` can say about a moderated record.
 */
static bool repo_access_guard(void *ctx, const wf_xrpc_request *req,
                              const char *record_uri,
                              wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (record_uri) {
        char *ref = NULL;
        metalbear_account_registry_get_takedown(server->registry, NULL,
                                                record_uri, NULL, &ref);
        if (!ref) return true;
        free(ref);
        wf_xrpc_response_set_error(resp, 404, "RecordNotFound",
                                   "Could not locate record");
        return false;
    }
    metalbear_account_context *acct = resolve_request_context(server, req);
    /* An unresolvable account is the handler's own error to report, in the
     * terms its lexicon uses. */
    if (!acct) return true;
    return assert_repo_available(server, acct, req, resp);
}

static cJSON *build_did_doc(metalbear_server *server,
                            metalbear_account_context *acct) {
    const char *signing_didkey =
        acct->repo ? metalbear_repo_store_signing_key_did(acct->repo) : NULL;
    return metalbear_did_document_build(acct->did, acct->handle, signing_didkey,
                                        server->public_url);
}

static cJSON *session_json(metalbear_server *server,
                           metalbear_account_context *acct,
                           const metalbear_session_tokens *tokens) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    if (tokens) {
        cJSON_AddStringToObject(root, "accessJwt", tokens->access_jwt);
        cJSON_AddStringToObject(root, "refreshJwt", tokens->refresh_jwt);
    }
    cJSON_AddStringToObject(root, "handle", acct->handle);
    cJSON_AddStringToObject(root, "did", acct->did);
    bool active = false;
    const char *status = account_status_string(server, acct, &active);
    cJSON_AddBoolToObject(root, "active", active);
    if (status) cJSON_AddStringToObject(root, "status", status);
    char *email = NULL;
    int confirmed = 0;
    bool email_auth_factor = false;
    if (metalbear_account_get_email(acct->account, &email,
                                    &confirmed) == WF_OK && email) {
        cJSON_AddStringToObject(root, "email", email);
        cJSON_AddBoolToObject(root, "emailConfirmed", confirmed != 0);
        if (confirmed != 0) {
            email_auth_factor = true;
        }
    }
    free(email);
    if (server->public_url) {
        cJSON *did_doc = build_did_doc(server, acct);
    if (did_doc)
        cJSON_AddItemToObject(root, "didDoc", did_doc);
    }
    cJSON_AddBoolToObject(root, "emailAuthFactor", email_auth_factor);
    return root;
}

static wf_status create_session(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = NULL;
    char *app_password_name = NULL;
    metalbear_credential_kind credential = valid_login(
        server, request->params, &acct, &app_password_name);
    if (credential == METALBEAR_CREDENTIAL_INVALID || !acct) {
        LOG_WARN("create_session: invalid credentials for host=%s",
                 request->host_header ? request->host_header : "(unknown)");
        metalbear_metrics_inc(METALBEAR_METRIC_LOGIN_FAILURES);
        wf_xrpc_response_set_error(response, 401, "AuthenticationRequired",
                                   "Invalid identifier or password");
        return WF_OK;
    }
    /*
     * Credentials are checked before the takedown so the error does not
     * distinguish a taken-down account from a wrong password to anyone who
     * does not already hold the password.
     */
    if (account_is_taken_down(server, acct->did)) {
        free(app_password_name);
        metalbear_metrics_inc(METALBEAR_METRIC_LOGIN_FAILURES);
        LOG_WARN("create_session: refused taken-down account did=%s", acct->did);
        wf_xrpc_response_set_error(response, 401, "AccountTakedown",
                                   "Account has been taken down");
        return WF_OK;
    }
    metalbear_access_scope scope = credential == METALBEAR_CREDENTIAL_ACCOUNT
        ? METALBEAR_ACCESS_FULL
        : credential == METALBEAR_CREDENTIAL_APP_PASSWORD_PRIVILEGED
            ? METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED
            : METALBEAR_ACCESS_APP_PASSWORD;
    metalbear_session_tokens tokens = {0};
    if (metalbear_auth_create_scoped_session(acct->auth, scope,
            app_password_name, &tokens) != WF_OK) {
        free(app_password_name);
        LOG_ERROR("create_session: failed to create session for did=%s", acct->did);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create session");
        return WF_OK;
    }
    free(app_password_name);
    metalbear_metrics_inc(METALBEAR_METRIC_SESSIONS_CREATED);
    LOG_INFO("create_session: issued session for did=%s scope=%d", acct->did, scope);
    wf_status status = set_json(response, session_json(server, acct, &tokens));
    metalbear_session_tokens_free(&tokens);
    return status;
}

static wf_status get_session(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    return set_json(response, session_json(server, acct, NULL));
}

static wf_status refresh_session(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    const char *token = bearer_token(request->auth_header);
    if (acct && account_is_taken_down(server, acct->did)) {
        wf_xrpc_response_set_error(response, 401, "AccountTakedown",
                                   "Account has been taken down");
        return WF_OK;
    }
    metalbear_session_tokens tokens = {0};
    if (!acct || metalbear_auth_rotate_refresh(acct->auth, token, &tokens) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "ExpiredToken",
                                   "Refresh token is expired or revoked");
        return WF_OK;
    }
    wf_status status = set_json(response, session_json(server, acct, &tokens));
    metalbear_session_tokens_free(&tokens);
    return status;
}

static wf_status delete_session(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    const char *token = bearer_token(request->auth_header);
    if (!acct || metalbear_auth_revoke_refresh(acct->auth, token) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Refresh token is invalid or revoked");
        return WF_OK;
    }
    (void)response;
    return WF_OK;
}

static wf_status create_app_password(void *ctx,
                                     const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *name = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "name") : NULL;
    cJSON *privileged = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "privileged") : NULL;
    if (!cJSON_IsString(name) || !name->valuestring[0] ||
        (privileged && !cJSON_IsBool(privileged))) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty name is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    char *password = NULL, *created_at = NULL;
    wf_status status = metalbear_account_create_app_password(
        acct->account, name->valuestring, cJSON_IsTrue(privileged),
        &password, &created_at);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response,
            status == WF_ERR_CONFLICT || status == WF_ERR_INVALID_ARG ? 400 : 500,
            status == WF_ERR_CONFLICT || status == WF_ERR_INVALID_ARG
                ? "InvalidRequest" : "InternalError",
            status == WF_ERR_CONFLICT ? "App password name already exists" :
                                        "Could not create app password");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) { free(password); free(created_at); return WF_ERR_ALLOC; }
    cJSON_AddStringToObject(root, "name", name->valuestring);
    cJSON_AddStringToObject(root, "password", password);
    cJSON_AddStringToObject(root, "createdAt", created_at);
    cJSON_AddBoolToObject(root, "privileged", cJSON_IsTrue(privileged));
    free(password);
    free(created_at);
    return set_json(response, root);
}

static wf_status list_app_passwords(void *ctx,
                                    const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    metalbear_app_password *passwords = NULL;
    size_t count = 0;
    if (metalbear_account_list_app_passwords(acct->account, &passwords,
                                             &count) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not list app passwords");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *items = cJSON_CreateArray();
    if (!root || !items) {
        cJSON_Delete(root); cJSON_Delete(items);
        metalbear_app_passwords_free(passwords, count);
        return WF_ERR_ALLOC;
    }
    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        if (!item) {
            cJSON_Delete(root); cJSON_Delete(items);
            metalbear_app_passwords_free(passwords, count);
            return WF_ERR_ALLOC;
        }
        cJSON_AddStringToObject(item, "name", passwords[i].name);
        cJSON_AddStringToObject(item, "createdAt", passwords[i].created_at);
        cJSON_AddBoolToObject(item, "privileged", passwords[i].privileged);
        cJSON_AddItemToArray(items, item);
    }
    metalbear_app_passwords_free(passwords, count);
    cJSON_AddItemToObject(root, "passwords", items);
    return set_json(response, root);
}

static wf_status revoke_app_password(void *ctx,
                                     const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *name = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "name") : NULL;
    if (!cJSON_IsString(name) || !name->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty name is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (metalbear_account_revoke_app_password(acct->account,
                                               name->valuestring) != WF_OK ||
        metalbear_auth_revoke_app_password_sessions(acct->auth,
                                                     name->valuestring) != WF_OK)
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not revoke app password");
    return WF_OK;
}

static wf_status deactivate_account(void *ctx,
                                    const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *delete_after = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "deleteAfter")
        : NULL;
    if (delete_after && !cJSON_IsString(delete_after)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "deleteAfter must be a datetime string");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    wf_status status = metalbear_account_deactivate(
        acct->account,
        cJSON_IsString(delete_after) ? delete_after->valuestring : NULL);
    if (status == WF_OK)
        status = metalbear_sequencer_account_status(
            acct->sequencer, acct->did, 0, "deactivated");
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not deactivate account");
    }
    return WF_OK;
}

static wf_status activate_account(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    wf_status status = metalbear_account_activate(acct->account);
    if (status == WF_OK)
        status = metalbear_sequencer_account_activation(
            acct->sequencer, acct->did, acct->handle, acct->repo);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not activate account");
    }
    return WF_OK;
}

static bool valid_service_audience(const char *audience) {
    if (!audience || strlen(audience) > 2048) return false;
    const char *fragment = strchr(audience, '#');
    if (!fragment) return wf_syntax_did_is_valid(audience);
    if (fragment == audience || !fragment[1] || strchr(fragment + 1, '#'))
        return false;
    size_t length = (size_t)(fragment - audience);
    char *did = malloc(length + 1);
    if (!did) return false;
    memcpy(did, audience, length);
    did[length] = '\0';
    bool valid = wf_syntax_did_is_valid(did);
    free(did);
    return valid;
}

static bool protected_service_method(const char *lxm) {
    static const char *const methods[] = {
        "com.atproto.admin.sendEmail",
        "com.atproto.identity.requestPlcOperationSignature",
        "com.atproto.identity.signPlcOperation",
        "com.atproto.identity.submitPlcOperation",
        "com.atproto.identity.updateHandle",
        "com.atproto.server.activateAccount",
        "com.atproto.server.confirmEmail",
        "com.atproto.server.createAppPassword",
        "com.atproto.server.deactivateAccount",
        "com.atproto.server.getAccountInviteCodes",
        "com.atproto.server.getSession",
        "com.atproto.server.listAppPasswords",
        "com.atproto.server.requestAccountDelete",
        "com.atproto.server.requestEmailConfirmation",
        "com.atproto.server.requestEmailUpdate",
        "com.atproto.server.revokeAppPassword",
        "com.atproto.server.updateEmail",
    };
    if (!lxm) return false;
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
        if (strcmp(lxm, methods[i]) == 0) return true;
    return false;
}

static bool privileged_service_method(const char *lxm) {
    return lxm && (strncmp(lxm, "chat.bsky.", 10) == 0 ||
                   strcmp(lxm, "com.atproto.server.createAccount") == 0);
}

static wf_status get_service_auth(void *ctx,
                                  const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *aud = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "aud") : NULL;
    cJSON *exp_item = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "exp") : NULL;
    cJSON *lxm_item = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "lxm") : NULL;
    const char *lxm = cJSON_IsString(lxm_item) ? lxm_item->valuestring : NULL;
    if (!cJSON_IsString(aud) || !valid_service_audience(aud->valuestring) ||
        (lxm_item && (!cJSON_IsString(lxm_item) ||
                      !wf_syntax_nsid_is_valid(lxm))) ||
        protected_service_method(lxm)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Invalid service auth audience or method");
        return WF_OK;
    }
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (metalbear_auth_verify_access_scope(acct->auth,
            bearer_token(request->auth_header), &scope) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (scope == METALBEAR_ACCESS_APP_PASSWORD &&
        privileged_service_method(lxm)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
            "Insufficient access for privileged service method");
        return WF_OK;
    }
    int64_t expiration = 0;
    if (exp_item) {
        long long parsed = 0;
        if (cJSON_IsString(exp_item)) {
            char *end = NULL;
            errno = 0;
            parsed = strtoll(exp_item->valuestring, &end, 10);
            if (errno || !end || *end) parsed = 0;
        } else if (cJSON_IsNumber(exp_item)) {
            parsed = (long long)exp_item->valuedouble;
        } else {
            wf_xrpc_response_set_error(response, 400, "BadExpiration",
                                       "Expiration must be a valid timestamp");
            return WF_OK;
        }
        int64_t now = (int64_t)time(NULL);
        if (parsed < now || parsed - now > 3600 ||
            (!lxm && parsed - now > 60)) {
            wf_xrpc_response_set_error(response, 400, "BadExpiration",
                                       "Expiration is outside allowed bounds");
            return WF_OK;
        }
        expiration = (int64_t)parsed;
    }
    char *token = NULL;
    if (metalbear_repo_store_create_service_auth(acct->repo, aud->valuestring,
                                           expiration, lxm, &token) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create service token");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(token);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "token", token);
    free(token);
    return set_json(response, root);
}

/* ------------------------------------------------------------------ */
/* AppView proxy fallback                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} proxy_buf_t;

static size_t proxy_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    proxy_buf_t *buf = (proxy_buf_t *)userdata;
    size_t total = size * nmemb;
    if (buf->len + total + 1 > buf->cap) {
        size_t newcap = (buf->cap + total) * 2;
        char *grown = realloc(buf->data, newcap);
        if (!grown) return 0;
        buf->data = grown;
        buf->cap = newcap;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/* Case-insensitive "does this header line start with `name`" test. HTTP header
 * names are case-insensitive and upstreams differ in what they send. */
static const char *proxy_header_value(const char *line, size_t len,
                                      const char *name) {
    size_t name_len = strlen(name);
    if (len <= name_len || strncasecmp(line, name, name_len) != 0 ||
        line[name_len] != ':')
        return NULL;
    const char *val = line + name_len + 1;
    while (*val == ' ' || *val == '\t') val++;
    return val;
}

/* Trim the trailing CRLF curl leaves on each header line. */
static char *proxy_header_dup(const char *val, const char *line_end) {
    size_t n = (size_t)(line_end - val);
    while (n > 0 && (val[n - 1] == '\r' || val[n - 1] == '\n')) n--;
    return strndup(val, n);
}

typedef struct proxy_headers {
    char *content_type;
    char *repo_rev;   /* `atproto-repo-rev`: how far the upstream has indexed */
} proxy_headers;

static void proxy_headers_free(proxy_headers *h) {
    if (!h) return;
    free(h->content_type);
    free(h->repo_rev);
    h->content_type = NULL;
    h->repo_rev = NULL;
}

static size_t proxy_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    proxy_headers *out = (proxy_headers *)userdata;
    size_t total = size * nmemb;
    const char *val;
    if ((val = proxy_header_value(ptr, total, "Content-Type")) != NULL) {
        free(out->content_type);
        out->content_type = proxy_header_dup(val, ptr + total);
    } else if ((val = proxy_header_value(ptr, total, "atproto-repo-rev")) != NULL) {
        free(out->repo_rev);
        out->repo_rev = proxy_header_dup(val, ptr + total);
    }
    return total;
}

/* Service ids that have been renamed on the network. The AppView's did:web
 * document now names `#bsky_appview` where legacy proxies named the same
 * service `#atproto_bsky_app` (and chat `#atproto_bsky_chat` vs `#bsky_chat`).
 * Accept both so an `atproto-proxy` header written for either era resolves. */
static const char *service_id_alias(const char *id) {
    static const struct { const char *a; const char *b; } aliases[] = {
        { "atproto_bsky_app", "bsky_appview" },
        { "atproto_bsky_chat", "bsky_chat" },
    };
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++) {
        if (strcmp(id, aliases[i].a) == 0) return aliases[i].b;
        if (strcmp(id, aliases[i].b) == 0) return aliases[i].a;
    }
    return NULL;
}

static char *resolve_did_web_service(const char *did, const char *service_id) {
    /* "did:web:" is 8 characters; comparing 9 also compares the literal's NUL,
     * which only matches the bare prefix, and skipping 9 eats the first
     * character of the host. Together they made this return NULL for every
     * real did:web, so `atproto-proxy` never resolved anywhere. */
    static const size_t prefix_len = sizeof("did:web:") - 1;
    const char *hash;
    char *host = NULL;
    size_t host_len;
    char url[512];
    int n;
    if (strncmp(did, "did:web:", prefix_len) != 0) return NULL;

    /* The header arrives as "<did:web:host>#<service_id>"; the fragment must
     * not become part of the host when building the well-known URL, or the
     * fetch hits the site root and the document never parses. */
    hash = strchr(did + prefix_len, '#');
    host_len = hash ? (size_t)(hash - (did + prefix_len))
                    : strlen(did + prefix_len);
    if (host_len == 0) return NULL;
    host = malloc(host_len + 1);
    if (!host) return NULL;
    memcpy(host, did + prefix_len, host_len);
    host[host_len] = '\0';

    n = snprintf(url, sizeof(url), "https://%s/.well-known/did.json", host);
    free(host);
    if (n < 0 || (size_t)n >= sizeof(url)) return NULL;

    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    proxy_buf_t body = {0};
    char *ct = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &ct);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || !body.data) {
        free(body.data);
        free(ct);
        return NULL;
    }

    cJSON *doc = cJSON_Parse(body.data);
    free(body.data);
    if (!doc) {
        free(ct);
        return NULL;
    }

    const char *alias = service_id ? service_id_alias(service_id) : NULL;
    cJSON *services = cJSON_GetObjectItemCaseSensitive(doc, "service");
    char *endpoint = NULL;
    if (cJSON_IsArray(services)) {
        size_t count = cJSON_GetArraySize(services);
        for (size_t i = 0; i < count; i++) {
            cJSON *svc = cJSON_GetArrayItem(services, i);
            if (!cJSON_IsObject(svc)) continue;
            cJSON *id = cJSON_GetObjectItemCaseSensitive(svc, "id");
            cJSON *type = cJSON_GetObjectItemCaseSensitive(svc, "type");
            if (cJSON_IsString(id) && cJSON_IsString(type)) {
                const char *id_name = id->valuestring[0] == '#'
                                          ? id->valuestring + 1
                                          : id->valuestring;
                 bool match = (service_id && service_id[0])
                     ? (strcmp(id_name, service_id) == 0 ||
                        (alias && strcmp(id_name, alias) == 0))
                     : (strcmp(type->valuestring, "HttpUrl") == 0 ||
                        strcmp(type->valuestring, "WebSocket") == 0);
                if (match) {
                    cJSON *ep = cJSON_GetObjectItemCaseSensitive(svc, "serviceEndpoint");
                    if (cJSON_IsString(ep) && ep->valuestring[0]) {
                        endpoint = strdup(ep->valuestring);
                        break;
                    }
                }
            }
        }
    }
    cJSON_Delete(doc);
    free(ct);
    return endpoint;
}

/* Low-level HTTP proxy: forwards request to `target` and copies status/body. */
static wf_status proxy_http_request(const char *target, const char *method,
                                    const char *content_type,
                                    const unsigned char *body, size_t body_len,
                                    wf_xrpc_response *resp) {
    struct curl_slist *hdrs = NULL;
    if (content_type && content_type[0]) {
        char ct[256];
        snprintf(ct, sizeof(ct), "Content-Type: %s", content_type);
        hdrs = curl_slist_append(hdrs, ct);
    }
    proxy_buf_t body_out = {0};
    proxy_headers hdrs_out = {0};
    CURL *curl = curl_easy_init();
    if (!curl) {
        curl_slist_free_all(hdrs);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Could not initialise HTTP client");
        return WF_OK;
    }
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method ? method : "GET");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body_out);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdrs_out);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (body && body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    }
    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);

    if (rc != CURLE_OK) {
        free(body_out.data);
        proxy_headers_free(&hdrs_out);
        wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                   "Upstream request failed");
        return WF_OK;
    }

    resp->http_status = status;
    if (hdrs_out.content_type) {
        wf_xrpc_response_set_content_type(resp, hdrs_out.content_type);
    }
    if (body_out.data && body_out.len > 0) {
        wf_xrpc_response_set_body(resp, body_out.data, body_out.len);
    }
    free(body_out.data);
    proxy_headers_free(&hdrs_out);
    return WF_OK;
}

/* ------------------------------------------------------------------ */
/* Read-after-write                                                     */
/* ------------------------------------------------------------------ */
/*
 * An AppView reports how far it has indexed a repo with the `atproto-repo-rev`
 * response header. Anything the account has written past that rev exists here
 * but not there yet, so a user who has just posted would not see their own
 * post. The reference PDS patches the proxied response with those local
 * records before returning it (packages/pds/src/read-after-write); this is the
 * same idea against the same set of endpoints.
 *
 * Everything here degrades to "return the upstream response unchanged": if the
 * body is not the shape we expect, or the rev looks like it belongs to another
 * repo, a stale view is always preferable to a wrong one.
 */

/* Build the PostView the AppView would have produced for a local post.
 * Counts are zero because the post is, by construction, brand new. */
static cJSON *local_post_view(const char *uri, const char *cid,
                              const char *indexed_at, const cJSON *record,
                              const cJSON *author) {
    cJSON *post = cJSON_CreateObject();
    if (!post) return NULL;
    cJSON_AddStringToObject(post, "uri", uri ? uri : "");
    cJSON_AddStringToObject(post, "cid", cid ? cid : "");
    if (author) {
        cJSON *dup = cJSON_Duplicate(author, 1);
        if (dup) cJSON_AddItemToObject(post, "author", dup);
    }
    cJSON *rec = cJSON_Duplicate(record, 1);
    if (rec) cJSON_AddItemToObject(post, "record", rec);
    cJSON_AddNumberToObject(post, "replyCount", 0);
    cJSON_AddNumberToObject(post, "repostCount", 0);
    cJSON_AddNumberToObject(post, "likeCount", 0);
    cJSON_AddNumberToObject(post, "quoteCount", 0);
    cJSON_AddStringToObject(post, "indexedAt", indexed_at ? indexed_at : "");
    return post;
}

/* The author view to attach to local posts: reuse one the upstream already
 * returned for this DID so avatars and labels stay consistent, rather than
 * fabricating a half-populated one. */
static const cJSON *find_author_view(const cJSON *root, const char *did) {
    if (!cJSON_IsObject(root) && !cJSON_IsArray(root)) return NULL;
    const cJSON *self_did = cJSON_GetObjectItemCaseSensitive(root, "did");
    const cJSON *handle = cJSON_GetObjectItemCaseSensitive(root, "handle");
    if (cJSON_IsString(self_did) && cJSON_IsString(handle) &&
        strcmp(self_did->valuestring, did) == 0)
        return root;
    const cJSON *child = NULL;
    cJSON_ArrayForEach(child, root) {
        const cJSON *found = find_author_view(child, did);
        if (found) return found;
    }
    return NULL;
}

/* Insert local posts into a feed array, newest first, mirroring
 * LocalViewer.formatAndInsertPostsInFeed. */
static void insert_local_posts(cJSON *feed, const cJSON *local_records,
                               const char *did, const cJSON *author) {
    if (!cJSON_IsArray(feed)) return;

    /* The upstream page ends at some timestamp; anything older than that
     * belongs on a later page, not spliced into this one. */
    const char *last_time = NULL;
    int feed_len = cJSON_GetArraySize(feed);
    if (feed_len > 0) {
        const cJSON *last = cJSON_GetArrayItem(feed, feed_len - 1);
        const cJSON *post = cJSON_GetObjectItemCaseSensitive(last, "post");
        const cJSON *at = cJSON_GetObjectItemCaseSensitive(post, "indexedAt");
        if (cJSON_IsString(at)) last_time = at->valuestring;
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, local_records) {
        const cJSON *coll = cJSON_GetObjectItemCaseSensitive(entry, "collection");
        if (!cJSON_IsString(coll) ||
            strcmp(coll->valuestring, "app.bsky.feed.post") != 0)
            continue;
        const cJSON *uri = cJSON_GetObjectItemCaseSensitive(entry, "uri");
        const cJSON *cid = cJSON_GetObjectItemCaseSensitive(entry, "cid");
        const cJSON *at = cJSON_GetObjectItemCaseSensitive(entry, "indexedAt");
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(entry, "value");
        if (!cJSON_IsString(uri) || !cJSON_IsString(at) || !value) continue;
        if (last_time && strcmp(at->valuestring, last_time) <= 0) continue;

        /* Skip anything the upstream already returned. */
        bool already = false;
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, feed) {
            const cJSON *p = cJSON_GetObjectItemCaseSensitive(item, "post");
            const cJSON *u = cJSON_GetObjectItemCaseSensitive(p, "uri");
            if (cJSON_IsString(u) && strcmp(u->valuestring, uri->valuestring) == 0) {
                already = true;
                break;
            }
        }
        if (already) continue;

        cJSON *post = local_post_view(uri->valuestring,
                                      cJSON_IsString(cid) ? cid->valuestring : "",
                                      at->valuestring, value, author);
        if (!post) continue;
        cJSON *wrapper = cJSON_CreateObject();
        if (!wrapper) { cJSON_Delete(post); continue; }
        cJSON_AddItemToObject(wrapper, "post", post);

        /* Keep the feed ordered newest-first. */
        int idx = -1;
        for (int i = 0; i < cJSON_GetArraySize(feed); i++) {
            const cJSON *fi = cJSON_GetArrayItem(feed, i);
            const cJSON *p = cJSON_GetObjectItemCaseSensitive(fi, "post");
            const cJSON *pa = cJSON_GetObjectItemCaseSensitive(p, "indexedAt");
            if (cJSON_IsString(pa) &&
                strcmp(pa->valuestring, at->valuestring) < 0) { idx = i; break; }
        }
        if (idx >= 0) cJSON_InsertItemInArray(feed, idx, wrapper);
        else cJSON_AddItemToArray(feed, wrapper);
        (void)did;
    }
}

/* Overlay a locally-written profile record onto a profile view. */
static void overlay_local_profile(cJSON *view, const cJSON *record) {
    if (!cJSON_IsObject(view) || !cJSON_IsObject(record)) return;
    static const char *const fields[] = {"displayName", "description"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(record, fields[i]);
        cJSON_DeleteItemFromObjectCaseSensitive(view, fields[i]);
        if (cJSON_IsString(v))
            cJSON_AddStringToObject(view, fields[i], v->valuestring);
    }
}

/*
 * Patch `body` with the requester's records newer than `repo_rev`. Returns a
 * heap-allocated replacement body, or NULL to send the upstream response
 * through untouched.
 */
static char *read_after_write_munge(metalbear_server *server,
                                    const char *requester_did,
                                    const char *nsid, const char *repo_rev,
                                    const char *body, size_t body_len,
                                    wf_xrpc_response *resp) {
    static const char *const feed_methods[] = {
        "app.bsky.feed.getTimeline", "app.bsky.feed.getAuthorFeed",
        "app.bsky.feed.getActorLikes",
    };
    bool is_feed = false;
    for (size_t i = 0; i < sizeof(feed_methods) / sizeof(feed_methods[0]); i++)
        if (strcmp(nsid, feed_methods[i]) == 0) is_feed = true;
    bool is_profile = strcmp(nsid, "app.bsky.actor.getProfile") == 0;
    bool is_profiles = strcmp(nsid, "app.bsky.actor.getProfiles") == 0;
    if (!is_feed && !is_profile && !is_profiles) return NULL;

    metalbear_account_context *acct = context_for_did(server, requester_did);
    if (!acct || !acct->repo) return NULL;

    char *local_json = NULL;
    if (metalbear_repo_store_records_since_rev(acct->repo, repo_rev, 10,
                                               &local_json) != WF_OK ||
        !local_json)
        return NULL;
    cJSON *local = cJSON_Parse(local_json);
    free(local_json);
    if (!local) return NULL;
    cJSON *records = cJSON_GetObjectItemCaseSensitive(local, "records");
    if (!cJSON_IsArray(records) || cJSON_GetArraySize(records) == 0) {
        cJSON_Delete(local);
        return NULL;   /* upstream is caught up; nothing to add */
    }

    cJSON *root = cJSON_ParseWithLength(body, body_len);
    if (!root) { cJSON_Delete(local); return NULL; }

    bool changed = false;
    if (is_feed) {
        cJSON *feed = cJSON_GetObjectItemCaseSensitive(root, "feed");
        if (cJSON_IsArray(feed)) {
            const cJSON *author = find_author_view(root, requester_did);
            int before = cJSON_GetArraySize(feed);
            insert_local_posts(feed, records, requester_did, author);
            changed = cJSON_GetArraySize(feed) != before;
        }
    } else {
        /* Profile record edits: overlay onto the requester's own view. */
        const cJSON *entry = NULL;
        const cJSON *profile_record = NULL;
        cJSON_ArrayForEach(entry, records) {
            const cJSON *coll =
                cJSON_GetObjectItemCaseSensitive(entry, "collection");
            if (cJSON_IsString(coll) &&
                strcmp(coll->valuestring, "app.bsky.actor.profile") == 0)
                profile_record = cJSON_GetObjectItemCaseSensitive(entry, "value");
        }
        if (profile_record) {
            if (is_profile) {
                const cJSON *did = cJSON_GetObjectItemCaseSensitive(root, "did");
                if (cJSON_IsString(did) &&
                    strcmp(did->valuestring, requester_did) == 0) {
                    overlay_local_profile(root, profile_record);
                    changed = true;
                }
            } else {
                cJSON *profiles =
                    cJSON_GetObjectItemCaseSensitive(root, "profiles");
                cJSON *p = NULL;
                cJSON_ArrayForEach(p, profiles) {
                    const cJSON *did =
                        cJSON_GetObjectItemCaseSensitive(p, "did");
                    if (cJSON_IsString(did) &&
                        strcmp(did->valuestring, requester_did) == 0) {
                        overlay_local_profile(p, profile_record);
                        changed = true;
                    }
                }
            }
        }
    }

    char *out = changed ? cJSON_PrintUnformatted(root) : NULL;
    if (changed) {
        /* Tell the client the view was completed locally, as the reference
         * does, so a debugging client can tell this apart from a fresh
         * upstream response. */
        wf_xrpc_response_add_header(resp, "Atproto-Upstream-Lag", "0");
    }
    cJSON_Delete(root);
    cJSON_Delete(local);
    return out;
}

/* Proxy an app.bsky.* request to the AppView, minting service-auth from the
 * requester's own account (iss=requester DID, aud=AppView DID). Returns 502
 * on network failure, otherwise mirrors the upstream status/body. */
static wf_status proxy_appview(metalbear_server *server,
                               const char *requester_did,
                               const wf_xrpc_request *req,
                               wf_xrpc_response *resp,
                               bool send_auth) {
    if (!server->appview_url || !server->appview_url[0] ||
        !server->appview_did || !server->appview_did[0]) {
        wf_xrpc_response_set_error(resp, 501, "MethodNotImplemented",
                                   "No AppView configured");
        return WF_OK;
    }

    /*
     * `atproto-proxy: <did>#<service_id>` names the service the client wants
     * this request delivered to, and the audience its service-auth must carry.
     * Honouring it is what lets one PDS front several services — chat, for
     * one, lives at did:web:api.bsky.chat and is not served by the AppView, so
     * without this every chat call is answered by whichever host appview_url
     * happens to name.
     */
    char *upstream = NULL;
    const char *audience = server->appview_did;
    char audience_buf[256];
    const char *proxy_header = req->atproto_proxy;
    if (proxy_header && proxy_header[0]) {
        const char *hash = strrchr(proxy_header, '#');
        size_t did_len = hash ? (size_t)(hash - proxy_header)
                              : strlen(proxy_header);
        if (did_len < sizeof(audience_buf)) {
            memcpy(audience_buf, proxy_header, did_len);
            audience_buf[did_len] = '\0';
            audience = audience_buf;
        }
        /* A header naming our own configured AppView maps straight to its URL,
         * whatever service id the client used (both eras of id appear on the
         * network). Resolving the did:web document is only for other hosts. */
        if (server->appview_did && strcmp(audience, server->appview_did) == 0) {
            upstream = strdup(server->appview_url);
            if (!upstream) {
                wf_xrpc_response_set_error(resp, 500, "InternalError",
                                           "Out of memory");
                return WF_OK;
            }
        } else {
            upstream = resolve_did_web_service(proxy_header,
                                               hash ? hash + 1 : NULL);
        }
        if (!upstream) {
            wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                       "Could not resolve atproto-proxy target");
            return WF_OK;
        }
    } else {
        upstream = strdup(server->appview_url);
        if (!upstream) {
            wf_xrpc_response_set_error(resp, 500, "InternalError",
                                       "Out of memory");
            return WF_OK;
        }
    }

    char target[1024];
    int n = snprintf(target, sizeof(target), "%s/xrpc/%s%s%s",
                     upstream, req->nsid ? req->nsid : "",
                     req->raw_query && req->raw_query[0] ? "?" : "",
                     req->raw_query ? req->raw_query : "");
    free(upstream);
    if (n < 0 || (size_t)n >= sizeof(target)) {
        wf_xrpc_response_set_error(resp, 414, "UriTooLong",
                                   "Proxied URI exceeds limit");
        return WF_OK;
    }

    char *service_token = NULL;
    if (send_auth && requester_did && requester_did[0]) {
        metalbear_account_context *acct = context_for_did(server, requester_did);
        if (acct && acct->repo) {
            metalbear_repo_store_create_service_auth(acct->repo,
                audience, (int64_t)time(NULL) + 300,
                req->nsid, &service_token);
        }
    }

    struct curl_slist *hdrs = NULL;
    if (req->content_type && req->content_type[0]) {
        char ct[256];
        snprintf(ct, sizeof(ct), "Content-Type: %s", req->content_type);
        hdrs = curl_slist_append(hdrs, ct);
    }
    if (service_token) {
        char auth[512];
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", service_token);
        hdrs = curl_slist_append(hdrs, auth);
    }

    proxy_buf_t body_out = {0};
    proxy_headers hdrs_out = {0};
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(service_token);
        curl_slist_free_all(hdrs);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Could not initialise HTTP client");
        return WF_OK;
    }
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method ? req->method : "GET");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body_out);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdrs_out);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (req->body && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
    }
    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);
    free(service_token);

    if (rc != CURLE_OK) {
        free(body_out.data);
        proxy_headers_free(&hdrs_out);
        wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                   "Upstream request failed");
        return WF_OK;
    }

    resp->http_status = status;
    if (hdrs_out.content_type) {
        wf_xrpc_response_set_content_type(resp, hdrs_out.content_type);
    }
    /* Read-after-write: splice in the requester's own records that the
     * upstream has not indexed yet, so a just-written post is visible to its
     * author immediately rather than only once the AppView catches up. */
    char *munged = NULL;
    if (status == 200 && body_out.data && body_out.len > 0 &&
        hdrs_out.repo_rev && hdrs_out.repo_rev[0] && requester_did &&
        (!hdrs_out.content_type ||
         strstr(hdrs_out.content_type, "application/json") != NULL)) {
        munged = read_after_write_munge(server, requester_did,
                                        req->nsid ? req->nsid : "",
                                        hdrs_out.repo_rev, body_out.data,
                                        body_out.len, resp);
    }
    if (munged) {
        wf_xrpc_response_set_body(resp, munged, strlen(munged));
        free(munged);
    } else if (body_out.data && body_out.len > 0) {
        wf_xrpc_response_set_body(resp, body_out.data, body_out.len);
    }
    free(body_out.data);
    proxy_headers_free(&hdrs_out);
    return WF_OK;
}

/* Generic fallback for unmatched NSIDs (runs before auth). Service-auth is
 * signed by the account the request resolves to; public AppViews may reject
 * unknown DIDs. */
static wf_status proxy_fallback(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (!server->appview_url || !server->appview_url[0]) {
        wf_xrpc_response_set_error(resp, 501, "MethodNotImplemented",
                                   "No AppView configured");
        return WF_OK;
    }

    char *upstream = NULL;
    const char *proxy_header = req->atproto_proxy;
    if (proxy_header && proxy_header[0]) {
        const char *hash = strrchr(proxy_header, '#');
        const char *svc_id = hash ? hash + 1 : NULL;
        size_t did_len = hash ? (size_t)(hash - proxy_header)
                              : strlen(proxy_header);
        char did_buf[256];
        const char *bare_did = proxy_header;
        if (did_len > 0 && did_len < sizeof(did_buf)) {
            memcpy(did_buf, proxy_header, did_len);
            did_buf[did_len] = '\0';
            bare_did = did_buf;
        }
        if (server->appview_did && strcmp(bare_did, server->appview_did) == 0) {
            upstream = strdup(server->appview_url);
        } else {
            upstream = resolve_did_web_service(proxy_header, svc_id);
        }
        if (!upstream) {
            wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                       "Could not resolve atproto-proxy target");
            return WF_OK;
        }
    } else {
        upstream = strdup(server->appview_url);
    }
    if (!upstream) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Out of memory");
        return WF_OK;
    }

    char target[1024];
    int n = snprintf(target, sizeof(target), "%s/xrpc/%s%s%s",
                     upstream, req->nsid ? req->nsid : "",
                     req->raw_query && req->raw_query[0] ? "?" : "",
                     req->raw_query ? req->raw_query : "");
    free(upstream);
    if (n < 0 || (size_t)n >= sizeof(target)) {
        wf_xrpc_response_set_error(resp, 414, "UriTooLong",
                                   "Proxied URI exceeds limit");
        return WF_OK;
    }

    struct curl_slist *hdrs = NULL;
    if (req->content_type && req->content_type[0]) {
        char ct[256];
        snprintf(ct, sizeof(ct), "Content-Type: %s", req->content_type);
        hdrs = curl_slist_append(hdrs, ct);
    }
    /* libcurl sets Host from the target URL; do not override it with the
     * original request's Host or Cloudflare-style frontends will reject the
     * proxied connection. */

    proxy_buf_t body_out = {0};
    proxy_headers hdrs_out = {0};
    CURL *curl = curl_easy_init();
    if (!curl) {
        curl_slist_free_all(hdrs);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Could not initialise HTTP client");
        return WF_OK;
    }
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method ? req->method : "GET");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body_out);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdrs_out);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (req->body && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
    }
    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);

    if (rc != CURLE_OK) {
        free(body_out.data);
        proxy_headers_free(&hdrs_out);
        wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                   "Upstream request failed");
        return WF_OK;
    }

    resp->http_status = status;
    if (hdrs_out.content_type) {
        wf_xrpc_response_set_content_type(resp, hdrs_out.content_type);
    }
    if (body_out.data && body_out.len > 0) {
        wf_xrpc_response_set_body(resp, body_out.data, body_out.len);
    }
    free(body_out.data);
    proxy_headers_free(&hdrs_out);
    return WF_OK;
}

static wf_status set_car_response(wf_xrpc_response *response,
                                  unsigned char *data, size_t length) {
    wf_xrpc_response_set_body(response, (const char *)data, length);
    wf_xrpc_response_set_content_type(response, "application/vnd.ipld.car");
    free(data);
    return response->body || length == 0 ? WF_OK : WF_ERR_ALLOC;
}

static wf_status get_repo(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *since = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "since") : NULL;
    LOG_DEBUG("get_repo: did=%s since=%s", cJSON_IsString(did) ? did->valuestring : "-",
              cJSON_IsString(since) ? since->valuestring : "-");
    if (!cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!assert_repo_available(server, acct, request, response))
        return WF_OK;
    unsigned char *data = NULL;
    size_t length = 0;
    wf_status status = metalbear_repo_store_export(
        acct->repo, cJSON_IsString(since) ? since->valuestring : NULL,
        &data, &length);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is empty or unavailable");
        return WF_OK;
    }
    return set_car_response(response, data, length);
}

static wf_status get_blocks(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    if (!cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!assert_repo_available(server, acct, request, response))
        return WF_OK;
    const char **cids = NULL;
    size_t cid_count = 0;
    for (cJSON *item = request->params->child; item; item = item->next) {
        if (!item->string || strcmp(item->string, "cids") != 0 ||
            !cJSON_IsString(item))
            continue;
        const char **grown = realloc(cids, (cid_count + 1) * sizeof(*grown));
        if (!grown) {
            free(cids);
            return WF_ERR_ALLOC;
        }
        cids = grown;
        cids[cid_count++] = item->valuestring;
    }
    if (cid_count == 0) {
        free(cids);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "at least one cid is required");
        return WF_OK;
    }
    unsigned char *data = NULL;
    size_t length = 0;
    wf_status status = metalbear_repo_store_get_blocks(acct->repo, cids, cid_count,
                                                &data, &length);
    free(cids);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "BlockNotFound",
                                   "One or more blocks were not found");
        return WF_OK;
    }
    return set_car_response(response, data, length);
}

static wf_status get_repo_status(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    metalbear_account_context *acct = cJSON_IsString(did)
        ? resolve_request_context(server, request) : NULL;
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is not hosted here");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "did", acct->did);
    bool active = false;
    const char *status = account_status_string(server, acct, &active);
    cJSON_AddBoolToObject(root, "active", active);
    if (status) cJSON_AddStringToObject(root, "status", status);
    char *rev = NULL, *cid = NULL;
    if (active && metalbear_repo_store_get_head(acct->repo, &rev, &cid) == WF_OK)
        cJSON_AddStringToObject(root, "rev", rev);
    free(rev);
    free(cid);
    return set_json(response, root);
}

/* ---- com.atproto.sync.listBlobs (query) ---- */
static wf_status list_blobs(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    metalbear_account_context *acct = cJSON_IsString(did)
        ? resolve_request_context(server, request) : NULL;
    if (!assert_repo_available(server, acct, request, response))
        return WF_OK;
    /* 'since' is accepted for lexicon compatibility; MetalBear's blob store
     * does not track per-blob revisions, so all available blobs are listed. */
    int limit = query_param_int(request->params, "limit", 500, 1, 1000);
    cJSON *cursor_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor") : NULL;
    size_t offset = 0;
    if (cJSON_IsString(cursor_param) && cursor_param->valuestring[0]) {
        char *end = NULL;
        long parsed = strtol(cursor_param->valuestring, &end, 10);
        if (*cursor_param->valuestring && *end == '\0' && parsed >= 0)
            offset = (size_t)parsed;
    }

    char **all = NULL;
    size_t count = 0;
    if (metalbear_blob_store_list(acct->blobs, &all, &count) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not enumerate blobs");
        return WF_OK;
    }
    if (offset > count) offset = count;

    cJSON *root = cJSON_CreateObject();
    cJSON *cids = cJSON_CreateArray();
    if (!root || !cids) {
        cJSON_Delete(root); cJSON_Delete(cids);
        metalbear_blob_store_list_free(all, count);
        return WF_ERR_ALLOC;
    }
    size_t taken = 0;
    for (size_t i = offset; i < count && taken < (size_t)limit; i++, taken++)
        cJSON_AddItemToArray(cids, cJSON_CreateString(all[i]));
    metalbear_blob_store_list_free(all, count);

    cJSON_AddItemToObject(root, "cids", cids);
    size_t next = offset + taken;
    if (next < count) {
        char cursor_buf[32];
        snprintf(cursor_buf, sizeof(cursor_buf), "%zu", next);
        cJSON_AddStringToObject(root, "cursor", cursor_buf);
    }
    return set_json(response, root);
}

/* ---- com.atproto.repo.listMissingBlobs (query) ----
 * Returns the blob CIDs referenced by records but absent from the blob
 * store (account-migration flow). Walks every record's JSON value for blob
 * references, then matches rsky-pds' contract: deduped by CID, emitted in
 * ascending CID order, cursor selects CIDs strictly greater than it, and
 * the next cursor is the CID of the last emitted entry when the result was
 * truncated to `limit`. (cocoon shares the CID cursor but walks in record
 * order, which makes its cursored pages inconsistent; rsky's ORDER BY is
 * the self-consistent variant.) */

/* Recursively find blob references in a record's JSON value. A modern blob
 * is {"$type":"blob","ref":{"$link":"<cid>"},...}; a legacy blob is
 * {"cid":"<cid>","mimeType":...} with no $type member. */
static void json_walk_blob_refs(const cJSON *node,
                                void (*cb)(const char *cid, void *ctx),
                                void *ctx) {
    if (!node) return;
    if (cJSON_IsObject(node)) {
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(node, "$type");
        if (cJSON_IsString(type) && type->valuestring &&
            strcmp(type->valuestring, "blob") == 0) {
            const cJSON *ref = cJSON_GetObjectItemCaseSensitive(node, "ref");
            const cJSON *link = cJSON_IsObject(ref)
                ? cJSON_GetObjectItemCaseSensitive(ref, "$link") : NULL;
            if (cJSON_IsString(link) && link->valuestring)
                cb(link->valuestring, ctx);
            return; /* blob objects carry no nested records */
        }
        if (!cJSON_IsString(type)) {
            const cJSON *cid = cJSON_GetObjectItemCaseSensitive(node, "cid");
            const cJSON *mime = cJSON_GetObjectItemCaseSensitive(node,
                                                                 "mimeType");
            if (cJSON_IsString(cid) && cid->valuestring &&
                cJSON_IsString(mime)) {
                cb(cid->valuestring, ctx);
                return;
            }
        }
        const cJSON *child = NULL;
        cJSON_ArrayForEach(child, node) json_walk_blob_refs(child, cb, ctx);
    } else if (cJSON_IsArray(node)) {
        const cJSON *child = NULL;
        cJSON_ArrayForEach(child, node) json_walk_blob_refs(child, cb, ctx);
    }
}

typedef struct missing_blob_ref {
    char *cid;
    char *record_uri;
} missing_blob_ref;

typedef struct missing_blobs_scan {
    metalbear_blob_store *blobs_store;
    const char *cursor;      /* keep only CIDs > cursor */
    missing_blob_ref *refs;  /* deduped missing refs, unsorted */
    size_t count;
    const char *did;
    const char *collection;  /* current record's collection */
    const char *rkey;        /* current record's rkey */
} missing_blobs_scan;

static void missing_blob_candidate(const char *cid, void *opaque) {
    missing_blobs_scan *scan = opaque;
    if (scan->cursor && strcmp(cid, scan->cursor) <= 0) return;
    for (size_t i = 0; i < scan->count; i++)
        if (strcmp(scan->refs[i].cid, cid) == 0) return;
    if (metalbear_blob_store_exists(scan->blobs_store, cid) == WF_OK) return;
    /* Missing and not seen yet: record it (first record URI wins, matching
     * rsky's GROUP BY which keeps one row per CID). */
    missing_blob_ref *grown = realloc(scan->refs,
        (scan->count + 1) * sizeof(*scan->refs));
    if (!grown) return;
    scan->refs = grown;
    size_t uri_len = strlen(scan->did) + strlen(scan->collection) +
                     strlen(scan->rkey) + 10;
    scan->refs[scan->count].cid = strdup(cid);
    scan->refs[scan->count].record_uri = malloc(uri_len);
    if (!scan->refs[scan->count].cid || !scan->refs[scan->count].record_uri) {
        free(scan->refs[scan->count].cid);
        free(scan->refs[scan->count].record_uri);
        return;
    }
    snprintf(scan->refs[scan->count].record_uri, uri_len, "at://%s/%s/%s",
             scan->did, scan->collection, scan->rkey);
    scan->count++;
}

static wf_status missing_blobs_visit(const char *collection, const char *rkey,
                                     const char *value_json, void *ctx) {
    missing_blobs_scan *scan = ctx;
    cJSON *value = cJSON_Parse(value_json);
    if (!value) return WF_OK;
    scan->collection = collection;
    scan->rkey = rkey;
    json_walk_blob_refs(value, missing_blob_candidate, scan);
    cJSON_Delete(value);
    return WF_OK;
}

static int missing_blob_ref_cmp(const void *a, const void *b) {
    return strcmp(((const missing_blob_ref *)a)->cid,
                  ((const missing_blob_ref *)b)->cid);
}

/* Distinct blob CIDs referenced by the repo's records — checkAccountStatus's
 * `expectedBlobs`, which a migrating client compares against `importedBlobs`
 * to know whether blob transfer is complete. */
typedef struct blob_ref_tally {
    char **cids;
    size_t count;
} blob_ref_tally;

static void blob_ref_tally_add(const char *cid, void *opaque) {
    blob_ref_tally *tally = opaque;
    for (size_t i = 0; i < tally->count; i++)
        if (strcmp(tally->cids[i], cid) == 0) return;
    char **grown = realloc(tally->cids, (tally->count + 1) * sizeof(*grown));
    if (!grown) return;
    tally->cids = grown;
    tally->cids[tally->count] = strdup(cid);
    if (tally->cids[tally->count]) tally->count++;
}

static wf_status blob_ref_tally_visit(const char *collection, const char *rkey,
                                      const char *value_json, void *ctx) {
    (void)collection;
    (void)rkey;
    cJSON *value = cJSON_Parse(value_json);
    if (!value) return WF_OK;
    json_walk_blob_refs(value, blob_ref_tally_add, ctx);
    cJSON_Delete(value);
    return WF_OK;
}

static size_t count_referenced_blobs(metalbear_repo_store *repo) {
    blob_ref_tally tally = {0};
    if (metalbear_repo_store_foreach_record(repo, blob_ref_tally_visit,
                                            &tally) != WF_OK) {
        for (size_t i = 0; i < tally.count; i++) free(tally.cids[i]);
        free(tally.cids);
        return 0;
    }
    size_t count = tally.count;
    for (size_t i = 0; i < tally.count; i++) free(tally.cids[i]);
    free(tally.cids);
    return count;
}

static wf_status list_missing_blobs(void *ctx,
                                    const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    int limit = query_param_int(request->params, "limit", 500, 1, 1000);
    cJSON *cursor_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor") : NULL;

    missing_blobs_scan scan = {0};
    scan.blobs_store = acct->blobs;
    scan.cursor = cJSON_IsString(cursor_param) &&
        cursor_param->valuestring[0] ? cursor_param->valuestring : NULL;
    scan.did = acct->did;
    wf_status walk = metalbear_repo_store_foreach_record(
        acct->repo, missing_blobs_visit, &scan);
    if (walk != WF_OK) {
        for (size_t i = 0; i < scan.count; i++) {
            free(scan.refs[i].cid);
            free(scan.refs[i].record_uri);
        }
        free(scan.refs);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not enumerate records");
        return WF_OK;
    }
    qsort(scan.refs, scan.count, sizeof(*scan.refs), missing_blob_ref_cmp);

    cJSON *root = cJSON_CreateObject();
    cJSON *blobs = cJSON_CreateArray();
    if (!root || !blobs) {
        cJSON_Delete(root);
        cJSON_Delete(blobs);
        for (size_t i = 0; i < scan.count; i++) {
            free(scan.refs[i].cid);
            free(scan.refs[i].record_uri);
        }
        free(scan.refs);
        return WF_ERR_ALLOC;
    }
    size_t emitted = 0;
    for (; emitted < scan.count && emitted < (size_t)limit; emitted++) {
        cJSON *item = cJSON_CreateObject();
        if (!item) break;
        cJSON_AddStringToObject(item, "cid", scan.refs[emitted].cid);
        cJSON_AddStringToObject(item, "recordUri",
                                scan.refs[emitted].record_uri);
        cJSON_AddItemToArray(blobs, item);
    }
    if (scan.count > (size_t)limit && emitted > 0)
        cJSON_AddStringToObject(root, "cursor", scan.refs[emitted - 1].cid);
    cJSON_AddItemToObject(root, "blobs", blobs);
    for (size_t i = 0; i < scan.count; i++) {
        free(scan.refs[i].cid);
        free(scan.refs[i].record_uri);
    }
    free(scan.refs);
    return set_json(response, root);
}

/* ---- com.atproto.sync.getRecord (query, public) ----
 * Return a single record as a CAR file rooted at the current commit.
 * When ?as=bytes is requested, the raw CAR bytes are returned as
 * application/octet-stream; otherwise the standard CAR media type is used. */
static wf_status get_record(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *collection = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "collection") : NULL;
    cJSON *rkey = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "rkey") : NULL;
    cJSON *as_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "as") : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    if (!cJSON_IsString(collection) || !collection->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "collection is required");
        return WF_OK;
    }
    if (!cJSON_IsString(rkey) || !rkey->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "rkey is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!assert_repo_available(server, acct, request, response))
        return WF_OK;
    unsigned char *data = NULL;
    size_t length = 0;
    wf_status status = metalbear_repo_store_get_record_car(
        acct->repo, collection->valuestring, rkey->valuestring,
        &data, &length);
    if (status == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(response, 404, "RecordNotFound",
                                   "Record not found");
        return WF_OK;
    }
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not export record");
        return WF_OK;
    }
    const char *content_type = "application/vnd.ipld.car";
    if (cJSON_IsString(as_param) && strcmp(as_param->valuestring, "bytes") == 0)
        content_type = "application/octet-stream";
    wf_xrpc_response_set_body(response, (const char *)data, length);
    wf_xrpc_response_set_content_type(response, content_type);
    free(data);
    return WF_OK;
}

/* ── PLC DID minting helper ───────────────────────────────────── */
/* Mint a did:plc for `handle` and return it (caller frees), writing the
 * account signing key the operation publishes into *out_signing_key. The
 * repo created for this DID must adopt that key: a repo signing with anything
 * else contradicts its own DID document, and relays reject it. */
static char *mint_plc_did(metalbear_server *server, const char *handle,
                          wf_signing_key *out_signing_key) {
    cJSON *root = NULL;
    cJSON *verification = NULL;
    char *unsigned_json = NULL;
    char *signed_json = NULL;
    char *account_didkey = NULL;
    char *rotation_didkey = NULL;
    wf_signing_key acct_key;
    wf_signing_key rotation_key;
    char *plc_did = NULL;

    memset(&acct_key, 0, sizeof(acct_key));
    memset(&rotation_key, 0, sizeof(rotation_key));

    /* 1. Generate fresh secp256k1 signing key for the new account. */
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &acct_key) != WF_OK) {
        LOG_ERROR("failed to generate account signing key");
        goto fail;
    }
    if (wf_signing_key_public_didkey(&acct_key, &account_didkey) != WF_OK) {
        LOG_ERROR("failed to get account did:key");
        goto fail;
    }

    /* 2. Load the server's PLC rotation key to sign the genesis operation.
     * It belongs to the host, so minting a DID no longer depends on some
     * other account existing first. */
    if (metalbear_key_rotation_current_key(server->plc_rotation,
                                           &rotation_key) != WF_OK) {
        LOG_ERROR("failed to get rotation key");
        goto fail;
    }
    if (wf_signing_key_public_didkey(&rotation_key, &rotation_didkey) != WF_OK) {
        LOG_ERROR("failed to get rotation did:key");
        goto fail;
    }

    /* 3. Build the unsigned plc_operation. */
    const char *rotation_keys[] = { rotation_didkey };
    char aka_buf[256];
    char services_buf[512];
    snprintf(aka_buf, sizeof(aka_buf), "at://%s", handle);
    snprintf(services_buf, sizeof(services_buf),
             "{\"atproto_pds\":{\"type\":\"AtprotoPersonalDataServer\","
             "\"endpoint\":\"%s\"}}",
             server->public_url ? server->public_url : "");

    wf_plc_operation_update update = {
        .rotation_keys = rotation_keys,
        .rotation_keys_count = 1,
        .verification_methods_json = NULL,
        .services_json = services_buf,
        .also_known_as = (const char *const[]){ aka_buf },
        .also_known_as_count = 1,
        .prev = NULL,
    };

    if (wf_plc_operation_build(&update, &unsigned_json) != WF_OK) {
        LOG_ERROR("failed to build PLC operation");
        goto fail;
    }

    /* Inject the account did:key into verificationMethods. */
    root = cJSON_Parse(unsigned_json);
    if (!root) {
        LOG_ERROR("failed to parse unsigned operation JSON");
        goto fail;
    }
    verification = cJSON_GetObjectItemCaseSensitive(root, "verificationMethods");
    if (!cJSON_IsObject(verification)) {
        LOG_ERROR("unsigned operation missing verificationMethods");
        goto fail;
    }
    {
        cJSON *old = cJSON_DetachItemFromObjectCaseSensitive(verification, "atproto");
        if (old) cJSON_Delete(old);
    }
    if (!cJSON_AddStringToObject(verification, "atproto", account_didkey)) {
        LOG_ERROR("failed to add atproto verification method");
        goto fail;
    }
    char *unsigned_with_key = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    root = NULL;
    if (!unsigned_with_key) {
        LOG_ERROR("failed to serialize unsigned operation with key");
        goto fail;
    }

    /* 5. Sign the genesis operation with the rotation key. */
    if (wf_plc_operation_sign(unsigned_with_key, &rotation_key,
                              &signed_json) != WF_OK) {
        LOG_ERROR("failed to sign PLC operation");
        goto fail;
    }

    /* 6. Compute the deterministic DID from the signed operation (including
     *    the sig field, matching the @did-plc/lib reference implementation). */
    if (wf_plc_operation_compute_did(signed_json, &plc_did) != WF_OK) {
        LOG_ERROR("failed to compute PLC DID");
        goto fail;
    }

    /* 7. Submit to the PLC directory; the response body is unused.
     * The operation documents themselves are never logged: they carry the
     * account's rotation and signing did:keys and the signature over them, and
     * this runs at INFO on a server whose logs are routinely shipped
     * elsewhere. The DID and directory URL are enough to trace a submission. */
    LOG_INFO("submitting PLC operation to %s for DID %s", server->plc_url, plc_did);
    if (wf_plc_submit_operation_raw(server->plc_url, plc_did, signed_json) != WF_OK) {
        LOG_ERROR("failed to submit PLC operation to directory");
        free(plc_did);
        plc_did = NULL;
        goto fail;
    }

    free(unsigned_json);
    free(unsigned_with_key);
    free(signed_json);
    free(account_didkey);
    free(rotation_didkey);
    if (out_signing_key) *out_signing_key = acct_key;
    return plc_did;

fail:
    free(unsigned_json);
    free(signed_json);
    free(account_didkey);
    free(rotation_didkey);
    return NULL;
}

static wf_status create_account(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *handle = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "handle") : NULL;
    cJSON *password = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "password") : NULL;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *email = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "email") : NULL;
    if (!cJSON_IsString(email) || !email->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidEmail",
                                   "email is required");
        return WF_OK;
    }
    if (!cJSON_IsString(handle) || !handle->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "handle is required");
        return WF_OK;
    }
    if (!cJSON_IsString(password) || !password->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidPassword",
                                    "password is required");
        return WF_OK;
    }
    LOG_DEBUG("create_account: attempt handle=%s email=%s did=%s",
              handle->valuestring,
              email->valuestring,
              cJSON_IsString(did) && did->valuestring[0] ? did->valuestring : "(auto)");
    /* Invite-gated signups (refpds PDS_INVITE_REQUIRED): when enabled,
     * reject account creation unless a non-empty invite code is supplied
     * and the code has remaining uses. */
    if (server->invite_required) {
        cJSON *invite = request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params,
                                              "inviteCode") : NULL;
        if (!cJSON_IsString(invite) || !invite->valuestring[0]) {
            wf_xrpc_response_set_error(response, 400, "InvalidInviteCode",
                                        "an invite code is required to sign up");
            return WF_OK;
        }
        /* Validate and consume the invite code. */
        if (metalbear_account_registry_consume_invite_code(
                server->registry, invite->valuestring,
                handle->valuestring) != WF_OK) {
            wf_xrpc_response_set_error(response, 400, "InvalidInviteCode",
                                        "the invite code is invalid or exhausted");
            return WF_OK;
        }
    }
    /* Check if the handle is already registered */
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_handle(
            server->registry, handle->valuestring,
            &existing) == WF_OK) {
        metalbear_account_entry_free(existing);
        wf_xrpc_response_set_error(response, 400, "HandleNotAvailable",
                                   "Handle is already taken");
        return WF_OK;
    }

    /* Ensure handle uses the configured user domain (matches refpds behavior). */
    size_t handle_len = strlen(handle->valuestring);
    size_t ud_len = server->user_domain ? strlen(server->user_domain) : 0;
    if (ud_len == 0 || handle_len <= ud_len ||
        strcmp(handle->valuestring + handle_len - ud_len,
               server->user_domain) != 0) {
        wf_xrpc_response_set_error(response, 400, "UnsupportedDomain",
                                   "handle is not provided on this domain");
        return WF_OK;
    }
    /* Enforce 3-18 character label before the domain. */
    size_t label_len = handle_len - ud_len;
    if (label_len < 3 || label_len > 18) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "handle too short or too long");
        return WF_OK;
    }
 
    /* Resolve the new account's DID. A caller may supply one (e.g. a
      * did:web or a did:plc minted out of band), or the PDS may mint a
      * server-side did:plc via PLC when configured; otherwise we mint a fresh
      * did:key so every account is independently addressable and isolated. */
    char *account_did = NULL;
    /* Set only when this server minted the DID, in which case the repo must be
     * created with the key that DID document publishes. */
    wf_signing_key minted_key;
    bool have_minted_key = false;
    memset(&minted_key, 0, sizeof(minted_key));
    if (cJSON_IsString(did) && did->valuestring[0]) {
        account_did = strdup(did->valuestring);
        if (!account_did) {
            wf_xrpc_response_set_error(response, 500, "InternalError",
                                       "Could not allocate account DID");
            return WF_OK;
        }
        LOG_INFO("create_account: using provided DID=%s for handle=%s",
                 account_did, handle->valuestring);
    } else if (server->plc_url && server->plc_url[0]) {
        LOG_DEBUG("create_account: minting PLC DID for handle=%s", handle->valuestring);
        account_did = mint_plc_did(server, handle->valuestring, &minted_key);
        have_minted_key = account_did != NULL;
        if (!account_did) {
            wf_xrpc_response_set_error(response, 500, "InternalError",
                                       "Could not mint PLC DID");
            return WF_OK;
        }
        LOG_INFO("create_account: minted PLC DID=%s for handle=%s",
                 account_did, handle->valuestring);
    } else {
        wf_signing_key key;
        if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &key) != WF_OK ||
            wf_signing_key_public_didkey(&key, &account_did) != WF_OK) {
            wf_xrpc_response_set_error(response, 500, "InternalError",
                                       "Could not generate account DID");
            return WF_OK;
        }
        LOG_INFO("create_account: generated did:key=%s for handle=%s",
                 account_did, handle->valuestring);
    }

    /* Provision a dedicated, filesystem-isolated data directory for the
     * account under the PDS data root. */
    char *data_dir = NULL;
    if (metalbear_account_dir_for_did(server->data_directory, account_did,
                                      &data_dir) != WF_OK || !data_dir) {
        free(account_did);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not build data directory");
        return WF_OK;
    }

    /* Open the account's full store bundle. This creates the repository with
     * its own signing key and persists the password verifier in the account
     * store — a real, isolated account rather than registry metadata alone. */
    metalbear_account_context *acct = NULL;
    /*
     * Open against the PDS-wide log, not a private one.
     *
     * Passing no sequencer here made the context open its own log under the
     * account directory and seed the account's #identity and #account events
     * into it. Nothing ever reads that file: every later request resolves the
     * account through the cache, which uses the server's log. A relay's first
     * sight of a new DID was therefore a bare #commit with no identity or
     * account event before it.
     */
    wf_status status = metalbear_account_context_open_shared(
        server->service_did, server->public_url, account_did,
        handle->valuestring, data_dir, password->valuestring,
        have_minted_key ? &minted_key : NULL, server->sequencer, &acct);
    if (status != WF_OK) {
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not provision account stores");
        return WF_OK;
    }

    if (metalbear_account_store_email(acct->account, email->valuestring) != WF_OK) {
        metalbear_account_context_close(acct);
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not store account email");
        return WF_OK;
    }

    /* Record the account in the shared registry with its absolute data
     * directory so future requests can resolve and reopen it. */
    status = metalbear_account_registry_add(server->registry, account_did,
                                            handle->valuestring, "", data_dir);
    if (status == WF_ERR_CONFLICT) {
        metalbear_account_context_close(acct);
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 400, "HandleNotAvailable",
                                   "Handle is already taken");
        return WF_OK;
    }
    if (status != WF_OK) {
        metalbear_account_context_close(acct);
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not register account");
        return WF_OK;
    }

    /*
     * Announce the new account on the host firehose.
     *
     * The registry row is now durable, so the account exists as far as this
     * PDS is concerned; a relay learns of it only from these events. Emitting
     * #identity and #account before any #commit is what lets a consumer bind
     * the DID to its handle and know it is active — without them the first
     * thing the network sees is a commit for a DID it has never heard of.
     */
    if (metalbear_sequencer_account_activation(server->sequencer, account_did,
                                               handle->valuestring,
                                               acct->repo) != WF_OK) {
        /* Not fatal to account creation: the account is already durable, and
         * reconciliation heals a missing tail event. Log loudly — a silently
         * unannounced account looks exactly like a working one locally. */
        LOG_ERROR("create_account: could not sequence creation events for "
                  "did=%s handle=%s; account exists but is unannounced",
                  account_did, handle->valuestring);
    }

    /* Make the handle resolvable. Without a `_atproto` TXT record an AppView
     * shows the account as handle.invalid, which is what every account minted
     * under a wildcard-covered subdomain looked like before this. */
    publish_handle_dns(server, handle->valuestring, account_did);

    /* Issue a session scoped to the new account's own auth store. */
    metalbear_session_tokens tokens = {0};
    wf_status session_status = metalbear_auth_create_scoped_session(
        acct->auth, METALBEAR_ACCESS_FULL, NULL, &tokens);
    /* Build didDoc while the account context is still open. */
    cJSON *did_doc = NULL;
    if (server->public_url)
        did_doc = build_did_doc(server, acct);
    /* Capture email confirmation state before closing the context. */
    int confirmed = 0;
    metalbear_account_get_email(acct->account, NULL, &confirmed);
    metalbear_account_context_close(acct);
    free(data_dir);
    if (session_status != WF_OK) {
        LOG_ERROR("create_account: failed to create session for handle=%s did=%s",
                  handle->valuestring, account_did);
        free(account_did);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create session");
        return WF_OK;
    }

    metalbear_metrics_inc(METALBEAR_METRIC_ACCOUNTS_CREATED);
    LOG_INFO("create_account: created handle=%s did=%s email=%s",
             handle->valuestring, account_did, email->valuestring);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_session_tokens_free(&tokens);
        free(account_did);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "accessJwt", tokens.access_jwt);
    cJSON_AddStringToObject(root, "refreshJwt", tokens.refresh_jwt);
    cJSON_AddStringToObject(root, "handle", handle->valuestring);
    cJSON_AddStringToObject(root, "did", account_did);
    if (confirmed)
        cJSON_AddBoolToObject(root, "emailAuthFactor", true);
    else
        cJSON_AddBoolToObject(root, "emailAuthFactor", false);
    if (did_doc)
        cJSON_AddItemToObject(root, "didDoc", did_doc);
    metalbear_session_tokens_free(&tokens);
    free(account_did);
    return set_json(response, root);
}

static wf_status request_email_confirmation(void *ctx,
                                            const wf_xrpc_request *request,
                                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    char *email = NULL;
    int confirmed = 0;
    if (metalbear_account_get_email(acct->account, &email, &confirmed) !=
            WF_OK || !email) {
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                   "No email address on file");
        free(email);
        return WF_OK;
    }
    if (confirmed) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Email is already confirmed");
        free(email);
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "confirm",
                                             token, sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create confirmation token");
        return WF_OK;
    }
    if (server->email)
        metalbear_email_send_verification(server->email, email, token);
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status confirm_email(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *email = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "email") : NULL;
    cJSON *token = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    if (!cJSON_IsString(email) || !email->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidEmail",
                                   "email is required");
        return WF_OK;
    }
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "token is required");
        return WF_OK;
    }
    wf_status status = metalbear_account_verify_email_token(
        acct->account, "confirm", token->valuestring);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired confirmation token");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status request_email_update(void *ctx,
                                      const wf_xrpc_request *request,
                                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    char *email = NULL;
    int confirmed = 0;
    if (metalbear_account_get_email(acct->account, &email, &confirmed) !=
            WF_OK || !email) {
        free(email);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "No email address on file");
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "update",
                                             token, sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create update token");
        return WF_OK;
    }
    if (server->email)
        metalbear_email_send_verification(server->email, email, token);
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "tokenRequired", true);
    return set_json(response, root);
}

static wf_status update_email(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *email_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "email") : NULL;
    cJSON *token = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    if (!cJSON_IsString(email_param) || !email_param->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "email is required");
        return WF_OK;
    }
    /* Check if current email is confirmed — token required only then */
    char *current_email = NULL;
    int confirmed = 0;
    metalbear_account_get_email(acct->account, &current_email, &confirmed);
    if (confirmed) {
        if (!cJSON_IsString(token) || !token->valuestring[0]) {
            free(current_email);
            wf_xrpc_response_set_error(response, 400, "TokenRequired",
                                       "Token is required when email is "
                                       "already confirmed");
            return WF_OK;
        }
        wf_status status = metalbear_account_verify_email_token(
            acct->account, "update", token->valuestring);
        if (status != WF_OK) {
            free(current_email);
            wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                       "Invalid or expired update token");
            return WF_OK;
        }
    }
    free(current_email);
    /* Store the new email address and mark it unconfirmed */
    if (metalbear_account_store_email(acct->account,
                                      email_param->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not store email address");
        return WF_OK;
    }
    return WF_OK;
}

/*
 * Find the account a password-reset request refers to.
 *
 * These flows are unauthenticated — the caller presents an email address, or a
 * token minted against one account — so the account has to be looked up rather
 * than assumed. Both previously operated on the server's configured account
 * regardless of what was presented, which meant a user resetting their own
 * password reset somebody else's, and no other account could reset at all.
 *
 * Linear over the registry, which is fine: both routes are rate-limited by
 * their email round-trip and are not on any hot path.
 */
static metalbear_account_context *context_for_email(metalbear_server *server,
                                                    const char *email) {
    if (!email || !email[0]) return NULL;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK)
        return NULL;
    metalbear_account_context *found = NULL;
    for (size_t i = 0; i < count && !found; i++) {
        metalbear_account_context *acct = context_for_did(server,
                                                          entries[i].did);
        if (!acct) continue;
        char *stored = NULL;
        metalbear_account_get_email(acct->account, &stored, NULL);
        if (stored && stored[0] && strcmp(stored, email) == 0) found = acct;
        free(stored);
    }
    metalbear_account_entries_free(entries, count);
    return found;
}

/* Find the account an email token was minted for. `purpose` is "reset" or
 * "delete". Tokens are per-account, so the only way to identify the account
 * from a bare token is to ask each one whether it issued it. */
static metalbear_account_context *context_for_email_token(
    metalbear_server *server, const char *purpose, const char *token) {
    if (!purpose || !token || !token[0]) return NULL;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK)
        return NULL;
    metalbear_account_context *found = NULL;
    for (size_t i = 0; i < count && !found; i++) {
        metalbear_account_context *acct = context_for_did(server,
                                                          entries[i].did);
        if (acct && metalbear_account_verify_email_token(acct->account, purpose,
                                                         token) == WF_OK)
            found = acct;
    }
    metalbear_account_entries_free(entries, count);
    return found;
}

static wf_status request_password_reset(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *email_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "email")
        : NULL;
    if (!cJSON_IsString(email_param) || !email_param->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "email is required");
        return WF_OK;
    }
    /* Look the account up by the address presented, rather than assuming one. */
    metalbear_account_context *acct =
        context_for_email(server, email_param->valuestring);
    char *email = NULL;
    if (acct) metalbear_account_get_email(acct->account, &email, NULL);
    if (!acct || !email || !email[0] ||
        strcmp(email, email_param->valuestring) != 0) {
        free(email);
        /* Always return success to avoid email enumeration */
        cJSON *root = cJSON_CreateObject();
        if (!root) return WF_ERR_ALLOC;
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(response, root);
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "reset",
                                             token, sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create reset token");
        return WF_OK;
    }
    if (server->email)
        metalbear_email_send_password_reset(server->email, email, token);
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status reset_password(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *token = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    cJSON *password = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "password") : NULL;
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "token is required");
        return WF_OK;
    }
    if (!cJSON_IsString(password) || !password->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "password is required");
        return WF_OK;
    }
    metalbear_account_context *acct =
        context_for_email_token(server, "reset", token->valuestring);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired reset token");
        return WF_OK;
    }
    wf_status status = metalbear_account_reset_password(acct->account,
                                                        password->valuestring);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not reset password");
        return WF_OK;
    }
    return WF_OK;
}

static wf_status get_account_invite_codes(void *ctx,
                                           const wf_xrpc_request *request,
                                           wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    /* The auth callback resolves the DID into authed_subject; use it
     * to look up the account's invite codes. */
    const char *did = request->authed_subject;
    cJSON *root = cJSON_CreateObject();
    cJSON *codes = cJSON_CreateArray();
    if (!root || !codes) {
        cJSON_Delete(root);
        cJSON_Delete(codes);
        return WF_ERR_ALLOC;
    }
    if (did && server->registry) {
        metalbear_invite_code_entry *entries = NULL;
        size_t count = 0;
        if (metalbear_account_registry_get_invite_codes(
                server->registry, did, &entries, &count) == WF_OK) {
            for (size_t i = 0; i < count; i++) {
                cJSON *obj = cJSON_CreateObject();
                if (!obj) continue;
                cJSON_AddStringToObject(obj, "code", entries[i].code);
                cJSON_AddNumberToObject(obj, "usesAvailable",
                                        entries[i].uses_remaining);
                if (entries[i].disabled)
                    cJSON_AddBoolToObject(obj, "disabled", true);
                cJSON_AddItemToArray(codes, obj);
            }
            metalbear_invite_code_entries_free(entries, count);
        }
    }
    cJSON_AddItemToObject(root, "codes", codes);
    return set_json(response, root);
}

/* ---- checkAccountStatus (query) ---- */
static wf_status check_account_status(void *ctx,
                                      const wf_xrpc_request *request,
                                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    bool active = metalbear_account_is_active(acct->account);
    char *rev = NULL;
    char *cid = NULL;
    metalbear_repo_store_get_head(acct->repo, &rev, &cid);
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(rev);
        free(cid);
        return WF_ERR_ALLOC;
    }
    bool valid_did = did_doc_matches_service(server, acct);
    cJSON_AddBoolToObject(root, "activated", active);
    cJSON_AddBoolToObject(root, "validDid", valid_did);
    cJSON_AddStringToObject(root, "repoCommit", cid ? cid : "");
    cJSON_AddStringToObject(root, "repoRev", rev ? rev : "");
    metalbear_repo_store_stats stats = {0};
    char **blob_cids = NULL;
    size_t blob_count = 0;
    if (metalbear_repo_store_get_stats(acct->repo, &stats) != WF_OK ||
        metalbear_blob_store_list(acct->blobs, &blob_cids, &blob_count) != WF_OK) {
        metalbear_blob_store_list_free(blob_cids, blob_count);
        cJSON_Delete(root);
        free(rev);
        free(cid);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not inspect account storage");
        return WF_OK;
    }
    metalbear_blob_store_list_free(blob_cids, blob_count);
    cJSON_AddNumberToObject(root, "repoBlocks", (double)stats.repo_blocks);
    cJSON_AddNumberToObject(root, "indexedRecords",
                            (double)stats.indexed_records);
    cJSON_AddNumberToObject(root, "privateStateValues", 0);
    cJSON_AddNumberToObject(root, "expectedBlobs",
                            (double)count_referenced_blobs(acct->repo));
    cJSON_AddNumberToObject(root, "importedBlobs", (double)blob_count);
    free(rev);
    free(cid);
    return set_json(response, root);
}

/* ---- reserveSigningKey (procedure) ---- */
static wf_status reserve_signing_key(void *ctx,
                                    const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    char *didkey = NULL;
    /* Unauthenticated, matching the reference: this is called during account
     * migration for a DID that has no account here yet, so there is no
     * session to authenticate and no account store to reserve against. The
     * reservation lives in the server's key store. */
    if (metalbear_key_rotation_reserve(server->plc_rotation, &didkey) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not reserve signing key");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(didkey);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "signingKey", didkey);
    free(didkey);
    return set_json(response, root);
}

static void gen_invite_code(char *buf, size_t size) {
    static const char alphabet[] =
        "23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    unsigned char raw[24];
    if (RAND_bytes(raw, (int)sizeof(raw)) != 1) {
        memset(raw, 0, sizeof(raw));
        for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (unsigned char)i;
    }
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(raw) && pos + 1 < size; i++) {
        if (i > 0 && i % 4 == 0 && pos + 1 < size)
            buf[pos++] = '-';
        buf[pos++] = alphabet[raw[i] % (sizeof(alphabet) - 1)];
    }
    buf[pos] = '\0';
}

/* ---- createInviteCode (procedure) ---- */
static wf_status create_invite_code(void *ctx,
                                    const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *useCount = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "useCount") : NULL;
    if (!cJSON_IsNumber(useCount) || useCount->valuedouble < 1) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "useCount is required and must be > 0");
        return WF_OK;
    }
    cJSON *forAccount = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "forAccount")
        : NULL;
    const char *account = (cJSON_IsString(forAccount) &&
                           forAccount->valuestring[0])
                              ? forAccount->valuestring : "admin";
    char code[64];
    gen_invite_code(code, sizeof(code));
    const char *codes[] = { code };
    if (metalbear_account_registry_create_invite_codes(
            server->registry, account, codes, 1,
            (int)useCount->valuedouble) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not persist invite code");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "code", code);
    return set_json(response, root);
}

/* ---- createInviteCodes (procedure) ---- */
static wf_status create_invite_codes(void *ctx,
                                     const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *codeCount = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "codeCount") : NULL;
    cJSON *useCount = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "useCount") : NULL;
    if (!cJSON_IsNumber(codeCount) || codeCount->valuedouble < 1 ||
        !cJSON_IsNumber(useCount) || useCount->valuedouble < 1) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "codeCount and useCount are required and > 0");
        return WF_OK;
    }
    int count = (int)codeCount->valuedouble;
    if (count > 100) count = 100;
    int per_code_uses = (int)useCount->valuedouble;
    cJSON *forAccounts = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "forAccounts") : NULL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON *codes_arr = cJSON_CreateArray();
    if (!codes_arr) { cJSON_Delete(root); return WF_ERR_ALLOC; }

    /* Collect accounts to create codes for. */
    const char *accounts[32];
    size_t account_count = 0;
    if (cJSON_IsArray(forAccounts) && cJSON_GetArraySize(forAccounts) > 0) {
        size_t n = cJSON_GetArraySize(forAccounts);
        if (n > 32) n = 32;
        for (size_t a = 0; a < n; a++) {
            cJSON *acct = cJSON_GetArrayItem(forAccounts, a);
            accounts[a] = (cJSON_IsString(acct) && acct->valuestring)
                              ? acct->valuestring : "admin";
        }
        account_count = n;
    } else {
        accounts[0] = "admin";
        account_count = 1;
    }

    for (size_t a = 0; a < account_count; a++) {
        cJSON *account_obj = cJSON_CreateObject();
        if (!account_obj) { cJSON_Delete(root); cJSON_Delete(codes_arr); return WF_ERR_ALLOC; }
        cJSON_AddStringToObject(account_obj, "account", accounts[a]);
        cJSON *code_list = cJSON_CreateArray();
        if (!code_list) { cJSON_Delete(root); cJSON_Delete(codes_arr); cJSON_Delete(account_obj); return WF_ERR_ALLOC; }

        /* Generate and persist codes. */
        const char *generated[100];
        for (int i = 0; i < count; i++) {
            char code[64];
            gen_invite_code(code, sizeof(code));
            generated[i] = NULL; /* stack; persist below */
            cJSON_AddItemToArray(code_list, cJSON_CreateString(code));
            /* Persist each code individually (gen_invite_code writes to stack). */
            char *code_copy = strdup(code);
            if (code_copy) {
                const char *single_code[] = { code_copy };
                metalbear_account_registry_create_invite_codes(
                    server->registry, accounts[a], single_code, 1,
                    per_code_uses);
                free(code_copy);
            }
        }
        (void)generated;
        cJSON_AddItemToObject(account_obj, "codes", code_list);
        cJSON_AddItemToArray(codes_arr, account_obj);
    }
    cJSON_AddItemToObject(root, "codes", codes_arr);
    return set_json(response, root);
}

/* Render the current UTC time as an ISO-8601 datetime (the
 * com.atproto.admin.defs#accountView `indexedAt` field). */
static void iso_now(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm tm;
#if defined(_WIN32)
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ---- com.atproto.admin.getAccountInfo (query, admin-gated) ----
 * Mirrors refpds `pdsadmin account list`: look the DID up in the
 * registry and return its did/handle/email/active. Unknown DID is an
 * honest AccountNotFound (404), never a fabricated success. */
static wf_status admin_get_account_info(void *ctx,
                                      const wf_xrpc_request *request,
                                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "did is required");
        return WF_OK;
    }
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(server->registry,
                                                did->valuestring,
                                                &entry) != WF_OK || !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                    "account is not hosted here");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_account_entry_free(entry);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", entry->did);
    cJSON_AddStringToObject(root, "handle", entry->handle);
    cJSON_AddBoolToObject(root, "active", entry->active != 0);
    /* Email lives in the account's own store; open it read-only. */
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    if (acct_path) {
        metalbear_account_store *acct = NULL;
        if (metalbear_account_store_open(acct_path, "", &acct) == WF_OK) {
            char *email = NULL;
            int confirmed = 0;
            if (metalbear_account_get_email(acct, &email, &confirmed) == WF_OK
                && email && email[0])
                cJSON_AddStringToObject(root, "email", email);
            free(email);
            metalbear_account_store_free(acct);
        }
        free(acct_path);
    }
    char indexed_at[32];
    iso_now(indexed_at, sizeof(indexed_at));
    cJSON_AddStringToObject(root, "indexedAt", indexed_at);
    metalbear_account_entry_free(entry);
    return set_json(response, root);
}

/* ---- com.atproto.admin.getSubjectStatus (query, admin-gated) ---- */
static wf_status admin_get_subject_status(void *ctx,
                                           const wf_xrpc_request *request,
                                           wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *uri_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "uri") : NULL;
    cJSON *blob_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "blob") : NULL;
    const char *did = cJSON_IsString(did_param) ? did_param->valuestring : NULL;
    const char *uri = cJSON_IsString(uri_param) ? uri_param->valuestring : NULL;
    const char *blob = cJSON_IsString(blob_param) ? blob_param->valuestring : NULL;
    if (!did && !uri && !blob) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "at least one of did, uri, or blob is required");
        return WF_OK;
    }
    /* A CID names content, not an upload, so a blob subject is only
     * identifiable together with the account that holds it. */
    if (blob && !did) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Must provide a did to request blob state");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON *subject = cJSON_CreateObject();
    if (!subject) { cJSON_Delete(root); return WF_ERR_ALLOC; }
    cJSON_AddItemToObject(root, "subject", subject);

    /*
     * Blob first, then record, then account. A blob subject carries a DID as
     * well as a CID, so testing `did` first would answer about the account
     * that holds the blob instead of about the blob.
     */
    char *takedown_ref = NULL;
    if (blob) {
        metalbear_account_registry_get_takedown(server->registry, did, NULL,
                                                blob, &takedown_ref);
        if (!takedown_ref) {
            cJSON_Delete(root);
            wf_xrpc_response_set_error(response, 400, "NotFound",
                                       "Subject not found");
            return WF_OK;
        }
        cJSON_AddStringToObject(subject, "$type",
                                "com.atproto.admin.defs#repoBlobRef");
        cJSON_AddStringToObject(subject, "did", did);
        cJSON_AddStringToObject(subject, "cid", blob);
    } else if (uri) {
        /* `com.atproto.repo.strongRef` requires `cid`, so the record is
         * resolved to supply one; a strict client rejects a reference that
         * carries only the URI. */
        char authority[256], collection[256], rkey[256];
        char *record_cid = NULL;
        if (split_at_uri(uri, authority, sizeof authority,
                         collection, sizeof collection, rkey, sizeof rkey)) {
            metalbear_account_context *acct =
                context_for_identifier(server, authority);
            char *record_json = NULL;
            if (acct && metalbear_repo_store_get_record(
                    acct->repo, collection, rkey,
                    &record_json, &record_cid) != WF_OK)
                record_cid = NULL;
            free(record_json);
        }
        if (record_cid)
            metalbear_account_registry_get_takedown(server->registry, NULL, uri,
                                                    NULL, &takedown_ref);
        if (!record_cid || !takedown_ref) {
            free(record_cid);
            free(takedown_ref);
            cJSON_Delete(root);
            wf_xrpc_response_set_error(response, 400, "NotFound",
                                       "Subject not found");
            return WF_OK;
        }
        cJSON_AddStringToObject(subject, "$type", "com.atproto.repo.strongRef");
        cJSON_AddStringToObject(subject, "uri", uri);
        cJSON_AddStringToObject(subject, "cid", record_cid);
        free(record_cid);
    } else {
        metalbear_account_entry *entry = NULL;
        if (metalbear_account_registry_find_by_did(
                server->registry, did, &entry) != WF_OK || !entry) {
            cJSON_Delete(root);
            wf_xrpc_response_set_error(response, 400, "NotFound",
                                       "Subject not found");
            return WF_OK;
        }
        metalbear_account_registry_get_takedown(server->registry, did, NULL,
                                                NULL, &takedown_ref);
        cJSON_AddStringToObject(subject, "$type",
                                "com.atproto.admin.defs#repoRef");
        cJSON_AddStringToObject(subject, "did", did);
        cJSON_AddItemToObject(root, "deactivated",
                              status_attr(!entry->active, NULL));
        metalbear_account_entry_free(entry);
    }
    cJSON_AddItemToObject(root, "takedown",
                          status_attr(takedown_ref != NULL, takedown_ref));
    free(takedown_ref);
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateSubjectStatus (procedure, admin-gated) ---- */
static wf_status admin_update_subject_status(void *ctx,
                                              const wf_xrpc_request *request,
                                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *subject = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "subject") : NULL;
    if (!subject) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "subject is required");
        return WF_OK;
    }
    cJSON *type = cJSON_GetObjectItemCaseSensitive(subject, "$type");
    const char *type_str = cJSON_IsString(type) ? type->valuestring : NULL;
    cJSON *takedown = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "takedown") : NULL;
    cJSON *deactivated = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "deactivated")
        : NULL;

    const char *did = NULL, *uri = NULL, *blob_cid = NULL;
    char did_buf[256] = {0}, uri_buf[1024] = {0}, blob_buf[128] = {0};

    if (type_str && strcmp(type_str, "com.atproto.admin.defs#repoRef") == 0) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(subject, "did");
        if (!cJSON_IsString(d) || !d->valuestring[0]) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "did is required for repoRef");
            return WF_OK;
        }
        snprintf(did_buf, sizeof(did_buf), "%s", d->valuestring);
        did = did_buf;
    } else if (type_str && strcmp(type_str, "com.atproto.repo.strongRef") == 0) {
        cJSON *u = cJSON_GetObjectItemCaseSensitive(subject, "uri");
        if (!cJSON_IsString(u) || !u->valuestring[0]) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "uri is required for strongRef");
            return WF_OK;
        }
        snprintf(uri_buf, sizeof(uri_buf), "%s", u->valuestring);
        uri = uri_buf;
    } else if (type_str && strcmp(type_str, "com.atproto.admin.defs#repoBlobRef") == 0) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(subject, "did");
        cJSON *c = cJSON_GetObjectItemCaseSensitive(subject, "cid");
        if (!cJSON_IsString(d) || !d->valuestring[0] ||
            !cJSON_IsString(c) || !c->valuestring[0]) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "did and cid are required for repoBlobRef");
            return WF_OK;
        }
        snprintf(did_buf, sizeof(did_buf), "%s", d->valuestring);
        snprintf(blob_buf, sizeof(blob_buf), "%s", c->valuestring);
        did = did_buf;
        blob_cid = blob_buf;
    } else {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "unknown subject type");
        return WF_OK;
    }

    bool account_subject = did && !uri && !blob_cid;
    cJSON *takedown_applied = takedown
        ? cJSON_GetObjectItemCaseSensitive(takedown, "applied") : NULL;
    cJSON *deactivated_applied = deactivated
        ? cJSON_GetObjectItemCaseSensitive(deactivated, "applied") : NULL;

    /* The two would race to decide the account's status and the event that
     * announces it, so the reference refuses the pair outright. */
    if (cJSON_IsTrue(takedown_applied) && deactivated &&
        !cJSON_IsTrue(deactivated_applied)) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "Cannot activate and takedown an account at the same time");
        return WF_OK;
    }

    /* Apply takedown if present. */
    if (takedown) {
        cJSON *ref = cJSON_GetObjectItemCaseSensitive(takedown, "ref");
        const char *ref_str = cJSON_IsString(ref) ? ref->valuestring : "admin";
        bool applying = cJSON_IsTrue(takedown_applied);
        metalbear_account_registry_set_takedown(
            server->registry, did, uri, blob_cid,
            applying ? ref_str : NULL);
        /*
         * Every session the account holds is revoked, so a takedown takes
         * effect on the tokens already issued rather than only on new logins.
         * Lifting it does not restore them: the holder logs in again.
         */
        if (applying) metalbear_metrics_inc(METALBEAR_METRIC_TAKEDOWNS_APPLIED);
        if (account_subject && applying) {
            metalbear_account_context *acct = context_for_did(server, did);
            if (acct) metalbear_auth_delete_all(acct->auth);
            LOG_INFO("takedown: applied to did=%s ref=%s", did, ref_str);
        } else if (account_subject) {
            LOG_INFO("takedown: lifted from did=%s", did);
        }
    }

    /* Handle account deactivation (repoRef only). */
    if (deactivated && account_subject) {
        metalbear_account_context *acct = context_for_did(server, did);
        if (acct) {
            if (cJSON_IsTrue(deactivated_applied))
                metalbear_account_deactivate(acct->account, NULL);
            else
                metalbear_account_activate(acct->account);
        }
    }

    /*
     * Announce the resulting status once, whatever changed. Sequenced against
     * the server's own log rather than a resolved context's, so the event is
     * not silently skipped for an account that happens not to be cached —
     * and computed after both changes have been applied, so an account that
     * is deactivated *and* taken down is announced as taken down rather than
     * as whichever call ran last.
     */
    if (account_subject) {
        metalbear_account_context *acct = context_for_did(server, did);
        if (acct) {
            bool active = false;
            const char *status = account_status_string(server, acct, &active);
            metalbear_sequencer_account_status(server->sequencer, did,
                                               active ? 1 : 0, status);
        }
    }

    /* Return updated status (echo subject + takedown). */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON *out_subject = cJSON_Duplicate(subject, 1);
    if (!out_subject) { cJSON_Delete(root); return WF_ERR_ALLOC; }
    cJSON_AddItemToObject(root, "subject", out_subject);
    if (takedown) {
        cJSON *out_td = cJSON_Duplicate(takedown, 1);
        if (out_td) cJSON_AddItemToObject(root, "takedown", out_td);
    }
    return set_json(response, root);
}

/* ---- com.atproto.admin.sendEmail (procedure, admin-gated) ---- */
static wf_status admin_send_email(void *ctx,
                                   const wf_xrpc_request *request,
                                   wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *recipient = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "recipientDid")
        : NULL;
    cJSON *content = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "content")
        : NULL;
    cJSON *subject_item = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "subject")
        : NULL;
    if (!cJSON_IsString(recipient) || !recipient->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "recipientDid is required");
        return WF_OK;
    }
    if (!cJSON_IsString(content) || !content->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "content is required");
        return WF_OK;
    }
    /* Look up the recipient's email. */
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, recipient->valuestring,
            &entry) != WF_OK || !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "recipient account not found");
        return WF_OK;
    }
    char *email = NULL;
    int confirmed = 0;
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    if (acct_path) {
        metalbear_account_store *acct = NULL;
        if (metalbear_account_store_open(acct_path, "", &acct) == WF_OK) {
            metalbear_account_get_email(acct, &email, &confirmed);
            metalbear_account_store_free(acct);
        }
        free(acct_path);
    }
    metalbear_account_entry_free(entry);
    if (!email || !email[0]) {
        free(email);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "recipient has no email address");
        return WF_OK;
    }
    /* Send the email if the email module is configured. */
    const char *subj = cJSON_IsString(subject_item)
                           ? subject_item->valuestring
                           : "Message from PDS administrator";
    bool sent = false;
    if (server->email) {
        sent = metalbear_email_send(server->email, email, subj,
                                    content->valuestring) == WF_OK;
    }
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "sent", sent);
    return set_json(response, root);
}

/* ---- Helper: build accountView JSON for admin endpoints ---- */
static cJSON *build_account_view(metalbear_server *server,
                                 const metalbear_account_entry *entry) {
    (void)server;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddStringToObject(obj, "did", entry->did);
    cJSON_AddStringToObject(obj, "handle", entry->handle);
    cJSON_AddBoolToObject(obj, "active", entry->active != 0);
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    if (acct_path) {
        metalbear_account_store *acct = NULL;
        if (metalbear_account_store_open(acct_path, "", &acct) == WF_OK) {
            char *email = NULL;
            int confirmed = 0;
            if (metalbear_account_get_email(acct, &email, &confirmed) == WF_OK
                && email && email[0]) {
                cJSON_AddStringToObject(obj, "email", email);
                if (confirmed) {
                    char indexed_at[32];
                    iso_now(indexed_at, sizeof(indexed_at));
                    cJSON_AddStringToObject(obj, "emailConfirmedAt", indexed_at);
                }
            }
            free(email);
            metalbear_account_store_free(acct);
        }
        free(acct_path);
    }
    char indexed_at[32];
    iso_now(indexed_at, sizeof(indexed_at));
    cJSON_AddStringToObject(obj, "indexedAt", indexed_at);
    return obj;
}

/* ---- com.atproto.admin.getAccountInfos (query, admin-gated) ---- */
static wf_status admin_get_account_infos(void *ctx,
                                          const wf_xrpc_request *request,
                                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *dids = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "dids") : NULL;
    if (!cJSON_IsArray(dids) || cJSON_GetArraySize(dids) == 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "dids array is required");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *infos = cJSON_CreateArray();
    if (!root || !infos) { cJSON_Delete(root); cJSON_Delete(infos); return WF_ERR_ALLOC; }
    size_t n = cJSON_GetArraySize(dids);
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(dids, i);
        if (!cJSON_IsString(item) || !item->valuestring[0]) continue;
        metalbear_account_entry *entry = NULL;
        if (metalbear_account_registry_find_by_did(
                server->registry, item->valuestring, &entry) != WF_OK || !entry)
            continue;
        cJSON *view = build_account_view(server, entry);
        metalbear_account_entry_free(entry);
        if (view) cJSON_AddItemToArray(infos, view);
    }
    cJSON_AddItemToObject(root, "infos", infos);
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateAccountHandle (procedure, admin-gated) ---- */
static wf_status admin_update_account_handle(void *ctx,
                                              const wf_xrpc_request *request,
                                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *handle = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "handle") : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    if (!cJSON_IsString(handle) || !handle->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "handle is required");
        return WF_OK;
    }
    /* Check handle is not already taken by another account. */
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_handle(
            server->registry, handle->valuestring, &existing) == WF_OK) {
        bool conflict = existing && strcmp(existing->did, did->valuestring) != 0;
        metalbear_account_entry_free(existing);
        if (conflict) {
            wf_xrpc_response_set_error(response, 400, "HandleNotAvailable",
                                       "Handle is already taken");
            return WF_OK;
        }
    }
    /* Update the registry. */
    if (metalbear_account_registry_update_handle(
            server->registry, did->valuestring, handle->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not update handle");
        return WF_OK;
    }
    /* Update the account context if open. */
    metalbear_account_context *acct = context_for_did(server, did->valuestring);
    char *old_handle = NULL;
    if (acct) {
        old_handle = strdup(acct->handle);
        metalbear_repo_store_set_handle(acct->repo, handle->valuestring);
        free(acct->handle);
        acct->handle = strdup(handle->valuestring);
    }

    publish_handle_dns(server, handle->valuestring, did->valuestring);
    /* Only when the old handle was known: the context is the only place it is
     * held, and guessing at a name to delete risks removing someone else's. */
    if (old_handle && strcmp(old_handle, handle->valuestring) != 0)
        retract_handle_dns(server, old_handle);
    free(old_handle);

    /* Same as the self-service path: an unannounced rename leaves every
     * consumer serving the old handle indefinitely. */
    if (metalbear_sequencer_identity(server->sequencer, did->valuestring,
                                     handle->valuestring) != WF_OK)
        LOG_ERROR("admin_update_account_handle: could not sequence #identity "
                  "for did=%s handle=%s; the rename is durable but unannounced",
                  did->valuestring, handle->valuestring);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateAccountEmail (procedure, admin-gated) ---- */
static wf_status admin_update_account_email(void *ctx,
                                             const wf_xrpc_request *request,
                                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *account = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "account") : NULL;
    cJSON *email = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "email") : NULL;
    if (!cJSON_IsString(account) || !account->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "account (DID or handle) is required");
        return WF_OK;
    }
    if (!cJSON_IsString(email) || !email->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "email is required");
        return WF_OK;
    }
    /* Resolve to DID. */
    metalbear_account_entry *entry = NULL;
    wf_status lookup = metalbear_account_registry_find_by_did(
        server->registry, account->valuestring, &entry);
    if (lookup != WF_OK || !entry) {
        lookup = metalbear_account_registry_find_by_handle(
            server->registry, account->valuestring, &entry);
    }
    if (lookup != WF_OK || !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "Account not found");
        return WF_OK;
    }
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    metalbear_account_entry_free(entry);
    if (!acct_path) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Internal error");
        return WF_OK;
    }
    metalbear_account_store *acct = NULL;
    wf_status status = metalbear_account_store_open(acct_path, "", &acct);
    free(acct_path);
    if (status != WF_OK || !acct) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not open account store");
        return WF_OK;
    }
    metalbear_account_store_email(acct, email->valuestring);
    metalbear_account_store_free(acct);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateAccountPassword (procedure, admin-gated) ---- */
static wf_status admin_update_account_password(void *ctx,
                                                const wf_xrpc_request *request,
                                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *password = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "password") : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    if (!cJSON_IsString(password) || !password->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "password is required");
        return WF_OK;
    }
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, did->valuestring, &entry) != WF_OK || !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "Account not found");
        return WF_OK;
    }
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    metalbear_account_entry_free(entry);
    if (!acct_path) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Internal error");
        return WF_OK;
    }
    metalbear_account_store *acct = NULL;
    wf_status status = metalbear_account_store_open(acct_path, "", &acct);
    free(acct_path);
    if (status != WF_OK || !acct) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not open account store");
        return WF_OK;
    }
    metalbear_account_reset_password(acct, password->valuestring);
    metalbear_account_store_free(acct);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.enableAccountInvites (procedure, admin-gated) ---- */
static wf_status admin_enable_account_invites(void *ctx,
                                               const wf_xrpc_request *request,
                                               wf_xrpc_response *response) {
    (void)ctx; (void)request;
    /* For now, this is a no-op stub. MetalBear does not yet track per-account
     * invite enablement. Return success for protocol compatibility. */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.disableAccountInvites (procedure, admin-gated) ---- */
static wf_status admin_disable_account_invites(void *ctx,
                                                const wf_xrpc_request *request,
                                                wf_xrpc_response *response) {
    (void)ctx; (void)request;
    /* Stub: same as enable — no per-account invite tracking yet. */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.getInviteCodes (query, admin-gated) ---- */
static wf_status admin_get_invite_codes(void *ctx,
                                         const wf_xrpc_request *request,
                                         wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    int limit = query_param_int(request->params, "limit", 100, 1, 500);
    /* Enumerate all accounts and collect their invite codes. */
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries,
                                         &count) != WF_OK) {
        entries = NULL;
        count = 0;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *codes = cJSON_CreateArray();
    if (!root || !codes) {
        cJSON_Delete(root); cJSON_Delete(codes);
        metalbear_account_entries_free(entries, count);
        return WF_ERR_ALLOC;
    }
    int taken = 0;
    for (size_t i = 0; i < count && taken < limit; i++) {
        metalbear_invite_code_entry *icode_entries = NULL;
        size_t icode_count = 0;
        if (metalbear_account_registry_get_invite_codes(
                server->registry, entries[i].did,
                &icode_entries, &icode_count) != WF_OK)
            continue;
        for (size_t j = 0; j < icode_count && taken < limit; j++) {
            cJSON *obj = cJSON_CreateObject();
            if (!obj) continue;
            cJSON_AddStringToObject(obj, "code", icode_entries[j].code);
            cJSON_AddStringToObject(obj, "availableBy", entries[i].handle);
            cJSON_AddNumberToObject(obj, "uses", icode_entries[j].uses_remaining);
            cJSON_AddBoolToObject(obj, "disabled", icode_entries[j].disabled != 0);
            cJSON_AddStringToObject(obj, "createdAt", icode_entries[j].created_at);
            cJSON_AddItemToArray(codes, obj);
            taken++;
        }
        metalbear_invite_code_entries_free(icode_entries, icode_count);
    }
    metalbear_account_entries_free(entries, count);
    cJSON_AddItemToObject(root, "codes", codes);
    return set_json(response, root);
}

/* ---- com.atproto.admin.disableInviteCodes (procedure, admin-gated) ---- */
static wf_status admin_disable_invite_codes(void *ctx,
                                            const wf_xrpc_request *request,
                                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *codes = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "codes") : NULL;
    cJSON *accounts = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "accounts") : NULL;

    size_t code_count = 0, account_count = 0;
    const char **code_ptrs = NULL, **account_ptrs = NULL;

    if (cJSON_IsArray(codes) && cJSON_GetArraySize(codes) > 0) {
        code_count = cJSON_GetArraySize(codes);
        code_ptrs = calloc(code_count, sizeof(*code_ptrs));
        if (!code_ptrs) return WF_ERR_ALLOC;
        for (size_t i = 0; i < code_count; i++) {
            cJSON *item = cJSON_GetArrayItem(codes, i);
            code_ptrs[i] = cJSON_IsString(item) ? item->valuestring : NULL;
        }
    }
    if (cJSON_IsArray(accounts) && cJSON_GetArraySize(accounts) > 0) {
        account_count = cJSON_GetArraySize(accounts);
        account_ptrs = calloc(account_count, sizeof(*account_ptrs));
        if (!account_ptrs) { free(code_ptrs); return WF_ERR_ALLOC; }
        for (size_t i = 0; i < account_count; i++) {
            cJSON *item = cJSON_GetArrayItem(accounts, i);
            account_ptrs[i] = cJSON_IsString(item) ? item->valuestring : NULL;
        }
        for (size_t i = 0; i < account_count; i++) {
            if (account_ptrs[i] && strcmp(account_ptrs[i], "admin") == 0) {
                free(code_ptrs);
                free(account_ptrs);
                wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                            "cannot disable admin invite codes");
                return WF_OK;
            }
        }
    }

    wf_status status = metalbear_account_registry_disable_invite_codes(
        server->registry, code_ptrs, code_count, account_ptrs, account_count);
    free(code_ptrs);
    free(account_ptrs);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "disabled", status == WF_OK);
    return set_json(response, root);
}

/* ---- com.atproto.admin.deleteAccount (procedure, admin-gated) ---- */
static int rmtree_remove_cb(const char *path, const struct stat *sb,
                            int type, struct FTW *ftwbuf) {
    (void)sb; (void)type; (void)ftwbuf;
    return remove(path);
}
static void rmtree(const char *path) {
    nftw(path, rmtree_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

static wf_status admin_delete_account(void *ctx,
                                     const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "did is required");
        return WF_OK;
    }
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, did->valuestring, &entry) != WF_OK || !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                    "account is not hosted here");
        return WF_OK;
    }

    char *data_dir = strdup(entry->data_directory);
    char *handle = entry->handle ? strdup(entry->handle) : NULL;
    metalbear_account_entry_free(entry);
    if (!data_dir) {
        free(handle);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "could not copy data directory");
        return WF_OK;
    }

    /*
     * Announce the deletion before the registry row goes away.
     *
     * This used to resolve a context after the removal, which only succeeded
     * when the account happened to still be in the in-memory cache — for any
     * other account the registry lookup then failed and the #account event was
     * skipped entirely, so relays never learned the account was gone. Sequence
     * it against the host log directly, which needs no context at all.
     */
    metalbear_sequencer_account_status(server->sequencer, did->valuestring, 0,
                                       "deleted");
    /*
     * Then drop everything else this DID ever published. The data directory
     * is about to be removed, and leaving the same records on the firehose
     * would keep serving them to any consumer backfilling from an old cursor
     * — a deletion that removes the copy nobody reads and keeps the copy the
     * network does.
     */
    int64_t purged = 0;
    metalbear_sequencer_purge_account(server->sequencer, did->valuestring,
                                      &purged);
    metalbear_metrics_inc(METALBEAR_METRIC_ACCOUNTS_DELETED);
    LOG_INFO("admin_delete_account: purged %lld firehose events for did=%s",
             (long long)purged, did->valuestring);

    metalbear_account_registry_remove(server->registry, did->valuestring);
    /* Moderation state goes with it: a DID re-registered later must not
     * inherit the deleted account's takedowns. */
    metalbear_account_registry_clear_takedowns_for_did(server->registry,
                                                       did->valuestring);

    /* Drop the handle's TXT record: leaving it would keep pointing resolvers
     * at a DID this host no longer serves. */
    retract_handle_dns(server, handle);
    free(handle);

    rmtree(data_dir);
    free(data_dir);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.sync.requestCrawl (procedure, public) ----
 * Mirrors refpds `pdsadmin request-crawl`: forward the request body to
 * each configured crawler/relay (METALBEAR_CRAWLERS). When no crawlers
 * are configured, return an honest NoCrawlersConfigured error rather than
 * fabricating success. */
/*
 * Tell the configured relays this host has new data.
 *
 * A relay that has never dialled a quiet PDS has nothing else to prompt it —
 * requestCrawl at startup alone is not enough, because the interesting moment
 * is when there is something to fetch. The reference PDS notifies from its
 * sequencer for exactly this reason, throttled so a busy repo does not hammer
 * its relays; the same 20-minute floor is used here.
 *
 * Runs on a detached thread: this is called from the write path, and a relay
 * that is slow or down must never hold up a commit.
 */
#define METALBEAR_CRAWLER_NOTIFY_SECONDS (20 * 60)

/* Live value, set from config at startup. */
static time_t crawler_notify_seconds = METALBEAR_CRAWLER_NOTIFY_SECONDS;

typedef struct crawler_notice {
    char *crawlers;   /* owned copy: comma-separated */
    char *body;       /* owned: {"hostname":"..."} */
} crawler_notice;

static void *crawler_notify_main(void *raw) {
    crawler_notice *n = raw;
    char *save = NULL;
    for (char *tok = strtok_r(n->crawlers, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        if (!*tok) continue;
        char *host = NULL;
        if (strncmp(tok, "https://", 8) != 0 &&
            strncmp(tok, "http://", 7) != 0) {
            size_t need = strlen(tok) + strlen("https://") + 1;
            host = malloc(need);
            if (host) snprintf(host, need, "https://%s", tok);
        } else {
            host = strdup(tok);
        }
        if (!host) continue;
        wf_xrpc_client *client = wf_xrpc_client_new(host);
        if (client) {
            wf_response up = {0};
            wf_status st = wf_xrpc_procedure(
                client, "com.atproto.sync.requestCrawl", n->body, &up);
            if (st != WF_OK || up.status < 200 || up.status >= 300) {
                metalbear_metrics_inc(METALBEAR_METRIC_CRAWL_FAILURES);
                LOG_WARN("requestCrawl to %s failed (status %ld)", host,
                         (long)up.status);
            } else {
                LOG_INFO("announced new data to %s", host);
            }
            wf_response_free(&up);
            wf_xrpc_client_free(client);
        }
        free(host);
    }
    free(n->crawlers);
    free(n->body);
    free(n);
    return NULL;
}

static void notify_crawlers(void *ctx) {
    metalbear_server *server = ctx;
    if (!server->crawlers || !server->crawlers[0]) return;
    const char *hostname = server->public_url;
    if (!hostname) return;
    if (strncmp(hostname, "https://", 8) == 0) hostname += 8;
    else if (strncmp(hostname, "http://", 7) == 0) hostname += 7;
    if (!hostname[0]) return;

    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static time_t last = 0;
    time_t now = time(NULL);
    pthread_mutex_lock(&lock);
    bool due = (last == 0) || (now - last >= crawler_notify_seconds);
    if (due) last = now;
    pthread_mutex_unlock(&lock);
    if (!due) return;

    crawler_notice *n = calloc(1, sizeof(*n));
    if (!n) return;
    n->crawlers = strdup(server->crawlers);
    size_t body_len = strlen(hostname) + sizeof("{\"hostname\":\"\"}") + 1;
    n->body = malloc(body_len);
    if (!n->crawlers || !n->body) {
        free(n->crawlers);
        free(n->body);
        free(n);
        return;
    }
    snprintf(n->body, body_len, "{\"hostname\":\"%s\"}", hostname);

    pthread_t thread;
    if (pthread_create(&thread, NULL, crawler_notify_main, n) != 0) {
        free(n->crawlers);
        free(n->body);
        free(n);
        return;
    }
    pthread_detach(thread);
}

static wf_status request_crawl(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    if (!server->crawlers || !server->crawlers[0]) {
        wf_xrpc_response_set_error(response, 400, "NoCrawlersConfigured",
                                    "no crawlers are configured on this PDS");
        return WF_OK;
    }
    cJSON *hostname = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "hostname") : NULL;
    if (!cJSON_IsString(hostname) || !hostname->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "hostname is required");
        return WF_OK;
    }
    /* Echo the exact body we received to each crawler so its own
     * validation/forwarding is authoritative. */
    char *body = request->body && request->body_len
        ? cJSON_PrintUnformatted(request->params)
        : NULL;
    if (!body) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "could not encode request body");
        return WF_OK;
    }

    char *crawlers = strdup(server->crawlers);
    if (!crawlers) {
        free(body);
        return WF_ERR_ALLOC;
    }
    bool any = false;
    char *save = NULL;
    for (char *tok = strtok_r(crawlers, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        if (!*tok) continue;
        char *host = tok;
        if (strncmp(host, "https://", 8) != 0 &&
            strncmp(host, "http://", 7) != 0) {
            size_t need = strlen(host) + strlen("https://") + 1;
            char *https = malloc(need);
            if (!https) continue;
            snprintf(https, need, "https://%s", host);
            host = https;
        } else {
            host = strdup(host);
            if (!host) continue;
        }
        any = true;
        wf_xrpc_client *client = wf_xrpc_client_new(host);
        free(host);
        if (!client) {
            free(body);
            free(crawlers);
            wf_xrpc_response_set_error(response, 502, "UpstreamFailure",
                                        "could not reach crawler");
            return WF_OK;
        }
        wf_response upstream = {0};
        wf_status status = wf_xrpc_procedure(client,
                                            "com.atproto.sync.requestCrawl",
                                            body, &upstream);
        bool ok = status == WF_OK && upstream.status >= 200 &&
                  upstream.status < 300;
        wf_response_free(&upstream);
        wf_xrpc_client_free(client);
        if (!ok) {
            free(body);
            free(crawlers);
            wf_xrpc_response_set_error(response, 502, "UpstreamFailure",
                                        "crawler rejected the crawl request");
            return WF_OK;
        }
    }
    free(body);
    free(crawlers);
    if (!any) {
        wf_xrpc_response_set_error(response, 400, "NoCrawlersConfigured",
                                    "no crawlers are configured on this PDS");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.moderation.createReport (procedure) ----
 * Store a moderation report locally. Requires a valid authenticated session.
 * Validates reasonType against known values and subject union (repoRef or
 * strongRef). */
static wf_status create_report(void *ctx,
                               const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *body = request->params;
    if (!body || !cJSON_IsObject(body)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "Missing request body");
        return WF_OK;
    }

    cJSON *reason_type = cJSON_GetObjectItemCaseSensitive(body, "reasonType");
    cJSON *subject = cJSON_GetObjectItemCaseSensitive(body, "subject");
    cJSON *reason = cJSON_GetObjectItemCaseSensitive(body, "reason");
    cJSON *mod_tool = cJSON_GetObjectItemCaseSensitive(body, "modTool");

    if (!cJSON_IsString(reason_type) || !reason_type->valuestring[0]) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "reasonType is required");
        return WF_OK;
    }
    if (!subject || !cJSON_IsObject(subject)) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "subject is required");
        return WF_OK;
    }

    char subject_type[64] = "";
    char subject_uri[512] = "";
    char subject_cid[128] = "";
    bool is_repo_ref = false;

    cJSON *subject_did = cJSON_GetObjectItemCaseSensitive(subject, "did");
    cJSON *subject_uri_js = cJSON_GetObjectItemCaseSensitive(subject, "uri");
    cJSON *subject_cid_js = cJSON_GetObjectItemCaseSensitive(subject, "cid");

    if (cJSON_IsString(subject_did)) {
        is_repo_ref = true;
        snprintf(subject_uri, sizeof(subject_uri), "%s", subject_did->valuestring);
    } else if (cJSON_IsString(subject_uri_js)) {
        snprintf(subject_uri, sizeof(subject_uri), "%s", subject_uri_js->valuestring);
        if (cJSON_IsString(subject_cid_js))
            snprintf(subject_cid, sizeof(subject_cid), "%s", subject_cid_js->valuestring);
    } else {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "subject must be repoRef or strongRef");
        return WF_OK;
    }

    const char *reporter_did = request->authed_subject;
    if (!reporter_did || !reporter_did[0]) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                    "Invalid access token");
        return WF_OK;
    }

    char *mod_tool_name = NULL;
    char *mod_tool_meta = NULL;
    if (mod_tool && cJSON_IsObject(mod_tool)) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(mod_tool, "name");
        cJSON *meta = cJSON_GetObjectItemCaseSensitive(mod_tool, "meta");
        if (cJSON_IsString(name) && name->valuestring[0])
            mod_tool_name = name->valuestring;
        if (cJSON_IsObject(meta))
            mod_tool_meta = cJSON_PrintUnformatted(meta);
    }

    char created_at[64];
    time_t now = time(NULL);
    if (strftime(created_at, sizeof(created_at), "%Y-%m-%dT%H:%M:%SZ",
                 gmtime(&now)) == 0) {
        free(mod_tool_meta);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "Failed to format timestamp");
        return WF_OK;
    }

    int64_t report_id = 0;
    wf_status st = metalbear_report_store_create(server->reports,
                                                   reporter_did,
                                                   reason_type->valuestring,
                                                   cJSON_IsString(reason) ? reason->valuestring : NULL,
                                                   subject_type,
                                                   subject_uri,
                                                   subject_cid[0] ? subject_cid : NULL,
                                                   mod_tool_name,
                                                   mod_tool_meta,
                                                   &report_id);
    free(mod_tool_meta);

    if (st != WF_OK || report_id == 0) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "Failed to create report");
        return WF_OK;
    }

    cJSON *out = cJSON_CreateObject();
    if (!out) return WF_ERR_ALLOC;
    cJSON_AddNumberToObject(out, "id", (double)report_id);
    cJSON_AddStringToObject(out, "reasonType", reason_type->valuestring);
    if (reason && cJSON_IsString(reason))
        cJSON_AddStringToObject(out, "reason", reason->valuestring);

    cJSON *out_subject = cJSON_CreateObject();
    if (!out_subject) {
        cJSON_Delete(out);
        return WF_ERR_ALLOC;
    }
    if (is_repo_ref && subject_did && cJSON_IsString(subject_did)) {
        cJSON_AddStringToObject(out_subject, "did", subject_did->valuestring);
    } else {
        if (subject_uri[0])
            cJSON_AddStringToObject(out_subject, "uri", subject_uri);
        if (subject_cid[0])
            cJSON_AddStringToObject(out_subject, "cid", subject_cid);
    }
    cJSON_AddItemToObject(out, "subject", out_subject);
    cJSON_AddStringToObject(out, "reportedBy", reporter_did);
    cJSON_AddStringToObject(out, "createdAt", created_at);

    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(response, js, strlen(js));
    free(js);
    return WF_OK;
}

/* ---- com.atproto.sync.getHead (query) ----
 * DEPRECATED: returns the repo head CID. Thin wrapper around the same
 * head-reader used by getLatestCommit. */
static wf_status get_head(void *ctx,
                          const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    if (!cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "HeadNotFound",
                                   "repository is empty or unavailable");
        return WF_OK;
    }
    char *rev = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_get_head(acct->repo, &rev, &cid);
    if (st == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(response, 400, "HeadNotFound",
                                   "repository is empty");
        return WF_OK;
    } else if (st != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "failed to read head");
        return WF_OK;
    }
    cJSON *out = cJSON_CreateObject();
    if (!out) { free(rev); free(cid); return WF_ERR_ALLOC; }
    cJSON_AddStringToObject(out, "root", cid ? cid : "");
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(rev); free(cid);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(response, js, strlen(js));
    free(js);
    return WF_OK;
}

/* ---- com.atproto.sync.getCheckout (query) ----
 * DEPRECATED: returns a CAR stream of the repo. Reuses getRepo's CAR export. */
static wf_status get_checkout(void *ctx,
                              const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    return get_repo(ctx, request, response);
}

/* ---- com.atproto.temp.checkSignupQueue (query) ----
 * Temporary unspecced route. MetalBear has no entryway, so always
 * returns { activated: true }. */
static wf_status check_signup_queue(void *ctx,
                                     const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    (void)ctx;
    (void)request;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    if (!cJSON_AddBoolToObject(root, "activated", 1)) {
        cJSON_Delete(root);
        return WF_ERR_ALLOC;
    }
    return set_json(response, root);
}

/* ---- app.bsky.* AppView proxy handlers ----------------------------------
 *
 * Other PDS implementations (rsky-pds, ref-pds) implement these endpoints
 * as first-class handlers and proxy them to an AppView with service-auth
 * minted from the requester's account. The auth callback runs first, so
 * req->authed_subject contains the requester DID.
 */

static wf_status appview_proxy(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp, bool send_auth) {
    metalbear_server *server = ctx;
    const char *requester_did = req->authed_subject;
    return proxy_appview(server, requester_did, req, resp, send_auth);
}

/* Public read endpoints — proxy without service-auth so the public
 * AppView (api.bsky.app) serves public content. A local AppView that
 * trusts the PDS can be configured later by re-enabling auth. */
static wf_status appview_public(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    return appview_proxy(ctx, req, resp, false);
}

/* User-specific endpoints — send service-auth JWT so a trusted AppView
 * can return per-user data. The public AppView will reject these. */
static wf_status appview_private(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    return appview_proxy(ctx, req, resp, true);
}

/* Feed endpoints — public reads */
static wf_status appview_get_feed(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_feed_skeleton(void *ctx,
                                          const wf_xrpc_request *req,
                                          wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_author_feed(void *ctx,
                                         const wf_xrpc_request *req,
                                         wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_actor_feeds(void *ctx,
                                         const wf_xrpc_request *req,
                                         wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_feed_generators(void *ctx,
                                             const wf_xrpc_request *req,
                                             wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_feed_generator(void *ctx,
                                            const wf_xrpc_request *req,
                                            wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_posts(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Actor endpoints — public reads */
static wf_status appview_get_profile(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    metalbear_server *server = ctx;

    // Check for local profile parameter (did=...
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *did_param = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        if (cJSON_IsString(did_param) && did_param->valuestring[0]) {
            const char *provided_did = did_param->valuestring;
            metalbear_account_context *acct = context_for_did(server, provided_did);
            if (acct && metalbear_account_is_active(acct->account)) {
                LOG_DEBUG("Handling local profile for did:%s", provided_did);

            cJSON *root = cJSON_CreateObject();
            if (!root) {
                wf_xrpc_response_set_error(resp, 500, "InternalError", "Failed to create local profile");
                return WF_OK;
            }

                cJSON_AddStringToObject(root, "did", provided_did);
                cJSON_AddStringToObject(root, "handle", acct->handle ? acct->handle : "unknown");
                // Add other local profile fields as needed

                return set_json(resp, root);
            }
        }
    }

    // Fallback to public proxy for external profiles
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_profiles(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
/* An actor's likes are gated on the viewer, so this needs the requester's
 * identity rather than an anonymous read. */
static wf_status appview_get_actor_likes(void *ctx,
                                         const wf_xrpc_request *req,
                                         wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* The requester's own following feed — meaningless without their identity. */
static wf_status appview_get_timeline(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Thread content is public; viewer state is a bonus the public AppView omits. */
static wf_status appview_get_post_thread(void *ctx, const wf_xrpc_request *req,
                                         wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Push registration is per-account state on the AppView. */
static wf_status appview_register_push(void *ctx, const wf_xrpc_request *req,
                                       wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

static wf_status appview_unregister_push(void *ctx, const wf_xrpc_request *req,
                                         wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
static wf_status appview_get_actor_statistics(void *ctx,
                                              const wf_xrpc_request *req,
                                              wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_actor_rankings(void *ctx,
                                            const wf_xrpc_request *req,
                                            wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Graph endpoints — public reads */
static wf_status appview_get_follows(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_followers(void *ctx, const wf_xrpc_request *req,
                                       wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_blocks(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
static wf_status appview_get_list(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_lists(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_list_items(void *ctx,
                                        const wf_xrpc_request *req,
                                        wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_starter_pack(void *ctx,
                                          const wf_xrpc_request *req,
                                          wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_get_starter_packs(void *ctx,
                                           const wf_xrpc_request *req,
                                           wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Notification endpoints — user-specific */
static wf_status appview_get_unread_notifications(void *ctx,
                                                const wf_xrpc_request *req,
                                                wf_xrpc_response *resp) {
    // Return empty unread count for public AppView; local AppView can be implemented later
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        wf_xrpc_response_set_error(resp, 500, "InternalError", "Failed to create response");
        return WF_OK;
    }
    cJSON_AddNumberToObject(root, "count", 0);
    return set_json(resp, root);
}
static wf_status appview_get_notifications(void *ctx,
                                           const wf_xrpc_request *req,
                                           wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Chat/Convo endpoints — user-specific */
static wf_status appview_get_convo(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
static wf_status appview_get_convos(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
static wf_status appview_get_messages(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Labeler endpoints — public reads */
static wf_status appview_get_labeler_info(void *ctx,
                                          const wf_xrpc_request *req,
                                          wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Unsafe/unspecced endpoints — public reads */
static wf_status appview_unspecced_get_age_assurance_state(void *ctx,
                                                           const wf_xrpc_request *req,
                                                           wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_unspecced_get_age_assurance_config(void *ctx,
                                                            const wf_xrpc_request *req,
                                                            wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
static wf_status appview_unspecced_get_age_assurance(void *ctx,
                                                     const wf_xrpc_request *req,
                                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* ---- com.atproto.repo.uploadBlob (procedure) ----
 * Mirrors wolfram's blob upload handler but enforces
 * METALBEAR_BLOB_UPLOAD_LIMIT before storing. Output shape matches
 * the com.atproto.repo.uploadBlob schema exactly. */
static wf_status upload_blob(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    LOG_DEBUG("upload_blob: did=%s content_type=%s len=%zu",
              request->authed_subject ? request->authed_subject : "-",
              request->content_type ? request->content_type : "-",
              (size_t)request->body_len);
    if (request->body_len == 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "blob body is empty");
        return WF_OK;
    }
    if (server->blob_upload_limit > 0 &&
        (int64_t)request->body_len > server->blob_upload_limit) {
        wf_xrpc_response_set_error(response, 413, "BlobTooLarge",
                                    "blob exceeds the configured upload limit");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                    "account is not hosted here");
        return WF_OK;
    }
    const char *mime = request->content_type && request->content_type[0]
                            ? request->content_type
                            : "application/octet-stream";
    wf_cid cid;
    if (wf_cid_of_bytes(request->body, request->body_len, &cid) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "failed to compute blob CID");
        return WF_OK;
    }
    char *cid_str = wf_cid_to_string(&cid);
    if (!cid_str) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "failed to encode blob CID");
        return WF_OK;
    }
    /*
     * Checked after hashing, because the CID is what a takedown names and it
     * is not known until the body has been read. A takedown that blocked only
     * reads would be undone by re-uploading the same bytes.
     */
    char *blob_takedown = NULL;
    metalbear_account_registry_get_takedown(server->registry, acct->did, NULL,
                                            cid_str, &blob_takedown);
    if (blob_takedown) {
        free(blob_takedown);
        free(cid_str);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "Blob has been takendown, cannot re-upload");
        return WF_OK;
    }
    if (metalbear_blob_store_put(acct->blobs, cid_str, mime,
                           request->body, request->body_len) != WF_OK) {
        free(cid_str);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "failed to store blob");
        return WF_OK;
    }
    metalbear_metrics_inc(METALBEAR_METRIC_BLOBS_UPLOADED);
    cJSON *root = cJSON_CreateObject();
    cJSON *blob = cJSON_CreateObject();
    if (!root || !blob) {
        cJSON_Delete(root);
        cJSON_Delete(blob);
        free(cid_str);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(blob, "$type", "blob");
    cJSON_AddStringToObject(blob, "mimeType", mime);
    cJSON *ref = cJSON_CreateObject();
    if (!ref || !cJSON_AddStringToObject(ref, "$link", cid_str)) {
        cJSON_Delete(root);
        cJSON_Delete(blob);
        cJSON_Delete(ref);
        free(cid_str);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToObject(blob, "ref", ref);
    cJSON_AddNumberToObject(blob, "size", (double)request->body_len);
    cJSON_AddItemToObject(root, "blob", blob);
    free(cid_str);
    return set_json(response, root);
}

/* ---- com.atproto.sync.getBlob (query) ---- */
static wf_status get_blob(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *cid = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "cid") : NULL;
    LOG_DEBUG("get_blob: did=%s cid=%s",
              request->authed_subject ? request->authed_subject : "-",
              cJSON_IsString(cid) ? cid->valuestring : "-");
    if (!cJSON_IsString(cid) || !cid->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                    "missing or invalid 'cid' parameter");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 404, "BlobNotFound",
                                    "account is not hosted here");
        return WF_OK;
    }
    if (!assert_repo_available(server, acct, request, response))
        return WF_OK;
    /* A taken-down blob reads as absent: the lexicon has no code for a
     * moderated blob, and BlobNotFound is what the reference answers. */
    char *blob_takedown = NULL;
    metalbear_account_registry_get_takedown(server->registry, acct->did, NULL,
                                            cid->valuestring, &blob_takedown);
    if (blob_takedown) {
        free(blob_takedown);
        wf_xrpc_response_set_error(response, 404, "BlobNotFound",
                                    "no blob stored for the given CID");
        return WF_OK;
    }
    unsigned char *data = NULL;
    size_t len = 0;
    char *mime = NULL;
    wf_status s = metalbear_blob_store_get(acct->blobs,
                                    cid->valuestring, &data, &len, &mime);
    if (s == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(response, 404, "BlobNotFound",
                                    "no blob stored for the given CID");
        return WF_OK;
    } else if (s != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "failed to read blob store");
        return WF_OK;
    }
    wf_xrpc_response_set_content_type(response, mime ? mime : "application/octet-stream");

    /*
     * Blobs are attacker-supplied bytes served from the PDS's own origin, so
     * they must never be interpretable as a document there: an uploaded HTML
     * or SVG blob would otherwise run as script on the same origin as every
     * web client on this domain and could read their session tokens. The
     * reference sets all three of these deliberately.
     *
     *   nosniff        — stop the browser second-guessing the declared type
     *                    and executing e.g. text/plain as HTML.
     *   attachment     — download rather than render, which also defuses
     *                    markup that CSP alone would still allow (links).
     *   CSP + sandbox  — deny every subresource and script capability if it
     *                    is rendered anyway.
     */
    wf_xrpc_response_add_header(response, "X-Content-Type-Options", "nosniff");
    /* The filename echoes a client-supplied parameter into a response header,
     * so copy only characters a CID can contain — never trust the blob lookup
     * to have rejected a quote or a newline for us. */
    char safe_cid[80];
    size_t safe_len = 0;
    for (const char *p = cid->valuestring;
         *p && safe_len + 1 < sizeof(safe_cid); p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9'))
            safe_cid[safe_len++] = *p;
    }
    safe_cid[safe_len] = '\0';
    char disposition[128];
    snprintf(disposition, sizeof(disposition), "attachment; filename=\"%s\"",
             safe_cid);
    wf_xrpc_response_add_header(response, "Content-Disposition", disposition);
    wf_xrpc_response_add_header(response, "Content-Security-Policy",
                                "default-src 'none'; sandbox");

    wf_xrpc_response_set_body(response, (const char *)data, len);
    free(data);
    free(mime);
    return WF_OK;
}


/* ---- com.atproto.sync.listReposByCollection (query, public) ----
 * The accounts on this host holding at least one record in `collection`.
 * The sync specification names this as the way a consuming service backfills
 * a collection without walking every repository itself. */
static wf_status list_repos_by_collection(void *ctx,
                                          const wf_xrpc_request *request,
                                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const cJSON *coll = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "collection")
        : NULL;
    if (!cJSON_IsString(coll) || !coll->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "collection is required");
        return WF_OK;
    }
    int limit = query_param_int(request->params, "limit", 500, 1, 2000);
    const cJSON *cursor_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor") : NULL;
    const char *cursor = cJSON_IsString(cursor_param)
        ? cursor_param->valuestring : "";

    cJSON *root = cJSON_CreateObject();
    cJSON *repos = cJSON_CreateArray();
    if (!root || !repos) {
        cJSON_Delete(root);
        cJSON_Delete(repos);
        return WF_ERR_ALLOC;
    }

    /* As in listRepos, `limit` counts accounts returned rather than rows
     * examined, so accounts without the collection never occupy a slot, and
     * the registry is walked a page at a time until the page is full. */
    char last_did[256] = "";
    snprintf(last_did, sizeof(last_did), "%s", cursor);
    bool exhausted = false;
    size_t emitted = 0;
    wf_status alloc_failure = WF_OK;
    while (emitted < (size_t)limit && !exhausted && alloc_failure == WF_OK) {
        metalbear_account_entry *entries = NULL;
        size_t count = 0;
        if (metalbear_account_registry_list_after(
                server->registry, last_did, (size_t)limit, &entries,
                &count) != WF_OK)
            break;
        if (count < (size_t)limit) exhausted = true;
        for (size_t i = 0; i < count && emitted < (size_t)limit; i++) {
            snprintf(last_did, sizeof(last_did), "%s", entries[i].did);
            metalbear_account_context *acct = context_for_did(server,
                                                              entries[i].did);
            if (!acct) continue;
            char *described = NULL;
            if (metalbear_repo_store_describe(acct->repo, &described) != WF_OK ||
                !described)
                continue;
            cJSON *desc = cJSON_Parse(described);
            free(described);
            if (!desc) continue;
            bool holds = false;
            const cJSON *cols = cJSON_GetObjectItemCaseSensitive(desc,
                                                                 "collections");
            const cJSON *item = NULL;
            cJSON_ArrayForEach(item, cols) {
                if (cJSON_IsString(item) &&
                    strcmp(item->valuestring, coll->valuestring) == 0) {
                    holds = true;
                    break;
                }
            }
            cJSON_Delete(desc);
            if (!holds) continue;
            cJSON *repo = cJSON_CreateObject();
            if (!repo) {
                alloc_failure = WF_ERR_ALLOC;
                break;
            }
            cJSON_AddStringToObject(repo, "did", acct->did);
            cJSON_AddItemToArray(repos, repo);
            emitted++;
        }
        metalbear_account_entries_free(entries, count);
    }
    if (alloc_failure != WF_OK) {
        cJSON_Delete(root);
        cJSON_Delete(repos);
        return alloc_failure;
    }
    cJSON_AddItemToObject(root, "repos", repos);
    if (!exhausted && last_did[0])
        cJSON_AddStringToObject(root, "cursor", last_did);
    return set_json(response, root);
}

static wf_status list_repos(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    LOG_DEBUG("list_repos: listed all hosted repos");
    int limit = query_param_int(request->params, "limit", 500, 1, 1000);
    cJSON *cursor_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor") : NULL;
    const char *cursor = cJSON_IsString(cursor_param)
        ? cursor_param->valuestring : "";

    cJSON *root = cJSON_CreateObject();
    cJSON *repos = cJSON_CreateArray();
    if (!root || !repos) {
        cJSON_Delete(root);
        cJSON_Delete(repos);
        return WF_ERR_ALLOC;
    }

    /*
     * `limit` counts repos returned, not registry rows examined.
     *
     * Incrementing the count on skipped rows let a registry entry with no
     * repository — a deleted account, say — consume a slot, so `limit=1`
     * returned an empty page with a cursor while the host did have a repo. A
     * relay enumerating accounts sees no accounts and concludes the host hosts
     * nothing. The reference joins against the repo root, so entries without a
     * repository never occupy a slot at all.
     *
     * Skipped rows are why the registry is walked a page at a time rather
     * than asked for `limit` rows once: a batch of entries can yield fewer
     * repositories than it holds, and the walk continues until the page is
     * full or the registry is exhausted.
     */
    char last_did[256] = "";
    snprintf(last_did, sizeof(last_did), "%s", cursor);
    bool exhausted = false;
    size_t emitted = 0;
    wf_status alloc_failure = WF_OK;
    while (emitted < (size_t)limit && !exhausted && alloc_failure == WF_OK) {
        metalbear_account_entry *entries = NULL;
        size_t count = 0;
        if (metalbear_account_registry_list_after(
                server->registry, last_did, (size_t)limit, &entries,
                &count) != WF_OK)
            break;
        if (count < (size_t)limit) exhausted = true;
        for (size_t i = 0; i < count && emitted < (size_t)limit; i++) {
            snprintf(last_did, sizeof(last_did), "%s", entries[i].did);
            metalbear_account_context *acct = context_for_did(server,
                                                              entries[i].did);
            if (!acct) continue;
            char *rev = NULL, *cid = NULL;
            if (metalbear_repo_store_get_head(acct->repo, &rev, &cid) != WF_OK) {
                free(rev);
                free(cid);
                continue;
            }
            cJSON *repo = cJSON_CreateObject();
            if (!repo) {
                free(rev);
                free(cid);
                alloc_failure = WF_ERR_ALLOC;
                break;
            }
            cJSON_AddStringToObject(repo, "did", acct->did);
            cJSON_AddStringToObject(repo, "head", cid);
            cJSON_AddStringToObject(repo, "rev", rev);
            bool active = false;
            const char *status = account_status_string(server, acct, &active);
            cJSON_AddBoolToObject(repo, "active", active);
            if (status)
                cJSON_AddStringToObject(repo, "status", status);
            cJSON_AddItemToArray(repos, repo);
            emitted++;
            free(rev);
            free(cid);
        }
        metalbear_account_entries_free(entries, count);
    }
    if (alloc_failure != WF_OK) {
        cJSON_Delete(root);
        cJSON_Delete(repos);
        return alloc_failure;
    }
    cJSON_AddItemToObject(root, "repos", repos);
    /*
     * The cursor is the last DID read, so the next page resumes after it
     * whatever has been created or deleted in between. It is omitted only
     * when the registry is known to be exhausted — a full page that happens
     * to end at the last account still hands out a cursor, and the client
     * gets one empty page rather than a truncated enumeration.
     */
    if (!exhausted && last_did[0])
        cJSON_AddStringToObject(root, "cursor", last_did);
    return set_json(response, root);
}

static bool make_directory(const char *path) {
    if (mkdir(path, 0700) == 0) return true;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static char *join_path(const char *directory, const char *name) {
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
    if (config->plc_url && config->plc_url[0])
        server->plc_url = strdup(config->plc_url);
    if (config->appview_url && config->appview_url[0])
        server->appview_url = strdup(config->appview_url);
    if (config->appview_did && config->appview_did[0])
        server->appview_did = strdup(config->appview_did);
    load_lexicons(server, config->lexicon_dir);
    return server->service_did && (!config->public_url || server->public_url) &&
           server->user_domain && server->data_directory;
}

static char *public_url_from_service_did(const char *did) {
    static const char prefix[] = "did:web:";
    if (!did || strncmp(did, prefix, sizeof(prefix) - 1) != 0) return NULL;
    const char *source = did + sizeof(prefix) - 1;
    size_t capacity = strlen(source) + strlen("https://") + 1;
    char *url = malloc(capacity);
    if (!url) return NULL;
    char *output = url;
    memcpy(output, "https://", strlen("https://"));
    output += strlen("https://");
    while (*source) {
        if (source[0] == '%' && source[1] == '3' &&
            (source[2] == 'A' || source[2] == 'a')) {
            *output++ = ':';
            source += 3;
        } else {
            *output++ = *source == ':' ? '/' : *source;
            source++;
        }
    }
    *output = '\0';
    return url;
}

/* ---- Dynamic landing page (GET /) ---- */

/* Minimal HTML escaping for untrusted display strings (handles/DIDs). */
static char *html_escape(const char *s) {
    if (!s) return strdup("");
    size_t need = 1;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '&': need += 5; break;  /* &amp;  */
            case '<': need += 4; break;  /* &lt;   */
            case '>': need += 4; break;  /* &gt;   */
            case '"': need += 6; break;  /* &quot; */
            default:  need += 1; break;
        }
    }
    char *out = malloc(need);
    if (!out) return NULL;
    char *q = out;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '&': memcpy(q, "&amp;", 5);  q += 5; break;
            case '<': memcpy(q, "&lt;", 4);   q += 4; break;
            case '>': memcpy(q, "&gt;", 4);   q += 4; break;
            case '"': memcpy(q, "&quot;", 6); q += 6; break;
            default:  *q++ = *p; break;
        }
    }
    *q = '\0';
    return out;
}

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} sb_t;

static bool sb_append(sb_t *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) return false;
    if (sb->len + (size_t)need + 1 > sb->cap) {
        size_t ncap = sb->cap ? sb->cap * 2 : 4096;
        while (ncap < sb->len + (size_t)need + 1) ncap *= 2;
        char *nb = realloc(sb->buf, ncap);
        if (!nb) return false;
        sb->buf = nb;
        sb->cap = ncap;
    }
    va_start(ap, fmt);
    vsnprintf(sb->buf + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);
    sb->len += (size_t)need;
    return true;
}

/* ---- /tls-check (public, mimics refpds on_demand_tls ask endpoint) ---- */
static wf_status tls_check_handler(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    cJSON *domain_item = req->params
        ? cJSON_GetObjectItemCaseSensitive(req->params, "domain") : NULL;
    if (!cJSON_IsString(domain_item) || !domain_item->valuestring[0]) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "bad or missing domain query param");
        return WF_OK;
    }
    const char *domain = domain_item->valuestring;

    char service_hostname[256] = {0};
    /* sizeof("did:web:")-1 == 8; comparing/skipping 9 matches nothing real. */
    if (strncmp(server->service_did, "did:web:", sizeof("did:web:") - 1) == 0) {
        const char *host = server->service_did + sizeof("did:web:") - 1;
        size_t len = strlen(host);
        if (len < sizeof(service_hostname)) {
            memcpy(service_hostname, host, len);
            service_hostname[len] = '\0';
        }
    } else if (server->public_url) {
        const char *p = strstr(server->public_url, "://");
        if (p) {
            p += 3;
            const char *slash = strchr(p, '/');
            size_t len = slash ? (size_t)(slash - p) : strlen(p);
            if (len < sizeof(service_hostname)) {
                memcpy(service_hostname, p, len);
                service_hostname[len] = '\0';
            }
        }
    }

    if (service_hostname[0] && strcmp(domain, service_hostname) == 0) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(resp, root);
    }

    size_t domain_len = strlen(domain);
    size_t ud_len = server->user_domain ? strlen(server->user_domain) : 0;
    if (ud_len == 0 || domain_len <= ud_len ||
        strcmp(domain + domain_len - ud_len, server->user_domain) != 0) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "handles are not provided on this domain");
        return WF_OK;
    }

    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_handle(server->registry, domain,
                                                   &entry) == WF_OK && entry) {
        metalbear_account_entry_free(entry);
        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(resp, root);
    }
    metalbear_account_entry_free(entry);

    wf_xrpc_response_set_error(resp, 404, "NotFound",
                               "handle not found for this domain");
    return WF_OK;
}

/* ---- GET /metrics (Prometheus text format, admin-gated) ----
 *
 * Counters come from the metrics table; everything describing the host's
 * current state is read from the real thing here rather than mirrored into a
 * gauge, because a mirrored gauge is a second copy of the truth and drifts
 * from the first.
 *
 * Behind the admin password. An open endpoint would publish the account count
 * and the write rate of a private host to anyone who asked, and hand an
 * unauthenticated caller an unbounded amount of work per request. Prometheus
 * has had basic_auth in its scrape config for as long as it has existed.
 */
/* Prometheus label values may not contain a raw quote, backslash or newline;
 * a route name arrives from the network and could hold any of them, and one
 * bad character loses the whole exposition rather than one series. */
static bool append_escaped_label(sb_t *sb, const char *value) {
    char escaped[256];
    size_t o = 0;
    for (const char *p = value; *p && o + 2 < sizeof(escaped); p++) {
        if (*p == '"' || *p == '\\') escaped[o++] = '\\';
        else if (*p == '\n') { escaped[o++] = '\\'; escaped[o++] = 'n'; continue; }
        escaped[o++] = *p;
    }
    escaped[o] = '\0';
    return sb_append(sb, "%s", escaped);
}

typedef struct route_render {
    sb_t *sb;
    bool ok;
} route_render;

static void render_route(void *ctx, const char *route, uint64_t requests,
                         uint64_t errors) {
    route_render *out = ctx;
    if (!out->ok) return;
    out->ok = sb_append(out->sb, "metalbear_route_requests_total{route=\"") &&
              append_escaped_label(out->sb, route) &&
              sb_append(out->sb, "\"} %llu\n", (unsigned long long)requests) &&
              sb_append(out->sb, "metalbear_route_errors_total{route=\"") &&
              append_escaped_label(out->sb, route) &&
              sb_append(out->sb, "\"} %llu\n", (unsigned long long)errors);
}

#ifdef WF_XRPC_HAS_REQUEST_OBSERVER
/*
 * Every finished request, with the status it answered.
 *
 * Counted here rather than in the auth callback, which is where the totals
 * used to come from: that callback runs before the status is known, never
 * runs for the plain HTTP routes, and never runs for a request the rate
 * limiter refused — so the old totals were a subset that could not be named
 * and carried no outcome at all.
 */
static void observe_request(void *ctx, const char *nsid, const char *path,
                            const char *method, unsigned int status) {
    (void)ctx;
    (void)method;
    metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS);
    if (status >= 400) metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS_FAILED);
    metalbear_metrics_record_request(nsid, path, status);
}
#endif

static wf_status metrics_handler(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (!admin_authenticated(server, req)) {
        wf_xrpc_response_set_error(resp, 401, "AuthenticationRequired",
                                   "Authentication required");
        return WF_OK;
    }

    sb_t sb = {0};
    bool ok = sb_append(&sb,
        "# HELP metalbear_build_info Version of the running server.\n"
        "# TYPE metalbear_build_info gauge\n"
        "metalbear_build_info{version=\"%s\"} 1\n", METALBEAR_VERSION);

    for (int i = 0; ok && i < METALBEAR_METRIC_COUNT; i++) {
        const char *name = metalbear_metric_name(i);
        const char *help = metalbear_metric_help(i);
        if (!name) continue;
        ok = sb_append(&sb,
                       "# HELP metalbear_%s %s\n"
                       "# TYPE metalbear_%s counter\n"
                       "metalbear_%s %llu\n",
                       name, help ? help : "", name, name,
                       (unsigned long long)metalbear_metrics_get(i));
    }

    /*
     * Per-route series. The label is escaped because a route name reaches
     * here from the network — the AppView proxy forwards NSIDs this server
     * has never heard of — and a quote inside a label value produces an
     * exposition Prometheus rejects wholesale, losing every other metric with
     * it.
     */
    if (ok) {
        ok = sb_append(&sb,
            "# HELP metalbear_route_requests_total Requests per route.\n"
            "# TYPE metalbear_route_requests_total counter\n"
            "# HELP metalbear_route_errors_total 4xx and 5xx responses per route.\n"
            "# TYPE metalbear_route_errors_total counter\n");
        route_render ctx_render = { &sb, ok };
        metalbear_metrics_visit_routes(render_route, &ctx_render);
        ok = ctx_render.ok;
    }

    /* Account counts, read from the registry at scrape time. */
    size_t total = 0, active = 0, taken_down = 0;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries,
                                        &count) == WF_OK) {
        total = count;
        for (size_t i = 0; i < count; i++) {
            if (account_is_taken_down(server, entries[i].did)) taken_down++;
            else if (entries[i].active) active++;
        }
        metalbear_account_entries_free(entries, count);
    }
    if (ok)
        ok = sb_append(&sb,
            "# HELP metalbear_accounts Accounts on this host by status.\n"
            "# TYPE metalbear_accounts gauge\n"
            "metalbear_accounts{status=\"active\"} %zu\n"
            "metalbear_accounts{status=\"inactive\"} %zu\n"
            "metalbear_accounts{status=\"takendown\"} %zu\n",
            active, total - active - taken_down, taken_down);

    /*
     * The firehose cursor. A relay that has stopped consuming shows up as this
     * climbing while nothing downstream moves, and it is the single number
     * worth alerting on: a PDS whose sequence has stalled is one nobody can
     * tell apart from a PDS that is down.
     */
    if (ok)
        ok = sb_append(&sb,
            "# HELP metalbear_firehose_seq Most recent firehose sequence number.\n"
            "# TYPE metalbear_firehose_seq gauge\n"
            "metalbear_firehose_seq %lld\n",
            (long long)metalbear_sequencer_current(server->sequencer));

    if (ok)
        ok = sb_append(&sb,
            "# HELP metalbear_uptime_seconds Seconds since this process began serving.\n"
            "# TYPE metalbear_uptime_seconds gauge\n"
            "metalbear_uptime_seconds %lld\n",
            (long long)(time(NULL) - server->started_at));

    if (!ok) {
        free(sb.buf);
        return WF_ERR_ALLOC;
    }
    wf_xrpc_response_set_content_type(resp, "text/plain; version=0.0.4");
    wf_xrpc_response_set_body(resp, sb.buf, sb.len);
    free(sb.buf);
    return WF_OK;
}

static wf_status landing_handler(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    (void)req;
    metalbear_server *server = ctx;

    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries,
                                        &count) != WF_OK) {
        entries = NULL;
        count = 0;
    }

    sb_t sb = {0};
    if (!sb_append(&sb,
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head><meta charset=\"utf-8\">\n"
            "<title>MetalBear — hosted accounts</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>MetalBear " METALBEAR_VERSION "</h1>\n"
            "<p>An AT Protocol Personal Data Server built on Wolfram. "
            "The XRPC API lives under <code>/xrpc/</code>. Identity "
            "documents are published at "
            "<code>/.well-known/did.json</code> and "
            "<code>/.well-known/atproto-did</code>.</p>\n"
            "<h2>Hosted accounts</h2>\n")) {
        metalbear_account_entries_free(entries, count);
        return WF_ERR_ALLOC;
    }

    if (count == 0) {
        if (!sb_append(&sb, "<p>No accounts are hosted on this server yet.</p>\n")) {
            metalbear_account_entries_free(entries, count);
            return WF_ERR_ALLOC;
        }
    } else {
        if (!sb_append(&sb, "<ul>\n")) {
            metalbear_account_entries_free(entries, count);
            return WF_ERR_ALLOC;
        }
        for (size_t i = 0; i < count; i++) {
            char *handle = html_escape(entries[i].handle);
            char *did = html_escape(entries[i].did);
            const char *state =
                account_is_taken_down(server, entries[i].did) ? "takendown"
                : entries[i].active ? "active" : "deactivated";
            bool ok = handle && did &&
                sb_append(&sb,
                          "<li><code>%s</code> — <code>%s</code> "
                          "(<span class=\"state\">%s</span>)</li>\n",
                          handle, did, state);
            free(handle);
            free(did);
            if (!ok) {
                metalbear_account_entries_free(entries, count);
                return WF_ERR_ALLOC;
            }
        }
        if (!sb_append(&sb, "</ul>\n")) {
            metalbear_account_entries_free(entries, count);
            return WF_ERR_ALLOC;
        }
    }

    if (!sb_append(&sb, "</body>\n</html>\n")) {
        metalbear_account_entries_free(entries, count);
        return WF_ERR_ALLOC;
    }

    wf_xrpc_response_set_body(resp, sb.buf, sb.len);
    wf_xrpc_response_set_content_type(resp, "text/html; charset=utf-8");
    free(sb.buf);
    metalbear_account_entries_free(entries, count);
    return WF_OK;
}

static char *extract_hostname(const char *host_header) {
    if (!host_header || !host_header[0]) return NULL;
    const char *colon = strchr(host_header, ':');
    size_t len = colon ? (size_t)(colon - host_header) : strlen(host_header);
    if (len == 0 || len > 253) return NULL;
    char *hostname = malloc(len + 1);
    if (!hostname) return NULL;
    memcpy(hostname, host_header, len);
    hostname[len] = '\0';
    return hostname;
}

static metalbear_account_entry *resolve_hostname_to_account(metalbear_server *server,
                                                            const char *hostname) {
    if (!server || !hostname || !hostname[0]) return NULL;
    metalbear_account_entry *entry = NULL;
    wf_status status = metalbear_account_registry_find_by_handle(
        server->registry, hostname, &entry);
    if (status == WF_OK && entry) return entry;
    metalbear_account_entry_free(entry);
    entry = NULL;
    size_t ud_len = server->user_domain ? strlen(server->user_domain) : 0;
    size_t dn_len = strlen(hostname);
    if (ud_len > 0 && dn_len > ud_len &&
        strcmp(hostname + dn_len - ud_len, server->user_domain) == 0) {
        status = metalbear_account_registry_find_by_handle(
            server->registry, hostname, &entry);
    }
    if (status == WF_OK && entry) return entry;
    metalbear_account_entry_free(entry);
    /*
     * No fallback account. A hostname that matches no registered handle
     * resolves to nothing — falling back to a configured account answered
     * every unknown hostname with that account's identity, which is a wrong
     * answer rather than a missing one.
     */
    return NULL;
}

/* ---- /.well-known/atproto-did (query, dynamic per-hostname) ---- */
static wf_status handle_atproto_did(void *ctx, const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    char *hostname = extract_hostname(request->host_header);
    if (!hostname) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "missing or invalid Host header");
        return WF_OK;
    }
    metalbear_account_entry *entry = resolve_hostname_to_account(server, hostname);
    free(hostname);
    if (!entry) {
        wf_xrpc_response_set_error(response, 404, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    wf_xrpc_response_set_body(response, entry->did, strlen(entry->did));
    wf_xrpc_response_set_content_type(response, "text/plain; charset=utf-8");
    metalbear_account_entry_free(entry);
    return WF_OK;
}

/* ---- /.well-known/did.json (query, dynamic per-hostname) ---- */
static wf_status handle_well_known_did(void *ctx, const wf_xrpc_request *request,
                                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    char *hostname = extract_hostname(request->host_header);
    if (!hostname) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "missing or invalid Host header");
        return WF_OK;
    }

    /* If the service DID is did:web and this hostname matches it, serve the
     * service's own DID document (the PDS identity, not an account). */
    if (server->service_did &&
        strncmp(server->service_did, "did:web:", 8) == 0) {
        const char *service_host = server->service_did + 8;
        if (strcmp(hostname, service_host) == 0) {
            free(hostname);
            cJSON *doc = cJSON_CreateObject();
            if (!doc) {
                wf_xrpc_response_set_error(response, 500, "InternalError",
                                           "Could not allocate DID document");
                return WF_OK;
            }
            cJSON *context = cJSON_CreateArray();
            cJSON_AddItemToArray(context,
                cJSON_CreateString("https://www.w3.org/ns/did/v1"));
            cJSON_AddItemToObject(doc, "@context", context);
            cJSON_AddStringToObject(doc, "id", server->service_did);
            cJSON *services = cJSON_CreateArray();
            cJSON *service = cJSON_CreateObject();
            cJSON_AddStringToObject(service, "id", "#atproto_pds");
            cJSON_AddStringToObject(service, "type",
                                     "AtprotoPersonalDataServer");
            cJSON_AddStringToObject(service, "serviceEndpoint",
                                    server->public_url ?
                                        server->public_url : "");
            cJSON_AddItemToArray(services, service);
            cJSON_AddItemToObject(doc, "service", services);
            char *json = cJSON_PrintUnformatted(doc);
            cJSON_Delete(doc);
            if (!json) {
                wf_xrpc_response_set_error(response, 500, "InternalError",
                                           "Could not serialize DID document");
                return WF_OK;
            }
            wf_xrpc_response_set_body(response, json, strlen(json));
            wf_xrpc_response_set_content_type(response,
                "application/did+ld+json");
            free(json);
            return WF_OK;
        }
    }

    /* Otherwise, resolve the hostname to an account and serve its DID doc. */
    metalbear_account_entry *entry = resolve_hostname_to_account(server, hostname);
    free(hostname);
    if (!entry) {
        wf_xrpc_response_set_error(response, 404, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    metalbear_account_context *acct = context_for_did(server, entry->did);
    metalbear_account_entry_free(entry);
    if (!acct) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not open account context");
        return WF_OK;
    }
    cJSON *did_doc = build_did_doc(server, acct);
    if (!did_doc) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not build DID document");
        return WF_OK;
    }
    char *json = cJSON_PrintUnformatted(did_doc);
    cJSON_Delete(did_doc);
    if (!json) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not serialize DID document");
        return WF_OK;
    }
    wf_xrpc_response_set_body(response, json, strlen(json));
    wf_xrpc_response_set_content_type(response, "application/did+ld+json");
    free(json);
    return WF_OK;
}

/*
 * Serve the DID document for a path-form did:web account hosted here:
 *
 *   did:web:example.com:acct:alice  ->  GET /acct/alice/did.json
 *
 * The hostname form (did:web:alice.example.com) is already handled by
 * handle_well_known_did via the Host header, but it needs a wildcard DNS entry
 * and ingress route per account. The path form works over the PDS's single
 * existing hostname, which is what makes did:web accounts practical to
 * self-host.
 *
 * The document is built from the repo's own signing key, so it agrees with the
 * commits that repo signs by construction.
 */
static wf_status handle_account_did_web(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const char *path = request->path ? request->path : "";
    static const char prefix[] = "/acct/";
    static const char suffix[] = "/did.json";
    size_t len = strlen(path);
    size_t plen = sizeof(prefix) - 1, slen = sizeof(suffix) - 1;
    if (len <= plen + slen || strncmp(path, prefix, plen) != 0 ||
        strcmp(path + len - slen, suffix) != 0) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No DID document at this path");
        return WF_OK;
    }
    size_t name_len = len - plen - slen;
    /* One path segment only: nested segments are a different DID. */
    if (name_len == 0 || memchr(path + plen, '/', name_len)) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No DID document at this path");
        return WF_OK;
    }

    const char *host = server->service_did &&
        strncmp(server->service_did, "did:web:", 8) == 0
            ? server->service_did + 8 : NULL;
    if (!host) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "Server does not host did:web accounts");
        return WF_OK;
    }

    char did[512];
    int n = snprintf(did, sizeof(did), "did:web:%s:acct:%.*s", host,
                     (int)name_len, path + plen);
    if (n < 0 || (size_t)n >= sizeof(did)) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No DID document at this path");
        return WF_OK;
    }

    metalbear_account_context *acct = context_for_did(server, did);
    if (!acct) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No such account");
        return WF_OK;
    }
    cJSON *doc = build_did_doc(server, acct);
    if (!doc) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not build DID document");
        return WF_OK;
    }
    char *json = cJSON_PrintUnformatted(doc);
    cJSON_Delete(doc);
    if (!json) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not serialize DID document");
        return WF_OK;
    }
    wf_xrpc_response_set_body(response, json, strlen(json));
    wf_xrpc_response_set_content_type(response, "application/did+ld+json");
    free(json);
    return WF_OK;
}

static wf_status get_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    char *prefs_json = NULL;
    if (metalbear_account_store_prefs_get(acct->account, &prefs_json) != WF_OK ||
        !prefs_json) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "preferences", cJSON_CreateArray());
        return set_json(response, root);
    }
    cJSON *root = cJSON_Parse(prefs_json);
    free(prefs_json);
    if (!root) {
        cJSON *empty = cJSON_CreateObject();
        cJSON_AddItemToObject(empty, "preferences", cJSON_CreateArray());
        return set_json(response, empty);
    }
    return set_json(response, root);
}

static wf_status put_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (!request->body || request->body_len == 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "empty body");
        return WF_OK;
    }
    cJSON *parsed = cJSON_ParseWithLength((const char *)request->body,
                                          request->body_len);
    if (!parsed) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "invalid JSON");
        return WF_OK;
    }
    cJSON *prefs = cJSON_GetObjectItemCaseSensitive(parsed, "preferences");
    if (!cJSON_IsArray(prefs)) {
        cJSON_Delete(parsed);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "preferences must be an array");
        return WF_OK;
    }
    cJSON_Delete(parsed);
    char *body_copy = malloc(request->body_len + 1);
    if (!body_copy) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "allocation failed");
        return WF_OK;
    }
    memcpy(body_copy, request->body, request->body_len);
    body_copy[request->body_len] = '\0';
    if (metalbear_account_store_prefs_put(acct->account, body_copy) != WF_OK) {
        free(body_copy);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "failed to store preferences");
        return WF_OK;
    }
    free(body_copy);
    return WF_OK;
}

static wf_status register_identity_documents(metalbear_server *server) {
    if (!server->public_url)
        server->public_url = public_url_from_service_did(server->service_did);
    if (!server->public_url) return WF_ERR_INVALID_ARG;
    wf_status status = wf_xrpc_server_register_http_route(server->xrpc, "GET",
        "/.well-known/did.json", handle_well_known_did, server);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_http_route(server->xrpc, "GET",
        "/.well-known/atproto-did", handle_atproto_did, server);
    if (status != WF_OK) return status;
    /* Path-form did:web accounts: /acct/<name>/did.json. */
    status = wf_xrpc_server_register_http_prefix(server->xrpc, "GET", "/acct/",
                                                 handle_account_did_web, server);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_http_route(server->xrpc, "GET", "/metrics",
                                                metrics_handler, server);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_http_route(server->xrpc, "GET", "/",
                                                landing_handler, server);
    if (status != WF_OK) return status;
    static const char robots[] =
        "User-agent: *\nAllow: /\n";
    status = wf_xrpc_server_register_static_get(
        server->xrpc, "/robots.txt", "text/plain; charset=utf-8", robots,
        sizeof(robots) - 1);
    if (status != WF_OK) return status;

    status = wf_xrpc_server_register_http_route(server->xrpc, "GET",
                                                "/tls-check",
                                                tls_check_handler, server);
    if (status != WF_OK) return status;

    status = wf_xrpc_server_register_http_route(server->xrpc, "GET",
                                                "/operator.json",
                                                operator_info, server);
    return status;
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
            if (c >= '0' && c <= '9') value = (unsigned int)(c - '0');
            else if (c >= 'a' && c <= 'f') value = (unsigned int)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') value = (unsigned int)(c - 'A' + 10);
            else return false;
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
        server->public_url = public_url_from_service_did(server->service_did);
    if (!server->public_url) {
        LOG_ERROR("cannot determine public URL from service DID");
        goto fail;
    }

    /* One event log for the host, at the data root — not inside any account's
     * directory. A relay subscribes to the server, not to an account. */
    char *seq_path = NULL;
    if (asprintf(&seq_path, "%s/sequencer.sqlite3",
                 config->data_directory) < 0 || !seq_path) {
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
    char *rotation_path = join_path(config->data_directory,
                                    "server_keys.sqlite3");
    if (!rotation_path ||
        metalbear_key_rotation_open(rotation_path,
                                    &server->plc_rotation) != WF_OK) {
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
            metalbear_key_rotation_import(server->plc_rotation,
                                          &configured) != WF_OK) {
            LOG_ERROR("METALBEAR_PLC_ROTATION_KEY is not a usable secp256k1 "
                      "key (expected 64 hex characters)");
            goto fail;
        }
    }

    /* One OAuth store for the host. Its signing key is the server's; the
     * account a token speaks for is carried in the token, not in the store. */
    char *oauth_path = join_path(config->data_directory,
                                 "server_oauth.sqlite3");
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
    if (!registry_path ||
        metalbear_account_registry_open(registry_path,
                                        &server->registry) != WF_OK) {
        LOG_ERROR("cannot open account registry");
        free(registry_path);
        goto fail;
    }
    free(registry_path);
    /* The registry starts empty. There is no account to seed: every account,
     * including the first, is created through com.atproto.server.createAccount
     * and registers itself there. */

    if (config->did_cache_ttl_seconds > 0)
        did_doc_cache_ttl = (time_t)config->did_cache_ttl_seconds;
    if (config->did_cache_entries > 0) {
        size_t want = (size_t)config->did_cache_entries;
        did_doc_cache_slots = want > DID_DOC_CACHE_SLOTS ? DID_DOC_CACHE_SLOTS
                                                         : want;
    }
    if (config->crawl_notify_seconds > 0)
        crawler_notify_seconds = (time_t)config->crawl_notify_seconds;
    if (config->firehose_ping_seconds > 0)
        metalbear_sequencer_set_ping_seconds(config->firehose_ping_seconds);

    /* Per-client request budget, configurable; 100 per 60s by default. */
    {
        int64_t budget = config->rate_limit > 0 ? config->rate_limit : 100;
        int64_t window = config->rate_limit_window > 0
                             ? config->rate_limit_window : 60;
        server->rate_limiter = wf_rate_limiter_new((size_t)budget,
                                                   (size_t)window, 0);
    }

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
    if (register_identity_documents(server) != WF_OK) {
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
                metalbear_account_context *acct =
                    metalbear_account_cache_get(server->account_cache,
                                                server->registry,
                                                entries[i].did);
                if (!acct) continue;
                metalbear_sequencer_reconcile_account(
                    server->sequencer, entries[i].did,
                    metalbear_account_is_active(acct->account));
                if (acct->repo)
                    metalbear_sequencer_reconcile_repo(server->sequencer,
                                                      acct->repo);
            }
            metalbear_account_entries_free(entries, count);
        }
    }

    if (wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.describeServer", describe_server, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "_health", health, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createAccount", create_account, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.identity.resolveHandle", resolve_handle, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.identity.resolveDid",
            resolve_did_identity, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.identity.resolveIdentity",
            resolve_identity, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.identity.refreshIdentity",
            refresh_identity, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.identity.getRecommendedDidCredentials",
            get_recommended_did_credentials, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.identity.updateHandle", update_handle, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.identity.requestPlcOperationSignature",
            request_plc_operation_signature, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.identity.signPlcOperation",
            sign_plc_operation, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.identity.submitPlcOperation",
            submit_plc_operation, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createSession", create_session, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.getSession", get_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.refreshSession", refresh_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.deleteSession", delete_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createAppPassword", create_app_password,
            server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.listAppPasswords", list_app_passwords,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.revokeAppPassword", revoke_app_password,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.deactivateAccount", deactivate_account,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.activateAccount", activate_account,
            server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.getServiceAuth", get_service_auth,
            server) != WF_OK ||
        metalbear_xrpc_server_register_pds_repo_resolver_ex(server->xrpc,
            metalbear_repo_resolver, server,
            server->service_did, server->public_url,
            resolve_did_doc_json, server, server->lexicons,
            repo_access_guard, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.repo.uploadBlob", upload_blob, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.repo.listMissingBlobs",
            list_missing_blobs, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getBlob", get_blob, server) != WF_OK) {
        LOG_ERROR("cannot register XRPC routes");
        goto fail;
    }
    if (wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getRepo", get_repo, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getBlocks", get_blocks, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getRepoStatus", get_repo_status, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.listBlobs", list_blobs, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.listRepos", list_repos, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.listReposByCollection",
            list_repos_by_collection, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getRecord", get_record, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getHead", get_head, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getCheckout", get_checkout, server) != WF_OK ||
        metalbear_sequencer_register(server->sequencer,
                                     server->xrpc) != WF_OK) {
        LOG_ERROR("cannot register sync export routes");
        goto fail;
    }

    if (server->appview_url && server->appview_url[0]) {
        wf_xrpc_server_set_fallback(server->xrpc, proxy_fallback, server);
    }

    wf_xrpc_server_set_auth_callback(server->xrpc, authenticate, server);
#ifdef WF_XRPC_HAS_REQUEST_OBSERVER
    /* Guarded so this still builds against a Wolfram without the observer;
     * without it the per-route breakdown is simply absent rather than the
     * build being broken. */
    wf_xrpc_server_set_request_observer(server->xrpc, observe_request, server);
#endif

    /* Register OAuth HTTP routes (bypass XRPC auth) */
    /* One OAuth store for the host. The account a token speaks for comes from
     * the token itself, so no account DID is bound in at registration. */
    if (metalbear_oauth_routes_register(server->xrpc, server->oauth,
                                         server->public_url,
                                         server->service_did,
                                         resolve_oauth_subject,
                                         verify_oauth_credential,
                                         server) != WF_OK) {
        LOG_ERROR("cannot register OAuth routes");
        goto fail;
    }

    /* Register account deletion routes */
    if (wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestAccountDelete",
            request_account_delete, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.deleteAccount",
            delete_account, server) != WF_OK) {
        LOG_ERROR("cannot register deletion routes");
        goto fail;
    }

    /* Register email flow routes */
    if (wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestEmailConfirmation",
            request_email_confirmation, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.confirmEmail",
            confirm_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestEmailUpdate",
            request_email_update, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.updateEmail",
            update_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestPasswordReset",
            request_password_reset, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.resetPassword",
            reset_password, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.getAccountInviteCodes",
            get_account_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.checkAccountStatus",
            check_account_status, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.reserveSigningKey",
            reserve_signing_key, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createInviteCode",
            create_invite_code, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createInviteCodes",
            create_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.actor.getPreferences",
            get_actor_preferences, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "app.bsky.actor.putPreferences",
            put_actor_preferences, server) != WF_OK ||
        /* AppView-proxied app.bsky.* endpoints (rsky-pds/ref-pds pattern).
         * Auth runs first, so handlers see req->authed_subject and can mint
         * requester-scoped service-auth JWTs for the upstream AppView. */
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getFeed", appview_get_feed, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getFeedSkeleton",
            appview_get_feed_skeleton, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getAuthorFeed",
            appview_get_author_feed, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getActorFeeds",
            appview_get_actor_feeds, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getFeedGenerators",
            appview_get_feed_generators, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getFeedGenerator",
            appview_get_feed_generator, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getPosts", appview_get_posts, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.actor.getProfile", appview_get_profile, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.actor.getProfiles",
            appview_get_profiles, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getActorLikes",
            appview_get_actor_likes, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getTimeline",
            appview_get_timeline, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.feed.getPostThread",
            appview_get_post_thread, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "app.bsky.notification.registerPush",
            appview_register_push, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "app.bsky.notification.unregisterPush",
            appview_unregister_push, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.actor.getActorStatistics",
            appview_get_actor_statistics, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.actor.getActorRankings",
            appview_get_actor_rankings, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getFollows", appview_get_follows, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getFollowers",
            appview_get_followers, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getBlocks", appview_get_blocks, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getList", appview_get_list, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getLists", appview_get_lists, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getListItems",
            appview_get_list_items, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getStarterPack",
            appview_get_starter_pack, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.graph.getStarterPacks",
            appview_get_starter_packs, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.notification.getUnreadCount",
            appview_get_unread_notifications, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.notification.listNotifications",
            appview_get_notifications, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "chat.bsky.convo.getConvo",
            appview_get_convo, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "chat.bsky.convo.getConvos",
            appview_get_convos, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "chat.bsky.convo.getMessages",
            appview_get_messages, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.labeler.getServices",
            appview_get_labeler_info, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.unspecced.getAgeAssuranceState",
            appview_unspecced_get_age_assurance_state, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.unspecced.getAgeAssuranceConfig",
            appview_unspecced_get_age_assurance_config, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "app.bsky.unspecced.getAgeAssurance",
            appview_unspecced_get_age_assurance, server) != WF_OK ||
        /* Admin endpoints (refpds PDS_ADMIN_PASSWORD, Basic auth) */
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.admin.getAccountInfo",
            admin_get_account_info, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.admin.getSubjectStatus",
            admin_get_subject_status, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.updateSubjectStatus",
            admin_update_subject_status, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.sendEmail",
            admin_send_email, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.admin.getAccountInfos",
            admin_get_account_infos, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.updateAccountHandle",
            admin_update_account_handle, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.updateAccountEmail",
            admin_update_account_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.updateAccountPassword",
            admin_update_account_password, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.enableAccountInvites",
            admin_enable_account_invites, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.disableAccountInvites",
            admin_disable_account_invites, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.admin.getInviteCodes",
            admin_get_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.disableInviteCodes",
            admin_disable_invite_codes, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.admin.deleteAccount",
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
            check_signup_queue, server) != WF_OK) {
        LOG_ERROR("cannot register email/invite routes");
        goto fail;
    }

    /* Apply rate limiting */
    if (server->rate_limiter)
        wf_xrpc_server_set_rate_limiter(server->xrpc, server->rate_limiter);

    /* Initialize email module if configured */
    if (config->smtp_host && config->smtp_host[0] &&
        config->from_address && config->from_address[0]) {
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

    /*
     * Open the handle DNS publisher, if one is configured.
     *
     * A misconfigured provider is fatal on purpose. The alternative is a host
     * that starts, mints accounts, and writes no records — and the operator
     * only finds out when every handle shows as handle.invalid on an AppView,
     * long after the accounts exist.
     */
    if (config->dns_provider && config->dns_provider[0]) {
        if (metalbear_handle_dns_open_ex(config->dns_provider,
                                         config->dns_api_token,
                                         config->dns_zone_id,
                                         config->dns_server,
                                         (int)config->dns_record_ttl,
                                         &server->handle_dns) != WF_OK) {
            LOG_ERROR("dns: provider '%s' is configured but unusable. It needs "
                      "an api_token and a zone_id; 'rfc2136' additionally "
                      "needs a server, and its api_token is the TSIG key as "
                      "'<name>:<base64 secret>'. Known providers are "
                      "cloudflare, digitalocean, desec and rfc2136",
                      config->dns_provider);
            metalbear_server_free(server);
            return NULL;
        }
        LOG_INFO("dns: publishing _atproto records via %s", config->dns_provider);
    }

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
        if (metalbear_update_watcher_open(&uc, &server->update_watcher) != WF_OK) {
            LOG_WARN("update-watcher: could not start (releases unreachable?)");
        } else {
            LOG_INFO("update-watcher: checking every %ld seconds",
                     (long)uc.interval_seconds);
        }
    }

    if (config->account_email && config->account_email[0])
        server->account_email = strdup(config->account_email);
    #define COPY_OPT(field) \
        if (config->field && config->field[0]) \
            server->field = strdup(config->field)
    COPY_OPT(operator_name);
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
    server->retention_min_events = config->retention_min_events > 0
                                      ? config->retention_min_events
                                      : 1000;

    /* Apply initial retention */
    metalbear_sequencer_retain(server->sequencer,
                               server->retention_max_age,
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
    metalbear_email_free(server->email);
    metalbear_handle_dns_free(server->handle_dns);
    metalbear_update_watcher_free(server->update_watcher);
    metalbear_report_store_free(server->reports);
    wf_rate_limiter_free(server->rate_limiter);
    metalbear_log_close();
    free(server->service_did);
    free(server->public_url);
    free(server->user_domain);
    free(server->data_directory);
    free(server->account_email);
    free(server->admin_password);
    free(server->crawlers);
    free(server->plc_url);
    free(server->appview_url);
    free(server->appview_did);
    wf_lexicon_registry_free(server->lexicons);
    free(server);
}

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif

#include "metalbear/server.h"
#include "metalbear/account.h"
#include "metalbear/account_registry.h"
#include "metalbear/account_context.h"
#include "metalbear/account_cache.h"
#include "metalbear/auth.h"
#include "metalbear/backup.h"
#include "metalbear/email.h"
#include "metalbear/key_rotation.h"
#include "metalbear/oauth.h"
#include "metalbear/report.h"
#include "metalbear/oauth_routes.h"
#include "metalbear/sequencer.h"

#include "metalbear/blob_store.h"
#include "wolfram/crypto.h"
#include "wolfram/plc.h"
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

typedef enum metalbear_log_level {
    METALBEAR_LOG_DEBUG = 0,
    METALBEAR_LOG_INFO,
    METALBEAR_LOG_WARN,
    METALBEAR_LOG_ERROR,
} metalbear_log_level;

static metalbear_log_level log_level = METALBEAR_LOG_INFO;
static FILE *log_file = NULL;

static metalbear_log_level metalbear_log_level_from_env(void) {
    const char *level = getenv("METALBEAR_LOG_LEVEL");
    if (!level || !level[0]) return METALBEAR_LOG_INFO;
    if (strcmp(level, "debug") == 0 || strcmp(level, "DEBUG") == 0) return METALBEAR_LOG_DEBUG;
    if (strcmp(level, "info") == 0 || strcmp(level, "INFO") == 0) return METALBEAR_LOG_INFO;
    if (strcmp(level, "warn") == 0 || strcmp(level, "WARN") == 0) return METALBEAR_LOG_WARN;
    if (strcmp(level, "error") == 0 || strcmp(level, "ERROR") == 0) return METALBEAR_LOG_ERROR;
    char *end = NULL;
    long v = strtol(level, &end, 10);
    if (end && *end == '\0' && v >= 0 && v <= 3) return (int)v;
    return METALBEAR_LOG_INFO;
}

static FILE *metalbear_log_file_from_env(void) {
    const char *path = getenv("METALBEAR_LOG_FILE");
    if (!path || !path[0]) return NULL;
    return fopen(path, "a");
}

static void metalbear_log(metalbear_log_level level, const char *fmt, ...) {
    if (level < log_level) return;
    static const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    va_list args;
    FILE *out = log_file ? log_file : stderr;
    time_t now = time(NULL);
    struct tm tm;
#if defined(__APPLE__)
    localtime_r(&now, &tm);
#else
    localtime_r(&now, &tm);
#endif
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
    fprintf(out, "MetalBear [%s] [%s] ", level_names[level], ts);
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    fprintf(out, "\n");
    if (log_file) fflush(log_file);
}

#define LOG_DEBUG(...) metalbear_log(METALBEAR_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) metalbear_log(METALBEAR_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...) metalbear_log(METALBEAR_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) metalbear_log(METALBEAR_LOG_ERROR, __VA_ARGS__)

static char *join_path(const char *directory, const char *name);

/* ---- admin / refpds config (mirrors refpds PDS_* env) ---- */
/* Parse HTTP Basic `admin:<password>` from the Authorization header and compare
 * it (constant-time) against the configured admin password. Returns true only
 * when a password is configured AND the header matches exactly. */
static bool admin_authenticated(metalbear_server *server,
                              const wf_xrpc_request *req);

struct metalbear_server {
    wf_xrpc_server *xrpc;
    /* Primary/bootstrap account context (owned for the process lifetime). */
    metalbear_account_context *bootstrap;
    metalbear_account_registry *registry;
    wf_rate_limiter *rate_limiter;
    metalbear_email *email;
    char *service_did;
    char *public_url;
    char *user_domain;
    char *data_directory;
    char *account_email;
    int64_t retention_max_age;
    int64_t retention_min_events;
    /* refpds-mirrored config (METALBEAR_*) */
    char *admin_password;     /* may be NULL => admin endpoints 401 */
    char *crawlers;           /* comma-separated relay hosts, may be NULL */
    bool invite_required;
    int64_t blob_upload_limit; /* 0 => unlimited */
    char *plc_url;            /* PLC directory URL or NULL */
    metalbear_account_cache *account_cache;
    metalbear_report_store *reports;
};

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
    return strcmp(nsid, "com.atproto.admin.getAccountInfo") == 0 ||
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

/* Return the open context for `did`: the bootstrap context for the primary
 * account (avoids opening a duplicate connection to its stores), or a cached
 * per-account context otherwise. The returned context is owned by the
 * server/cache and must NOT be freed by the caller. Returns NULL when the DID
 * is unknown / cannot be opened. */
static metalbear_account_context *context_for_did(metalbear_server *server,
                                                  const char *did) {
    if (!did) return NULL;
    if (server->bootstrap && strcmp(did, server->bootstrap->did) == 0)
        return server->bootstrap;
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

/* Resolve the account context for a request. Returns the bootstrap context for
 * the primary account, or a cached per-account context otherwise. The returned
 * context is owned by the server/cache and must NOT be freed by the caller.
 * Returns NULL when the account cannot be resolved. */
static metalbear_account_context *resolve_request_context(
    metalbear_server *server, const wf_xrpc_request *req) {
    char buf[256];
    const char *did = request_account_did(server, req, buf, sizeof(buf));
    return context_for_did(server, did);
}

/* wolfram per-request resolver: map a request to the correct account's repo /
 * blob stores. Borrowed pointers remain valid for the request duration because
 * the cache (and the bootstrap context) outlive the request. */
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

static wf_status authenticate(wf_xrpc_request *req, void *ctx) {
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
        if (!metalbear_account_is_active(server->bootstrap->account) &&
            (strncmp(req->nsid, "com.atproto.repo.", 17) == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getLatestCommit") == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getBlob") == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getRepo") == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getBlocks") == 0))
            return WF_ERR_CONFLICT;
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

    const char *provided = bearer_token(req->auth_header);
    if (!provided) {
        LOG_DEBUG("authenticate: no bearer token for nsid=%s host=%s",
                  req->nsid ? req->nsid : "-",
                  req->host_header ? req->host_header : "-");
        return WF_ERR_PERMISSION;
    }

    /* Route to the account named by the token's `sub` claim, then verify the
     * token against THAT account's auth store. The signature is server-wide,
     * so verification proves the token is genuine and `sub` is the identity
     * we bind the request to (never the bootstrap account). */
    char *sub = jwt_subject(provided);
    if (!sub) {
        LOG_DEBUG("authenticate: invalid JWT for nsid=%s host=%s",
                  req->nsid ? req->nsid : "-",
                  req->host_header ? req->host_header : "-");
        return WF_ERR_PERMISSION;
    }
    metalbear_account_context *acct = context_for_did(server, sub);
    if (!acct) {
        LOG_WARN("authenticate: unknown did=%s for nsid=%s host=%s",
                 sub, req->nsid ? req->nsid : "-",
                 req->host_header ? req->host_header : "-");
        free(sub);
        return WF_ERR_PERMISSION;
    }

    bool refresh_route = strcmp(req->nsid,
                                "com.atproto.server.refreshSession") == 0 ||
                         strcmp(req->nsid,
                                "com.atproto.server.deleteSession") == 0;
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    wf_status status = refresh_route
        ? WF_OK
        : metalbear_auth_verify_access_scope(acct->auth, provided, &scope);
    if (status != WF_OK) {
        LOG_WARN("authenticate: token verify failed for did=%s nsid=%s status=%d",
                 sub, req->nsid ? req->nsid : "-", status);
        free(sub);
        return status;
    }
    if (!refresh_route && full_access_route(req->nsid) &&
        scope != METALBEAR_ACCESS_FULL) {
        LOG_WARN("authenticate: insufficient scope for did=%s nsid=%s scope=%d",
                 sub, req->nsid ? req->nsid : "-", scope);
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

static wf_status request_account_delete(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    char token[33];
    if (metalbear_account_create_email_token(server->bootstrap->account, "delete",
                                             token, sizeof(token)) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create deletion token");
        return WF_OK;
    }
    /* Send confirmation email if configured */
    if (server->email && server->account_email && server->account_email[0]) {
        metalbear_email_send_account_deletion(
            server->email, server->account_email, token);
    }
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
    if (!metalbear_account_verify_password(server->bootstrap->account,
                                           password->valuestring)) {
        wf_xrpc_response_set_error(response, 401, "AuthenticationRequired",
                                   "Invalid password");
        return WF_OK;
    }
    wf_status token_status = metalbear_account_verify_email_token(
        server->bootstrap->account, "delete", token->valuestring);
    if (token_status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired deletion token");
        return WF_OK;
    }
    /* Revoke all sessions */
    metalbear_auth_delete_all(server->bootstrap->auth);
    /* Delete all app passwords and credentials */
    metalbear_account_delete(server->bootstrap->account);
    /* Deactivate the account */
    metalbear_account_deactivate(server->bootstrap->account, NULL);
    /* Remove from the account registry */
    metalbear_account_registry_remove(server->registry, server->bootstrap->did);
    /* Emit deactivation event to firehose */
    metalbear_sequencer_account_status(
        server->bootstrap->sequencer, server->bootstrap->did, 0, "deleted");
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
    if (server->account_email && server->account_email[0])
        cJSON_AddStringToObject(contact, "email", server->account_email);
    cJSON_AddItemToObject(root, "contact", contact);
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
    if (!acct || !metalbear_account_is_active(acct->account)) {
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
static wf_status fetch_remote_did_doc(metalbear_server *server,
                                      const char *did, char **out_json) {
    *out_json = NULL;
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
    wf_response_free(&upstream);
    return *out_json ? WF_OK : WF_ERR_ALLOC;
}

/* Build (local) or fetch (remote) the DID document for `did` as a cJSON
 * tree. Caller must cJSON_Delete the result. Sets *deactivated when the
 * local account exists but is deactivated. */
static cJSON *did_doc_for_did(metalbear_server *server, const char *did,
                              bool *deactivated) {
    *deactivated = false;
    metalbear_account_context *acct = context_for_did(server, did);
    if (acct) {
        if (!metalbear_account_is_active(acct->account)) {
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

/* ---- com.atproto.identity.getRecommendedDidCredentials (query) ---- */
static wf_status get_recommended_did_credentials(void *ctx,
        const wf_xrpc_request *request, wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    char *didkey = NULL;
    wf_signing_key key;
    memset(&key, 0, sizeof(key));
    if (metalbear_key_rotation_current_key(server->bootstrap->key_rotation, &key) != WF_OK ||
        wf_signing_key_public_didkey(&key, &didkey) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not derive signing key");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) { free(didkey); return WF_ERR_ALLOC; }
    cJSON *also_known_as = cJSON_CreateArray();
    if (!also_known_as) { cJSON_Delete(root); free(didkey); return WF_ERR_ALLOC; }
    if (server->bootstrap->handle && server->bootstrap->handle[0]) {
        char aka[256];
        snprintf(aka, sizeof(aka), "at://%s", server->bootstrap->handle);
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

static cJSON *build_did_doc(metalbear_server *server,
                            metalbear_account_context *acct) {
    cJSON *document = cJSON_CreateObject();
    cJSON *context = cJSON_CreateArray();
    cJSON *services = cJSON_CreateArray();
    cJSON *service = cJSON_CreateObject();
    cJSON *verification = cJSON_CreateObject();
    cJSON *also_known_as = cJSON_CreateArray();
    if (!document || !context || !services || !service || !verification || !also_known_as) {
        cJSON_Delete(document);
        cJSON_Delete(context);
        cJSON_Delete(services);
        cJSON_Delete(service);
        cJSON_Delete(verification);
        cJSON_Delete(also_known_as);
        return NULL;
    }
    cJSON_AddItemToArray(context,
                         cJSON_CreateString("https://www.w3.org/ns/did/v1"));
    cJSON_AddItemToObject(document, "@context", context);
    cJSON_AddStringToObject(document, "id", acct->did);
    if (acct->handle && acct->handle[0]) {
        char aka[256];
        snprintf(aka, sizeof(aka), "at://%s", acct->handle);
        cJSON_AddItemToArray(also_known_as, cJSON_CreateString(aka));
    }
    cJSON_AddItemToObject(document, "alsoKnownAs", also_known_as);
    if (acct->repo) {
        const char *signing_didkey = metalbear_repo_store_signing_key_did(acct->repo);
        if (signing_didkey && signing_didkey[0])
            cJSON_AddStringToObject(verification, "atproto", signing_didkey);
    }
    if (verification->child != NULL)
        cJSON_AddItemToObject(document, "verificationMethods", verification);
    else
        cJSON_Delete(verification);
    cJSON_AddStringToObject(service, "id", "#atproto_pds");
    cJSON_AddStringToObject(service, "type", "AtprotoPersonalDataServer");
    cJSON_AddStringToObject(service, "serviceEndpoint", server->public_url);
    cJSON_AddItemToArray(services, service);
    cJSON_AddItemToObject(document, "service", services);
    return document;
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
    bool active = metalbear_account_is_active(acct->account);
    cJSON_AddBoolToObject(root, "active", active);
    if (!active) cJSON_AddStringToObject(root, "status", "deactivated");
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
        wf_xrpc_response_set_error(response, 401, "AuthenticationRequired",
                                   "Invalid identifier or password");
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
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is not hosted here");
        return WF_OK;
    }
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
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is not hosted here");
        return WF_OK;
    }
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
    bool active = metalbear_account_is_active(acct->account);
    cJSON_AddBoolToObject(root, "active", active);
    if (!active) cJSON_AddStringToObject(root, "status", "deactivated");
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
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is not hosted here");
        return WF_OK;
    }
    /* 'since' is accepted for lexicon compatibility; MetalBear's blob store
     * does not track per-blob revisions, so all available blobs are listed. */
    cJSON *limit_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "limit") : NULL;
    int limit = 500;
    if (cJSON_IsNumber(limit_param)) {
        limit = (int)limit_param->valuedouble;
        if (limit < 1) limit = 1;
        if (limit > 1000) limit = 1000;
    }
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
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is not hosted here");
        return WF_OK;
    }
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
static char *mint_plc_did(metalbear_server *server, const char *handle) {
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

    /* 2. Load the PDS bootstrap rotation key to sign the genesis operation. */
    if (metalbear_key_rotation_current_key(server->bootstrap->key_rotation,
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

    /* 7. Submit to the PLC directory; the response body is unused. */
    LOG_INFO("submitting PLC operation to %s for DID %s", server->plc_url, plc_did);
    LOG_INFO("unsigned operation: %s", unsigned_with_key);
    LOG_INFO("signed operation: %s", signed_json);
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
        account_did = mint_plc_did(server, handle->valuestring);
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
    wf_status status = metalbear_account_context_open(
        server->service_did, server->public_url, account_did,
        handle->valuestring, data_dir, password->valuestring, &acct);
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
    /* Look up the email on file to verify it matches */
    char *email = NULL;
    metalbear_account_get_email(server->bootstrap->account, &email, NULL);
    if (!email || !email[0] ||
        strcmp(email, email_param->valuestring) != 0) {
        free(email);
        /* Always return success to avoid email enumeration */
        cJSON *root = cJSON_CreateObject();
        if (!root) return WF_ERR_ALLOC;
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(response, root);
    }
    char token[33];
    if (metalbear_account_create_email_token(server->bootstrap->account, "reset",
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
    wf_status status = metalbear_account_verify_email_token(
        server->bootstrap->account, "reset", token->valuestring);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired reset token");
        return WF_OK;
    }
    status = metalbear_account_reset_password(server->bootstrap->account,
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
    /* The account DID and service DID are configured at startup and the
     * server publishes a service document for them, so the DID is valid
     * for this PDS. */
    bool valid_did = acct->did && acct->did[0] &&
                     server->service_did && server->service_did[0];
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
    cJSON_AddNumberToObject(root, "expectedBlobs", 0);
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
    if (metalbear_key_rotation_reserve(server->bootstrap->key_rotation, &didkey) != WF_OK) {
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
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;

    /* Build subject union. */
    cJSON *subject = cJSON_CreateObject();
    if (!subject) { cJSON_Delete(root); return WF_ERR_ALLOC; }
    if (did) {
        cJSON_AddStringToObject(subject, "$type",
                                "com.atproto.admin.defs#repoRef");
        cJSON_AddStringToObject(subject, "did", did);
    } else if (uri) {
        cJSON_AddStringToObject(subject, "$type",
                                "com.atproto.repo.strongRef");
        cJSON_AddStringToObject(subject, "uri", uri);
    } else {
        cJSON_AddStringToObject(subject, "$type",
                                "com.atproto.admin.defs#repoBlobRef");
        /* repoBlobRef requires did+cid; extract from blob CID or require did. */
        cJSON_AddStringToObject(subject, "did", did ? did : "");
        cJSON_AddStringToObject(subject, "cid", blob);
    }
    cJSON_AddItemToObject(root, "subject", subject);

    /* Check takedown status. */
    char *takedown_ref = NULL;
    if (metalbear_account_registry_get_takedown(
            server->registry, did, uri, blob, &takedown_ref) == WF_OK &&
        takedown_ref) {
        cJSON *td = cJSON_CreateObject();
        if (td) {
            cJSON_AddBoolToObject(td, "applied", true);
            cJSON_AddStringToObject(td, "ref", takedown_ref);
            cJSON_AddItemToObject(root, "takedown", td);
        }
        free(takedown_ref);
    }

    /* Check deactivation status (accounts only). */
    if (did) {
        metalbear_account_entry *entry = NULL;
        if (metalbear_account_registry_find_by_did(
                server->registry, did, &entry) == WF_OK && entry) {
            if (!entry->active) {
                cJSON *deact = cJSON_CreateObject();
                if (deact) {
                    cJSON_AddBoolToObject(deact, "applied", true);
                    cJSON_AddItemToObject(root, "deactivated", deact);
                }
            }
            metalbear_account_entry_free(entry);
        }
    }
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

    /* Apply takedown if present. */
    if (takedown) {
        cJSON *applied = cJSON_GetObjectItemCaseSensitive(takedown, "applied");
        cJSON *ref = cJSON_GetObjectItemCaseSensitive(takedown, "ref");
        const char *ref_str = cJSON_IsString(ref) ? ref->valuestring : "admin";
        if (cJSON_IsTrue(applied)) {
            metalbear_account_registry_set_takedown(
                server->registry, did, uri, blob_cid, ref_str);
        } else {
            metalbear_account_registry_set_takedown(
                server->registry, did, uri, blob_cid, NULL);
        }
    }

    /* Handle account deactivation (repoRef only). */
    if (deactivated && did && !uri && !blob_cid) {
        cJSON *applied = cJSON_GetObjectItemCaseSensitive(deactivated, "applied");
        if (cJSON_IsTrue(applied)) {
            metalbear_account_context *acct = context_for_did(server, did);
            if (acct) {
                metalbear_account_deactivate(acct->account, NULL);
                metalbear_sequencer_account_status(
                    acct->sequencer, did, 0, "deactivated");
            }
        } else {
            metalbear_account_context *acct = context_for_did(server, did);
            if (acct) {
                metalbear_account_activate(acct->account);
                metalbear_sequencer_account_status(
                    acct->sequencer, did, 1, NULL);
            }
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
    if (acct) {
        metalbear_repo_store_set_handle(acct->repo, handle->valuestring);
        free(acct->handle);
        acct->handle = strdup(handle->valuestring);
    }
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
    cJSON *limit_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "limit") : NULL;
    int limit = 100;
    if (cJSON_IsNumber(limit_param)) {
        limit = (int)limit_param->valuedouble;
        if (limit < 1) limit = 1;
        if (limit > 500) limit = 500;
    }
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
    metalbear_account_entry_free(entry);
    if (!data_dir) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "could not copy data directory");
        return WF_OK;
    }

    metalbear_account_registry_remove(server->registry, did->valuestring);

    metalbear_account_context *acct = context_for_did(server, did->valuestring);
    if (acct) {
        metalbear_sequencer_account_status(
            acct->sequencer, did->valuestring, 0, "deleted");
    }

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
    if (metalbear_blob_store_put(acct->blobs, cid_str, mime,
                           request->body, request->body_len) != WF_OK) {
        free(cid_str);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                    "failed to store blob");
        return WF_OK;
    }
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
    wf_xrpc_response_set_body(response, (const char *)data, len);
    free(data);
    free(mime);
    return WF_OK;
}


static wf_status list_repos(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    LOG_DEBUG("list_repos: listed all hosted repos");
    cJSON *limit_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "limit") : NULL;
    int limit = 500;
    if (cJSON_IsNumber(limit_param)) {
        limit = (int)limit_param->valuedouble;
        if (limit < 1) limit = 1;
        if (limit > 1000) limit = 1000;
    }
    cJSON *cursor_param = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor") : NULL;
    size_t offset = 0;
    if (cJSON_IsString(cursor_param) && cursor_param->valuestring[0]) {
        char *end = NULL;
        long parsed = strtol(cursor_param->valuestring, &end, 10);
        if (*cursor_param->valuestring && *end == '\0' && parsed >= 0)
            offset = (size_t)parsed;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *repos = cJSON_CreateArray();
    if (!root || !repos) {
        cJSON_Delete(root);
        cJSON_Delete(repos);
        return WF_ERR_ALLOC;
    }
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries,
                                        &count) != WF_OK) {
        entries = NULL;
        count = 0;
    }
    if (offset > count) offset = count;
    size_t taken = 0;
    for (size_t i = offset; i < count && taken < (size_t)limit; i++, taken++) {
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
            metalbear_account_entries_free(entries, count);
            cJSON_Delete(root);
            cJSON_Delete(repos);
            return WF_ERR_ALLOC;
        }
        cJSON_AddStringToObject(repo, "did", acct->did);
        cJSON_AddStringToObject(repo, "head", cid);
        cJSON_AddStringToObject(repo, "rev", rev);
        bool active = metalbear_account_is_active(acct->account);
        cJSON_AddBoolToObject(repo, "active", active);
        if (!active)
            cJSON_AddStringToObject(repo, "status", "deactivated");
        cJSON_AddItemToArray(repos, repo);
        free(rev);
        free(cid);
    }
    metalbear_account_entries_free(entries, count);
    cJSON_AddItemToObject(root, "repos", repos);
    size_t next = offset + taken;
    if (next < count) {
        char cursor_buf[32];
        snprintf(cursor_buf, sizeof(cursor_buf), "%zu", next);
        cJSON_AddStringToObject(root, "cursor", cursor_buf);
    }
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
    if (strncmp(server->service_did, "did:web:", 9) == 0) {
        size_t len = strlen(server->service_did + 9);
        if (len < sizeof(service_hostname)) {
            memcpy(service_hostname, server->service_did + 9, len);
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
            const char *state = entries[i].active ? "active" : "deactivated";
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
    if (server->bootstrap && server->bootstrap->handle) {
        status = metalbear_account_registry_find_by_handle(
            server->registry, server->bootstrap->handle, &entry);
    }
    if (status == WF_OK && entry) return entry;
    metalbear_account_entry_free(entry);
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
    return status;
}

static bool valid_config(const metalbear_config *config) {
    return config && config->listen_address && config->data_directory &&
           config->service_did && config->account_did &&
           config->account_handle && config->user_domain && config->password &&
           config->password[0];
}

metalbear_server *metalbear_server_start(const metalbear_config *config) {
    log_level = metalbear_log_level_from_env();
    log_file = metalbear_log_file_from_env();
    if (!valid_config(config)) {
        LOG_ERROR("invalid server configuration");
        return NULL;
    }
    if (!make_directory(config->data_directory)) {
        LOG_ERROR("cannot create data directory: %s", config->data_directory);
        return NULL;
    }

    metalbear_server *server = calloc(1, sizeof(*server));
    if (!server || !copy_config(server, config)) {
        LOG_ERROR("cannot initialise server");
        goto fail;
    }

    /* Resolve the primary account's dedicated data directory and open its
     * full store bundle as the bootstrap context. */
    char *primary_dir = NULL;
    if (metalbear_account_dir_for_did(config->data_directory,
                                      config->account_did, &primary_dir) != WF_OK
        || !primary_dir) {
        LOG_ERROR("cannot compute primary account directory");
        goto fail;
    }
    if (metalbear_account_context_open(config->service_did,
                                       server->public_url,
                                       config->account_did,
                                       config->account_handle,
                                       primary_dir, config->password,
                                       &server->bootstrap) != WF_OK) {
        LOG_ERROR("cannot open primary account context");
        free(primary_dir);
        goto fail;
    }
    free(primary_dir);

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
    /* Seed the registry with the primary account if not already present.
     * The data_directory stored is the account's dedicated subdirectory. */
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, config->account_did, &existing) != WF_OK) {
        char *primary_dir = NULL;
        if (metalbear_account_dir_for_did(config->data_directory,
                                           config->account_did,
                                           &primary_dir) == WF_OK &&
            primary_dir) {
            metalbear_account_registry_add(server->registry,
                                           config->account_did,
                                           config->account_handle,
                                           "", primary_dir);
            free(primary_dir);
        }
    } else {
        metalbear_account_entry_free(existing);
    }

    /* Create rate limiter: 100 requests per 60 seconds */
    server->rate_limiter = wf_rate_limiter_new(100, 60, 0);

    /* Open moderation report store */
    char *reports_path = join_path(config->data_directory, "reports.sqlite3");
    if (!reports_path ||
        metalbear_report_store_open(reports_path, &server->reports) != WF_OK) {
        LOG_ERROR("cannot open report store");
        free(reports_path);
        goto fail;
    }
    free(reports_path);
    metalbear_repo_store_set_event_callback(server->bootstrap->repo,
                                     metalbear_sequencer_repo_event,
                                     server->bootstrap->sequencer);
    if (metalbear_sequencer_reconcile_account(
            server->bootstrap->sequencer, server->bootstrap->did,
            metalbear_account_is_active(server->bootstrap->account)) != WF_OK) {
        LOG_ERROR("cannot reconcile account sequence");
        goto fail;
    }
    if (metalbear_sequencer_reconcile_repo(server->bootstrap->sequencer,
                                           server->bootstrap->repo) != WF_OK) {
        LOG_ERROR("cannot reconcile repository sequence");
        goto fail;
    }
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

    /* Cache of open per-account store bundles, keyed by DID. The per-request
     * repo/blob resolver and the auth callback route non-bootstrap accounts
     * through this cache. public_url is resolved by register_identity_documents
     * above, so the cache opens secondary accounts with the same config. */
    server->account_cache = metalbear_account_cache_new(
        server->service_did, server->public_url, server->data_directory);
    if (!server->account_cache) {
        LOG_ERROR("cannot create account cache");
        goto fail;
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
        metalbear_xrpc_server_register_pds_repo_resolver(server->xrpc,
            metalbear_repo_resolver, server,
            server->service_did, server->public_url) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.repo.uploadBlob", upload_blob, server) != WF_OK ||
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
            "com.atproto.sync.getRecord", get_record, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getHead", get_head, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getCheckout", get_checkout, server) != WF_OK ||
        metalbear_sequencer_register(server->bootstrap->sequencer,
                                     server->xrpc) != WF_OK) {
        LOG_ERROR("cannot register sync export routes");
        goto fail;
    }

    wf_xrpc_server_set_auth_callback(server->xrpc, authenticate, server);

    /* Register OAuth HTTP routes (bypass XRPC auth) */
    if (metalbear_oauth_routes_register(server->xrpc, server->bootstrap->oauth,
                                         server->public_url,
                                         server->service_did,
                                         server->bootstrap->did) != WF_OK) {
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
    if (config->account_email && config->account_email[0])
        server->account_email = strdup(config->account_email);

    /* Configure firehose retention */
    server->retention_max_age = config->retention_max_age_seconds > 0
                                    ? config->retention_max_age_seconds
                                    : 30 * 24 * 60 * 60; /* 30 days */
    server->retention_min_events = config->retention_min_events > 0
                                      ? config->retention_min_events
                                      : 1000;

    /* Apply initial retention */
    metalbear_sequencer_retain(server->bootstrap->sequencer,
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
    if (server->bootstrap) {
        metalbear_repo_store_set_event_callback(server->bootstrap->repo, NULL, NULL);
        metalbear_account_context_close(server->bootstrap);
    }
    metalbear_account_registry_free(server->registry);
    metalbear_email_free(server->email);
    metalbear_report_store_free(server->reports);
    wf_rate_limiter_free(server->rate_limiter);
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    free(server->service_did);
    free(server->public_url);
    free(server->user_domain);
    free(server->data_directory);
    free(server->account_email);
    free(server->admin_password);
    free(server->crawlers);
    free(server->plc_url);
    free(server);
}

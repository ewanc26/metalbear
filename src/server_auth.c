/* Authentication and the routing rules that decide who may call what. */

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

static bool is_public_route(const char *nsid) {
    static const char *const public_routes[] = {
        "com.atproto.server.describeServer",
        "_health",
        "com.atproto.server.createSession",
        "com.atproto.server.createAccount",
        "com.atproto.server.requestPasswordReset",
        "com.atproto.server.resetPassword",
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
    for (size_t i = 0; i < sizeof(public_routes) / sizeof(public_routes[0]);
         i++)
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
bool admin_authenticated(metalbear_server *server, const wf_xrpc_request *req) {
    if (!server->admin_password || !server->admin_password[0]) return false;
    const char *header = req->auth_header;
    static const char prefix[] = "Basic ";
    if (!header || strncmp(header, prefix, sizeof(prefix) - 1) != 0)
        return false;
    const char *provided = header + sizeof(prefix) - 1;
    /* Skip trailing whitespace (newline) some clients append. */
    size_t provided_len = strlen(provided);
    while (provided_len > 0 && (provided[provided_len - 1] == '\r' ||
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
    /* EVP_EncodeBlock appends a trailing newline; strip it so lengths
     * match `provided`, which was already trimmed above. */
    while (elen > 0 && (encoded[elen - 1] == '\r' ||
                        encoded[elen - 1] == '\n' || encoded[elen - 1] == ' '))
        elen--;

    if ((size_t)elen != provided_len) return false;
    return CRYPTO_memcmp(encoded, provided, (size_t)elen) == 0;
}

const char *bearer_token(const char *header) {
    static const char prefix[] = "Bearer ";
    if (!header || strncmp(header, prefix, sizeof(prefix) - 1) != 0)
        return NULL;
    return header + sizeof(prefix) - 1;
}

/* Decode a named claim from a JWT *without* verifying its signature. This is
 * used only to route a request to the verifier that then performs real
 * signature/expiry/scope verification. Returns a caller-owned string, or NULL
 * on any parse failure. */
char *jwt_claim(const char *token, const char *name) {
    if (!token || !name) return NULL;
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
    if (decoded != WF_OK || !raw) return NULL;
    cJSON *payload = cJSON_ParseWithLength((const char *)raw, raw_len);
    free(raw);
    if (!payload) return NULL;
    cJSON *value = cJSON_GetObjectItemCaseSensitive(payload, name);
    char *result = NULL;
    if (cJSON_IsString(value) && value->valuestring[0])
        result = strdup(value->valuestring);
    cJSON_Delete(payload);
    return result;
}

char *jwt_subject(const char *token) {
    return jwt_claim(token, "sub");
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
                                    char **out_subject, char **out_scope) {
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
                                       const wf_xrpc_request *req, char *buf,
                                       size_t bufsz) {
    if (req->authed_subject && req->authed_subject[0])
        return req->authed_subject;
    const char *cand = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *repo = cJSON_GetObjectItemCaseSensitive(req->params, "repo");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        cand = cJSON_IsString(repo)
                   ? repo->valuestring
                   : (cJSON_IsString(did) ? did->valuestring : NULL);
        if (cand && strncmp(cand, "at://", 5) == 0) {
            const char *p = cand + 5;
            size_t n = 0;
            while (p[n] && p[n] != '/') n++;
            if (n == 0 || n >= bufsz) return NULL;
            memcpy(buf, p, n);
            buf[n] = '\0';
            cand = buf;
        }
    }
    if (!cand) return NULL;
    /* The `repo`/`did` param (and an at:// URI's authority) is an
     * "at-identifier" per the lexicon -- a handle or a DID, either one.
     * Resolving only literal did: strings silently failed every handle-based
     * read (describeRepo, listRecords, unauthenticated getRecord, ...) with
     * RepoNotFound, which is wrong: the reference resolves both. */
    if (strncmp(cand, "did:", 4) == 0) return cand;
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_handle(server->registry, cand,
                                                  &entry) != WF_OK ||
        !entry)
        return NULL;
    size_t n = strlen(entry->did);
    const char *resolved = NULL;
    if (n < bufsz) {
        memcpy(buf, entry->did, n + 1);
        resolved = buf;
    }
    metalbear_account_entry_free(entry);
    return resolved;
}

/*
 * Split `at://<authority>/<collection>/<rkey>` into its three parts, each
 * copied into the caller's buffer. Returns false unless all three are present
 * and fit: a strong reference names exactly one record, and a URI stopping at
 * the collection names a great many.
 */
bool split_at_uri(const char *uri, char *authority, size_t authority_sz,
                  char *collection, size_t collection_sz, char *rkey,
                  size_t rkey_sz) {
    if (!uri) return false;
    /* The syntax rules (authority, NSID, record key, no fragment) are
     * Wolfram's; only the "all three present and they fit" policy is ours. */
    wf_syntax_aturi parsed;
    if (!wf_syntax_aturi_parse(uri, &parsed)) return false;
    bool ok = parsed.authority && parsed.collection && parsed.record_key &&
              !parsed.fragment;
    const char *parts[3] = {parsed.authority, parsed.collection,
                            parsed.record_key};
    char *outs[3] = {authority, collection, rkey};
    size_t sizes[3] = {authority_sz, collection_sz, rkey_sz};
    for (int i = 0; ok && i < 3; i++) {
        size_t n = strlen(parts[i]);
        if (n == 0 || n >= sizes[i]) {
            ok = false;
            break;
        }
        memcpy(outs[i], parts[i], n + 1);
    }
    wf_syntax_aturi_free(&parsed);
    return ok;
}

/* Return the cached context for `did`. The returned context is owned by the
 * cache and must NOT be freed by the caller. Returns NULL when the DID is
 * unknown / cannot be opened. Every account resolves the same way — there is
 * no account the server holds open in preference to the others. */
metalbear_account_context *context_for_did(metalbear_server *server,
                                           const char *did) {
    if (!did) return NULL;
    metalbear_account_context *acct = metalbear_account_cache_get(
        server->account_cache, server->registry, did);
    if (!acct) LOG_WARN("context_for_did: unknown did=%s", did);
    return acct;
}

metalbear_account_context *context_for_identifier(metalbear_server *server,
                                                  const char *identifier) {
    metalbear_account_entry *entry = NULL;
    wf_status status = metalbear_account_registry_find_by_did(
        server->registry, identifier, &entry);
    if (status != WF_OK)
        status = metalbear_account_registry_find_by_handle(server->registry,
                                                           identifier, &entry);
    if (status != WF_OK || !entry) return NULL;
    metalbear_account_context *acct = context_for_did(server, entry->did);
    metalbear_account_entry_free(entry);
    return acct;
}

/* Resolve the account context for a request. The returned context is owned by
 * the cache and must NOT be freed by the caller. Returns NULL when the account
 * cannot be resolved. */
metalbear_account_context *resolve_request_context(metalbear_server *server,
                                                   const wf_xrpc_request *req) {
    char buf[256];
    const char *did = request_account_did(server, req, buf, sizeof(buf));
    return context_for_did(server, did);
}

/* XRPC request observer: fires once per request after the handler returns, on
 * the worker thread that served it. Wolfram exposes a single observer slot, so
 * this one backs both responsibilities:
 *  - drop every account context acquired on the request path (refcounted by
 *    metalbear_account_cache_get) so the bounded cache can evict idle accounts;
 *  - record per-route request/error counters.
 * Called for every request, so handlers never release by hand. */
void metalbear_account_cache_request_observer(void *ctx, const char *nsid,
                                              const char *path,
                                              const char *method,
                                              unsigned int status) {
    (void)ctx;
    (void)method;
    metalbear_account_cache_release_thread_local();
    metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS);
    if (status >= 400) metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS_FAILED);
    metalbear_metrics_record_request(nsid, path, status);
}

/* wolfram per-request resolver: map a request to the correct account's repo /
 * blob stores. Borrowed pointers remain valid for the request duration because
 * the cache outlives the request. */
wf_status metalbear_repo_resolver(void *ctx, const wf_xrpc_request *req,
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

/*
 * Routes the reference refuses to OAuth/DPoP credentials entirely --
 * `authorize: () => { throw new ForbiddenError('OAuth credentials are not
 * supported for this endpoint') }` in createAppPassword.ts, activateAccount.ts,
 * deactivateAccount.ts, requestAccountDelete.ts, getAccountInviteCodes.ts, and
 * (with a different message, same effect) requestEmailUpdate.ts. This is
 * independent of scope breadth: even an OAuth grant scoped for full access
 * ("atproto" alone) must never reach these, only a session JWT can. The other
 * three full_access_route entries (importRepo, requestPlcOperationSignature,
 * signPlcOperation) are different -- the reference allows OAuth there given a
 * matching account/identity scope, which MetalBear's scope model now DOES
 * enforce narrowly (see the repo:manage and identity:* checks further down
 * in authenticate(), just after this function's callers), so they fall
 * through to the full-access-or-nothing check below only for a session JWT
 * or an "atproto" (full-access) OAuth grant, not to bypass scope checking
 * outright.
 */
static bool oauth_forbidden_route(const char *nsid) {
    return strcmp(nsid, "com.atproto.server.createAppPassword") == 0 ||
           strcmp(nsid, "com.atproto.server.activateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.deactivateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.requestAccountDelete") == 0 ||
           strcmp(nsid, "com.atproto.server.requestEmailUpdate") == 0 ||
           strcmp(nsid, "com.atproto.server.getAccountInviteCodes") == 0;
}

static bool full_access_route(const char *nsid) {
    return strcmp(nsid, "com.atproto.server.createAppPassword") == 0 ||
           strcmp(nsid, "com.atproto.server.activateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.deactivateAccount") == 0 ||
           /* The reference requires ACCESS_FULL plus an explicit
            * repo:manage permission assertion for importRepo -- a
            * bulk-replace of the whole repository is not something an
            * app-password-scoped session should be able to trigger.
            * MetalBear has no separate "manage" permission tier, so
            * requiring full (non-app-password) access is the closest
            * faithful match with the scope categories this codebase
            * actually has. */
           strcmp(nsid, "com.atproto.repo.importRepo") == 0 ||
           /* requestPlcOperationSignature/signPlcOperation both register
            * with `scopes: ACCESS_FULL` in the reference (identity.ts) --
            * an app password, privileged or not, must never be able to
            * trigger a PLC identity operation (rotating signing/recovery
            * keys, alsoKnownAs, services). Both also separately admit
            * METALBEAR_ACCESS_TAKENDOWN via the exception below, matching
            * their `additional: [AuthScope.Takendown]`. */
           strcmp(nsid, "com.atproto.identity.requestPlcOperationSignature") ==
               0 ||
           strcmp(nsid, "com.atproto.identity.signPlcOperation") == 0 ||
           /* Also `scopes: ACCESS_FULL` in the reference, with no
            * takendown exception: requestAccountDelete (an account-deletion
            * token), requestEmailUpdate (an email-change token -- a path to
            * account takeover if an app password could request one), and
            * getAccountInviteCodes. */
           strcmp(nsid, "com.atproto.server.requestAccountDelete") == 0 ||
           strcmp(nsid, "com.atproto.server.requestEmailUpdate") == 0 ||
           strcmp(nsid, "com.atproto.server.getAccountInviteCodes") == 0;
}

/*
 * Routes a METALBEAR_ACCESS_TAKENDOWN session may reach despite the
 * account_is_taken_down gate below rejecting every other route -- the exact
 * set the reference lists via `additional: [AuthScope.Takendown]` on
 * deactivateAccount.ts, getRepo.ts, getBlob.ts, listBlobs.ts,
 * createReport.ts, getServiceAuth.ts, requestPlcOperationSignature.ts,
 * signPlcOperation.ts, and app/bsky/actor/getPreferences.ts, restricted to
 * the NSIDs MetalBear actually implements. Lets a taken-down holder export
 * their repo/blobs, sign a PLC op to migrate away, mint a service-auth
 * token, appeal via a report, or finalize deactivation -- nothing that
 * reads or writes through the normal repo-record surface.
 */
static bool takendown_route_allowed(const char *nsid) {
    return strcmp(nsid, "com.atproto.server.deactivateAccount") == 0 ||
           strcmp(nsid, "com.atproto.sync.getRepo") == 0 ||
           strcmp(nsid, "com.atproto.sync.getBlob") == 0 ||
           strcmp(nsid, "com.atproto.sync.listBlobs") == 0 ||
           strcmp(nsid, "com.atproto.moderation.createReport") == 0 ||
           strcmp(nsid, "com.atproto.server.getServiceAuth") == 0 ||
           strcmp(nsid, "com.atproto.identity.requestPlcOperationSignature") ==
               0 ||
           strcmp(nsid, "com.atproto.identity.signPlcOperation") == 0 ||
           strcmp(nsid, "app.bsky.actor.getPreferences") == 0;
}

/* Every "app.bsky.", "chat.bsky.", and "tools.ozone." route proxies to some
 * other service and requires rpc: scope there, matching the reference's
 * generic proxyHandler/assertRpc behavior (pipethrough.ts) -- a blanket
 * namespace check rather than a per-route allowlist, so a newly wired proxy
 * route (appview_routes.c's appview_get_ handlers, appview_register_push,
 * appview_unregister_push, or the generic proxy_fallback) needs no matching
 * addition here. tools.ozone.* has no sensible default target (the
 * reference falls back to an operator-configured modService MetalBear has
 * no equivalent config for), but a real moderator client always sends an
 * explicit atproto-proxy header naming its own ozone instance, and the
 * scope check below already prioritizes that verbatim over any default --
 * so the header-present case, the only one actually reachable, comes out
 * correct regardless. The one exception is app.bsky.actor's getPreferences
 * and putPreferences: the reference proxies those too, but MetalBear stores
 * preferences locally, so their audience is not the AppView and they get
 * their own self-referential check above instead. */
static bool proxied_appview_rpc_route(const char *nsid) {
    if (strncmp(nsid, "app.bsky.", 9) == 0) {
        return strcmp(nsid, "app.bsky.actor.getPreferences") != 0 &&
               strcmp(nsid, "app.bsky.actor.putPreferences") != 0;
    }
    return strncmp(nsid, "chat.bsky.", 10) == 0 ||
           strncmp(nsid, "tools.ozone.", 12) == 0;
}

/*
 * Wraps the auth callback to count refusals it makes for a reason the status
 * alone does not carry: the observer sees a 401, but not whether it came from
 * a missing token, an expired one, or an account that may not act.
 */
static wf_status authenticate_request(wf_xrpc_request *req, void *ctx);

wf_status metalbear_authenticate(wf_xrpc_request *req, void *ctx) {
    wf_status status = authenticate_request(req, ctx);
    if (status != WF_OK) metalbear_metrics_inc(METALBEAR_METRIC_AUTH_REFUSED);
    return status;
}

static wf_status authenticate_request(wf_xrpc_request *req, void *ctx) {
    metalbear_server *server = ctx;
    LOG_DEBUG("authenticate: nsid=%s method=%s host=%s auth=%s",
              req->nsid ? req->nsid : "-", req->method ? req->method : "-",
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
            const cJSON *repo =
                req->params
                    ? cJSON_GetObjectItemCaseSensitive(req->params, "repo")
                    : NULL;
            const cJSON *did =
                req->params
                    ? cJSON_GetObjectItemCaseSensitive(req->params, "did")
                    : NULL;
            const cJSON *target = cJSON_IsString(repo)
                                      ? repo
                                      : (cJSON_IsString(did) ? did : NULL);
            if (target) {
                metalbear_account_context *acct =
                    context_for_identifier(server, target->valuestring);
                if (acct && !metalbear_account_is_active(acct->account) &&
                    !account_is_taken_down(server, acct->did))
                    return WF_ERR_CONFLICT;
            }
        }
        /*
         * getRepo/getBlob/listBlobs are public so any relay can sync any
         * repo, but that leaves the taken-down account's own holder unable
         * to export their own data through the bearer-token path below,
         * which this NSID never reaches. Verify an offered token against
         * the *named* account's own store (never the caller's) and, only
         * when it is genuinely that account's METALBEAR_ACCESS_TAKENDOWN
         * session, set authed_subject so assert_repo_available's
         * self-access exception applies. Anyone else -- no token, someone
         * else's token, a token for a different scope -- falls through to
         * the anonymous path and the handler's ordinary RepoTakendown.
         */
        if (strcmp(req->nsid, "com.atproto.sync.getRepo") == 0 ||
            strcmp(req->nsid, "com.atproto.sync.getBlob") == 0 ||
            strcmp(req->nsid, "com.atproto.sync.listBlobs") == 0) {
            const cJSON *did =
                req->params
                    ? cJSON_GetObjectItemCaseSensitive(req->params, "did")
                    : NULL;
            const char *provided = bearer_token(req->auth_header);
            if (cJSON_IsString(did) && provided) {
                metalbear_account_context *acct =
                    context_for_did(server, did->valuestring);
                if (acct && account_is_taken_down(server, acct->did)) {
                    metalbear_access_scope tk_scope = METALBEAR_ACCESS_FULL;
                    if (metalbear_auth_verify_access_scope(
                            acct->auth, provided, &tk_scope) == WF_OK &&
                        tk_scope == METALBEAR_ACCESS_TAKENDOWN) {
                        req->authed_subject = strdup(acct->did);
                        req->authed_principal_kind = WF_XRPC_PRINCIPAL_USER;
                    }
                }
            }
        }
        return WF_OK;
    }
    if (req->params && cJSON_IsObject(req->params) &&
        strcmp(req->nsid, "app.bsky.actor.getPreferences") != 0) {
        cJSON *repo = cJSON_GetObjectItemCaseSensitive(req->params, "repo");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        cJSON *target =
            cJSON_IsString(repo) ? repo : (cJSON_IsString(did) ? did : NULL);
        if (target) {
            /* `repo`/`did` here is an at-identifier (com.atproto.repo.*'s own
             * lexicon type): a DID or a handle, either one, same as every
             * other identifier param in the protocol. A DID-only lookup
             * silently rejected any client that (reasonably) sent a handle
             * here with a misleading AuthenticationRequired, instead of the
             * NotFound/InvalidRequest an unknown identifier actually
             * deserves. context_for_identifier is the same DID-then-handle
             * resolution the rest of this file uses. getPreferences is
             * exempt: its `did` query param is the mod-service target, and
             * the handler resolves it (400 NotFound for an unknown DID) —
             * a pre-auth 401 here would win before the mod-service verifier
             * ever runs. */
            if (!context_for_identifier(server, target->valuestring))
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
        wf_status oauth_status =
            authenticate_oauth(server, req, &sub, &oauth_scope_str);
        if (oauth_status != WF_OK) return oauth_status;

        /* Unconditional, regardless of scope: see oauth_forbidden_route. A
         * full-access ("atproto") OAuth grant must not silently inherit the
         * privileges a session JWT has here. */
        if (oauth_forbidden_route(req->nsid)) {
            LOG_WARN("authenticate: OAuth credentials refused for nsid=%s "
                     "did=%s",
                     req->nsid ? req->nsid : "-", sub);
            free(oauth_scope_str);
            free(sub);
            return WF_ERR_PERMISSION;
        }

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
                    const char *nsid = req->nsid ? req->nsid : "";

                    /* Non-repo dynamic scopes (blob:/account:/identity:/rpc:)
                     * each gate exactly one XRPC method, matching the
                     * reference's per-route `assertBlob`/`assertAccount`/
                     * `assertIdentity`/`assertRpc` calls. A route handled
                     * here is fully decided by this block; it must not also
                     * fall into the repo/read fallback below (whose
                     * collection lookup would find nothing for these NSIDs
                     * and deny unconditionally). */
                    bool scope_checked = false;

                    if (strcmp(nsid, "com.atproto.repo.uploadBlob") == 0) {
                        scope_checked = true;
                        const char *mime =
                            req->content_type && req->content_type[0]
                                ? req->content_type
                                : "application/octet-stream";
                        if (!mb_scope_set_allows_blob(&scope_set, mime)) {
                            LOG_WARN("authenticate: OAuth scope denied blob "
                                     "did=%s mime=%s",
                                     sub, mime);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (strcmp(nsid, "com.atproto.repo.importRepo") ==
                               0) {
                        scope_checked = true;
                        if (!mb_scope_set_allows_account(
                                &scope_set, "repo", MB_ACCOUNT_ACTION_MANAGE)) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "importRepo did=%s",
                                     sub);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (strcmp(nsid,
                                      "com.atproto.identity."
                                      "requestPlcOperationSignature") == 0 ||
                               strcmp(nsid, "com.atproto.identity."
                                            "signPlcOperation") == 0) {
                        scope_checked = true;
                        if (!mb_scope_set_allows_identity(&scope_set, "*")) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "identity did=%s nsid=%s",
                                     sub, nsid);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (strcmp(nsid,
                                      "com.atproto.identity.updateHandle") ==
                               0) {
                        scope_checked = true;
                        if (!mb_scope_set_allows_identity(&scope_set,
                                                          "handle")) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "updateHandle did=%s",
                                     sub);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (strcmp(nsid,
                                      "com.atproto.server.getServiceAuth") ==
                               0) {
                        scope_checked = true;
                        cJSON *aud_param =
                            req->params ? cJSON_GetObjectItemCaseSensitive(
                                              req->params, "aud")
                                        : NULL;
                        cJSON *lxm_param =
                            req->params ? cJSON_GetObjectItemCaseSensitive(
                                              req->params, "lxm")
                                        : NULL;
                        const char *aud = cJSON_IsString(aud_param)
                                              ? aud_param->valuestring
                                              : NULL;
                        /* Matches getServiceAuth.ts: `const { aud, lxm = '*'
                         * } = params`. */
                        const char *lxm = (cJSON_IsString(lxm_param) &&
                                           lxm_param->valuestring[0])
                                              ? lxm_param->valuestring
                                              : "*";
                        if (!aud ||
                            !mb_scope_set_allows_rpc(&scope_set, lxm, aud)) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "getServiceAuth did=%s lxm=%s",
                                     sub, lxm);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (strcmp(nsid,
                                      "com.atproto.moderation.createReport") ==
                               0) {
                        scope_checked = true;
                        /* MetalBear handles createReport itself rather than
                         * proxying to a configured external moderation
                         * service (no such config exists), so the audience
                         * is this server's own PDS service id -- the same
                         * self-referential shape a proxied deployment's
                         * `did#serviceId` audience takes, just naming this
                         * server instead of a separate labeler. */
                        char aud_buf[320];
                        snprintf(aud_buf, sizeof(aud_buf), "%s#atproto_pds",
                                 server->service_did ? server->service_did
                                                     : "");
                        if (!mb_scope_set_allows_rpc(&scope_set, nsid,
                                                     aud_buf)) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "createReport did=%s",
                                     sub);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (strcmp(nsid, "app.bsky.actor.getPreferences") ==
                                   0 ||
                               strcmp(nsid, "app.bsky.actor.putPreferences") ==
                                   0) {
                        scope_checked = true;
                        /* The reference proxies these to the AppView and
                         * asserts rpc: there; MetalBear stores preferences
                         * locally instead (see proxied_appview_rpc_route's
                         * comment), so the audience is this server's own PDS
                         * service id -- the same self-referential pattern
                         * createReport uses above for the same reason. */
                        char aud_buf[320];
                        snprintf(aud_buf, sizeof(aud_buf), "%s#atproto_pds",
                                 server->service_did ? server->service_did
                                                     : "");
                        if (!mb_scope_set_allows_rpc(&scope_set, nsid,
                                                     aud_buf)) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "preferences did=%s nsid=%s",
                                     sub, nsid);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    } else if (proxied_appview_rpc_route(nsid)) {
                        scope_checked = true;
                        /* Matches the reference's computeProxyTo exactly: the
                         * atproto-proxy header verbatim if present, else
                         * "<appview_did>#bsky_appview" -- the fixed service
                         * id every reference deployment's default AppView
                         * audience uses (pipethrough.ts's defaultService).
                         * No network resolution needed for the scope check
                         * itself: it is a string comparison against what the
                         * grant named, not a lookup of where the header
                         * actually points -- that resolution only happens
                         * later, in proxy_appview, for the request itself.
                         *
                         * getFeed additionally asserts against the specific
                         * feed generator's own audience (resolved from the
                         * feed record the request names), which is not
                         * checked here -- that would need the same record
                         * lookup the handler itself does, not something
                         * cheap to repeat in this callback. A grant scoped
                         * to exactly that generator's DID is still accepted
                         * by proxy_appview itself failing safe elsewhere;
                         * this gate only covers the AppView-audience half. */
                        char aud_buf[512];
                        const char *aud;
                        if (req->atproto_proxy && req->atproto_proxy[0]) {
                            aud = req->atproto_proxy;
                        } else {
                            snprintf(
                                aud_buf, sizeof(aud_buf), "%s#bsky_appview",
                                server->appview_did ? server->appview_did : "");
                            aud = aud_buf;
                        }
                        if (!mb_scope_set_allows_rpc(&scope_set, nsid, aud)) {
                            LOG_WARN("authenticate: OAuth scope denied "
                                     "appview proxy did=%s nsid=%s aud=%s",
                                     sub, nsid, aud);
                            mb_scope_set_free(&scope_set);
                            free(oauth_scope_str);
                            free(sub);
                            return WF_ERR_PERMISSION;
                        }
                    }

                    if (!scope_checked) {
                        /* Determine the collection and action from the
                         * request */
                        mb_repo_action action = MB_REPO_ACTION_NONE;
                        const char *collection = NULL;
                        cJSON *coll_param = NULL;

                        if (strcmp(nsid, "com.atproto.repo.createRecord") ==
                            0) {
                            action = MB_REPO_ACTION_CREATE;
                            coll_param = req->params
                                             ? cJSON_GetObjectItemCaseSensitive(
                                                   req->params, "collection")
                                             : NULL;
                        } else if (strcmp(nsid, "com.atproto.repo.putRecord") ==
                                   0) {
                            action = MB_REPO_ACTION_UPDATE;
                            coll_param = req->params
                                             ? cJSON_GetObjectItemCaseSensitive(
                                                   req->params, "collection")
                                             : NULL;
                        } else if (strcmp(nsid,
                                          "com.atproto.repo.deleteRecord") ==
                                   0) {
                            action = MB_REPO_ACTION_DELETE;
                            coll_param = req->params
                                             ? cJSON_GetObjectItemCaseSensitive(
                                                   req->params, "collection")
                                             : NULL;
                        }

                        collection = cJSON_IsString(coll_param)
                                         ? coll_param->valuestring
                                         : NULL;

                        /* A collection may also arrive on a read that isn't
                         * one of the three write NSIDs above (e.g. a future
                         * or currently-public route reached with an OAuth
                         * token). Recover it generically so a matching repo
                         * scope is honored for those too, rather than only
                         * for writes. */
                        if (action == MB_REPO_ACTION_NONE && !collection) {
                            cJSON *generic_coll =
                                req->params ? cJSON_GetObjectItemCaseSensitive(
                                                  req->params, "collection")
                                            : NULL;
                            collection = cJSON_IsString(generic_coll)
                                             ? generic_coll->valuestring
                                             : NULL;
                        }

                        if (action != MB_REPO_ACTION_NONE && collection) {
                            if (!mb_scope_set_allows_repo(&scope_set,
                                                          collection, action)) {
                                LOG_WARN(
                                    "authenticate: OAuth scope denied "
                                    "did=%s nsid=%s collection=%s action=%d",
                                    sub, nsid, collection, action);
                                mb_scope_set_free(&scope_set);
                                free(oauth_scope_str);
                                free(sub);
                                return WF_ERR_PERMISSION;
                            }
                        } else if (action == MB_REPO_ACTION_NONE) {
                            /* Read or non-repo operation reaching this point
                             * without full ("atproto") access. A narrowly
                             * scoped OAuth grant must be limited to exactly
                             * the reads its scope implies: a matching repo
                             * scope for the request's collection, nothing
                             * broader. The AT Protocol OAuth spec requires
                             * every authorization request to include
                             * "atproto" (https://atproto.com/specs/oauth),
                             * so a grant that omits it and also carries no
                             * collection-scoped repo permission has no basis
                             * to read anything through this path -- deny
                             * outright rather than falling back to an
                             * implicit allow, which is what let any
                             * non-empty, non-full scope set reach every
                             * authenticated read regardless of what it
                             * actually named. */
                            if (!mb_scope_set_allows_read(&scope_set,
                                                          collection)) {
                                LOG_WARN(
                                    "authenticate: OAuth scope denied read "
                                    "did=%s nsid=%s collection=%s",
                                    sub, nsid, collection ? collection : "-");
                                mb_scope_set_free(&scope_set);
                                free(oauth_scope_str);
                                free(sub);
                                return WF_ERR_PERMISSION;
                            }
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

        /* app.bsky.actor.getPreferences accepts a moderator service's JWT as
         * an alternative to a user access token (the reference's
         * authorizationOrModService, the only route wired for it). A valid
         * service token from the configured mod_service DID bypasses the
         * per-account `sub` routing below and runs the handler in
         * WF_XRPC_PRINCIPAL_SERVICE mode, where the account acted on comes
         * from the undocumented `did` query param. A bearer token that fails
         * mod-service verification (unconfigured, malformed, wrong issuer,
         * bad signature, or a route other than getPreferences) falls through
         * to the normal user-token path unchanged. */
        if (strcmp(req->nsid, "app.bsky.actor.getPreferences") == 0 &&
            server->mod_service_did && server->mod_service_did[0]) {
            char *iss = NULL;
            if (metalbear_verify_mod_service_auth(server->mod_service_did,
                                                  server->service_did, provided,
                                                  &iss) == WF_OK &&
                iss) {
                LOG_DEBUG("authenticate: mod-service granted did=%s nsid=%s "
                          "host=%s",
                          iss, req->nsid ? req->nsid : "-",
                          req->host_header ? req->host_header : "-");
                req->authed_subject = iss;
                req->authed_principal_kind = WF_XRPC_PRINCIPAL_SERVICE;
                return WF_OK;
            }
            free(iss);
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

        bool refresh_route =
            strcmp(req->nsid, "com.atproto.server.refreshSession") == 0 ||
            strcmp(req->nsid, "com.atproto.server.deleteSession") == 0;
        /* `sub` is the token's unverified claim -- any string a caller cared
         * to put there, not necessarily a DID this server hosts. Resolving
         * it before verification (needed to find which account's auth store
         * even checks the signature) must not assume a match: an unknown
         * DID here used to dereference a NULL context_for_did() result
         * directly, letting anyone crash the whole multi-tenant server with
         * a JWT-shaped token naming an account that doesn't exist. */
        metalbear_account_context *sub_acct =
            refresh_route ? NULL : context_for_did(server, sub);
        if (!refresh_route && !sub_acct) {
            LOG_DEBUG("authenticate: unknown did=%s for nsid=%s host=%s", sub,
                      req->nsid ? req->nsid : "-",
                      req->host_header ? req->host_header : "-");
            free(sub);
            return WF_ERR_PERMISSION;
        }
        wf_status verify_status = refresh_route
                                      ? WF_OK
                                      : metalbear_auth_verify_access_scope(
                                            sub_acct->auth, provided, &scope);
        if (verify_status != WF_OK) {
            LOG_WARN("authenticate: token verify failed for did=%s nsid=%s "
                     "status=%d",
                     sub, req->nsid ? req->nsid : "-", verify_status);
            free(sub);
            return verify_status;
        }
        if (!refresh_route && full_access_route(req->nsid) &&
            scope != METALBEAR_ACCESS_FULL &&
            /* deactivateAccount, requestPlcOperationSignature, and
             * signPlcOperation each also take a takendown-scoped session --
             * see takendown_route_allowed, which lists exactly these plus
             * the routes that aren't full_access_route entries at all. */
            !(scope == METALBEAR_ACCESS_TAKENDOWN &&
              takendown_route_allowed(req->nsid))) {
            LOG_WARN(
                "authenticate: insufficient scope for did=%s nsid=%s scope=%d",
                sub, req->nsid ? req->nsid : "-", scope);
            free(sub);
            return WF_ERR_PERMISSION;
        }
    }

    metalbear_account_context *acct = context_for_did(server, sub);
    if (!acct) {
        LOG_WARN("authenticate: unknown did=%s for nsid=%s host=%s", sub,
                 req->nsid ? req->nsid : "-",
                 req->host_header ? req->host_header : "-");
        free(sub);
        return WF_ERR_PERMISSION;
    }

    /*
     * A takedown admits far fewer exceptions than a deactivation: most
     * routes a deactivated account may still reach exist so its holder can
     * reactivate, but a taken-down account reactivating itself would undo
     * the moderation action. Sessions are revoked when the takedown is
     * applied, but a token minted before it must not outlive it -- unless
     * it already carries the narrow METALBEAR_ACCESS_TAKENDOWN scope
     * createSession's `allowTakendown` issues, in which case
     * takendown_route_allowed decides route by route (export, migrate-away,
     * appeal; never normal repo access).
     *
     * The refresh pair is left to its handlers, which answer with the
     * lexicon's `AccountTakedown` rather than a bare authentication failure —
     * the difference a client needs to stop retrying and tell its user why.
     */
    if (account_is_taken_down(server, sub) &&
        (scope != METALBEAR_ACCESS_TAKENDOWN ||
         !takendown_route_allowed(req->nsid))) {
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

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
#include "sync/sync_routes.h"
#include "appview/appview_routes.h"
#include "moderation/moderation_routes.h"
#include "ops/status.h"

#include "metalbear/server.h"
#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/account/account_context.h"
#include "metalbear/account/account_cache.h"
#include "metalbear/oauth/auth.h"
#include "metalbear/repo/backup.h"
#include "metalbear/email.h"
#include "metalbear/dns/handle_dns.h"
#include "metalbear/repo/key_rotation.h"
#include "metalbear/oauth/oauth.h"
#include "metalbear/oauth/oauth_account_routes.h"
#include "metalbear/oauth/oauth_scope.h"
#include "metalbear/moderation/report.h"
#include "metalbear/oauth/oauth_routes.h"
#include "metalbear/sequencer.h"

#include "metalbear/repo/blob_store.h"
#include "metalbear/ops/update_watcher.h"
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
/* Parse HTTP Basic `admin:<password>` from the Authorization header and compare
 * it (constant-time) against the configured admin password. Returns true only
 * when a password is configured AND the header matches exactly. Declared
 * here for the module's own handlers and in server_internal.h for the
 * status endpoints in src/ops/status.c. */
bool admin_authenticated(metalbear_server *server, const wf_xrpc_request *req);

/* struct metalbear_server is defined in server_internal.h, shared with the
 * route-handler modules this file delegates to (src/admin/, etc.). */

/*
 * Point `_atproto.<handle>` at `did`, if a provider is configured.
 *
 * Never fatal to the operation that triggered it. The account or the rename is
 * already durable by the time this runs, and an unresolvable handle is a
 * recoverable state: the record can be written by hand, and the next handle
 * change tries again. Failing the request instead would leave the caller
 * believing nothing happened when the account exists.
 */
void publish_handle_dns(metalbear_server *server, const char *handle,
                        const char *did) {
    if (!server->handle_dns || !handle || !did) return;
    if (metalbear_handle_dns_publish(server->handle_dns, handle, did) !=
        WF_OK) {
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
void retract_handle_dns(metalbear_server *server, const char *handle) {
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

    if ((size_t)elen != provided_len) return false;
    return CRYPTO_memcmp(encoded, provided, (size_t)elen) == 0;
}

const char *bearer_token(const char *header) {
    static const char prefix[] = "Bearer ";
    if (!header || strncmp(header, prefix, sizeof(prefix) - 1) != 0)
        return NULL;
    return header + sizeof(prefix) - 1;
}

/* Decode the `sub` claim from a JWT *without* verifying its signature. This
 * is used only to route the request to the correct account's auth store, which
 * then performs real signature/expiry/scope verification. Returns a
 * caller-owned string, or NULL on any parse failure. */
char *jwt_subject(const char *token) {
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
    if (decoded != WF_OK || !raw) return NULL;
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
    char *outs[3] = {authority, collection, rkey};
    size_t sizes[3] = {authority_sz, collection_sz, rkey_sz};
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

/* wolfram per-request resolver: map a request to the correct account's repo /
 * blob stores. Borrowed pointers remain valid for the request duration because
 * the cache outlives the request. */
static wf_status metalbear_repo_resolver(void *ctx, const wf_xrpc_request *req,
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
    if (req->params && cJSON_IsObject(req->params)) {
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
             * resolution the rest of this file uses. */
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

wf_status set_json(wf_xrpc_response *response, cJSON *root) {
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
int query_param_int(const cJSON *params, const char *name, int fallback,
                    int min, int max) {
    const cJSON *p =
        params ? cJSON_GetObjectItemCaseSensitive(params, name) : NULL;
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

bool query_param_bool(const cJSON *params, const char *name, bool fallback) {
    const cJSON *p =
        params ? cJSON_GetObjectItemCaseSensitive(params, name) : NULL;
    if (cJSON_IsBool(p)) return cJSON_IsTrue(p);
    if (cJSON_IsString(p) && p->valuestring[0]) {
        if (strcmp(p->valuestring, "true") == 0 ||
            strcmp(p->valuestring, "1") == 0)
            return true;
        if (strcmp(p->valuestring, "false") == 0 ||
            strcmp(p->valuestring, "0") == 0)
            return false;
    }
    return fallback;
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
    if (!check_endpoint_rate_limit(server->rl_request_account_delete_day,
                                   server->rl_request_account_delete_hour,
                                   acct->did, 1, response)) {
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "delete", token,
                                             sizeof(token)) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create deletion token");
        return WF_OK;
    }
    /* Send confirmation to the requester's own address. */
    char *acct_email = NULL;
    metalbear_account_get_email(acct->account, &acct_email, NULL);
    const char *to =
        (acct_email && acct_email[0]) ? acct_email : server->account_email;
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
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    cJSON *password =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "password")
            : NULL;
    cJSON *token =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "token")
            : NULL;
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
        cJSON_AddNumberToObject(root, "blobUploadLimit",
                                (double)server->blob_upload_limit);
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
        if (server->operator_name)
            cJSON_AddStringToObject(op, "name", server->operator_name);
        if (server->operator_email)
            cJSON_AddStringToObject(op, "email", server->operator_email);
        else if (server->account_email)
            cJSON_AddStringToObject(op, "email", server->account_email);
        if (server->operator_url)
            cJSON_AddStringToObject(op, "url", server->operator_url);
        if (server->support_url)
            cJSON_AddStringToObject(op, "supportUrl", server->support_url);
        cJSON_AddItemToObject(root, "operator", op);
    }

    cJSON *sw = cJSON_CreateObject();
    if (sw) {
        cJSON_AddStringToObject(sw, "name", "MetalBear");
        cJSON_AddStringToObject(sw, "version", METALBEAR_VERSION);
        /* The SDK version, so the frontend landing page can name the pair it
         * is running without a second admin-gated call. */
        cJSON_AddStringToObject(sw, "wolframVersion", WOLFRAM_VERSION_STRING);
        /* Build provenance: not a secret (unlike admin-gated
         * /_debug/health's identity/config fields) -- an operator's users
         * and the landing page both benefit from knowing exactly which
         * commit is live. */
        cJSON_AddStringToObject(sw, "commit", METALBEAR_BUILD_COMMIT);
        cJSON_AddStringToObject(sw, "builtAt", METALBEAR_BUILD_TIME);
        /* Where this build sits on the software release life cycle
         * (https://en.wikipedia.org/wiki/Software_release_life_cycle) --
         * "pre-alpha"/"alpha"/"beta"/"rc"/"stable" by convention, set via
         * -DMETALBEAR_RELEASE_STAGE at build time. Public for the same
         * reason commit/builtAt are: a client deciding how much to trust an
         * instance benefits from knowing this without guessing from the 0.x
         * version number alone. */
        cJSON_AddStringToObject(sw, "releaseStage", METALBEAR_RELEASE_STAGE);
        cJSON_AddStringToObject(sw, "repository",
                                "https://github.com/ewanc26/metalbear");
        cJSON_AddStringToObject(sw, "license", "AGPL-3.0-only");
        cJSON_AddItemToObject(root, "software", sw);
    }

    if (server->instance_description)
        cJSON_AddStringToObject(root, "description",
                                server->instance_description);
    /* A testing instance says so, so nobody mistakes its accounts for people.
     */
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

/* The takedown ref recorded against an account, or NULL. Caller frees. */
char *account_takedown_ref(metalbear_server *server, const char *did) {
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
const char *account_status_string(metalbear_server *server,
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
bool account_is_taken_down(metalbear_server *server, const char *did) {
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
bool assert_repo_available(metalbear_server *server,
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

/* Sum of per-operation costs for an applyWrites batch, matching
 * rate-limits.ts's ratelimitPoints exactly: 3 per create, 2 per update, 1
 * per delete (and, matching its own `else` fallthrough, 1 for anything else
 * too — an unrecognized op is still one write attempt). Returns 0 (no extra
 * charge) when `params` carries no `writes` array at all; applyWrites'
 * handler rejects that shape on its own regardless of rate limiting. */
static unsigned int apply_writes_rate_limit_cost(const cJSON *params) {
    const cJSON *writes =
        params ? cJSON_GetObjectItemCaseSensitive(params, "writes") : NULL;
    if (!cJSON_IsArray(writes)) return 0;
    unsigned int cost = 0;
    const cJSON *op = NULL;
    cJSON_ArrayForEach(op, writes) {
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(op, "$type");
        const char *t = cJSON_IsString(type) ? type->valuestring : "";
        if (strcmp(t, "com.atproto.repo.applyWrites#create") == 0) {
            cost += 3;
        } else if (strcmp(t, "com.atproto.repo.applyWrites#update") == 0) {
            cost += 2;
        } else {
            cost += 1;
        }
    }
    return cost;
}

/* The repo-write cost this request charges against the shared
 * repo-write-hour/-day buckets (rate-limits.ts): 3/2/1 for a single
 * createRecord/putRecord/deleteRecord, the summed per-operation cost for an
 * applyWrites batch, or 0 for every other route this guard also covers
 * (reads, describeRepo, etc.), which this rate limit does not apply to. */
static unsigned int repo_write_rate_limit_cost(const wf_xrpc_request *req) {
    const char *nsid = req->nsid ? req->nsid : "";
    if (strcmp(nsid, "com.atproto.repo.createRecord") == 0) return 3;
    if (strcmp(nsid, "com.atproto.repo.putRecord") == 0) return 2;
    if (strcmp(nsid, "com.atproto.repo.deleteRecord") == 0) return 1;
    if (strcmp(nsid, "com.atproto.repo.applyWrites") == 0)
        return apply_writes_rate_limit_cost(req->params);
    return 0;
}

/*
 * The repository layer's access guard, consulted by every route registered
 * through metalbear_xrpc_server_register_pds_repo_resolver_ex. A read of the
 * repository as a whole reports the availability errors; a single record
 * reads as absent, which is both what the reference answers and the only
 * thing `com.atproto.repo.getRecord` can say about a moderated record.
 */
static bool repo_access_guard(void *ctx, const wf_xrpc_request *req,
                              const char *record_uri, wf_xrpc_response *resp) {
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
    if (!assert_repo_available(server, acct, req, resp)) return false;

    unsigned int write_cost = repo_write_rate_limit_cost(req);
    if (write_cost > 0 &&
        !check_endpoint_rate_limit(server->rl_repo_write_hour,
                                   server->rl_repo_write_day, acct->did,
                                   write_cost, resp)) {
        return false;
    }
    return true;
}

cJSON *build_did_doc(metalbear_server *server,
                     metalbear_account_context *acct) {
    const char *signing_didkey =
        acct->repo ? metalbear_repo_store_signing_key_did(acct->repo) : NULL;
    return metalbear_did_document_build(acct->did, acct->handle, signing_didkey,
                                        server->public_url);
}

/*
 * Consume from up to two rate-limiter tiers under the same key, matching the
 * reference PDS's MethodRateLimit[] semantics for multi-tier endpoints
 * (createSession, requestPasswordReset, requestAccountDelete,
 * requestEmailConfirmation, requestEmailUpdate): every tier is always
 * charged — never short-circuited on the first hit — and the request is
 * rejected if any tier is empty, reporting whichever tier's retry-after is
 * longest. `tier_b` may be NULL for a single-tier check.
 *
 * Always sets RateLimit-Limit/Remaining/Reset/Policy on `response` — success
 * or rejection — reporting whichever tier has fewer points remaining,
 * matching the reference's CombinedRateLimiter ("lowest wins";
 * rate-limiter.ts). On rejection also fills the same
 * {"error":"RateLimitExceeded",...} body and Retry-After header Wolfram's
 * own built-in limiter uses, and returns false; returns true otherwise.
 */
bool check_endpoint_rate_limit(wf_rate_limiter *tier_a, wf_rate_limiter *tier_b,
                               const char *key, unsigned int cost,
                               wf_xrpc_response *response) {
    if (!key) key = "unknown";
    if (cost == 0) cost = 1;
    wf_rate_limiter *tiers[2] = {tier_a, tier_b};
    wf_rate_limit_status statuses[2] = {0};
    wf_status results[2] = {WF_OK, WF_OK};
    bool limited = false;
    int reported = -1;

    for (int i = 0; i < 2; i++) {
        if (!tiers[i]) continue;
        results[i] =
            wf_rate_limiter_consume_status(tiers[i], key, cost, &statuses[i]);
        if (results[i] != WF_OK) limited = true;
        if (reported < 0 ||
            statuses[i].remaining < statuses[reported].remaining) {
            reported = i;
        }
    }

    if (reported >= 0) {
        char num[16];
        snprintf(num, sizeof(num), "%u", statuses[reported].limit);
        wf_xrpc_response_add_header(response, "RateLimit-Limit", num);
        snprintf(num, sizeof(num), "%u", statuses[reported].reset_at);
        wf_xrpc_response_add_header(response, "RateLimit-Reset", num);
        snprintf(num, sizeof(num), "%u", statuses[reported].remaining);
        wf_xrpc_response_add_header(response, "RateLimit-Remaining", num);
        snprintf(num, sizeof(num), "%u;w=%u", statuses[reported].limit,
                 statuses[reported].duration_seconds);
        wf_xrpc_response_add_header(response, "RateLimit-Policy", num);
    }

    if (!limited) return true;

    /* Retry-After: the furthest-out reset among the tiers that actually
     * rejected this request. */
    time_t now = time(NULL);
    unsigned int retry_after = 0;
    for (int i = 0; i < 2; i++) {
        if (!tiers[i] || results[i] == WF_OK) continue;
        unsigned int ra = statuses[i].reset_at > (unsigned int)now
                              ? statuses[i].reset_at - (unsigned int)now
                              : 1;
        if (ra > retry_after) retry_after = ra;
    }
    char message[128];
    snprintf(message, sizeof(message),
             "Rate limit exceeded. Retry after %u seconds.", retry_after);
    wf_xrpc_response_set_error(response, 429, "RateLimitExceeded", message);
    char ra_str[16];
    snprintf(ra_str, sizeof(ra_str), "%u", retry_after);
    wf_xrpc_response_add_header(response, "Retry-After", ra_str);
    return false;
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

static wf_status get_service_auth(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *aud = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "aud")
                     : NULL;
    cJSON *exp_item =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "exp")
            : NULL;
    cJSON *lxm_item =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "lxm")
            : NULL;
    const char *lxm = cJSON_IsString(lxm_item) ? lxm_item->valuestring : NULL;
    if (!cJSON_IsString(aud) || !valid_service_audience(aud->valuestring) ||
        (lxm_item &&
         (!cJSON_IsString(lxm_item) || !wf_syntax_nsid_is_valid(lxm))) ||
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
    if (metalbear_auth_verify_access_scope(
            acct->auth, bearer_token(request->auth_header), &scope) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    /*
     * A takendown-scoped session is let through the takendown gate for
     * getServiceAuth specifically so its holder can migrate away -- minting
     * a service-auth token to call createAccount on another PDS. It has no
     * business minting one for anything else, matching the reference's
     * explicit `isTakendown(scope) && lxm !== createAccount.lxm` refusal
     * (server/getServiceAuth.ts).
     */
    if (scope == METALBEAR_ACCESS_TAKENDOWN &&
        (!lxm || strcmp(lxm, "com.atproto.server.createAccount") != 0)) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Bad token scope");
        return WF_OK;
    }
    if (scope == METALBEAR_ACCESS_APP_PASSWORD &&
        privileged_service_method(lxm)) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
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
    if (metalbear_repo_store_create_service_auth(
            acct->repo, aud->valuestring, expiration, lxm, &token) != WF_OK) {
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

/* ---- com.atproto.temp.checkSignupQueue (query) ----
 * Temporary unspecced route. MetalBear has no entryway, so always
 * returns { activated: true }. */
static wf_status check_signup_queue(void *ctx, const wf_xrpc_request *request,
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
    if (metalbear_blob_store_put(acct->blobs, cid_str, mime, request->body,
                                 request->body_len) != WF_OK) {
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

/* ---- /tls-check (public, mimics refpds on_demand_tls ask endpoint) ---- */
static wf_status tls_check_handler(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    cJSON *domain_item =
        req->params ? cJSON_GetObjectItemCaseSensitive(req->params, "domain")
                    : NULL;
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
                                                  &entry) == WF_OK &&
        entry) {
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

static metalbear_account_entry *
resolve_hostname_to_account(metalbear_server *server, const char *hostname) {
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
        status = metalbear_account_registry_find_by_handle(server->registry,
                                                           hostname, &entry);
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
    metalbear_account_entry *entry =
        resolve_hostname_to_account(server, hostname);
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
static wf_status handle_well_known_did(void *ctx,
                                       const wf_xrpc_request *request,
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
            cJSON_AddItemToArray(
                context, cJSON_CreateString("https://www.w3.org/ns/did/v1"));
            cJSON_AddItemToObject(doc, "@context", context);
            cJSON_AddStringToObject(doc, "id", server->service_did);
            cJSON *services = cJSON_CreateArray();
            cJSON *service = cJSON_CreateObject();
            cJSON_AddStringToObject(service, "id", "#atproto_pds");
            cJSON_AddStringToObject(service, "type",
                                    "AtprotoPersonalDataServer");
            cJSON_AddStringToObject(service, "serviceEndpoint",
                                    server->public_url ? server->public_url
                                                       : "");
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
    metalbear_account_entry *entry =
        resolve_hostname_to_account(server, hostname);
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

    const char *host =
        server->service_did && strncmp(server->service_did, "did:web:", 8) == 0
            ? server->service_did + 8
            : NULL;
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

static wf_status get_actor_preferences(void *ctx,
                                       const wf_xrpc_request *request,
                                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    char *prefs_json = NULL;
    if (metalbear_account_store_prefs_get(acct->account, &prefs_json) !=
            WF_OK ||
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

static wf_status put_actor_preferences(void *ctx,
                                       const wf_xrpc_request *request,
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
    cJSON *parsed =
        cJSON_ParseWithLength((const char *)request->body, request->body_len);
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
    wf_status status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/.well-known/did.json", handle_well_known_did,
        server);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_http_route(server->xrpc, "GET",
                                                "/.well-known/atproto-did",
                                                handle_atproto_did, server);
    if (status != WF_OK) return status;
    /* Path-form did:web accounts: /acct/<name>/did.json. */
    status = wf_xrpc_server_register_http_prefix(
        server->xrpc, "GET", "/acct/", handle_account_did_web, server);
    if (status != WF_OK) return status;
    status = metalbear_status_register(server);
    if (status != WF_OK) return status;
    static const char robots[] = "User-agent: *\nAllow: /\n";
    status = wf_xrpc_server_register_static_get(server->xrpc, "/robots.txt",
                                                "text/plain; charset=utf-8",
                                                robots, sizeof(robots) - 1);
    if (status != WF_OK) return status;

    status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/tls-check", tls_check_handler, server);
    if (status != WF_OK) return status;

    status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/operator.json", operator_info, server);
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
        server->public_url = public_url_from_service_did(server->service_did);
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
                metalbear_account_context *acct = metalbear_account_cache_get(
                    server->account_cache, server->registry, entries[i].did);
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
        wf_xrpc_server_register_query(server->xrpc,
                                      "com.atproto.server.getServiceAuth",
                                      get_service_auth, server) != WF_OK ||
        metalbear_xrpc_server_register_pds_repo_resolver_ex(
            server->xrpc, metalbear_repo_resolver, server, server->service_did,
            server->public_url, resolve_did_doc_json, server, server->lexicons,
            repo_access_guard, server, server->accepting_imports,
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

    if (server->appview_url && server->appview_url[0]) {
        wf_xrpc_server_set_fallback(server->xrpc, proxy_fallback, server);
    }

    wf_xrpc_server_set_auth_callback(server->xrpc, authenticate, server);

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
                                      check_signup_queue, server) != WF_OK) {
        LOG_ERROR("cannot register email/invite routes");
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
    metalbear_email_free(server->email);
    metalbear_handle_dns_free(server->handle_dns);
    metalbear_update_watcher_free(server->update_watcher);
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
    wf_lexicon_registry_free(server->lexicons);
    free(server);
}

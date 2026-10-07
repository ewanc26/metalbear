/* Per-request guards: takedown and deactivation checks, rate limits and the
 * repo access guard. */

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
bool metalbear_repo_access_guard(void *ctx, const wf_xrpc_request *req,
                                 const char *record_uri,
                                 wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (record_uri) {
        char *ref = NULL;
        metalbear_account_registry_get_takedown(server->registry, NULL,
                                                record_uri, NULL, &ref);
        if (!ref) return true;
        free(ref);
        wf_xrpc_response_set_error(resp, 400, "RecordNotFound",
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

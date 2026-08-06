#include "sync_routes.h"
#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static wf_status set_car_response(wf_xrpc_response *response,
                                  unsigned char *data, size_t length) {
    wf_xrpc_response_set_body(response, (const char *)data, length);
    wf_xrpc_response_set_content_type(response, "application/vnd.ipld.car");
    free(data);
    return response->body || length == 0 ? WF_OK : WF_ERR_ALLOC;
}

wf_status get_repo(void *ctx, const wf_xrpc_request *request,
                   wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    cJSON *since =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "since")
            : NULL;
    LOG_DEBUG("get_repo: did=%s since=%s",
              cJSON_IsString(did) ? did->valuestring : "-",
              cJSON_IsString(since) ? since->valuestring : "-");
    if (!cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!assert_repo_available(server, acct, request, response)) return WF_OK;
    unsigned char *data = NULL;
    size_t length = 0;
    wf_status status = metalbear_repo_store_export(
        acct->repo, cJSON_IsString(since) ? since->valuestring : NULL, &data,
        &length);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is empty or unavailable");
        return WF_OK;
    }
    return set_car_response(response, data, length);
}

wf_status get_blocks(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    if (!cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!assert_repo_available(server, acct, request, response)) return WF_OK;
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
    wf_status status = metalbear_repo_store_get_blocks(
        acct->repo, cids, cid_count, &data, &length);
    free(cids);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "BlockNotFound",
                                   "One or more blocks were not found");
        return WF_OK;
    }
    return set_car_response(response, data, length);
}

wf_status get_repo_status(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    metalbear_account_context *acct =
        cJSON_IsString(did) ? resolve_request_context(server, request) : NULL;
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
    if (active &&
        metalbear_repo_store_get_head(acct->repo, &rev, &cid) == WF_OK)
        cJSON_AddStringToObject(root, "rev", rev);
    free(rev);
    free(cid);
    return set_json(response, root);
}

/* ---- com.atproto.sync.listBlobs (query) ---- */
wf_status list_blobs(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    metalbear_account_context *acct =
        cJSON_IsString(did) ? resolve_request_context(server, request) : NULL;
    if (!assert_repo_available(server, acct, request, response)) return WF_OK;
    /* 'since' is accepted for lexicon compatibility; MetalBear's blob store
     * does not track per-blob revisions, so all available blobs are listed. */
    int limit = query_param_int(request->params, "limit", 500, 1, 1000);
    cJSON *cursor_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor")
            : NULL;
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
        cJSON_Delete(root);
        cJSON_Delete(cids);
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

/* Blob-ref discovery lives in blob_store.h (metalbear_blob_walk_refs) — the
 * write path needs the same walk to associate/dereference blobs on record
 * writes, so it is shared rather than duplicated here. */

typedef struct missing_blob_ref {
    char *cid;
    char *record_uri;
} missing_blob_ref;

typedef struct missing_blobs_scan {
    metalbear_blob_store *blobs_store;
    const char *cursor;     /* keep only CIDs > cursor */
    missing_blob_ref *refs; /* deduped missing refs, unsorted */
    size_t count;
    const char *did;
    const char *collection; /* current record's collection */
    const char *rkey;       /* current record's rkey */
} missing_blobs_scan;

static void missing_blob_candidate(const char *cid, void *opaque) {
    missing_blobs_scan *scan = opaque;
    if (scan->cursor && strcmp(cid, scan->cursor) <= 0) return;
    for (size_t i = 0; i < scan->count; i++)
        if (strcmp(scan->refs[i].cid, cid) == 0) return;
    if (metalbear_blob_store_exists(scan->blobs_store, cid) == WF_OK) return;
    /* Missing and not seen yet: record it (first record URI wins, matching
     * rsky's GROUP BY which keeps one row per CID). */
    missing_blob_ref *grown =
        realloc(scan->refs, (scan->count + 1) * sizeof(*scan->refs));
    if (!grown) return;
    scan->refs = grown;
    size_t uri_len =
        strlen(scan->did) + strlen(scan->collection) + strlen(scan->rkey) + 10;
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
    metalbear_blob_walk_refs(value, missing_blob_candidate, scan);
    cJSON_Delete(value);
    return WF_OK;
}

static int missing_blob_ref_cmp(const void *a, const void *b) {
    return strcmp(((const missing_blob_ref *)a)->cid,
                  ((const missing_blob_ref *)b)->cid);
}

wf_status list_missing_blobs(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    int limit = query_param_int(request->params, "limit", 500, 1, 1000);
    cJSON *cursor_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor")
            : NULL;

    missing_blobs_scan scan = {0};
    scan.blobs_store = acct->blobs;
    scan.cursor = cJSON_IsString(cursor_param) && cursor_param->valuestring[0]
                      ? cursor_param->valuestring
                      : NULL;
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
wf_status get_record(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    cJSON *collection =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "collection")
            : NULL;
    cJSON *rkey =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "rkey")
            : NULL;
    cJSON *as_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "as")
            : NULL;
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
    if (!assert_repo_available(server, acct, request, response)) return WF_OK;
    unsigned char *data = NULL;
    size_t length = 0;
    wf_status status = metalbear_repo_store_get_record_car(
        acct->repo, collection->valuestring, rkey->valuestring, &data, &length);
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

void sync_configure_crawler_notify(time_t seconds) {
    if (seconds > 0) crawler_notify_seconds = seconds;
}

typedef struct crawler_notice {
    char *crawlers; /* owned copy: comma-separated */
    char *body;     /* owned: {"hostname":"..."} */
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

void notify_crawlers(void *ctx) {
    metalbear_server *server = ctx;
    if (!server->crawlers || !server->crawlers[0]) return;
    const char *hostname = server->public_url;
    if (!hostname) return;
    if (strncmp(hostname, "https://", 8) == 0)
        hostname += 8;
    else if (strncmp(hostname, "http://", 7) == 0)
        hostname += 7;
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

wf_status request_crawl(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    if (!server->crawlers || !server->crawlers[0]) {
        wf_xrpc_response_set_error(response, 400, "NoCrawlersConfigured",
                                   "no crawlers are configured on this PDS");
        return WF_OK;
    }
    cJSON *hostname =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "hostname")
            : NULL;
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
        wf_status status = wf_xrpc_procedure(
            client, "com.atproto.sync.requestCrawl", body, &upstream);
        bool ok =
            status == WF_OK && upstream.status >= 200 && upstream.status < 300;
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

/* ---- com.atproto.sync.getHead (query) ----
 * DEPRECATED: returns the repo head CID. Thin wrapper around the same
 * head-reader used by getLatestCommit. */
wf_status get_head(void *ctx, const wf_xrpc_request *request,
                   wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
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
    if (!out) {
        free(rev);
        free(cid);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(out, "root", cid ? cid : "");
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(rev);
    free(cid);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(response, js, strlen(js));
    free(js);
    return WF_OK;
}

/* ---- com.atproto.sync.getCheckout (query) ----
 * DEPRECATED: returns a CAR stream of the repo. Reuses getRepo's CAR export. */
wf_status get_checkout(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response) {
    return get_repo(ctx, request, response);
}

/* ---- com.atproto.sync.getBlob (query) ---- */
wf_status get_blob(void *ctx, const wf_xrpc_request *request,
                   wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *cid = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "cid")
                     : NULL;
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
    if (!assert_repo_available(server, acct, request, response)) return WF_OK;
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
    wf_status s = metalbear_blob_store_get(acct->blobs, cid->valuestring, &data,
                                           &len, &mime);
    if (s == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(response, 404, "BlobNotFound",
                                   "no blob stored for the given CID");
        return WF_OK;
    } else if (s != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "failed to read blob store");
        return WF_OK;
    }
    wf_xrpc_response_set_content_type(response,
                                      mime ? mime : "application/octet-stream");

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
wf_status list_repos_by_collection(void *ctx, const wf_xrpc_request *request,
                                   wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const cJSON *coll =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "collection")
            : NULL;
    if (!cJSON_IsString(coll) || !coll->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "collection is required");
        return WF_OK;
    }
    int limit = query_param_int(request->params, "limit", 500, 1, 2000);
    const cJSON *cursor_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor")
            : NULL;
    const char *cursor =
        cJSON_IsString(cursor_param) ? cursor_param->valuestring : "";

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
        if (metalbear_account_registry_list_after(server->registry, last_did,
                                                  (size_t)limit, &entries,
                                                  &count) != WF_OK)
            break;
        if (count < (size_t)limit) exhausted = true;
        for (size_t i = 0; i < count && emitted < (size_t)limit; i++) {
            snprintf(last_did, sizeof(last_did), "%s", entries[i].did);
            metalbear_account_context *acct =
                context_for_did(server, entries[i].did);
            if (!acct) continue;
            char *described = NULL;
            if (metalbear_repo_store_describe(acct->repo, &described) !=
                    WF_OK ||
                !described)
                continue;
            cJSON *desc = cJSON_Parse(described);
            free(described);
            if (!desc) continue;
            bool holds = false;
            const cJSON *cols =
                cJSON_GetObjectItemCaseSensitive(desc, "collections");
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

wf_status list_repos(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    LOG_DEBUG("list_repos: listed all hosted repos");
    int limit = query_param_int(request->params, "limit", 500, 1, 1000);
    cJSON *cursor_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor")
            : NULL;
    const char *cursor =
        cJSON_IsString(cursor_param) ? cursor_param->valuestring : "";

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
        if (metalbear_account_registry_list_after(server->registry, last_did,
                                                  (size_t)limit, &entries,
                                                  &count) != WF_OK)
            break;
        if (count < (size_t)limit) exhausted = true;
        for (size_t i = 0; i < count && emitted < (size_t)limit; i++) {
            snprintf(last_did, sizeof(last_did), "%s", entries[i].did);
            metalbear_account_context *acct =
                context_for_did(server, entries[i].did);
            if (!acct) continue;
            char *rev = NULL, *cid = NULL;
            if (metalbear_repo_store_get_head(acct->repo, &rev, &cid) !=
                WF_OK) {
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
            if (status) cJSON_AddStringToObject(repo, "status", status);
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

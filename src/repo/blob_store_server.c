/*
 * blob_store_server.c — register blob persistence/serving routes on an
 * wf_xrpc_server so MetalBear can act as a PDS for blobs.
 *
 * Routes:
 *   com.atproto.repo.uploadBlob (procedure): the request body IS the raw blob
 *     bytes with a Content-Type; the handler computes the raw multicodec CID,
 *     stores it, and returns { blob: { $type, mimeType, ref: {"$link": cid},
 * size } }. com.atproto.sync.getBlob (query): reads `did` (ignored) and `cid`
 * params, looks the blob up, and returns the raw bytes with the stored
 * Content-Type.
 */

#include "blob_store_server.h"
#include "../server_internal.h"

#include "metalbear/account/account_context.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/repo/blob_store.h"
#include "metalbear/repo/repo_store.h"
#include "wolfram/xrpc_server.h"
#include "wolfram/repo/cid.h"

#include <cJSON.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Internal routing bundle installed by the blob-store server registrations.
 * When `resolver` is NULL the handlers use the single `fallback_blobs`;
 * otherwise `resolver` picks the per-request blob store (and may also
 * resolve a repo store). The bundle is heap-allocated and owned by the
 * server (freed in wf_xrpc_server_free).
 */
typedef struct metalbear_pds_repo_bundle {
    metalbear_xrpc_repo_resolver resolver;
    void *resolver_ctx;
    metalbear_repo_store *fallback_repo;
    metalbear_blob_store *fallback_blobs;
} metalbear_pds_repo_bundle;

/*
 * Resolve the blob store for a request from the registration's bundle.
 * Returns the store to use (never NULL on success) or NULL after writing a
 * 400 AccountNotFound response when the resolver fails / resolves no store.
 * When no resolver is set the single fallback store is returned.
 */
static metalbear_blob_store *resolve_blobs(metalbear_pds_repo_bundle *b,
                                           const wf_xrpc_request *req,
                                           wf_xrpc_response *resp) {
    metalbear_blob_store *blobs = b->fallback_blobs;
    if (b->resolver) {
        metalbear_repo_store *out_repo = NULL;
        metalbear_blob_store *out_blobs = NULL;
        if (b->resolver(b->resolver_ctx, req, &out_repo, &out_blobs) != WF_OK ||
            !out_blobs) {
            wf_xrpc_response_set_error(resp, 400, "AccountNotFound",
                                       "Account is not hosted here");
            return NULL;
        }
        blobs = out_blobs;
    }
    return blobs;
}

/* Escape a string for inclusion inside a JSON string (returns owned buffer). */
static char *bs_json_escape(const char *s) {
    size_t need = 0;
    for (const char *p = s; p && *p; p++) {
        if (*p == '"' || *p == '\\')
            need += 2;
        else
            need += 1;
    }
    char *out = (char *)malloc(need + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (const char *p = s; p && *p; p++) {
        if (*p == '"' || *p == '\\') out[o++] = '\\';
        out[o++] = *p;
    }
    out[o] = '\0';
    return out;
}

static wf_status blob_upload_handler(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    metalbear_blob_store *store =
        resolve_blobs((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!store) return WF_OK;

    if (!req->body || req->body_len == 0) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "blob body is empty");
        return WF_OK;
    }

    const char *mime = req->content_type && req->content_type[0]
                           ? req->content_type
                           : "application/octet-stream";

    /* Compute the blob CID (raw multicodec, sha-256) — matches what a real
     * PDS returns and what metalbear_agent_sync_get_blob expects as the ref. */
    wf_cid cid;
    if (wf_cid_of_bytes(req->body, req->body_len, &cid) != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "failed to compute blob CID");
        return WF_OK;
    }
    char *cid_str = wf_cid_to_string(&cid);
    if (!cid_str) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "failed to encode blob CID");
        return WF_OK;
    }

    if (metalbear_blob_store_put(store, cid_str, mime, req->body,
                                 req->body_len) != WF_OK) {
        free(cid_str);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "failed to store blob");
        return WF_OK;
    }

    char *esc_mime = bs_json_escape(mime);
    if (!esc_mime) {
        free(cid_str);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "failed to build response");
        return WF_OK;
    }

    /* TypedBlobRef shape per the com.atproto.repo.uploadBlob output schema. */
    char *json = (char *)malloc(strlen(cid_str) + strlen(esc_mime) + 128);
    if (!json) {
        free(cid_str);
        free(esc_mime);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "failed to build response");
        return WF_OK;
    }
    snprintf(json, strlen(cid_str) + strlen(esc_mime) + 128,
             "{\"blob\":{\"$type\":\"blob\",\"mimeType\":\"%s\","
             "\"ref\":{\"$link\":\"%s\"},\"size\":%zu}}",
             esc_mime, cid_str, req->body_len);

    wf_xrpc_response_set_body(resp, json, strlen(json));
    free(json);
    free(cid_str);
    free(esc_mime);
    return WF_OK;
}

static wf_status blob_get_handler(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    metalbear_blob_store *store =
        resolve_blobs((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!store) return WF_OK;

    cJSON *cid = req->params
                     ? cJSON_GetObjectItemCaseSensitive(req->params, "cid")
                     : NULL;
    if (!cJSON_IsString(cid) || !cid->valuestring || !*cid->valuestring) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "missing or invalid 'cid' parameter");
        return WF_OK;
    }

    unsigned char *data = NULL;
    size_t len = 0;
    char *mime = NULL;
    wf_status s =
        metalbear_blob_store_get(store, cid->valuestring, &data, &len, &mime);
    if (s == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(resp, 404, "BlobNotFound",
                                   "no blob stored for the given CID");
        return WF_OK;
    } else if (s != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "failed to read blob store");
        return WF_OK;
    }

    /* Serve the raw bytes with the stored Content-Type.
     *
     * Blobs are attacker-supplied bytes served from the PDS's own origin,
     * so they must never be interpretable as a document there -- see the
     * matching, more detailed comment on com.atproto.sync.getBlob in
     * sync_routes.c, which this mirrors exactly. This registration path
     * (metalbear_xrpc_server_register_blob_store[_resolver], used directly
     * by embedders rather than through the full PDS route registration in
     * server.c) previously omitted all three headers, serving blobs with
     * nothing stopping a browser from rendering an uploaded HTML/SVG blob
     * as same-origin script. */
    wf_xrpc_response_set_content_type(resp, mime);
    wf_xrpc_response_add_header(resp, "X-Content-Type-Options", "nosniff");
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
    wf_xrpc_response_add_header(resp, "Content-Disposition", disposition);
    wf_xrpc_response_add_header(resp, "Content-Security-Policy",
                                "default-src 'none'; sandbox");
    wf_xrpc_response_set_body(resp, (const char *)data, len);
    free(data);
    free(mime);
    return WF_OK;
}

/* ---- com.atproto.repo.uploadBlob (procedure) ----
 * Mirrors the resolver-less/resolver-based handlers above but runs against
 * the full PDS server context: enforces METALBEAR_BLOB_UPLOAD_LIMIT, resolves
 * the account via resolve_request_context, and checks for a blob takedown
 * before storing. Output shape matches the com.atproto.repo.uploadBlob
 * schema exactly. Registered directly by server.c (not through the bundle
 * used by metalbear_xrpc_server_register_blob_store[_resolver], which have
 * no account or rate-limit context to enforce). */
wf_status upload_blob(void *ctx, const wf_xrpc_request *request,
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

wf_status
metalbear_xrpc_server_register_blob_store(wf_xrpc_server *server,
                                          metalbear_blob_store *store) {
    if (!server || !store) {
        return WF_ERR_INVALID_ARG;
    }
    /* Single-store path: build a resolver-less bundle that always serves
     * `store`. The server owns the bundle and frees it on
     * wf_xrpc_server_free, preserving the caller-owned `store` contract. */
    metalbear_pds_repo_bundle *b =
        (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->fallback_blobs = store;
    wf_xrpc_server_own_ctx(server, b, free);
    wf_status s = wf_xrpc_server_register_procedure(
        server, "com.atproto.repo.uploadBlob", blob_upload_handler, b);
    if (s != WF_OK) return s;
    return wf_xrpc_server_register_query(server, "com.atproto.sync.getBlob",
                                         blob_get_handler, b);
}

wf_status metalbear_xrpc_server_register_blob_store_resolver(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx) {
    if (!server) return WF_ERR_INVALID_ARG;
    metalbear_pds_repo_bundle *b =
        (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->resolver = resolver;
    b->resolver_ctx = ctx;
    wf_xrpc_server_own_ctx(server, b, free);
    wf_status s = wf_xrpc_server_register_procedure(
        server, "com.atproto.repo.uploadBlob", blob_upload_handler, b);
    if (s != WF_OK) return s;
    return wf_xrpc_server_register_query(server, "com.atproto.sync.getBlob",
                                         blob_get_handler, b);
}

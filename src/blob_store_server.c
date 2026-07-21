/*
 * blob_store_server.c — register blob persistence/serving routes on an
 * wf_xrpc_server so MetalBear can act as a PDS for blobs.
 *
 * Routes:
 *   com.atproto.repo.uploadBlob (procedure): the request body IS the raw blob
 *     bytes with a Content-Type; the handler computes the raw multicodec CID,
 *     stores it, and returns { blob: { $type, mimeType, ref: {"$link": cid}, size } }.
 *   com.atproto.sync.getBlob (query): reads `did` (ignored) and `cid` params,
 *     looks the blob up, and returns the raw bytes with the stored Content-Type.
 */

#include "metalbear/blob_store.h"
#include "metalbear/repo_store.h"
#include "wolfram/xrpc_server.h"
#include "wolfram/repo/cid.h"

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
        if (*p == '"' || *p == '\\') need += 2;
        else need += 1;
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
    metalbear_blob_store *store = resolve_blobs((metalbear_pds_repo_bundle *)ctx, req, resp);
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
        free(cid_str); free(esc_mime);
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
    metalbear_blob_store *store = resolve_blobs((metalbear_pds_repo_bundle *)ctx, req, resp);
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
    wf_status s = metalbear_blob_store_get(store, cid->valuestring, &data, &len, &mime);
    if (s == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(resp, 404, "BlobNotFound",
                                    "no blob stored for the given CID");
        return WF_OK;
    } else if (s != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                    "failed to read blob store");
        return WF_OK;
    }

    /* Serve the raw bytes with the stored Content-Type. */
    wf_xrpc_response_set_content_type(resp, mime);
    wf_xrpc_response_set_body(resp, (const char *)data, len);
    free(data);
    free(mime);
    return WF_OK;
}

wf_status metalbear_xrpc_server_register_blob_store(wf_xrpc_server *server,
                                              metalbear_blob_store *store) {
    if (!server || !store) {
        return WF_ERR_INVALID_ARG;
    }
    /* Single-store path: build a resolver-less bundle that always serves
     * `store`. The server owns the bundle and frees it on
     * wf_xrpc_server_free, preserving the caller-owned `store` contract. */
    metalbear_pds_repo_bundle *b = (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->fallback_blobs = store;
    wf_xrpc_server_own_ctx(server, b, free);
    wf_status s = wf_xrpc_server_register_procedure(
        server, "com.atproto.repo.uploadBlob", blob_upload_handler, b);
    if (s != WF_OK) return s;
    return wf_xrpc_server_register_query(
        server, "com.atproto.sync.getBlob", blob_get_handler, b);
}

wf_status metalbear_xrpc_server_register_blob_store_resolver(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx) {
    if (!server) return WF_ERR_INVALID_ARG;
    metalbear_pds_repo_bundle *b = (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->resolver = resolver;
    b->resolver_ctx = ctx;
    wf_xrpc_server_own_ctx(server, b, free);
    wf_status s = wf_xrpc_server_register_procedure(
        server, "com.atproto.repo.uploadBlob", blob_upload_handler, b);
    if (s != WF_OK) return s;
    return wf_xrpc_server_register_query(
        server, "com.atproto.sync.getBlob", blob_get_handler, b);
}

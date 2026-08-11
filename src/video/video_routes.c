/*
 * video_routes.c — app.bsky.video.* handlers.
 *
 * Minimal, self-contained video support: a video upload is stored as an
 * ordinary blob in the account's blob store and the job is reported completed
 * immediately, because MetalBear performs no transcoding. The job is
 * stateless: everything getJobStatus needs to reconstruct a finished job is
 * encoded in the job ID (vid-<unix_ts>-<cid>-<size>). A production
 * deployment that wants HLS playlists / thumbnails would hand the blob off to
 * an external video processor instead; the wire contract here matches the
 * app.bsky.video lexicons regardless.
 */

#include "video_routes.h"
#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/account/account_context.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/repo/blob_store.h"
#include "wolfram/repo/cid.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* app.bsky.embed.video#main's video blob accepts up to 100mb. */
#define METALBEAR_VIDEO_MAX_BYTES (100u * 1024u * 1024u)

/* job ID layout: vid-<unix_ts>-<cid>-<size>; the CID alphabet (base32
 * lower) contains no '-', so a dash is an unambiguous field separator. */
#define METALBEAR_VIDEO_JOB_PREFIX "vid-"
#define METALBEAR_VIDEO_JOB_PREFIX_LEN (sizeof(METALBEAR_VIDEO_JOB_PREFIX) - 1)

/*
 * Reconstruct the state a vid- job ID encodes: the blob CID and its size.
 * Returns true and sets out_cid (owned, free() by caller) / out_size on
 * success, false when job_id is not one of ours.
 */
static bool video_parse_job_id(const char *job_id, char **out_cid,
                               int64_t *out_size) {
    if (!job_id || strncmp(job_id, METALBEAR_VIDEO_JOB_PREFIX,
                           METALBEAR_VIDEO_JOB_PREFIX_LEN) != 0) {
        return false;
    }
    const char *rest = job_id + METALBEAR_VIDEO_JOB_PREFIX_LEN;
    char *end = NULL;
    (void)strtoll(rest, &end, 10); /* unix timestamp, not used */
    if (!end || *end != '-') {
        return false;
    }
    rest = end + 1;
    const char *dash = strchr(rest, '-');
    if (!dash || dash == rest) {
        return false;
    }
    char *cid = strndup(rest, (size_t)(dash - rest));
    if (!cid) {
        return false;
    }
    long long size = strtoll(dash + 1, &end, 10);
    if (!end || *end != '\0' || size < 0) {
        free(cid);
        return false;
    }
    *out_cid = cid;
    *out_size = (int64_t)size;
    return true;
}

/* ---- app.bsky.video.uploadVideo (procedure) ---- */

wf_status video_upload(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    LOG_DEBUG("video_upload: did=%s content_type=%s len=%zu",
              request->authed_subject ? request->authed_subject : "-",
              request->content_type ? request->content_type : "-",
              (size_t)request->body_len);
    if (request->body_len == 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "video body is empty");
        return WF_OK;
    }
    if (request->body_len > METALBEAR_VIDEO_MAX_BYTES) {
        wf_xrpc_response_set_error(response, 413, "InvalidRequest",
                                   "video exceeds the 100MB upload limit");
        return WF_OK;
    }
    const char *mime = request->content_type && request->content_type[0]
                           ? request->content_type
                           : "video/mp4";
    if (strcmp(mime, "video/mp4") != 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "video must be video/mp4");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    wf_cid cid;
    if (wf_cid_of_bytes(request->body, request->body_len, &cid) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "failed to compute video CID");
        return WF_OK;
    }
    char *cid_str = wf_cid_to_string(&cid);
    if (!cid_str) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "failed to encode video CID");
        return WF_OK;
    }
    if (metalbear_blob_store_put(acct->blobs, cid_str, mime, request->body,
                                 request->body_len) != WF_OK) {
        free(cid_str);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "failed to store video blob");
        return WF_OK;
    }
    metalbear_metrics_inc(METALBEAR_METRIC_BLOBS_UPLOADED);

    char job_id[320];
    snprintf(job_id, sizeof(job_id), METALBEAR_VIDEO_JOB_PREFIX "%lld-%s-%zu",
             (long long)time(NULL), cid_str, (size_t)request->body_len);

    cJSON *root = cJSON_CreateObject();
    cJSON *job_status = cJSON_CreateObject();
    cJSON *blob = cJSON_CreateObject();
    cJSON *ref = cJSON_CreateObject();
    if (!root || !job_status || !blob || !ref) {
        cJSON_Delete(root);
        cJSON_Delete(job_status);
        cJSON_Delete(blob);
        cJSON_Delete(ref);
        free(cid_str);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(job_status, "jobId", job_id);
    cJSON_AddStringToObject(job_status, "did", acct->did);
    cJSON_AddStringToObject(job_status, "state", "JOB_STATE_COMPLETED");
    cJSON_AddNumberToObject(job_status, "progress", 100);
    cJSON_AddStringToObject(blob, "$type", "blob");
    cJSON_AddStringToObject(blob, "mimeType", mime);
    cJSON_AddStringToObject(ref, "$link", cid_str);
    cJSON_AddItemToObject(blob, "ref", ref);
    cJSON_AddNumberToObject(blob, "size", (double)request->body_len);
    cJSON_AddItemToObject(job_status, "blob", blob);
    cJSON_AddItemToObject(root, "jobStatus", job_status);
    free(cid_str);
    return set_json(response, root);
}

/* ---- app.bsky.video.getJobStatus (query) ---- */

wf_status video_get_job_status(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const char *job_id = NULL;
    const cJSON *params = request->params;
    if (params) {
        cJSON *jid = cJSON_GetObjectItem(params, "jobId");
        if (cJSON_IsString(jid)) job_id = jid->valuestring;
    }
    char *cid = NULL;
    int64_t size = 0;
    if (!video_parse_job_id(job_id, &cid, &size)) {
        wf_xrpc_response_set_error(response, 404, "NotFound", "job not found");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        free(cid);
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    bool have_blob = metalbear_blob_store_exists(acct->blobs, cid) == WF_OK;

    cJSON *root = cJSON_CreateObject();
    cJSON *job_status = cJSON_CreateObject();
    if (!root || !job_status) {
        cJSON_Delete(root);
        cJSON_Delete(job_status);
        free(cid);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(job_status, "jobId", job_id);
    cJSON_AddStringToObject(job_status, "did", acct->did);
    cJSON_AddStringToObject(job_status, "state", "JOB_STATE_COMPLETED");
    cJSON_AddNumberToObject(job_status, "progress", 100);
    if (have_blob) {
        cJSON *blob = cJSON_CreateObject();
        cJSON *ref = cJSON_CreateObject();
        if (!blob || !ref) {
            cJSON_Delete(blob);
            cJSON_Delete(ref);
            cJSON_Delete(root);
            cJSON_Delete(job_status);
            free(cid);
            return WF_ERR_ALLOC;
        }
        cJSON_AddStringToObject(blob, "$type", "blob");
        cJSON_AddStringToObject(blob, "mimeType", "video/mp4");
        cJSON_AddStringToObject(ref, "$link", cid);
        cJSON_AddItemToObject(blob, "ref", ref);
        cJSON_AddNumberToObject(blob, "size", (double)size);
        cJSON_AddItemToObject(job_status, "blob", blob);
    }
    cJSON_AddItemToObject(root, "jobStatus", job_status);
    free(cid);
    return set_json(response, root);
}

/* ---- app.bsky.video.getUploadLimits (query) ---- */

wf_status video_get_upload_limits(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    (void)ctx;
    (void)request;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "canUpload", true);
    cJSON_AddNumberToObject(root, "remainingDailyVideos", 100);
    cJSON_AddNumberToObject(root, "remainingDailyBytes", 1073741824);
    return set_json(response, root);
}

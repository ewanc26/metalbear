/*
 * video_routes.c — app.bsky.video.* handlers.
 *
 * The legacy single-request route stores an ordinary account blob and reports
 * it completed immediately; its stateless vid- job ID carries everything
 * getJobStatus needs. The current multipart routes use the account's durable
 * SQLite upload store and bounded streamed part files, then publish the
 * assembled object through that same blob store. MetalBear performs no
 * transcoding; a deployment that wants HLS or thumbnails can hand the finished
 * blob to an external processor without changing the upload-phase contract.
 */

#include "video_routes.h"
#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/video.h"
#include "metalbear/video_upload.h"
#include "metalbear/account/account_context.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/repo/blob_store.h"
#include "wolfram/repo/cid.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
                                   "video exceeds the 300MB upload limit");
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
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    uint64_t bytes = 0;
    uint32_t videos = 0, open = 0;
    metalbear_video_upload_get_limits(acct->video_uploads, &bytes, &videos,
                                      &open);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "canUpload", true);
    cJSON_AddNumberToObject(root, "remainingDailyVideos", videos);
    cJSON_AddNumberToObject(root, "remainingDailyBytes", (double)bytes);
    return set_json(response, root);
}

/* ---- durable multipart upload procedures ---- */

typedef struct video_part_stream {
    metalbear_video_part_writer *writer;
    uint32_t part_number;
    uint64_t size_bytes;
} video_part_stream;

static const char *upload_state_name(metalbear_video_upload_state state) {
    switch (state) {
        case METALBEAR_VIDEO_UPLOAD_CREATED:
            return "created";
        case METALBEAR_VIDEO_UPLOAD_FINISHING:
            return "finishing";
        case METALBEAR_VIDEO_UPLOAD_COMPLETED:
            return "completed";
        case METALBEAR_VIDEO_UPLOAD_FAILED:
            return "failed";
        case METALBEAR_VIDEO_UPLOAD_ABORTED:
            return "aborted";
        case METALBEAR_VIDEO_UPLOAD_EXPIRED:
            return "expired";
    }
    return "failed";
}

static wf_status upload_error(wf_xrpc_response *response,
                              metalbear_video_upload_result result,
                              const char *detail) {
    int status = 400;
    const char *error = "InvalidRequest";
    const char *message = detail && detail[0] ? detail : "invalid upload";
    switch (result) {
        case METALBEAR_VIDEO_UPLOAD_NOT_FOUND:
            status = 404;
            error = "UploadNotFound";
            message = "upload was not found";
            break;
        case METALBEAR_VIDEO_UPLOAD_EXPIRED_RESULT:
            error = "UploadExpired";
            message = "upload has expired";
            break;
        case METALBEAR_VIDEO_UPLOAD_INVALID_PART:
            error = "InvalidPartNumber";
            message = "part number is outside the upload range";
            break;
        case METALBEAR_VIDEO_UPLOAD_PART_SIZE_MISMATCH:
            error = "PartSizeMismatch";
            message = "Content-Length does not match the expected part size";
            break;
        case METALBEAR_VIDEO_UPLOAD_NOT_READY:
            status = 409;
            error = "UploadNotReady";
            message =
                "upload finalisation or another part write is in progress";
            break;
        case METALBEAR_VIDEO_UPLOAD_FAILED_RESULT:
            error = "UploadFailed";
            message = detail && detail[0] ? detail : "upload has failed";
            break;
        case METALBEAR_VIDEO_UPLOAD_ABORTED_RESULT:
            error = "UploadAborted";
            message = "upload has been aborted";
            break;
        case METALBEAR_VIDEO_UPLOAD_ALREADY_COMPLETED:
            error = "UploadAlreadyCompleted";
            message = "upload has already completed";
            break;
        case METALBEAR_VIDEO_UPLOAD_MISSING_PARTS:
            error = "MissingParts";
            message = detail && detail[0] ? detail : "upload has missing parts";
            break;
        case METALBEAR_VIDEO_UPLOAD_UNSUPPORTED_CONTENT_TYPE:
            error = "UnsupportedContentType";
            message = "only video/mp4 is supported";
            break;
        case METALBEAR_VIDEO_UPLOAD_TOO_LARGE:
            error = "VideoTooLarge";
            message = "video exceeds the 300MB upload limit";
            break;
        case METALBEAR_VIDEO_UPLOAD_DAILY_LIMIT:
            status = 429;
            error = "DailyLimitExceeded";
            message = "daily video allowance is exhausted";
            break;
        case METALBEAR_VIDEO_UPLOAD_TOO_MANY_OPEN:
            status = 429;
            error = "TooManyOpenUploads";
            message = "too many multipart uploads are open";
            break;
        case METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED:
            status = 503;
            error = "ServiceOverloaded";
            message = "video upload storage is temporarily unavailable";
            break;
        case METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST:
            error = "InvalidRequest";
            break;
        case METALBEAR_VIDEO_UPLOAD_INTERNAL:
            status = 500;
            error = "InternalError";
            message = "video upload failed internally";
            break;
        case METALBEAR_VIDEO_UPLOAD_OK:
            return WF_OK;
    }
    wf_xrpc_response_set_error(response, status, error, message);
    return WF_OK;
}

static const char *json_job_id(const wf_xrpc_request *request) {
    cJSON *job =
        request->params ? cJSON_GetObjectItem(request->params, "jobId") : NULL;
    return cJSON_IsString(job) ? job->valuestring : NULL;
}

static cJSON *
completed_job_status(const metalbear_account_context *acct,
                     const metalbear_video_upload_status *status) {
    cJSON *job = cJSON_CreateObject();
    cJSON *blob = cJSON_CreateObject();
    cJSON *ref = cJSON_CreateObject();
    if (!job || !blob || !ref) {
        cJSON_Delete(job);
        cJSON_Delete(blob);
        cJSON_Delete(ref);
        return NULL;
    }
    cJSON_AddStringToObject(job, "jobId", status->completed_job_id);
    cJSON_AddStringToObject(job, "did", acct->did);
    cJSON_AddStringToObject(job, "state", "JOB_STATE_COMPLETED");
    cJSON_AddNumberToObject(job, "progress", 100);
    cJSON_AddStringToObject(blob, "$type", "blob");
    cJSON_AddStringToObject(blob, "mimeType", status->mime_type);
    cJSON_AddStringToObject(ref, "$link", status->cid);
    cJSON_AddItemToObject(blob, "ref", ref);
    cJSON_AddNumberToObject(blob, "size", (double)status->size_bytes);
    cJSON_AddItemToObject(job, "blob", blob);
    return job;
}

static cJSON *upload_status_json(const metalbear_account_context *acct,
                                 const metalbear_video_upload_status *status) {
    cJSON *root = cJSON_CreateObject();
    cJSON *parts = cJSON_CreateArray();
    if (!root || !parts) {
        cJSON_Delete(root);
        cJSON_Delete(parts);
        return NULL;
    }
    cJSON_AddStringToObject(root, "jobId", status->job_id);
    cJSON_AddNumberToObject(root, "partSizeBytes",
                            (double)status->part_size_bytes);
    cJSON_AddNumberToObject(root, "partCount", status->part_count);
    for (size_t i = 0; i < status->received_part_count; ++i)
        cJSON_AddItemToArray(parts,
                             cJSON_CreateNumber(status->received_parts[i]));
    cJSON_AddItemToObject(root, "receivedParts", parts);
    cJSON_AddStringToObject(root, "expiresAt", status->expires_at);
    cJSON_AddStringToObject(root, "state", upload_state_name(status->state));
    if (status->state == METALBEAR_VIDEO_UPLOAD_COMPLETED) {
        cJSON_AddStringToObject(root, "completedJobId",
                                status->completed_job_id);
        cJSON *job = completed_job_status(acct, status);
        if (!job) {
            cJSON_Delete(root);
            return NULL;
        }
        cJSON_AddItemToObject(root, "jobStatus", job);
    } else if (status->state == METALBEAR_VIDEO_UPLOAD_FAILED) {
        cJSON_AddStringToObject(root, "failureReason", status->failure_reason);
    }
    return root;
}

wf_status video_start_upload(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    cJSON *size = request->params
                      ? cJSON_GetObjectItem(request->params, "sizeBytes")
                      : NULL;
    cJSON *mime = request->params
                      ? cJSON_GetObjectItem(request->params, "mimeType")
                      : NULL;
    cJSON *name =
        request->params ? cJSON_GetObjectItem(request->params, "name") : NULL;
    if (!cJSON_IsNumber(size) || size->valuedouble < 1 ||
        size->valuedouble > (double)UINT64_MAX ||
        (double)(uint64_t)size->valuedouble != size->valuedouble ||
        !cJSON_IsString(mime)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "sizeBytes and mimeType are required");
        return WF_OK;
    }
    metalbear_video_upload_status status = {0};
    metalbear_video_upload_result result = metalbear_video_upload_start(
        acct->video_uploads, (uint64_t)size->valuedouble, mime->valuestring,
        cJSON_IsString(name) ? name->valuestring : NULL, &status);
    if (result != METALBEAR_VIDEO_UPLOAD_OK)
        return upload_error(response, result, NULL);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "jobId", status.job_id);
    cJSON_AddNumberToObject(root, "partSizeBytes",
                            (double)status.part_size_bytes);
    cJSON_AddNumberToObject(root, "partCount", status.part_count);
    cJSON_AddStringToObject(root, "expiresAt", status.expires_at);
    return set_json(response, root);
}

static wf_status video_upload_part_begin(void *ctx,
                                         const wf_xrpc_request *request,
                                         void **out_stream_ctx,
                                         wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    if (!request->has_content_length) {
        wf_xrpc_response_set_error(response, 411, "PartSizeMismatch",
                                   "Content-Length is required");
        return WF_OK;
    }
    if (!request->content_type ||
        strcmp(request->content_type, "application/octet-stream") != 0) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "part body must be application/octet-stream");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    const char *job_id = json_job_id(request);
    int part_number = query_param_int(request->params, "partNumber", 0, 0,
                                      METALBEAR_VIDEO_MAX_PARTS + 1);
    if (!job_id || part_number < 1) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "jobId and partNumber are required");
        return WF_OK;
    }
    video_part_stream *stream = calloc(1, sizeof(*stream));
    if (!stream) return WF_ERR_ALLOC;
    metalbear_video_upload_result result = metalbear_video_upload_part_begin(
        acct->video_uploads, job_id, (uint32_t)part_number,
        request->content_length, &stream->writer);
    if (result != METALBEAR_VIDEO_UPLOAD_OK) {
        free(stream);
        return upload_error(response, result, NULL);
    }
    stream->part_number = (uint32_t)part_number;
    stream->size_bytes = request->content_length;
    *out_stream_ctx = stream;
    return WF_OK;
}

static wf_status video_upload_part_write(void *ctx, void *stream_ctx,
                                         const unsigned char *data,
                                         size_t data_len,
                                         wf_xrpc_response *response) {
    (void)ctx;
    video_part_stream *stream = stream_ctx;
    metalbear_video_upload_result result =
        metalbear_video_upload_part_write(stream->writer, data, data_len);
    return result == METALBEAR_VIDEO_UPLOAD_OK
               ? WF_OK
               : upload_error(response, result, NULL);
}

static wf_status video_upload_part_finish(void *ctx, void *stream_ctx,
                                          wf_xrpc_response *response) {
    (void)ctx;
    video_part_stream *stream = stream_ctx;
    metalbear_video_upload_result result =
        metalbear_video_upload_part_finish(stream->writer);
    if (result != METALBEAR_VIDEO_UPLOAD_OK)
        return upload_error(response, result, NULL);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddNumberToObject(root, "partNumber", stream->part_number);
    cJSON_AddNumberToObject(root, "sizeBytes", (double)stream->size_bytes);
    return set_json(response, root);
}

static void video_upload_part_cleanup(void *ctx, void *stream_ctx,
                                      bool completed) {
    (void)ctx;
    (void)completed;
    video_part_stream *stream = stream_ctx;
    if (!stream) return;
    metalbear_video_upload_part_free(stream->writer);
    free(stream);
}

const wf_xrpc_streaming_procedure_handler video_upload_part_handler = {
    video_upload_part_begin, video_upload_part_write, video_upload_part_finish,
    video_upload_part_cleanup};

wf_status video_finish_upload(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    const char *job_id = json_job_id(request);
    if (!acct || !job_id) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "hosted account and jobId are required");
        return WF_OK;
    }
    metalbear_video_upload_status status = {0};
    char detail[1025];
    metalbear_video_upload_result result = metalbear_video_upload_finish(
        acct->video_uploads, job_id, &status, detail, sizeof(detail));
    if (result != METALBEAR_VIDEO_UPLOAD_OK)
        return upload_error(response, result,
                            result == METALBEAR_VIDEO_UPLOAD_FAILED_RESULT
                                ? status.failure_reason
                                : detail);
    cJSON *root = cJSON_CreateObject();
    cJSON *job = completed_job_status(acct, &status);
    if (!root || !job) {
        cJSON_Delete(root);
        cJSON_Delete(job);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "completedJobId", status.completed_job_id);
    cJSON_AddItemToObject(root, "jobStatus", job);
    return set_json(response, root);
}

wf_status video_abort_upload(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    const char *job_id = json_job_id(request);
    if (!acct || !job_id) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "hosted account and jobId are required");
        return WF_OK;
    }
    metalbear_video_upload_status status = {0};
    metalbear_video_upload_result result =
        metalbear_video_upload_abort(acct->video_uploads, job_id, &status);
    if (result != METALBEAR_VIDEO_UPLOAD_OK)
        return upload_error(response, result, status.failure_reason);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "state", upload_state_name(status.state));
    if (status.state == METALBEAR_VIDEO_UPLOAD_COMPLETED)
        cJSON_AddStringToObject(root, "completedJobId",
                                status.completed_job_id);
    if (status.state == METALBEAR_VIDEO_UPLOAD_FAILED)
        cJSON_AddStringToObject(root, "failureReason", status.failure_reason);
    return set_json(response, root);
}

wf_status video_get_upload_status(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    const char *job_id = json_job_id(request);
    if (!acct || !job_id) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "hosted account and jobId are required");
        return WF_OK;
    }
    metalbear_video_upload_status status = {0};
    metalbear_video_upload_result result =
        metalbear_video_upload_get_status(acct->video_uploads, job_id, &status);
    if (result != METALBEAR_VIDEO_UPLOAD_OK)
        return upload_error(response, result, NULL);
    cJSON *root = upload_status_json(acct, &status);
    return root ? set_json(response, root) : WF_ERR_ALLOC;
}

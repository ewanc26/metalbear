#ifndef METALBEAR_VIDEO_UPLOAD_H
#define METALBEAR_VIDEO_UPLOAD_H

#include "metalbear/repo/blob_store.h"
#include "metalbear/video.h"
#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define METALBEAR_VIDEO_PART_BYTES UINT64_C(5000000)
#define METALBEAR_VIDEO_MAX_PARTS 60
#define METALBEAR_VIDEO_MAX_OPEN_UPLOADS 4
#define METALBEAR_VIDEO_DAILY_BYTES UINT64_C(1073741824)
#define METALBEAR_VIDEO_DAILY_COUNT 100

typedef struct metalbear_video_upload_store metalbear_video_upload_store;
typedef struct metalbear_video_part_writer metalbear_video_part_writer;

typedef enum metalbear_video_upload_state {
    METALBEAR_VIDEO_UPLOAD_CREATED = 0,
    METALBEAR_VIDEO_UPLOAD_FINISHING,
    METALBEAR_VIDEO_UPLOAD_COMPLETED,
    METALBEAR_VIDEO_UPLOAD_FAILED,
    METALBEAR_VIDEO_UPLOAD_ABORTED,
    METALBEAR_VIDEO_UPLOAD_EXPIRED,
} metalbear_video_upload_state;

typedef enum metalbear_video_upload_result {
    METALBEAR_VIDEO_UPLOAD_OK = 0,
    METALBEAR_VIDEO_UPLOAD_NOT_FOUND,
    METALBEAR_VIDEO_UPLOAD_EXPIRED_RESULT,
    METALBEAR_VIDEO_UPLOAD_INVALID_PART,
    METALBEAR_VIDEO_UPLOAD_PART_SIZE_MISMATCH,
    METALBEAR_VIDEO_UPLOAD_NOT_READY,
    METALBEAR_VIDEO_UPLOAD_FAILED_RESULT,
    METALBEAR_VIDEO_UPLOAD_ABORTED_RESULT,
    METALBEAR_VIDEO_UPLOAD_ALREADY_COMPLETED,
    METALBEAR_VIDEO_UPLOAD_MISSING_PARTS,
    METALBEAR_VIDEO_UPLOAD_UNSUPPORTED_CONTENT_TYPE,
    METALBEAR_VIDEO_UPLOAD_TOO_LARGE,
    METALBEAR_VIDEO_UPLOAD_DAILY_LIMIT,
    METALBEAR_VIDEO_UPLOAD_TOO_MANY_OPEN,
    METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED,
    METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST,
    METALBEAR_VIDEO_UPLOAD_INTERNAL,
} metalbear_video_upload_result;

typedef struct metalbear_video_upload_status {
    char job_id[257];
    uint64_t size_bytes;
    uint64_t part_size_bytes;
    uint32_t part_count;
    uint32_t received_parts[METALBEAR_VIDEO_MAX_PARTS];
    size_t received_part_count;
    char expires_at[32];
    metalbear_video_upload_state state;
    char completed_job_id[257];
    char cid[128];
    char mime_type[256];
    char failure_reason[1025];
} metalbear_video_upload_status;

wf_status metalbear_video_upload_store_open(
    const char *database_path, const char *parts_directory,
    metalbear_blob_store *blobs, metalbear_video_upload_store **out);
void metalbear_video_upload_store_free(metalbear_video_upload_store *store);

metalbear_video_upload_result metalbear_video_upload_start(
    metalbear_video_upload_store *store, uint64_t size_bytes,
    const char *mime_type, const char *name,
    metalbear_video_upload_status *out);

metalbear_video_upload_result metalbear_video_upload_part_begin(
    metalbear_video_upload_store *store, const char *job_id,
    uint32_t part_number, uint64_t content_length,
    metalbear_video_part_writer **out);
metalbear_video_upload_result metalbear_video_upload_part_write(
    metalbear_video_part_writer *writer, const unsigned char *data,
    size_t data_len);
metalbear_video_upload_result metalbear_video_upload_part_finish(
    metalbear_video_part_writer *writer);
void metalbear_video_upload_part_free(metalbear_video_part_writer *writer);

metalbear_video_upload_result metalbear_video_upload_finish(
    metalbear_video_upload_store *store, const char *job_id,
    metalbear_video_upload_status *out, char *detail, size_t detail_size);
metalbear_video_upload_result metalbear_video_upload_abort(
    metalbear_video_upload_store *store, const char *job_id,
    metalbear_video_upload_status *out);
metalbear_video_upload_result metalbear_video_upload_get_status(
    metalbear_video_upload_store *store, const char *job_id,
    metalbear_video_upload_status *out);

void metalbear_video_upload_get_limits(metalbear_video_upload_store *store,
                                       uint64_t *remaining_bytes,
                                       uint32_t *remaining_videos,
                                       uint32_t *open_uploads);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_VIDEO_UPLOAD_H */

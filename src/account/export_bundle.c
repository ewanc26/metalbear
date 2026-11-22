#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "metalbear/account/export_bundle.h"

#include "metalbear/repo/blob_store.h"
#include "metalbear/repo/repo_store.h"

#include <cJSON.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A tiny growable byte buffer. The bundle is assembled in memory because
 * wf_xrpc_response_set_body copies the bytes anyway; one allocation chain is
 * freed on every error path below.
 */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} bundle_buffer;

static bool buffer_reserve(bundle_buffer *b, size_t extra) {
    if (b->len + extra <= b->cap) return true;
    size_t need = b->len + extra;
    size_t cap = b->cap ? b->cap : 8192;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) return false;
        cap *= 2;
    }
    unsigned char *p = realloc(b->data, cap);
    if (!p) return false;
    b->data = p;
    b->cap = cap;
    return true;
}

static bool buffer_append(bundle_buffer *b, const void *src, size_t n) {
    if (n == 0) return true;
    if (!buffer_reserve(b, n)) return false;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return true;
}

static bool buffer_zeros(bundle_buffer *b, size_t n) {
    if (n == 0) return true;
    if (!buffer_reserve(b, n)) return false;
    memset(b->data + b->len, 0, n);
    b->len += n;
    return true;
}

/* Append one regular-file entry in POSIX ustar format. We cap entries at
 * 2 GiB (the 11-octal-digit size field would hold more, but a bundle this
 * large is already held twice in memory by the response copy). */
static bool tar_write_file(bundle_buffer *b, const char *name,
                           const unsigned char *data, size_t size) {
    if (strlen(name) >= 100 || size > 0x7FFFFFFFu) return false;

    unsigned char header[512];
    memset(header, 0, sizeof(header));
    memcpy(header, name, strlen(name));
    memcpy(header + 100, "0000644\0", 8); /* mode */
    memcpy(header + 108, "0000000\0", 8); /* uid */
    memcpy(header + 116, "0000000\0", 8); /* gid */
    snprintf((char *)header + 124, 12, "%011o", (unsigned)size);
    memcpy(header + 136, "00000000000\0", 12); /* mtime */
    memset(header + 148, ' ', 8);              /* checksum placeholder */
    header[156] = '0';                         /* regular file */
    memcpy(header + 257, "ustar", 5);
    header[263] = '0';
    header[264] = '0';

    unsigned long checksum = 0;
    for (size_t i = 0; i < sizeof(header); i++) checksum += header[i];
    snprintf((char *)header + 148, 8, "%06lo", checksum);
    header[154] = '\0';
    header[155] = ' ';

    if (!buffer_append(b, header, sizeof(header))) return false;
    if (!buffer_append(b, data, size)) return false;
    size_t pad = (512 - (size % 512)) % 512;
    return buffer_zeros(b, pad);
}

typedef struct {
    char *cid;
    char *mime;
    unsigned char *data;
    size_t len;
} export_blob;

static void export_blobs_free(export_blob *blobs, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(blobs[i].cid);
        free(blobs[i].mime);
        free(blobs[i].data);
    }
    free(blobs);
}

wf_status metalbear_export_bundle_build(metalbear_account_context *acct,
                                        const char *signing_key_did,
                                        const char *indexed_at,
                                        unsigned char **out_data,
                                        size_t *out_len) {
    if (!acct || !acct->repo || !acct->blobs || !out_data || !out_len)
        return WF_ERR_INVALID_ARG;
    *out_data = NULL;
    *out_len = 0;

    /* Take the CAR and the blob list before allocating the archive, so an
     * early failure never leaves a half-built bundle behind. */
    unsigned char *car = NULL;
    size_t car_len = 0;
    wf_status st =
        metalbear_repo_store_export(acct->repo, NULL, &car, &car_len);
    if (st != WF_OK) return st;

    char **cids = NULL;
    size_t cid_count = 0;
    st = metalbear_blob_store_list(acct->blobs, &cids, &cid_count);
    if (st != WF_OK) {
        free(car);
        return st;
    }

    export_blob *blobs = calloc(cid_count ? cid_count : 1, sizeof(*blobs));
    if (!blobs) {
        metalbear_blob_store_list_free(cids, cid_count);
        free(car);
        return WF_ERR_ALLOC;
    }
    size_t blob_count = 0;
    for (size_t i = 0; i < cid_count; i++) {
        export_blob *blob = &blobs[blob_count];
        st = metalbear_blob_store_get(acct->blobs, cids[i], &blob->data,
                                      &blob->len, &blob->mime);
        if (st != WF_OK) {
            /* A blob can disappear between list and get; skip it rather than
             * failing the whole export. */
            blob->data = NULL;
            blob->mime = NULL;
            continue;
        }
        blob->cid = strdup(cids[i]);
        if (!blob->cid) {
            free(blob->data);
            free(blob->mime);
            blob->data = NULL;
            blob->mime = NULL;
            continue;
        }
        blob_count++;
    }
    metalbear_blob_store_list_free(cids, cid_count);

    cJSON *manifest = cJSON_CreateObject();
    cJSON *blob_array = cJSON_CreateArray();
    if (!manifest || !blob_array) {
        cJSON_Delete(manifest);
        cJSON_Delete(blob_array);
        export_blobs_free(blobs, blob_count);
        free(car);
        return WF_ERR_ALLOC;
    }
    cJSON_AddNumberToObject(manifest, "version", 1);
    cJSON_AddStringToObject(manifest, "did", acct->did ? acct->did : "");
    cJSON_AddStringToObject(manifest, "handle",
                            acct->handle ? acct->handle : "");
    cJSON_AddStringToObject(manifest, "signingKey",
                            signing_key_did ? signing_key_did : "");
    cJSON_AddStringToObject(manifest, "indexedAt",
                            indexed_at ? indexed_at : "");
    cJSON_AddStringToObject(manifest, "repoFile", "repo.car");

    for (size_t i = 0; i < blob_count; i++) {
        cJSON *item = cJSON_CreateObject();
        if (!item) {
            cJSON_Delete(manifest);
            export_blobs_free(blobs, blob_count);
            free(car);
            return WF_ERR_ALLOC;
        }
        char path[256];
        snprintf(path, sizeof(path), "blobs/%s", blobs[i].cid);
        cJSON_AddStringToObject(item, "cid", blobs[i].cid);
        cJSON_AddStringToObject(item, "mimeType",
                                blobs[i].mime ? blobs[i].mime : "");
        cJSON_AddStringToObject(item, "path", path);
        cJSON_AddItemToArray(blob_array, item);
    }
    cJSON_AddItemToObject(manifest, "blobs", blob_array);

    char *manifest_json = cJSON_PrintUnformatted(manifest);
    cJSON_Delete(manifest);
    if (!manifest_json) {
        export_blobs_free(blobs, blob_count);
        free(car);
        return WF_ERR_ALLOC;
    }

    bundle_buffer out = {0};
    bool ok = tar_write_file(&out, "manifest.json",
                             (const unsigned char *)manifest_json,
                             strlen(manifest_json));
    if (ok) ok = tar_write_file(&out, "repo.car", car, car_len);
    for (size_t i = 0; ok && i < blob_count; i++) {
        char path[256];
        snprintf(path, sizeof(path), "blobs/%s", blobs[i].cid);
        ok = tar_write_file(&out, path, blobs[i].data, blobs[i].len);
    }
    /* Two 512-byte zero blocks mark the end of a tar archive. */
    if (ok) ok = buffer_zeros(&out, 1024);

    free(manifest_json);
    export_blobs_free(blobs, blob_count);
    free(car);

    if (!ok) {
        free(out.data);
        return WF_ERR_ALLOC;
    }
    *out_data = out.data;
    *out_len = out.len;
    return WF_OK;
}

#include "repo_store_internal.h"

#include "metalbear/repo/blob_store.h"

#include "wolfram/identity.h"
#include "wolfram/repo/diff.h"
#include "wolfram/repo/record.h"
#include "wolfram/server.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* XRPC server route handlers                                          */
/* ------------------------------------------------------------------ */

/*
 * Internal routing bundle installed by the PDS repo server registrations.
 * When `resolver` is NULL the handlers use the single `fallback_repo`;
 * otherwise `resolver` picks the per-request store. The bundle is
 * heap-allocated and owned by the server (freed in wf_xrpc_server_free).
 */
typedef struct metalbear_pds_repo_bundle {
    metalbear_xrpc_repo_resolver resolver;
    void *resolver_ctx;
    metalbear_repo_store *fallback_repo;
    metalbear_blob_store *fallback_blobs;
    char *service_did;
    char *public_url;
    metalbear_xrpc_did_doc_provider did_doc_provider;
    void *did_doc_ctx;
    const wf_lexicon_registry *lexicons; /* borrowed */
    metalbear_xrpc_repo_access_guard guard;
    void *guard_ctx;
    /* importRepo gate (refpds PDS_ACCEPTING_REPO_IMPORTS /
     * PDS_MAX_REPO_IMPORT_SIZE): accepting_imports defaults true in both
     * constructors below; max_import_size 0 means unlimited. */
    bool accepting_imports;
    int64_t max_import_size;
} metalbear_pds_repo_bundle;

/* Run the access guard, if one is installed. False means the guard has
 * already written the refusal into `resp`. */
static bool repo_access_allowed(metalbear_pds_repo_bundle *b,
                                const wf_xrpc_request *req,
                                const char *record_uri,
                                wf_xrpc_response *resp) {
    if (!b->guard) return true;
    return b->guard(b->guard_ctx, req, record_uri, resp);
}

/*
 * Resolve the repo store for a request from the registration's bundle.
 * Returns the store to use (never NULL on success) or NULL after writing a
 * 400 RepoNotFound response when the resolver fails / resolves no store.
 * When no resolver is set the single fallback store is returned.
 */
/*
 * As resolve_repo, but also resolves the account's blob store into
 * `out_blobs` (NULL on any failure path, including when a resolver simply
 * has none to offer). Write handlers need both stores to track which blobs
 * a record references.
 */
static metalbear_repo_store *
resolve_repo_and_blobs(metalbear_pds_repo_bundle *b, const wf_xrpc_request *req,
                       wf_xrpc_response *resp,
                       metalbear_blob_store **out_blobs) {
    metalbear_repo_store *store = b->fallback_repo;
    metalbear_blob_store *blobs = b->fallback_blobs;
    if (b->resolver) {
        metalbear_repo_store *out_repo = NULL;
        metalbear_blob_store *resolved_blobs = NULL;
        if (b->resolver(b->resolver_ctx, req, &out_repo, &resolved_blobs) !=
                WF_OK ||
            !out_repo) {
            wf_xrpc_response_set_error(resp, 400, "RepoNotFound",
                                       "Repository is not hosted here");
            if (out_blobs) *out_blobs = NULL;
            return NULL;
        }
        store = out_repo;
        blobs = resolved_blobs;
    }
    if (!repo_access_allowed(b, req, NULL, resp)) {
        if (out_blobs) *out_blobs = NULL;
        return NULL;
    }
    if (out_blobs) *out_blobs = blobs;
    return store;
}

static metalbear_repo_store *resolve_repo(metalbear_pds_repo_bundle *b,
                                          const wf_xrpc_request *req,
                                          wf_xrpc_response *resp) {
    return resolve_repo_and_blobs(b, req, resp, NULL);
}

/*
 * Blob reference bookkeeping for the repo write path — mirrors the reference
 * PDS's insertBlobs/associateBlob (record_blob rows) and
 * deleteDereferencedBlobs (a blob dropped by every record that named it is
 * garbage, deleted immediately rather than on a timer). `blobs` may be NULL
 * (no blob store resolved for this account), in which case every helper
 * below is a no-op.
 *
 * A record may reference a blob CID that has not been uploaded yet — the
 * migration flow deliberately allows this (com.atproto.repo.listMissingBlobs
 * exists precisely to let a client discover such records and backfill the
 * blobs afterward; see its handler's comment). So association here is
 * best-effort: a CID with no matching stored blob is simply not associated,
 * silently, matching the reference PDS's own record_blob rows, which name a
 * blobCid whether or not that blob has actually landed yet.
 */
typedef struct blob_assoc_ctx {
    metalbear_blob_store *blobs;
    const char *uri;
} blob_assoc_ctx;

static void blob_associate_cb(const char *cid, void *opaque) {
    blob_assoc_ctx *c = opaque;
    /* WF_ERR_NOT_FOUND (blob not uploaded yet) is expected and not an error
     * here — see the module comment above. */
    (void)metalbear_blob_store_associate(c->blobs, cid, c->uri);
}

/* Associate every blob `record_json` references with `uri`. Call this
 * BEFORE untrack_superseded_blobs for the record it is replacing, so a blob
 * shared between the old and new value is already re-associated by the time
 * the old value's association is dropped. */
static void track_written_blobs(metalbear_blob_store *blobs, const char *uri,
                                const char *record_json) {
    if (!blobs || !record_json) return;
    cJSON *value = cJSON_Parse(record_json);
    if (!value) return;
    blob_assoc_ctx c = {blobs, uri};
    metalbear_blob_walk_refs(value, blob_associate_cb, &c);
    cJSON_Delete(value);
}

/* A small deduplicated set of owned CID strings, used only to answer "is
 * this CID also in the new value" while dereferencing an old one. */
typedef struct blob_cid_set {
    char **cids;
    size_t count;
} blob_cid_set;

static void blob_cid_set_add(const char *cid, void *opaque) {
    blob_cid_set *set = opaque;
    for (size_t i = 0; i < set->count; i++)
        if (set->cids[i] && strcmp(set->cids[i], cid) == 0) return;
    char **grown =
        (char **)realloc(set->cids, (set->count + 1) * sizeof(*grown));
    if (!grown)
        return; /* best-effort: a missed entry only costs an extra,
                 * harmless dissociate call below, never a leak */
    set->cids = grown;
    set->cids[set->count] = strdup(cid);
    set->count++;
}

static bool blob_cid_set_contains(const blob_cid_set *set, const char *cid) {
    for (size_t i = 0; i < set->count; i++)
        if (set->cids[i] && strcmp(set->cids[i], cid) == 0) return true;
    return false;
}

static void blob_cid_set_free(blob_cid_set *set) {
    for (size_t i = 0; i < set->count; i++) free(set->cids[i]);
    free(set->cids);
}

typedef struct blob_dissociate_except_ctx {
    metalbear_blob_store *blobs;
    const char *uri;
    const blob_cid_set *keep;
} blob_dissociate_except_ctx;

static void blob_dissociate_except_cb(const char *cid, void *opaque) {
    blob_dissociate_except_ctx *c = opaque;
    if (c->keep && blob_cid_set_contains(c->keep, cid))
        return; /* still referenced by the record's new value */
    (void)metalbear_blob_store_dissociate(c->blobs, cid, c->uri);
}

/*
 * Dissociate every blob `old_json` referenced from `uri`, except one also
 * referenced by `new_json` (pass NULL for a delete, where nothing is kept).
 *
 * This is not simply "associate the new value before dissociating the old
 * one": when a record is replaced but keeps referencing the SAME blob CID,
 * old and new both name the identical (cid, uri) pair — associating it is a
 * no-op (it is already associated), so an unconditional dissociate would
 * still drop the count to zero and delete a blob the record still uses.
 * Skipping CIDs the new value keeps is the only correct rule; it also
 * mirrors the reference PDS's deleteDereferencedBlobs, which excludes
 * `newBlobCids` from the set of rows it deletes for exactly this reason.
 */
static void untrack_superseded_blobs(metalbear_blob_store *blobs,
                                     const char *uri, const char *old_json,
                                     const char *new_json) {
    if (!blobs || !old_json) return;
    cJSON *old_value = cJSON_Parse(old_json);
    if (!old_value) return;
    blob_cid_set keep = {0};
    if (new_json) {
        cJSON *new_value = cJSON_Parse(new_json);
        if (new_value) {
            metalbear_blob_walk_refs(new_value, blob_cid_set_add, &keep);
            cJSON_Delete(new_value);
        }
    }
    blob_dissociate_except_ctx c = {blobs, uri, &keep};
    metalbear_blob_walk_refs(old_value, blob_dissociate_except_cb, &c);
    cJSON_Delete(old_value);
    blob_cid_set_free(&keep);
}

static void free_owned_strings(char **arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; i++) free(arr[i]);
    free(arr);
}

/*
 * Query-string parameters always arrive as JSON strings — the HTTP layer has
 * no lexicon to coerce them against — so a plain cJSON_IsNumber /
 * cJSON_IsTrue test silently discards every value a client actually sends and
 * falls back to the default. `?limit=1&reverse=true` was being served as
 * limit=50, reverse=false.
 */
static int query_param_int(const cJSON *params, const char *name, int fallback,
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

static bool query_param_bool(const cJSON *params, const char *name,
                             bool fallback) {
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

/*
 * Run a write's record through the lexicon corpus and report the outcome the
 * way the reference PDS does.
 *
 * Returns 0 and writes an `InvalidRecord` response when the record has a
 * schema and violates it, or when the caller passed validate:true for a
 * collection with no schema. Returns 1 to continue, with *out_status set to
 * the value that belongs in the response's validationStatus and *out_report
 * telling the caller whether to emit that field at all — validate:false means
 * nothing was checked, so the field is omitted rather than guessed.
 */
static int check_record(const metalbear_pds_repo_bundle *b, const cJSON *body,
                        const char *collection, const char *record_json,
                        wf_xrpc_response *resp,
                        metalbear_validation_status *out_status,
                        bool *out_report) {
    const cJSON *validate =
        body ? cJSON_GetObjectItemCaseSensitive(body, "validate") : NULL;
    bool explicit_off = cJSON_IsFalse(validate) ||
                        (cJSON_IsString(validate) &&
                         strcmp(validate->valuestring, "false") == 0);
    bool explicit_on =
        cJSON_IsTrue(validate) || (cJSON_IsString(validate) &&
                                   strcmp(validate->valuestring, "true") == 0);

    *out_status = METALBEAR_VALIDATION_UNKNOWN;
    *out_report = !explicit_off;
    if (explicit_off) return 1;

    /* The $type, when present, must name the collection being written to. */
    cJSON *parsed = cJSON_Parse(record_json);
    cJSON *type =
        parsed ? cJSON_GetObjectItemCaseSensitive(parsed, "$type") : NULL;
    if (cJSON_IsString(type) && strcmp(type->valuestring, collection) != 0) {
        char detail[512];
        snprintf(detail, sizeof(detail), "Invalid $type: expected %s, got %s",
                 collection, type->valuestring);
        cJSON_Delete(parsed);
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest", detail);
        return 0;
    }
    cJSON_Delete(parsed);

    /* The reference reports every record problem as a plain InvalidRequest
     * carrying a descriptive message — its InvalidRecordError is an internal
     * class converted to InvalidRequestError(err.message). `InvalidRecord` is
     * not a name the lexicons define, so emitting it would diverge. */
    char *message = NULL;
    wf_status st =
        metalbear_validate_record(b->lexicons, collection, record_json,
                                  explicit_on, out_status, &message);
    if (st == WF_ERR_NOT_FOUND) {
        char detail[512];
        snprintf(detail, sizeof(detail), "Unknown lexicon type: %s",
                 collection);
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest", detail);
        return 0;
    }
    if (st == WF_ERR_VALIDATION) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   message ? message
                                           : "record failed validation");
        free(message);
        return 0;
    }
    free(message);
    return st == WF_OK;
}

/* Reject a syntactically invalid record key with the message the reference
 * uses. Returns 1 when the key is absent (the PDS mints one) or valid. */
static int check_rkey(const cJSON *rkey, wf_xrpc_response *resp) {
    if (!cJSON_IsString(rkey) || !rkey->valuestring[0]) return 1;
    if (wf_syntax_record_key_is_valid(rkey->valuestring)) return 1;
    char detail[320];
    snprintf(detail, sizeof(detail), "Invalid record key: %s",
             rkey->valuestring);
    wf_xrpc_response_set_error(resp, 400, "InvalidRequest", detail);
    return 0;
}

static const char *validation_status_text(metalbear_validation_status s) {
    return s == METALBEAR_VALIDATION_VALID ? "valid" : "unknown";
}

/*
 * Report a repo-write failure using the names the lexicon actually defines.
 * The only write error com.atproto.repo.{create,put,delete}Record and
 * applyWrites declare is `InvalidSwap`, which clients branch on to retry an
 * optimistic write; a missing record is `RecordNotFound`, and everything else
 * falls back to the generic `InvalidRequest`. Invented names such as
 * `CreationFailed` are invisible to a client matching on the lexicon.
 */
static void set_write_error(wf_xrpc_response *resp, wf_status st,
                            const char *context) {
    switch (st) {
        case WF_ERR_CONFLICT:
            wf_xrpc_response_set_error(resp, 400, "InvalidSwap",
                                       "swap CID did not match current value");
            return;
        case WF_ERR_NOT_FOUND:
            wf_xrpc_response_set_error(resp, 400, "RecordNotFound",
                                       "record not found");
            return;
        default:
            wf_xrpc_response_set_error(resp, 400, "InvalidRequest", context);
            return;
    }
}

static wf_status h_create_record(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    metalbear_blob_store *blobs = NULL;
    metalbear_repo_store *s = resolve_repo_and_blobs(
        (metalbear_pds_repo_bundle *)ctx, req, resp, &blobs);
    if (!s) return WF_OK;
    cJSON *body = req->params;
    if (!body || !cJSON_IsObject(body)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "request body required");
        return WF_OK;
    }
    cJSON *collection = cJSON_GetObjectItemCaseSensitive(body, "collection");
    cJSON *rkey = cJSON_GetObjectItemCaseSensitive(body, "rkey");
    cJSON *record = cJSON_GetObjectItemCaseSensitive(body, "record");
    cJSON *swap = cJSON_GetObjectItemCaseSensitive(body, "swapCommit");
    if (!collection || !cJSON_IsString(collection) || !record) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "collection and record required");
        return WF_OK;
    }
    char *rec_json = cJSON_PrintUnformatted(record);
    if (!rec_json) return WF_ERR_ALLOC;

    metalbear_validation_status vstatus;
    bool report_status = false;
    if (!check_rkey(rkey, resp) ||
        !check_record((metalbear_pds_repo_bundle *)ctx, body,
                      collection->valuestring, rec_json, resp, &vstatus,
                      &report_status)) {
        free(rec_json);
        return WF_OK;
    }

    const char *rk = (rkey && cJSON_IsString(rkey)) ? rkey->valuestring : NULL;
    const char *swap_str =
        (swap && cJSON_IsString(swap)) ? swap->valuestring : NULL;
    char *uri = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_create_record(
        s, collection->valuestring, rk, rec_json, swap_str, &uri, &cid);
    if (st != WF_OK) {
        free(rec_json);
        set_write_error(resp, st, "record creation failed");
        return WF_OK;
    }
    track_written_blobs(blobs, uri, rec_json);
    free(rec_json);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "uri", uri ? uri : "");
    cJSON_AddStringToObject(out, "cid", cid ? cid : "");
    if (report_status)
        cJSON_AddStringToObject(out, "validationStatus",
                                validation_status_text(vstatus));
    add_commit_meta(s, out);
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(uri);
    free(cid);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static wf_status h_put_record(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    metalbear_blob_store *blobs = NULL;
    metalbear_repo_store *s = resolve_repo_and_blobs(
        (metalbear_pds_repo_bundle *)ctx, req, resp, &blobs);
    if (!s) return WF_OK;
    cJSON *body = req->params;
    if (!body || !cJSON_IsObject(body)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "request body required");
        return WF_OK;
    }
    cJSON *collection = cJSON_GetObjectItemCaseSensitive(body, "collection");
    cJSON *rkey = cJSON_GetObjectItemCaseSensitive(body, "rkey");
    cJSON *record = cJSON_GetObjectItemCaseSensitive(body, "record");
    cJSON *swap = cJSON_GetObjectItemCaseSensitive(body, "swapCommit");
    cJSON *swapRec = cJSON_GetObjectItemCaseSensitive(body, "swapRecord");
    if (!collection || !cJSON_IsString(collection) || !rkey ||
        !cJSON_IsString(rkey) || !record) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "collection, rkey and record required");
        return WF_OK;
    }
    char *rec_json = cJSON_PrintUnformatted(record);
    if (!rec_json) return WF_ERR_ALLOC;

    const char *swap_str =
        (swap && cJSON_IsString(swap)) ? swap->valuestring : NULL;
    const char *swaprec_str =
        (swapRec && cJSON_IsString(swapRec)) ? swapRec->valuestring : NULL;

    metalbear_validation_status vstatus;
    bool report_status = false;
    if (!check_rkey(rkey, resp) ||
        !check_record((metalbear_pds_repo_bundle *)ctx, body,
                      collection->valuestring, rec_json, resp, &vstatus,
                      &report_status)) {
        free(rec_json);
        return WF_OK;
    }

    /* Capture the record it may replace BEFORE the write lands, so its blobs
     * can be dissociated afterward — putRecord upserts by rkey and there is
     * no other way to learn the prior value once the store has overwritten
     * it. Absent (WF_ERR_NOT_FOUND) simply means this is a create. */
    char *old_json = NULL, *old_cid_unused = NULL;
    (void)metalbear_repo_store_get_record(s, collection->valuestring,
                                          rkey->valuestring, &old_json,
                                          &old_cid_unused);
    free(old_cid_unused);

    char *uri = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_put_record(
        s, collection->valuestring, rkey->valuestring, rec_json, swap_str,
        swaprec_str, &uri, &cid);
    if (st != WF_OK) {
        free(rec_json);
        free(old_json);
        set_write_error(resp, st, "record put failed");
        return WF_OK;
    }
    track_written_blobs(blobs, uri, rec_json);
    untrack_superseded_blobs(blobs, uri, old_json, rec_json);
    free(rec_json);
    free(old_json);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "uri", uri ? uri : "");
    cJSON_AddStringToObject(out, "cid", cid ? cid : "");
    if (report_status)
        cJSON_AddStringToObject(out, "validationStatus",
                                validation_status_text(vstatus));
    add_commit_meta(s, out);
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(uri);
    free(cid);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static wf_status h_delete_record(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    metalbear_blob_store *blobs = NULL;
    metalbear_repo_store *s = resolve_repo_and_blobs(
        (metalbear_pds_repo_bundle *)ctx, req, resp, &blobs);
    if (!s) return WF_OK;
    cJSON *body = req->params;
    if (!body || !cJSON_IsObject(body)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "request body required");
        return WF_OK;
    }
    cJSON *collection = cJSON_GetObjectItemCaseSensitive(body, "collection");
    cJSON *rkey = cJSON_GetObjectItemCaseSensitive(body, "rkey");
    cJSON *swap = cJSON_GetObjectItemCaseSensitive(body, "swapCommit");
    cJSON *swapRec = cJSON_GetObjectItemCaseSensitive(body, "swapRecord");
    if (!collection || !cJSON_IsString(collection) || !rkey ||
        !cJSON_IsString(rkey)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "collection and rkey required");
        return WF_OK;
    }
    const char *swap_str =
        (swap && cJSON_IsString(swap)) ? swap->valuestring : NULL;
    const char *swaprec_str =
        (swapRec && cJSON_IsString(swapRec)) ? swapRec->valuestring : NULL;
    /* Capture the value being deleted BEFORE it is gone, so its blobs can be
     * dissociated afterward. */
    char *old_json = NULL, *old_cid_unused = NULL;
    (void)metalbear_repo_store_get_record(s, collection->valuestring,
                                          rkey->valuestring, &old_json,
                                          &old_cid_unused);
    free(old_cid_unused);
    wf_status st = metalbear_repo_store_delete_record(
        s, collection->valuestring, rkey->valuestring, swap_str, swaprec_str);
    /* Deleting a record that is not there is a no-op success, matching the
     * reference PDS: the response simply carries no `commit`. Clients delete
     * idempotently (retried unlikes, unfollows), so a 404 here would surface
     * as a spurious error on a retry that has nothing left to do. A swap
     * guard that fails is still a real InvalidSwap conflict. */
    if (st != WF_OK && st != WF_ERR_NOT_FOUND) {
        free(old_json);
        set_write_error(resp, st, "record could not be deleted");
        return WF_OK;
    }
    if (st == WF_OK) {
        char *uri =
            make_uri(s->did, collection->valuestring, rkey->valuestring);
        untrack_superseded_blobs(blobs, uri, old_json, NULL);
        free(uri);
    }
    free(old_json);
    cJSON *out = cJSON_CreateObject();
    if (st == WF_OK) add_commit_meta(s, out);
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static wf_status h_get_record(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    metalbear_repo_store *s =
        resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    cJSON *p = req->params;
    if (!p || !cJSON_IsObject(p)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "query parameters required");
        return WF_OK;
    }
    cJSON *collection = cJSON_GetObjectItemCaseSensitive(p, "collection");
    cJSON *rkey = cJSON_GetObjectItemCaseSensitive(p, "rkey");
    if (!collection || !cJSON_IsString(collection) || !rkey ||
        !cJSON_IsString(rkey)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "collection and rkey required");
        return WF_OK;
    }
    /* A taken-down record reads as absent. It is still in the repository —
     * removing it would rewrite history — so the guard is what withholds it. */
    char *guard_uri =
        make_uri(s->did, collection->valuestring, rkey->valuestring);
    bool allowed = repo_access_allowed((metalbear_pds_repo_bundle *)ctx, req,
                                       guard_uri, resp);
    free(guard_uri);
    if (!allowed) return WF_OK;
    char *rec = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_get_record(
        s, collection->valuestring, rkey->valuestring, &rec, &cid);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 404, "RecordNotFound",
                                   "record not found");
        return WF_OK;
    }
    /* The optional `cid` parameter pins the request to one version of the
     * record. Returning the current version regardless would hand the caller
     * different content than it asked for; the reference reports
     * RecordNotFound when the stored CID does not match. */
    cJSON *want_cid = cJSON_GetObjectItemCaseSensitive(p, "cid");
    if (cJSON_IsString(want_cid) && want_cid->valuestring[0] &&
        (!cid || strcmp(cid, want_cid->valuestring) != 0)) {
        free(rec);
        free(cid);
        wf_xrpc_response_set_error(resp, 404, "RecordNotFound",
                                   "record not found at requested cid");
        return WF_OK;
    }
    cJSON *out = cJSON_CreateObject();
    char *uri = make_uri(s->did, collection->valuestring, rkey->valuestring);
    cJSON_AddStringToObject(out, "uri", uri);
    free(uri);
    cJSON_AddStringToObject(out, "cid", cid);
    cJSON *val = cJSON_Parse(rec);
    if (val) cJSON_AddItemToObject(out, "value", val);
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(rec);
    free(cid);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static wf_status h_apply_writes(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    metalbear_blob_store *blobs = NULL;
    metalbear_repo_store *s = resolve_repo_and_blobs(
        (metalbear_pds_repo_bundle *)ctx, req, resp, &blobs);
    if (!s) return WF_OK;
    cJSON *body = req->params;
    if (!body || !cJSON_IsObject(body)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "request body required");
        return WF_OK;
    }
    cJSON *writes = cJSON_GetObjectItemCaseSensitive(body, "writes");
    cJSON *swap = cJSON_GetObjectItemCaseSensitive(body, "swapCommit");
    if (!writes || !cJSON_IsArray(writes)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "writes array required");
        return WF_OK;
    }
    const char *swap_str =
        (swap && cJSON_IsString(swap)) ? swap->valuestring : NULL;

    /* Validate every record BEFORE anything is committed. The batch is atomic,
     * so one invalid record rejects the whole request rather than landing the
     * others. Statuses are kept per write and stitched into the matching
     * result below, which the store cannot do since it has no registry. */
    int write_count = cJSON_GetArraySize(writes);
    if (write_count > 200) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "Too many writes. Max: 200");
        return WF_OK;
    }
    metalbear_validation_status *statuses =
        write_count ? calloc((size_t)write_count, sizeof(*statuses)) : NULL;
    if (write_count && !statuses) return WF_ERR_ALLOC;
    /* The value replaced or removed by an update/delete op, captured now
     * (before anything is committed) since it is the only chance to learn
     * it — the store overwrites it inside metalbear_repo_store_apply_writes.
     * NULL for create ops and for update/delete ops with no prior record. */
    char **old_values =
        write_count ? calloc((size_t)write_count, sizeof(*old_values)) : NULL;
    if (write_count && !old_values) {
        free(statuses);
        return WF_ERR_ALLOC;
    }
    bool report_status = true;
    int idx = 0;
    const cJSON *w = NULL;
    cJSON_ArrayForEach(w, writes) {
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(w, "$type");
        const cJSON *coll = cJSON_GetObjectItemCaseSensitive(w, "collection");
        const cJSON *val = cJSON_GetObjectItemCaseSensitive(w, "value");
        const cJSON *rk = cJSON_GetObjectItemCaseSensitive(w, "rkey");
        if (!check_rkey(rk, resp)) {
            free(statuses);
            free_owned_strings(old_values, (size_t)write_count);
            return WF_OK;
        }
        bool is_write = cJSON_IsString(type) && val && cJSON_IsString(coll) &&
                        (strcmp(type->valuestring,
                                "com.atproto.repo.applyWrites#create") == 0 ||
                         strcmp(type->valuestring,
                                "com.atproto.repo.applyWrites#update") == 0);
        bool is_update = cJSON_IsString(type) &&
                         strcmp(type->valuestring,
                                "com.atproto.repo.applyWrites#update") == 0;
        bool is_delete = cJSON_IsString(type) &&
                         strcmp(type->valuestring,
                                "com.atproto.repo.applyWrites#delete") == 0;
        if ((is_update || is_delete) && cJSON_IsString(coll) &&
            cJSON_IsString(rk) && rk->valuestring[0]) {
            char *old_cid_unused = NULL;
            (void)metalbear_repo_store_get_record(
                s, coll->valuestring, rk->valuestring, &old_values[idx],
                &old_cid_unused);
            free(old_cid_unused);
        }
        if (is_write) {
            char *rec_json = cJSON_PrintUnformatted(val);
            if (!rec_json) {
                free(statuses);
                free_owned_strings(old_values, (size_t)write_count);
                return WF_ERR_ALLOC;
            }
            bool report_one = true;
            int ok = check_record((metalbear_pds_repo_bundle *)ctx, body,
                                  coll->valuestring, rec_json, resp,
                                  &statuses[idx], &report_one);
            free(rec_json);
            if (!ok) {
                free(statuses);
                free_owned_strings(old_values, (size_t)write_count);
                return WF_OK;
            }
            report_status = report_one;
        }
        idx++;
    }

    char *writes_json = cJSON_PrintUnformatted(writes);
    if (!writes_json) {
        free(statuses);
        free_owned_strings(old_values, (size_t)write_count);
        return WF_ERR_ALLOC;
    }

    char *cid = NULL, *rev = NULL, *results = NULL;
    wf_status st = metalbear_repo_store_apply_writes(s, writes_json, swap_str,
                                                     &cid, &rev, &results);
    free(writes_json);
    if (st != WF_OK) {
        free(statuses);
        free_owned_strings(old_values, (size_t)write_count);
        set_write_error(resp, st, "applyWrites failed");
        return WF_OK;
    }

    cJSON *out = cJSON_CreateObject();
    cJSON *commit = cJSON_CreateObject();
    cJSON_AddStringToObject(commit, "cid", cid ? cid : "");
    cJSON_AddStringToObject(commit, "rev", rev ? rev : "");
    cJSON_AddItemToObject(out, "commit", commit);
    cJSON *res = cJSON_Parse(results);
    if (res) {
        /* Results are emitted in write order, so index i describes write i. */
        for (int i = 0; i < cJSON_GetArraySize(res) && i < write_count; i++) {
            cJSON *entry = cJSON_GetArrayItem(res, i);
            if (!cJSON_GetObjectItemCaseSensitive(entry, "validationStatus"))
                continue;
            cJSON_DeleteItemFromObjectCaseSensitive(entry, "validationStatus");
            if (report_status)
                cJSON_AddStringToObject(entry, "validationStatus",
                                        validation_status_text(statuses[i]));
        }

        /* Blob reference bookkeeping — mirrors the reference PDS's
         * insertBlobs + deleteDereferencedBlobs. Phase 1 associates every
         * blob a create/update's NEW value references; phase 2 dissociates
         * every blob an update/delete's OLD value referenced. Doing all of
         * phase 1 before any of phase 2 means a blob reused elsewhere in the
         * same batch (moved from one record to another) never touches a
         * zero reference count in between. */
        for (int i = 0; i < cJSON_GetArraySize(res) && i < write_count; i++) {
            const cJSON *wi = cJSON_GetArrayItem(writes, i);
            const cJSON *type = cJSON_GetObjectItemCaseSensitive(wi, "$type");
            const cJSON *val = cJSON_GetObjectItemCaseSensitive(wi, "value");
            cJSON *entry = cJSON_GetArrayItem(res, i);
            cJSON *entry_uri = cJSON_GetObjectItemCaseSensitive(entry, "uri");
            bool is_create_or_update =
                cJSON_IsString(type) &&
                (strcmp(type->valuestring,
                        "com.atproto.repo.applyWrites#create") == 0 ||
                 strcmp(type->valuestring,
                        "com.atproto.repo.applyWrites#update") == 0);
            if (is_create_or_update && cJSON_IsString(entry_uri) && val) {
                char *val_json = cJSON_PrintUnformatted(val);
                track_written_blobs(blobs, entry_uri->valuestring, val_json);
                free(val_json);
            }
        }
        for (int i = 0; i < cJSON_GetArraySize(res) && i < write_count; i++) {
            if (!old_values[i]) continue;
            const cJSON *wi = cJSON_GetArrayItem(writes, i);
            const cJSON *type = cJSON_GetObjectItemCaseSensitive(wi, "$type");
            if (!cJSON_IsString(type)) continue;
            if (strcmp(type->valuestring,
                       "com.atproto.repo.applyWrites#update") == 0) {
                cJSON *entry = cJSON_GetArrayItem(res, i);
                cJSON *entry_uri =
                    cJSON_GetObjectItemCaseSensitive(entry, "uri");
                const cJSON *val =
                    cJSON_GetObjectItemCaseSensitive(wi, "value");
                if (cJSON_IsString(entry_uri)) {
                    char *val_json = val ? cJSON_PrintUnformatted(val) : NULL;
                    untrack_superseded_blobs(blobs, entry_uri->valuestring,
                                             old_values[i], val_json);
                    free(val_json);
                }
            } else if (strcmp(type->valuestring,
                              "com.atproto.repo.applyWrites#delete") == 0) {
                const cJSON *coll =
                    cJSON_GetObjectItemCaseSensitive(wi, "collection");
                const cJSON *rk = cJSON_GetObjectItemCaseSensitive(wi, "rkey");
                if (cJSON_IsString(coll) && cJSON_IsString(rk)) {
                    char *uri =
                        make_uri(s->did, coll->valuestring, rk->valuestring);
                    untrack_superseded_blobs(blobs, uri, old_values[i], NULL);
                    free(uri);
                }
            }
        }

        cJSON_AddItemToObject(out, "results", res);
    }
    free(statuses);
    free_owned_strings(old_values, (size_t)write_count);
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(cid);
    free(rev);
    free(results);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static wf_status h_query_labels(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    (void)req;
    (void)ctx;
    /* MetalBear is a PDS: it stores no labels and runs no moderation
     * service. The reference implementation does not serve this endpoint
     * from the PDS at all -- com.atproto.label.queryLabels is implemented
     * by the AppView (packages/bsky/src/api/com/atproto/label/queryLabels.ts),
     * reading rows populated from the com.atproto.label.subscribeLabels
     * firehose that a labeler publishes. Returning {"labels":[]} would claim
     * "queried, found none" when the truth is "this server cannot answer
     * this query at all" -- exactly the fabricated success AGENTS.md
     * forbids for a stub. Report the honest XRPC status instead. TODO: if
     * MetalBear ever hosts its own labeler, replace this with real storage
     * and per-collection/source/date filtering. */
    wf_xrpc_response_set_error(resp, 501, "MethodNotImplemented",
                               "com.atproto.label.queryLabels is not served "
                               "by this PDS; label data is published by "
                               "labelers via com.atproto.label.subscribeLabels "
                               "and queried from an AppView, not a PDS");
    return WF_OK;
}

static wf_status h_describe_repo(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    metalbear_repo_store *s =
        resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    char *json = NULL;
    wf_status st = metalbear_repo_store_describe(s, &json);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "describeRepo failed");
        return WF_OK;
    }
    metalbear_pds_repo_bundle *bundle = (metalbear_pds_repo_bundle *)ctx;
    cJSON *root = cJSON_Parse(json);
    free(json);
    if (!root) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "describeRepo JSON parse failed");
        return WF_OK;
    }

    const char *did = metalbear_repo_store_did(s);
    const char *handle = metalbear_repo_store_handle(s);

    /* Prefer the authoritative document from the identity layer (PLC / did:web)
     * so `handleIsCorrect` reflects a real bi-directional resolution rather
     * than the PDS simply agreeing with itself. Fall back to the locally
     * derived document when no provider is wired up. */
    cJSON *did_doc = NULL;
    if (bundle->did_doc_provider) {
        char *resolved = bundle->did_doc_provider(bundle->did_doc_ctx, did);
        if (resolved) {
            did_doc = cJSON_Parse(resolved);
            free(resolved);
        }
    }
    bool resolved_doc = did_doc != NULL;
    if (!did_doc)
        did_doc = metalbear_did_document_build(
            did, handle, metalbear_repo_store_signing_key_did(s),
            bundle->public_url);

    /* didDoc is a required output field; without one the response would not
     * satisfy the lexicon, so fail loudly instead of shipping a partial. */
    if (!did_doc) {
        cJSON_Delete(root);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "could not resolve DID document");
        return WF_OK;
    }

    const char *claimed = metalbear_did_document_handle(did_doc);
    bool handle_is_correct =
        resolved_doc && claimed && handle && strcmp(claimed, handle) == 0;
    cJSON_AddBoolToObject(root, "handleIsCorrect", handle_is_correct);
    cJSON_AddItemToObject(root, "didDoc", did_doc);

    char *updated = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!updated) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "describeRepo JSON serialize failed");
        return WF_OK;
    }
    wf_xrpc_response_set_body(resp, updated, strlen(updated));
    free(updated);
    return WF_OK;
}

/* ── Route handlers ──────────────────────────────────────────────────── */

static wf_status h_list_records(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    metalbear_repo_store *s =
        resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    cJSON *p = req->params;
    if (!p || !cJSON_IsObject(p)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "query parameters required");
        return WF_OK;
    }
    cJSON *collection = cJSON_GetObjectItemCaseSensitive(p, "collection");
    if (!collection || !cJSON_IsString(collection) ||
        !collection->valuestring || !*collection->valuestring) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "collection required");
        return WF_OK;
    }
    cJSON *cursor = cJSON_GetObjectItemCaseSensitive(p, "cursor");
    int lim = query_param_int(p, "limit", 50, 1, 100);
    int rev = query_param_bool(p, "reverse", false) ? 1 : 0;
    const char *cur =
        (cursor && cJSON_IsString(cursor)) ? cursor->valuestring : NULL;
    char *json = NULL;
    wf_status st = metalbear_repo_store_list_records(s, collection->valuestring,
                                                     cur, rev, lim, &json);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "failed to list records");
        return WF_OK;
    }
    wf_xrpc_response_set_body(resp, json, strlen(json));
    free(json);
    return WF_OK;
}

static wf_status h_get_latest_commit(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    metalbear_repo_store *s =
        resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    char *rev = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_get_head(s, &rev, &cid);
    if (st == WF_ERR_NOT_FOUND) {
        /* The lexicon declares RepoNotFound; an invented name is as unusable
         * to a client as a generic one. */
        wf_xrpc_response_set_error(resp, 400, "RepoNotFound",
                                   "repository is empty");
        return WF_OK;
    } else if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "failed to read head");
        return WF_OK;
    }
    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "cid", cid ? cid : "");
    cJSON_AddStringToObject(out, "rev", rev ? rev : "");
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(rev);
    free(cid);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

/* ── importRepo (com.atproto.repo.importRepo) ──────────────────────
 * Accept a CAR POST body, verify its commit against the store's own
 * signing key, and adopt its content as the account's repo state.
 *
 * Gated on the accepting_imports config flag and a size cap
 * (max_import_size), and the route itself requires full access (see
 * full_access_route in server.c) rather than any valid session -- matching
 * the reference's acceptingImports config check, maxImportSize blobLimit,
 * and repo:manage scope requirement.
 *
 * Onto an existing repo (s->head already set): wf_repo_diff_verify diffs the
 * imported snapshot against the live repo (mirroring the reference's
 * verifyDiff) and the resulting create/update/delete operations are
 * reapplied via wf_repo_apply_writes -- the same primitive applyWrites
 * uses -- producing ONE new commit with a fresh rev, chained onto the
 * current head and signed with this account's own key. A #commit event is
 * emitted describing the ops.
 *
 * Onto a still-empty repo (no commits yet -- e.g. immediately post-
 * createAccount, before any writes): there is no base to diff against, so
 * the imported commit is adopted as-is (still signature-verified) and a
 * #sync event is emitted.
 *
 * NOTE on parity: this deliberately does NOT replicate the reference's
 * exact mechanism. Per `packages/pds/src/api/com/atproto/repo/importRepo.ts`
 * and `packages/repo/src/sync/consumer.ts` (verifyDiff) in the
 * bluesky-social/atproto reference source, the reference's "fresh rev" is a
 * local SQL bookkeeping column (`repo_root.rev`) that is allowed to diverge
 * from the rev embedded in the actual served commit CBOR -- it never
 * re-signs anything, and it never sequences a firehose event for an import
 * at all (no other repo-mutating endpoint skips that). This handler instead
 * keeps rev-in-the-database and rev-in-the-signed-commit consistent (this
 * codebase has no decoupled-rev concept -- rev is always parsed from the
 * head commit itself, see parse_commit_at) and always tells relays what
 * changed. See issue #22 for the full investigation. */

static wf_status h_import_repo(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    metalbear_pds_repo_bundle *b = (metalbear_pds_repo_bundle *)ctx;
    /* Manage-scope auth (repo:manage-equivalent) is enforced in server.c's
     * full_access_route gate before this handler ever runs -- see
     * authenticate_request. */
    if (!b->accepting_imports) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "Service is not accepting repo imports");
        return WF_OK;
    }

    metalbear_repo_store *s = resolve_repo(b, req, resp);
    if (!s) return WF_OK;
    if (!req->body || req->body_len == 0) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "CAR body required");
        return WF_OK;
    }
    if (b->max_import_size > 0 && (int64_t)req->body_len > b->max_import_size) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "CAR body exceeds maximum import size");
        return WF_OK;
    }

    wf_car imported = {0};
    if (wf_car_parse(req->body, req->body_len, &imported) != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "InvalidCAR",
                                   "imported CAR failed to parse");
        return WF_OK;
    }
    if (imported.root_count != 1) {
        /* Matches the reference's exact message
         * (importRepo.ts: `throw new InvalidRequestError('expected one
         * root')`); a CAR naming zero or multiple roots doesn't name a
         * single repo snapshot to adopt. Checked ahead of signature
         * verification so it is actually reachable -- wf_repo_verify itself
         * rejects a non-single-root CAR as a parse failure, which would
         * otherwise always report the generic InvalidCAR first. */
        wf_car_free(&imported);
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "expected one root");
        return WF_OK;
    }

    wf_cid old_head = s->head;
    wf_status st;

    if (s->head.len == 0) {
        /* No existing commit to diff against (e.g. a freshly created
         * account that has not written anything on this host yet): there is
         * no chain to preserve, so the imported commit is adopted as-is.
         * It is verified against the DID's CURRENTLY PUBLISHED #atproto key
         * -- not this account's own local signing key, which createAccount
         * just generated and which has never been published anywhere, so it
         * can only match an imported commit by coincidence. This is
         * precisely the migration bootstrap case (createAccount with an
         * existing `did`, immediately followed by importRepo): the DID
         * document has not been repointed at this host yet, so the commit
         * being imported is still signed by whichever server currently
         * holds the identity. Resolving the published key here mirrors the
         * reference PDS's verifyRepo, which resolves the signing key from
         * the DID document rather than trusting local state. Every
         * subsequent import instead goes through the diff-and-reapply path
         * below, which never adopts a foreign commit verbatim and does use
         * this account's own key, since by then it is the one that signed
         * the base being diffed against. */
        wf_xrpc_client *resolve_client =
            wf_xrpc_client_new("https://localhost");
        if (!resolve_client) {
            wf_car_free(&imported);
            return WF_ERR_ALLOC;
        }
        char *published_key = NULL;
        wf_status key_st = wf_did_resolve_verification_key(
            resolve_client, s->did, "#atproto", &published_key);
        wf_xrpc_client_free(resolve_client);
        if (key_st != WF_OK) {
            wf_car_free(&imported);
            wf_xrpc_response_set_error(
                resp, 400, "InvalidCAR",
                "could not resolve this DID's currently published signing "
                "key");
            return WF_OK;
        }

        wf_repo_verify_options opts = {s->did, published_key, NULL};
        wf_commit commit;
        st = wf_repo_verify(&imported, &opts, &commit);
        free(published_key);
        if (st != WF_OK) {
            wf_car_free(&imported);
            wf_xrpc_response_set_error(resp, 400, "InvalidCAR",
                                       "imported CAR failed verification");
            return WF_OK;
        }
        for (size_t i = 0; i < imported.block_count; i++) {
            if (wf_car_find_block(&s->car, &imported.blocks[i].cid)) continue;
            wf_car_block *nb =
                realloc(s->car.blocks, (s->car.block_count + 1) * sizeof(*nb));
            if (!nb) {
                wf_car_free(&imported);
                return WF_ERR_ALLOC;
            }
            s->car.blocks = nb;
            wf_car_block *blk = &s->car.blocks[s->car.block_count];
            blk->cid = imported.blocks[i].cid;
            blk->data_len = imported.blocks[i].data_len;
            blk->data = blk->data_len ? malloc(blk->data_len) : NULL;
            if (blk->data_len && !blk->data) {
                wf_car_free(&imported);
                return WF_ERR_ALLOC;
            }
            if (blk->data_len)
                memcpy(blk->data, imported.blocks[i].data, blk->data_len);
            s->car.block_count++;
        }
        wf_cid new_head = imported.roots[0];
        wf_car_free(&imported);

        st = commit_persist(s, &new_head);
        if (st != WF_OK) {
            wf_xrpc_response_set_error(resp, 500, "InternalError",
                                       "failed to persist imported repo");
            return WF_OK;
        }
        reindex_all(s);
        emit_sync_event(s);
    } else {
        /* An existing base commit: diff the imported snapshot against it
         * (wf_repo_diff_verify mirrors the reference's verifyDiff, and
         * confirms the imported commit is validly signed by this account's
         * own key) and reapply the resulting record-level operations as ONE
         * new commit with a fresh rev, chained onto the current head via
         * wf_repo_apply_writes -- the same primitive applyWrites uses. This
         * is deliberately NOT wf_repo_diff_apply: that adopts the imported
         * commit's own rev/prev/sig verbatim, which would splice a foreign
         * commit into this repo's chain instead of extending it. */
        wf_repo_verify_options opts = {s->did, s->signing_key_didkey, NULL};
        wf_repo_diff diff = {0};
        st = wf_repo_diff_verify(&s->car, &s->head, &imported, &opts, &diff);
        wf_car_free(&imported);
        if (st != WF_OK) {
            wf_xrpc_response_set_error(resp, 400, "InvalidCAR",
                                       "imported CAR failed verification");
            return WF_OK;
        }

        if (diff.operation_count == 0) {
            /* Identical snapshot re-imported: a genuine no-op rather than a
             * content-free commit that just advances rev. */
            wf_repo_diff_free(&diff);
        } else {
            wf_repo_write *writes =
                calloc(diff.operation_count, sizeof(*writes));
            if (!writes) {
                wf_repo_diff_free(&diff);
                return WF_ERR_ALLOC;
            }
            for (size_t i = 0; i < diff.operation_count; i++) {
                wf_repo_operation *op = &diff.operations[i];
                writes[i].collection = op->collection;
                writes[i].rkey = op->rkey;
                if (op->action == WF_REPO_DELETE) {
                    writes[i].action = WF_REPO_WRITE_DELETE;
                    continue;
                }
                wf_car_block *leaf =
                    wf_car_find_block(&diff.new_blocks, &op->cid);
                if (!leaf) {
                    free(writes);
                    wf_repo_diff_free(&diff);
                    wf_xrpc_response_set_error(
                        resp, 400, "InvalidCAR",
                        "imported CAR is missing a referenced record block");
                    return WF_OK;
                }
                writes[i].action = op->action == WF_REPO_CREATE
                                       ? WF_REPO_WRITE_CREATE
                                       : WF_REPO_WRITE_UPDATE;
                writes[i].record_cbor = leaf->data;
                writes[i].record_cbor_len = leaf->data_len;
            }

            wf_cid new_commit = {{0}, 0};
            st = wf_repo_apply_writes(&s->car, &s->head, s->did, writes,
                                      diff.operation_count, &s->key,
                                      &new_commit);
            if (st != WF_OK) {
                free(writes);
                wf_repo_diff_free(&diff);
                wf_xrpc_response_set_error(
                    resp, 400, "InvalidRequest",
                    "imported repo diverges from the current repo");
                return WF_OK;
            }
            st = commit_persist(s, &new_commit);
            if (st != WF_OK) {
                free(writes);
                wf_repo_diff_free(&diff);
                wf_xrpc_response_set_error(resp, 500, "InternalError",
                                           "failed to persist imported repo");
                return WF_OK;
            }
            reindex_all(s);

            metalbear_repo_store_op *events =
                calloc(diff.operation_count, sizeof(*events));
            if (!events) {
                free(writes);
                wf_repo_diff_free(&diff);
                return WF_ERR_ALLOC;
            }
            for (size_t i = 0; i < diff.operation_count; i++) {
                events[i].action =
                    writes[i].action == WF_REPO_WRITE_CREATE   ? "create"
                    : writes[i].action == WF_REPO_WRITE_UPDATE ? "update"
                                                               : "delete";
                events[i].collection = writes[i].collection;
                events[i].rkey = writes[i].rkey;
                events[i].cid = writes[i].out_record;
                events[i].has_cid = writes[i].action != WF_REPO_WRITE_DELETE;
            }
            emit_commit_event_ops(s, &old_head, events, diff.operation_count);
            free(events);
            free(writes);
            wf_repo_diff_free(&diff);
        }
    }

    cJSON *out = cJSON_CreateObject();
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static void free_pds_repo_bundle(void *ptr) {
    metalbear_pds_repo_bundle *b = ptr;
    if (!b) return;
    free(b->service_did);
    free(b->public_url);
    free(b);
}

static wf_status register_pds_repo_handlers(wf_xrpc_server *server,
                                            metalbear_pds_repo_bundle *b);

wf_status metalbear_xrpc_server_register_pds_repo(wf_xrpc_server *server,
                                                  metalbear_repo_store *store,
                                                  const char *service_did,
                                                  const char *public_url) {
    if (!server || !store) return WF_ERR_INVALID_ARG;
    metalbear_pds_repo_bundle *b =
        (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->fallback_repo = store;
    b->accepting_imports = true;
    if (service_did) b->service_did = strdup(service_did);
    if (public_url) b->public_url = strdup(public_url);
    wf_xrpc_server_own_ctx(server, b, free_pds_repo_bundle);
    return register_pds_repo_handlers(server, b);
}

static wf_status register_pds_repo_handlers(wf_xrpc_server *server,
                                            metalbear_pds_repo_bundle *b) {
    if (!server || !b) return WF_ERR_INVALID_ARG;
    wf_status s;
    s = wf_xrpc_server_register_procedure(
        server, "com.atproto.repo.createRecord", h_create_record, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_procedure(server, "com.atproto.repo.putRecord",
                                          h_put_record, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_procedure(
        server, "com.atproto.repo.deleteRecord", h_delete_record, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_procedure(
        server, "com.atproto.repo.applyWrites", h_apply_writes, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_query(server, "com.atproto.repo.getRecord",
                                      h_get_record, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_query(server, "com.atproto.repo.describeRepo",
                                      h_describe_repo, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_query(server, "com.atproto.repo.listRecords",
                                      h_list_records, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_query(server, "com.atproto.label.queryLabels",
                                      h_query_labels, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_query(
        server, "com.atproto.sync.getLatestCommit", h_get_latest_commit, b);
    if (s != WF_OK) return s;
    /* importRepo (CAR POST body) — see h_import_repo. uploadBlob is
     * registered separately by wf_xrpc_server_register_blob_store. */
    s = wf_xrpc_server_register_procedure(server, "com.atproto.repo.importRepo",
                                          h_import_repo, b);
    if (s != WF_OK) return s;
    return WF_OK;
}

wf_status metalbear_xrpc_server_register_pds_repo_resolver(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx,
    const char *service_did, const char *public_url) {
    return metalbear_xrpc_server_register_pds_repo_resolver_ex(
        server, resolver, ctx, service_did, public_url, NULL, NULL, NULL, NULL,
        NULL, true, 0);
}

wf_status metalbear_xrpc_server_register_pds_repo_resolver_ex(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx,
    const char *service_did, const char *public_url,
    metalbear_xrpc_did_doc_provider did_doc_provider, void *did_doc_ctx,
    const wf_lexicon_registry *lexicons, metalbear_xrpc_repo_access_guard guard,
    void *guard_ctx, bool accepting_imports, int64_t max_import_size) {
    if (!server) return WF_ERR_INVALID_ARG;
    metalbear_pds_repo_bundle *b =
        (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->resolver = resolver;
    b->resolver_ctx = ctx;
    b->did_doc_provider = did_doc_provider;
    b->did_doc_ctx = did_doc_ctx;
    b->lexicons = lexicons;
    b->guard = guard;
    b->guard_ctx = guard_ctx;
    b->accepting_imports = accepting_imports;
    b->max_import_size = max_import_size;
    if (service_did) b->service_did = strdup(service_did);
    if (public_url) b->public_url = strdup(public_url);
    wf_xrpc_server_own_ctx(server, b, free);
    return register_pds_repo_handlers(server, b);
}

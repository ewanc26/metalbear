/*
 * repo_store.c — durable, writable repo storage engine for a self-hosted
 * AT Protocol PDS (first coherent PDS slice).
 *
 * Reuses the SDK's existing, tested repo primitives rather than
 * reimplementing them:
 *   - wf_repo_create_record / wf_repo_update_record / wf_repo_delete_record
 *     / wf_repo_get_record (src/repo/repo.c) build the MST mutations and
 *     call wf_commit_create to produce a signed v3 commit.
 *   - wf_cid_* / wf_car_* / wf_mst_* implement DAG-CBOR, content addressing,
 *     and the MST.
 *   - wf_repo_verify (src/repo/diff.c) verifies the produced commit against
 *     the repo signing key.
 *
 * Records are kept in a content-addressed SQLite block store; the head
 * commit CID is tracked separately so the store is durable across
 * restarts.
 */

#include "repo_store_internal.h"

#include "metalbear/repo/blob_store.h"

#include "wolfram/repo/cbor.h"
#include "wolfram/repo/record.h"
#include "wolfram/repo/diff.h"
#include "wolfram/repo/mst.h"
#include "wolfram/syntax.h"
#include "wolfram/server.h"
#include "wolfram/tid.h"

#include <cJSON.h>
#include <pthread.h>
#include <sqlite3.h>

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Generic JSON <-> DAG-CBOR (records may be arbitrary lexicons)      */
/* ------------------------------------------------------------------ */

static wf_cbor_item *cbor_from_json(const cJSON *j) {
    if (!j) return NULL;

    if (cJSON_IsNull(j)) {
        wf_cbor_item *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = WF_CBOR_SIMPLE;
        v->simple_value = 22;
        return v;
    }
    if (cJSON_IsBool(j)) {
        wf_cbor_item *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = WF_CBOR_SIMPLE;
        v->simple_value = cJSON_IsTrue(j) ? 21 : 20;
        return v;
    }
    if (cJSON_IsNumber(j)) {
        double d = j->valuedouble;
        if (!isfinite(d) || d != floor(d) || fabs(d) > 9007199254740991.0)
            return NULL; /* DAG-CBOR forbids floats / oversized ints */
        wf_cbor_item *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        if (d >= 0) {
            v->type = WF_CBOR_UNSIGNED;
            v->uinteger = (uint64_t)d;
        } else {
            v->type = WF_CBOR_NEGATIVE;
            v->neginteger = (uint64_t)(-1.0 - d);
        }
        return v;
    }
    if (cJSON_IsString(j)) {
        wf_cbor_item *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = WF_CBOR_STRING;
        size_t n = strlen(j->valuestring);
        v->string.str = malloc(n + 1);
        if (!v->string.str) {
            free(v);
            return NULL;
        }
        memcpy(v->string.str, j->valuestring, n + 1);
        v->string.len = n;
        return v;
    }
    if (cJSON_IsArray(j)) {
        int n = cJSON_GetArraySize((cJSON *)j);
        wf_cbor_item *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = WF_CBOR_ARRAY;
        v->children.count = (size_t)n;
        v->children.items =
            n ? calloc((size_t)n, sizeof(wf_cbor_item *)) : NULL;
        if (n && !v->children.items) {
            free(v);
            return NULL;
        }
        int i = 0;
        const cJSON *child;
        cJSON_ArrayForEach(child, (cJSON *)j) {
            v->children.items[i] = cbor_from_json(child);
            if (!v->children.items[i]) {
                wf_cbor_free(v);
                return NULL;
            }
            i++;
        }
        return v;
    }
    if (cJSON_IsObject(j)) {
        /* Single-key $link / $bytes objects round-trip to CID / bytes. */
        int count = cJSON_GetArraySize((cJSON *)j);
        if (count == 1) {
            const cJSON *only = cJSON_GetArrayItem((cJSON *)j, 0);
            if (only->string && strcmp(only->string, "$link") == 0 &&
                cJSON_IsString(only)) {
                wf_cid cid;
                if (wf_cid_from_string(only->valuestring, &cid) == WF_OK) {
                    wf_cbor_item *v = calloc(1, sizeof(*v));
                    if (!v) return NULL;
                    v->type = WF_CBOR_LINK;
                    v->bytes.len = cid.len;
                    if (cid.len) {
                        v->bytes.data = malloc(cid.len);
                        if (!v->bytes.data) {
                            free(v);
                            return NULL;
                        }
                        memcpy(v->bytes.data, cid.bytes, cid.len);
                    }
                    return v;
                }
            } else if (only->string && strcmp(only->string, "$bytes") == 0 &&
                       cJSON_IsString(only)) {
                unsigned char *raw = NULL;
                size_t raw_len = 0;
                if (wf_crypto_base64url_decode(only->valuestring, &raw,
                                               &raw_len) == WF_OK) {
                    wf_cbor_item *v = calloc(1, sizeof(*v));
                    if (v) {
                        v->type = WF_CBOR_BYTES;
                        v->bytes.len = raw_len;
                        v->bytes.data = raw;
                        return v;
                    }
                }
                free(raw);
            }
        }

        wf_cbor_item *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = WF_CBOR_MAP;
        v->map.count = (size_t)count;
        v->map.pairs =
            count ? calloc((size_t)count, sizeof(wf_cbor_pair)) : NULL;
        if (count && !v->map.pairs) {
            free(v);
            return NULL;
        }
        size_t i = 0;
        const cJSON *child;
        cJSON_ArrayForEach(child, (cJSON *)j) {
            wf_cbor_item *k = NULL;
            wf_cbor_item *val = NULL;
            if (child->string) {
                k = calloc(1, sizeof(*k));
                if (k) {
                    k->type = WF_CBOR_STRING;
                    size_t n = strlen(child->string);
                    k->string.str = malloc(n + 1);
                    if (k->string.str) {
                        memcpy(k->string.str, child->string, n + 1);
                        k->string.len = n;
                    } else {
                        free(k);
                        k = NULL;
                    }
                }
            }
            val = cbor_from_json(child);
            if (!k || !val) {
                wf_cbor_free(k);
                wf_cbor_free(val);
                wf_cbor_free(v);
                return NULL;
            }
            v->map.pairs[i].key = k;
            v->map.pairs[i].value = val;
            i++;
        }
        return v;
    }
    return NULL;
}

static cJSON *cbor_to_json(const wf_cbor_item *item) {
    if (!item) return cJSON_CreateNull();
    switch (item->type) {
        case WF_CBOR_UNSIGNED:
            return cJSON_CreateNumber((double)item->uinteger);
        case WF_CBOR_NEGATIVE:
            return cJSON_CreateNumber(-1.0 - (double)item->neginteger);
        case WF_CBOR_STRING:
            return cJSON_CreateString(item->string.str ? item->string.str : "");
        case WF_CBOR_BYTES: {
            char *b64 = NULL;
            cJSON *o = cJSON_CreateObject();
            if (o && item->bytes.len)
                wf_crypto_base64url_encode(item->bytes.data, item->bytes.len,
                                           &b64);
            if (o) cJSON_AddStringToObject(o, "$bytes", b64 ? b64 : "");
            free(b64);
            return o;
        }
        case WF_CBOR_LINK: {
            wf_cid cid;
            memset(&cid, 0, sizeof(cid));
            cid.len = item->bytes.len;
            if (item->bytes.len)
                memcpy(cid.bytes, item->bytes.data, item->bytes.len);
            char *cidstr = wf_cid_to_string(&cid);
            cJSON *o = cJSON_CreateObject();
            if (o) cJSON_AddStringToObject(o, "$link", cidstr ? cidstr : "");
            free(cidstr);
            return o;
        }
        case WF_CBOR_ARRAY: {
            cJSON *a = cJSON_CreateArray();
            if (!a) return NULL;
            for (size_t i = 0; i < item->children.count; i++) {
                cJSON *e = cbor_to_json(item->children.items[i]);
                if (!e) {
                    cJSON_Delete(a);
                    return NULL;
                }
                cJSON_AddItemToArray(a, e);
            }
            return a;
        }
        case WF_CBOR_MAP: {
            cJSON *o = cJSON_CreateObject();
            if (!o) return NULL;
            for (size_t i = 0; i < item->map.count; i++) {
                const wf_cbor_item *k = item->map.pairs[i].key;
                cJSON *val = cbor_to_json(item->map.pairs[i].value);
                if (!val || k->type != WF_CBOR_STRING) {
                    cJSON_Delete(val);
                    cJSON_Delete(o);
                    return NULL;
                }
                cJSON_AddItemToObject(o, k->string.str ? k->string.str : "",
                                      val);
            }
            return o;
        }
        case WF_CBOR_SIMPLE:
            if (item->simple_value == 21) return cJSON_CreateTrue();
            if (item->simple_value == 20) return cJSON_CreateFalse();
            return cJSON_CreateNull();
    }
    return cJSON_CreateNull();
}

/* Encode a record JSON object (must contain $type) to canonical DAG-CBOR. */
static wf_status encode_record_json(const char *record_json,
                                    unsigned char **out_cbor, size_t *out_len) {
    if (out_cbor) *out_cbor = NULL;
    if (out_len) *out_len = 0;
    if (!record_json || !out_cbor || !out_len) return WF_ERR_INVALID_ARG;

    cJSON *root = cJSON_Parse(record_json);
    if (!root || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return WF_ERR_INVALID_ARG;
    }
    if (cJSON_GetObjectItemCaseSensitive(root, "$type") == NULL) {
        /* Records must carry a $type to be valid DAG-CBOR records. */
        cJSON_Delete(root);
        return WF_ERR_INVALID_ARG;
    }
    wf_cbor_item *item = cbor_from_json(root);
    cJSON_Delete(root);
    if (!item) return WF_ERR_INVALID_ARG;

    *out_cbor = wf_cbor_serialize(item, out_len);
    wf_cbor_free(item);
    return *out_cbor ? WF_OK : WF_ERR_ALLOC;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

char *make_uri(const char *did, const char *collection, const char *rkey) {
    size_t n = strlen("at://") + strlen(did) + 1 + strlen(collection) + 1 +
               strlen(rkey) + 1;
    char *u = malloc(n);
    if (!u) return NULL;
    snprintf(u, n, "at://%s/%s/%s", did, collection, rkey);
    return u;
}

static void set_root(metalbear_repo_store *s) {
    s->car.roots = &s->head;
    s->car.root_count = s->head.len > 0 ? 1 : 0;
}

/* Fill a `commit` meta object {cid, rev} from the current head. */
void add_commit_meta(metalbear_repo_store *s, cJSON *parent) {
    cJSON *commit = cJSON_CreateObject();
    char *cid = s->head.len ? wf_cid_to_string(&s->head) : strdup("");
    char rev[64] = "";
    if (s->head.len) {
        wf_car_block *blk = wf_car_find_block(&s->car, &s->head);
        if (blk) {
            wf_commit cm;
            if (wf_commit_parse(blk->data, blk->data_len, &cm) == WF_OK)
                snprintf(rev, sizeof(rev), "%s", cm.rev);
        }
    }
    cJSON_AddStringToObject(commit, "cid", cid ? cid : "");
    free(cid);
    cJSON_AddStringToObject(commit, "rev", rev);
    cJSON_AddItemToObject(parent, "commit", commit);
}

/* Fetch a record's raw CBOR + CID from the current head. */
static wf_status get_record_cbor(metalbear_repo_store *s,
                                 const char *collection, const char *rkey,
                                 unsigned char **out_data, size_t *out_len,
                                 wf_cid *out_record_cid) {
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;
    return wf_repo_get_record(&s->car, &s->head, collection, rkey, out_data,
                              out_len, out_record_cid);
}

/* Forward declaration (defined in the Persistence section below). */
/* Defined below, alongside the commit-event helpers. */
static int parse_commit_at(metalbear_repo_store *s, const wf_cid *cid,
                           wf_commit *out);

static wf_status index_upsert_record(metalbear_repo_store *s,
                                     const char *collection, const char *rkey,
                                     const char *cid, const char *value);

static wf_status
apply_writes_locked(metalbear_repo_store *s, const char *writes_json,
                    const char *swap_commit_or_null, char **out_commit_cid,
                    char **out_commit_rev, char **out_results_json);

/* Current head commit CID as a base32 string ("" when repo is empty). */
static char *head_cid_string(metalbear_repo_store *s) {
    return s->head.len ? wf_cid_to_string(&s->head) : strdup("");
}

/* Compare a requested compare-and-swap CID (may be NULL/empty) against the
 * current value (a base32 string). Returns WF_OK when they match or when no
 * swap was requested, else WF_ERR_CONFLICT — distinct from WF_ERR_INVALID_ARG
 * so the route handlers can report the lexicon's `InvalidSwap` error, which
 * clients branch on to retry an optimistic write. */
static wf_status check_swap(const char *requested, const char *current) {
    if (!requested || !*requested) return WF_OK;
    if (!current || strcmp(requested, current) != 0) return WF_ERR_CONFLICT;
    return WF_OK;
}

/* If the record JSON carries a $type, it must equal `collection`.
 * A missing $type is allowed (a real PDS would stamp it). Returns 1
 * when the constraint is satisfied. */
static int record_type_matches(const char *record_json,
                               const char *collection) {
    cJSON *root = cJSON_Parse(record_json);
    if (!root) return 1;
    cJSON *t = cJSON_GetObjectItemCaseSensitive(root, "$type");
    int ok = (t && cJSON_IsString(t))
                 ? (strcmp(t->valuestring, collection) == 0)
                 : 1;
    cJSON_Delete(root);
    return ok;
}

wf_status metalbear_validate_record(const wf_lexicon_registry *lexicons,
                                    const char *collection,
                                    const char *record_json,
                                    bool require_schema,
                                    metalbear_validation_status *out_status,
                                    char **out_message) {
    if (out_status) *out_status = METALBEAR_VALIDATION_UNKNOWN;
    if (out_message) *out_message = NULL;
    if (!collection || !record_json) return WF_ERR_INVALID_ARG;

    /* Nothing to check against. The reference reports `unknown` here rather
     * than rejecting, so that a PDS still hosts collections whose lexicons it
     * does not carry — unless the caller explicitly demanded validation. */
    if (!lexicons || !wf_lexicon_registry_contains(lexicons, collection))
        return require_schema ? WF_ERR_NOT_FOUND : WF_OK;

    wf_validate_result result = wf_validate_record(
        lexicons, collection, record_json, strlen(record_json));
    if (result.success) {
        wf_validate_result_free(&result);
        if (out_status) *out_status = METALBEAR_VALIDATION_VALID;
        return WF_OK;
    }
    if (out_message && result.errors) {
        const char *path = result.errors->path ? result.errors->path : "record";
        const char *msg =
            result.errors->message ? result.errors->message : "is invalid";
        /* "Invalid " + collection + " record: " + path + " " + msg + NUL */
        size_t n = strlen("Invalid  record:  ") + strlen(collection) +
                   strlen(path) + strlen(msg) + 1;
        char *text = malloc(n);
        if (text) {
            snprintf(text, n, "Invalid %s record: %s %s", collection, path,
                     msg);
            *out_message = text;
        }
    }
    wf_validate_result_free(&result);
    return WF_ERR_VALIDATION;
}

/* Decode a record block (by CID) into canonical record JSON, or NULL. */
static char *decode_record_json(metalbear_repo_store *s,
                                const wf_cid *record_cid) {
    wf_car_block *blk = wf_car_find_block(&s->car, record_cid);
    if (!blk) return NULL;
    wf_cbor_item *item = wf_cbor_parse(blk->data, blk->data_len);
    if (!item) return NULL;
    cJSON *j = cbor_to_json(item);
    wf_cbor_free(item);
    if (!j) return NULL;
    char *js = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    return js;
}

/* Rebuild the `records` index from the current head commit's MST, so
 * listRecords stays consistent after an importRepo. */
static wf_status reindex_collect(metalbear_repo_store *s,
                                 const wf_cid *node_cid) {
    if (node_cid->len == 0) return WF_OK;
    wf_car_block *b = wf_car_find_block(&s->car, node_cid);
    if (!b) return WF_OK;
    wf_mst_node node;
    memset(&node, 0, sizeof(node));
    wf_status st = wf_mst_node_parse(b->data, b->data_len, node_cid, &node);
    if (st != WF_OK) return st;
    if (node.left.len) {
        st = reindex_collect(s, &node.left);
        if (st != WF_OK) {
            wf_mst_node_free(&node);
            return st;
        }
    }
    for (size_t i = 0; i < node.count; i++) {
        if (node.entries[i].subtree.len == 0) {
            unsigned char *k = node.entries[i].key;
            size_t kl = node.entries[i].key_len;
            unsigned char *slash = memchr(k, '/', kl);
            if (slash) {
                size_t clen = (size_t)(slash - k);
                size_t rlen = kl - clen - 1;
                char *coll = malloc(clen + 1);
                char *rk = malloc(rlen + 1);
                if (coll && rk) {
                    memcpy(coll, k, clen);
                    coll[clen] = '\0';
                    memcpy(rk, slash + 1, rlen);
                    rk[rlen] = '\0';
                    char *cidstr = wf_cid_to_string(&node.entries[i].value);
                    if (cidstr) {
                        char *js =
                            decode_record_json(s, &node.entries[i].value);
                        if (js) {
                            index_upsert_record(s, coll, rk, cidstr, js);
                            free(js);
                        }
                        free(cidstr);
                    }
                }
                free(coll);
                free(rk);
            }
        } else {
            st = reindex_collect(s, &node.entries[i].subtree);
            if (st != WF_OK) {
                wf_mst_node_free(&node);
                return st;
            }
        }
    }
    wf_mst_node_free(&node);
    return WF_OK;
}

wf_status reindex_all(metalbear_repo_store *s) {
    sqlite3_exec(s->db, "DELETE FROM records;", NULL, NULL, NULL);
    if (s->head.len == 0) return WF_OK;
    wf_car_block *b = wf_car_find_block(&s->car, &s->head);
    if (!b) return WF_OK;
    wf_commit cm;
    memset(&cm, 0, sizeof(cm));
    wf_status st = wf_commit_parse(b->data, b->data_len, &cm);
    if (st != WF_OK) return st;
    return reindex_collect(s, &cm.data);
}

/* ------------------------------------------------------------------ */
/* Persistence                                                         */
/* ------------------------------------------------------------------ */

static wf_status persist_new_blocks(metalbear_repo_store *s) {
    char revision[64] = "";
    wf_car_block *head_block = wf_car_find_block(&s->car, &s->head);
    if (head_block) {
        wf_commit commit;
        if (wf_commit_parse(head_block->data, head_block->data_len, &commit) ==
            WF_OK)
            snprintf(revision, sizeof(revision), "%s", commit.rev);
    }
    for (size_t i = s->persisted_blocks; i < s->car.block_count; i++) {
        wf_car_block *blk = &s->car.blocks[i];
        char *cidstr = wf_cid_to_string(&blk->cid);
        if (!cidstr) return WF_ERR_ALLOC;
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(
                s->db,
                "INSERT OR IGNORE INTO blocks (cid, data, repo_rev) "
                "VALUES (?, ?, ?);",
                -1, &stmt, NULL) != SQLITE_OK) {
            free(cidstr);
            return WF_ERR_INTERNAL;
        }
        sqlite3_bind_text(stmt, 1, cidstr, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, blk->data, (int)blk->data_len,
                          SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, revision, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        free(cidstr);
        if (rc != SQLITE_DONE) return WF_ERR_INTERNAL;
    }
    s->persisted_blocks = s->car.block_count;
    return WF_OK;
}

/* Maintain the `records` index used by listRecords. The index mirrors the
 * live MST head: each (collection, rkey) maps to its current value + CID. */
static wf_status index_upsert_record(metalbear_repo_store *s,
                                     const char *collection, const char *rkey,
                                     const char *cid, const char *value) {
    /* Stamp the rev this record landed at, and when, so read-after-write can
     * find records an AppView has not caught up to. The head is already
     * updated by the time the index is written. */
    char rev_buf[64] = "";
    wf_commit head;
    if (parse_commit_at(s, &s->head, &head))
        snprintf(rev_buf, sizeof(rev_buf), "%s", head.rev);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            s->db,
            "INSERT OR REPLACE INTO records"
            " (collection, rkey, cid, value, repo_rev, indexed_at)"
            " VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, collection, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, cid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, value, -1, SQLITE_TRANSIENT);
    if (rev_buf[0])
        sqlite3_bind_text(stmt, 5, rev_buf, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 5);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

static wf_status index_delete_record(metalbear_repo_store *s,
                                     const char *collection, const char *rkey) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            s->db, "DELETE FROM records WHERE collection = ? AND rkey = ?;", -1,
            &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, collection, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rkey, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

static wf_status persist_head(metalbear_repo_store *s) {
    char *cidstr = s->head.len ? wf_cid_to_string(&s->head) : NULL;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            s->db, "INSERT OR REPLACE INTO head (id, cid) VALUES (0, ?);", -1,
            &stmt, NULL) != SQLITE_OK) {
        free(cidstr);
        return WF_ERR_INTERNAL;
    }
    if (cidstr)
        sqlite3_bind_text(stmt, 1, cidstr, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 1);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(cidstr);
    return rc == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

/* Persist the new head commit (and any new blocks) atomically. */
wf_status commit_persist(metalbear_repo_store *s, const wf_cid *new_head) {
    s->head = *new_head;
    set_root(s);

    if (sqlite3_exec(s->db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    wf_status st = persist_new_blocks(s);
    if (st == WF_OK) st = persist_head(s);
    if (st == WF_OK)
        sqlite3_exec(s->db, "COMMIT;", NULL, NULL, NULL);
    else
        sqlite3_exec(s->db, "ROLLBACK;", NULL, NULL, NULL);
    return st;
}

static wf_status load_all_blocks(metalbear_repo_store *s) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT cid, data FROM blocks;", -1, &stmt,
                           NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    wf_status st = WF_OK;
    for (;;) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            st = WF_ERR_INTERNAL;
            break;
        }
        wf_cid cid;
        const char *cidstr = (const char *)sqlite3_column_text(stmt, 0);
        if (wf_cid_from_string(cidstr, &cid) != WF_OK) {
            st = WF_ERR_PARSE;
            break;
        }
        const unsigned char *data =
            (const unsigned char *)sqlite3_column_blob(stmt, 1);
        int dlen = sqlite3_column_bytes(stmt, 1);

        wf_car_block *nb = realloc(s->car.blocks, (s->car.block_count + 1) *
                                                      sizeof(wf_car_block));
        if (!nb) {
            st = WF_ERR_ALLOC;
            break;
        }
        s->car.blocks = nb;
        wf_car_block *blk = &s->car.blocks[s->car.block_count];
        blk->cid = cid;
        blk->data_len = (size_t)dlen;
        blk->data = dlen ? malloc((size_t)dlen) : NULL;
        if (dlen && !blk->data) {
            st = WF_ERR_ALLOC;
            break;
        }
        if (dlen) memcpy(blk->data, data, (size_t)dlen);
        s->car.block_count++;
    }
    sqlite3_finalize(stmt);
    return st;
}

static void free_store(metalbear_repo_store *s) {
    if (!s) return;
    pthread_mutex_destroy(&s->mutex);
    if (s->db) sqlite3_close(s->db);
    for (size_t i = 0; i < s->car.block_count; i++) free(s->car.blocks[i].data);
    free(s->car.blocks);
    free(s->did);
    free(s->handle);
    free(s->signing_key_didkey);
    free(s->path);
    free(s);
}

/* ------------------------------------------------------------------ */
/* Open / close                                                        */
/* ------------------------------------------------------------------ */

wf_status metalbear_repo_store_open(const char *path, const char *did,
                                    const char *handle,
                                    metalbear_repo_store **out) {
    return metalbear_repo_store_open_with_key(path, did, handle, NULL, out);
}

wf_status metalbear_repo_store_open_with_key(const char *path, const char *did,
                                             const char *handle,
                                             const wf_signing_key *signing_key,
                                             metalbear_repo_store **out) {
    if (!path || !*path || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;

    metalbear_repo_store *s = calloc(1, sizeof(*s));
    if (!s) return WF_ERR_ALLOC;
    s->path = strdup(path);
    if (!s->path) {
        free(s);
        return WF_ERR_ALLOC;
    }

    if (sqlite3_open_v2(path, &s->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }

    const char *schema =
        "CREATE TABLE IF NOT EXISTS meta ("
        "  id INTEGER PRIMARY KEY CHECK(id=0),"
        "  did TEXT NOT NULL, handle TEXT NOT NULL,"
        "  key_type INTEGER NOT NULL, key_bytes BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS blocks ("
        "  cid TEXT PRIMARY KEY, data BLOB NOT NULL, repo_rev TEXT);"
        "CREATE TABLE IF NOT EXISTS head ("
        "  id INTEGER PRIMARY KEY CHECK(id=0), cid TEXT);"
        "CREATE TABLE IF NOT EXISTS records ("
        "  collection TEXT NOT NULL, rkey TEXT NOT NULL,"
        "  cid TEXT NOT NULL, value TEXT NOT NULL,"
        "  PRIMARY KEY (collection, rkey));";
    char *errmsg = NULL;
    if (sqlite3_exec(s->db, schema, NULL, NULL, &errmsg) != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        free_store(s);
        return WF_ERR_INTERNAL;
    }

    /* Migration for stores created before incremental CAR export tracked the
     * revision that introduced each block. Legacy rows remain NULL and are
     * included in full exports; all newly persisted blocks carry repo_rev. */
    int has_repo_rev = 0;
    sqlite3_stmt *column_stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "PRAGMA table_info(blocks);", -1,
                           &column_stmt, NULL) != SQLITE_OK) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }
    while (sqlite3_step(column_stmt) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(column_stmt, 1);
        if (name && strcmp(name, "repo_rev") == 0) has_repo_rev = 1;
    }
    sqlite3_finalize(column_stmt);
    if (!has_repo_rev &&
        sqlite3_exec(s->db, "ALTER TABLE blocks ADD COLUMN repo_rev TEXT;",
                     NULL, NULL, NULL) != SQLITE_OK) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }

    /* Read-after-write needs to know which records post-date a given repo rev,
     * and when each was written, so a just-created record can be spliced into
     * an AppView response that has not indexed it yet. Legacy rows keep NULL
     * and are simply never treated as "recent". */
    int has_record_rev = 0, has_indexed_at = 0;
    column_stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "PRAGMA table_info(records);", -1,
                           &column_stmt, NULL) != SQLITE_OK) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }
    while (sqlite3_step(column_stmt) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(column_stmt, 1);
        if (!name) continue;
        if (strcmp(name, "repo_rev") == 0) has_record_rev = 1;
        if (strcmp(name, "indexed_at") == 0) has_indexed_at = 1;
    }
    sqlite3_finalize(column_stmt);
    if ((!has_record_rev &&
         sqlite3_exec(s->db, "ALTER TABLE records ADD COLUMN repo_rev TEXT;",
                      NULL, NULL, NULL) != SQLITE_OK) ||
        (!has_indexed_at &&
         sqlite3_exec(s->db, "ALTER TABLE records ADD COLUMN indexed_at TEXT;",
                      NULL, NULL, NULL) != SQLITE_OK)) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            s->db,
            "SELECT did, handle, key_type, key_bytes FROM meta WHERE id=0;", -1,
            &stmt, NULL) != SQLITE_OK) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }

    wf_status st = WF_OK;
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) {
        const char *d = (const char *)sqlite3_column_text(stmt, 0);
        const char *h = (const char *)sqlite3_column_text(stmt, 1);
        int kt = sqlite3_column_int(stmt, 2);
        const void *kb = sqlite3_column_blob(stmt, 3);
        int kbl = sqlite3_column_bytes(stmt, 3);

        /*
         * The account registry is the authority on which DID this repo
         * belongs to, not the repo's own meta row. Historically the stored
         * value was loaded and the caller's `did` ignored outright, so a repo
         * created under a placeholder DID (e.g. before a real did:plc was
         * minted) kept that DID forever: every AT-URI it returned pointed at a
         * DID that resolves nowhere, and every commit was signed claiming an
         * identity whose DID document does not list this repo's signing key.
         * Nothing surfaced the divergence.
         *
         * A repo's DID is immutable in atproto — the commit objects already
         * written embed it in signed CBOR, so it cannot be corrected by
         * rewriting this row. Refuse to open instead of silently producing
         * unfederatable data; recovery means re-creating the repo under the
         * correct DID.
         *
         * The reference implementation avoids the whole failure mode by never
         * treating the store as the authority: its actor store is constructed
         * with the DID from the account lookup and threads it through.
         */
        if (did && *did && d && *d && strcmp(did, d) != 0) {
            sqlite3_finalize(stmt);
            fprintf(stderr,
                    "metalbear: repo at %s belongs to %s but was opened for "
                    "%s; refusing to serve it. A repo's DID is immutable "
                    "(already-signed commits embed it), so this repo must be "
                    "re-created under the correct DID.\n",
                    path, d, did);
            free_store(s);
            return WF_ERR_INVALID_ARG;
        }

        s->did = strdup(d ? d : "");
        s->handle = strdup(h ? h : "");
        s->key.type = (wf_key_type)kt;
        if (kbl == (int)sizeof(s->key.bytes))
            memcpy(s->key.bytes, kb, sizeof(s->key.bytes));
        sqlite3_finalize(stmt);

        if (wf_signing_key_public_didkey(&s->key, &s->signing_key_didkey) !=
            WF_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }
        st = load_all_blocks(s);
        if (st != WF_OK) {
            free_store(s);
            return st;
        }

        /* Load head commit CID, if any. */
        if (sqlite3_prepare_v2(s->db, "SELECT cid FROM head WHERE id=0;", -1,
                               &stmt, NULL) != SQLITE_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }
        int hstep = sqlite3_step(stmt);
        if (hstep == SQLITE_ROW) {
            const char *hc = (const char *)sqlite3_column_text(stmt, 0);
            if (hc && wf_cid_from_string(hc, &s->head) != WF_OK) {
                sqlite3_finalize(stmt);
                free_store(s);
                return WF_ERR_PARSE;
            }
        }
        sqlite3_finalize(stmt);
        s->persisted_blocks = s->car.block_count;
        set_root(s);
    } else {
        sqlite3_finalize(stmt);
        if (!did || !*did) {
            free_store(s);
            return WF_ERR_INVALID_ARG;
        }

        wf_signing_key key;
        if (signing_key) {
            key = *signing_key;
        } else if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &key) !=
                   WF_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }
        s->did = strdup(did);
        s->handle = strdup(handle ? handle : "");
        s->key = key;
        if (wf_signing_key_public_didkey(&s->key, &s->signing_key_didkey) !=
            WF_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }

        if (sqlite3_prepare_v2(
                s->db,
                "INSERT INTO meta (id, did, handle, key_type, key_bytes) "
                "VALUES (0, ?, ?, ?, ?);",
                -1, &stmt, NULL) != SQLITE_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }
        sqlite3_bind_text(stmt, 1, s->did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, s->handle, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, (int)s->key.type);
        sqlite3_bind_blob(stmt, 4, s->key.bytes, (int)sizeof(s->key.bytes),
                          SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }
        set_root(s);
    }

    if (pthread_mutex_init(&s->mutex, NULL) != 0) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }

    *out = s;
    return WF_OK;
}

void metalbear_repo_store_free(metalbear_repo_store *store) {
    free_store(store);
}

const char *metalbear_repo_store_did(const metalbear_repo_store *store) {
    return store ? store->did : NULL;
}
const char *metalbear_repo_store_handle(const metalbear_repo_store *store) {
    return store ? store->handle : NULL;
}

const char *
metalbear_repo_store_signing_key_did(const metalbear_repo_store *store) {
    if (!store) return NULL;
    return store->signing_key_didkey;
}

wf_status metalbear_repo_store_set_handle(metalbear_repo_store *store,
                                          const char *handle) {
    if (!store || !handle || !wf_syntax_handle_is_valid(handle))
        return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    char *copy = strdup(handle);
    if (!copy) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_ALLOC;
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db, "UPDATE meta SET handle=? WHERE id=0;",
                           -1, &stmt, NULL) != SQLITE_OK) {
        free(copy);
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_INTERNAL;
    }
    sqlite3_bind_text(stmt, 1, handle, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE || sqlite3_changes(store->db) != 1) {
        free(copy);
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_INTERNAL;
    }
    free(store->handle);
    store->handle = copy;
    pthread_mutex_unlock(&store->mutex);
    return WF_OK;
}

wf_status
metalbear_repo_store_get_stats(metalbear_repo_store *store,
                               metalbear_repo_store_stats *out_stats) {
    if (!out_stats) return WF_ERR_INVALID_ARG;
    memset(out_stats, 0, sizeof(*out_stats));
    if (!store) return WF_ERR_INVALID_ARG;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
                           "SELECT (SELECT COUNT(*) FROM blocks), "
                           "(SELECT COUNT(*) FROM records);",
                           -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return WF_ERR_INTERNAL;
    }
    sqlite3_int64 blocks = sqlite3_column_int64(stmt, 0);
    sqlite3_int64 records = sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt);
    if (blocks < 0 || records < 0 || (uint64_t)blocks > (uint64_t)SIZE_MAX ||
        (uint64_t)records > (uint64_t)SIZE_MAX)
        return WF_ERR_INTERNAL;
    out_stats->repo_blocks = (size_t)blocks;
    out_stats->indexed_records = (size_t)records;
    return WF_OK;
}

void metalbear_repo_store_set_event_callback(
    metalbear_repo_store *store, metalbear_repo_store_event_cb callback,
    void *context) {
    if (!store) return;
    pthread_mutex_lock(&store->mutex);
    store->event_cb = callback;
    store->event_ctx = context;
    pthread_mutex_unlock(&store->mutex);
}

static int parse_commit_at(metalbear_repo_store *s, const wf_cid *cid,
                           wf_commit *out) {
    if (!s || !cid || !cid->len || !out) return 0;
    const wf_car_block *block = wf_car_find_block(&s->car, cid);
    return block && wf_commit_parse(block->data, block->data_len, out) == WF_OK;
}

/* Emit one #commit event describing `ops_count` mutations landed by a single
 * signed commit. */
void emit_commit_event_ops(metalbear_repo_store *s, const wf_cid *old_head,
                           const metalbear_repo_store_op *ops,
                           size_t ops_count) {
    if (!s || !s->event_cb) return;
    wf_commit current = {0}, previous = {0};
    if (!parse_commit_at(s, &s->head, &current)) return;
    int has_previous = parse_commit_at(s, old_head, &previous);
    unsigned char *blocks = NULL;
    size_t blocks_len = 0;
    if (metalbear_repo_store_export(s, has_previous ? previous.rev : NULL,
                                    &blocks, &blocks_len) != WF_OK)
        return;
    metalbear_repo_store_event event = {
        .kind = METALBEAR_REPO_STORE_EVENT_COMMIT,
        .did = s->did,
        .commit_cid = s->head,
        .rev = current.rev,
        .since = has_previous ? previous.rev : NULL,
        .prev_data = previous.data,
        .has_prev_data = has_previous,
        .ops = ops,
        .ops_count = ops_count,
        .blocks = blocks,
        .blocks_len = blocks_len,
    };
    s->event_cb(&event, s->event_ctx);
    free(blocks);
}

static void emit_commit_event(metalbear_repo_store *s, const wf_cid *old_head,
                              const char *action, const char *collection,
                              const char *rkey, const wf_cid *cid,
                              const wf_cid *prev) {
    metalbear_repo_store_op op = {
        .action = action,
        .collection = collection,
        .rkey = rkey,
        .cid = cid ? *cid : (wf_cid){{0}, 0},
        .has_cid = cid != NULL,
        .prev = prev ? *prev : (wf_cid){{0}, 0},
        .has_prev = prev != NULL,
    };
    emit_commit_event_ops(s, old_head, &op, 1);
}

void emit_sync_event(metalbear_repo_store *s) {
    if (!s || !s->event_cb) return;
    wf_commit current = {0};
    if (!parse_commit_at(s, &s->head, &current)) return;
    unsigned char *blocks = NULL;
    size_t blocks_len = 0;
    if (metalbear_repo_store_export_commit(s, &blocks, &blocks_len) != WF_OK)
        return;
    metalbear_repo_store_event event = {
        .kind = METALBEAR_REPO_STORE_EVENT_SYNC,
        .did = s->did,
        .commit_cid = s->head,
        .rev = current.rev,
        .blocks = blocks,
        .blocks_len = blocks_len,
    };
    s->event_cb(&event, s->event_ctx);
    free(blocks);
}

/* ------------------------------------------------------------------ */
/* createRecord backlink-conflict dedup                                */
/*                                                                       */
/* Matches the reference's getBacklinks/getBacklinkConflicts (actor-store/
 * record/reader.ts): only these four collections get automatic dedup, and
 * only createRecord calls it -- neither putRecord nor applyWrites do. "Ensures
 * that we don't end up with duplicate likes, reposts, and follows from race
 * conditions" (the reference's own comment). The reference backs this with a
 * dedicated indexed `backlink` SQL table; the `records` table already carries
 * each record's JSON in `value`, so the equivalent lookup here is a plain
 * json_extract() query scoped by collection instead of a second index.       */
/* ------------------------------------------------------------------ */

static const char *backlink_path_for_collection(const char *collection) {
    if (strcmp(collection, "app.bsky.graph.follow") == 0 ||
        strcmp(collection, "app.bsky.graph.block") == 0)
        return "$.subject";
    if (strcmp(collection, "app.bsky.feed.like") == 0 ||
        strcmp(collection, "app.bsky.feed.repost") == 0)
        return "$.subject.uri";
    return NULL;
}

/* The new record's own backlink target at `path` (a DID for follow/block, an
 * AT-URI for like/repost) -- what an existing record's target must equal to
 * conflict. NULL when absent or the wrong shape; caller frees. */
static char *backlink_target(const char *record_json, const char *path) {
    cJSON *root = cJSON_Parse(record_json);
    if (!root) return NULL;
    cJSON *subject = cJSON_GetObjectItemCaseSensitive(root, "subject");
    char *out = NULL;
    if (strcmp(path, "$.subject") == 0) {
        if (cJSON_IsString(subject) && subject->valuestring[0])
            out = strdup(subject->valuestring);
    } else {
        cJSON *uri = cJSON_IsObject(subject)
                         ? cJSON_GetObjectItemCaseSensitive(subject, "uri")
                         : NULL;
        if (cJSON_IsString(uri) && uri->valuestring[0])
            out = strdup(uri->valuestring);
    }
    cJSON_Delete(root);
    return out;
}

/* Existing records in `collection` whose own backlink target (at `path`)
 * equals `target`. Returns a caller-owned array of caller-owned rkey
 * strings (NULL if none or on allocation failure); *out_count is the
 * element count either way. */
static char **find_backlink_conflicts(metalbear_repo_store *s,
                                      const char *collection, const char *path,
                                      const char *target, size_t *out_count) {
    *out_count = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
                           "SELECT rkey FROM records WHERE collection=? AND "
                           "json_extract(value, ?)=?;",
                           -1, &stmt, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(stmt, 1, collection, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, target, -1, SQLITE_TRANSIENT);
    char **rkeys = NULL;
    size_t count = 0, cap = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *rk = (const char *)sqlite3_column_text(stmt, 0);
        if (!rk) continue;
        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 4;
            char **tmp = realloc(rkeys, ncap * sizeof(*rkeys));
            if (!tmp) break;
            rkeys = tmp;
            cap = ncap;
        }
        char *copy = strdup(rk);
        if (!copy) break;
        rkeys[count++] = copy;
    }
    sqlite3_finalize(stmt);
    *out_count = count;
    return rkeys;
}

static void free_backlink_conflicts(char **rkeys, size_t count) {
    if (!rkeys) return;
    for (size_t i = 0; i < count; i++) free(rkeys[i]);
    free(rkeys);
}

/* Delete every conflicting record and create the new one as a single atomic
 * commit (routed through apply_writes, the same batch primitive applyWrites
 * itself uses) rather than a separate delete-then-create -- so a relay never
 * observes an inconsistent intermediate state, and the deletion can't land
 * without the create if either half fails. Mirrors
 * metalbear_repo_store_create_record's own out_uri/out_cid contract. */
static wf_status create_record_with_backlink_cleanup(
    metalbear_repo_store *s, const char *collection, const char *rkey,
    const char *record_json, char *const *conflict_rkeys, size_t conflict_count,
    char **out_uri, char **out_cid) {
    cJSON *writes = cJSON_CreateArray();
    if (!writes) return WF_ERR_ALLOC;
    for (size_t i = 0; i < conflict_count; i++) {
        cJSON *del = cJSON_CreateObject();
        if (!del ||
            !cJSON_AddStringToObject(del, "$type",
                                     "com.atproto.repo.applyWrites#delete") ||
            !cJSON_AddStringToObject(del, "collection", collection) ||
            !cJSON_AddStringToObject(del, "rkey", conflict_rkeys[i])) {
            cJSON_Delete(del);
            cJSON_Delete(writes);
            return WF_ERR_ALLOC;
        }
        cJSON_AddItemToArray(writes, del);
    }
    cJSON *value = cJSON_Parse(record_json);
    cJSON *create = cJSON_CreateObject();
    if (!value || !create ||
        !cJSON_AddStringToObject(create, "$type",
                                 "com.atproto.repo.applyWrites#create") ||
        !cJSON_AddStringToObject(create, "collection", collection) ||
        !cJSON_AddStringToObject(create, "rkey", rkey) ||
        !cJSON_AddItemToObject(create, "value", value)) {
        cJSON_Delete(value);
        cJSON_Delete(create);
        cJSON_Delete(writes);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToArray(writes, create);

    char *writes_json = cJSON_PrintUnformatted(writes);
    cJSON_Delete(writes);
    if (!writes_json) return WF_ERR_ALLOC;

    char *commit_cid = NULL, *commit_rev = NULL, *results_json = NULL;
    wf_status st = apply_writes_locked(s, writes_json, NULL, &commit_cid,
                                       &commit_rev, &results_json);
    free(writes_json);
    free(commit_cid);
    free(commit_rev);
    if (st != WF_OK) {
        free(results_json);
        return st;
    }

    /* The create result is always last: deletes were staged first. */
    cJSON *results = cJSON_Parse(results_json);
    free(results_json);
    cJSON *last =
        results ? cJSON_GetArrayItem(results, cJSON_GetArraySize(results) - 1)
                : NULL;
    cJSON *uri = last ? cJSON_GetObjectItemCaseSensitive(last, "uri") : NULL;
    cJSON *cid = last ? cJSON_GetObjectItemCaseSensitive(last, "cid") : NULL;
    wf_status result = WF_ERR_INTERNAL;
    if (cJSON_IsString(uri) && cJSON_IsString(cid)) {
        *out_uri = strdup(uri->valuestring);
        *out_cid = strdup(cid->valuestring);
        result = (*out_uri && *out_cid) ? WF_OK : WF_ERR_ALLOC;
    }
    cJSON_Delete(results);
    return result;
}

/* ------------------------------------------------------------------ */
/* Write / read operations                                             */
/* ------------------------------------------------------------------ */

static wf_status create_record_locked(metalbear_repo_store *s,
                                      const char *collection,
                                      const char *rkey_or_null,
                                      const char *record_json,
                                      const char *swap_commit_or_null,
                                      char **out_uri, char **out_cid) {
    if (!s || !collection || !*collection || !record_json || !out_uri ||
        !out_cid)
        return WF_ERR_INVALID_ARG;
    *out_uri = NULL;
    *out_cid = NULL;

    /* (c) record-key validation (atproto charset/length rules). */
    char rkey_buf[16];
    const char *rkey = rkey_or_null;
    if (!rkey || !*rkey) {
        if (wf_tid_now(rkey_buf) != WF_OK) return WF_ERR_INVALID_ARG;
        rkey = rkey_buf;
    } else if (!wf_syntax_record_key_is_valid(rkey)) {
        return WF_ERR_INVALID_ARG; /* mapped to 400 InvalidRequest ("Invalid
                                      record key") */
    }

    /* (b) $type, when present, must equal the target collection. */
    if (!record_type_matches(record_json, collection))
        return WF_ERR_INVALID_ARG; /* mapped to 400 InvalidRequest ("Invalid
                                      $type") */

    /* (a) CAS: swapCommit must match the current repo head (if supplied). */
    char *head = head_cid_string(s);
    wf_status st = check_swap(swap_commit_or_null, head);
    free(head);
    if (st != WF_OK) return st;

    /* Backlink-conflict dedup (follow/block/like/repost only): replace, not
     * accumulate, a duplicate from a race condition. See the block comment
     * above create_record_with_backlink_cleanup. */
    const char *backlink_path = backlink_path_for_collection(collection);
    if (backlink_path) {
        char *target = backlink_target(record_json, backlink_path);
        if (target) {
            size_t conflict_count = 0;
            char **conflicts = find_backlink_conflicts(
                s, collection, backlink_path, target, &conflict_count);
            free(target);
            /* An explicit rkey that happens to match an existing record is
             * the ordinary overwrite path, not a backlink conflict -- leave
             * it to whatever "already exists" error wf_repo_create_record
             * gives below. */
            for (size_t i = 0; i < conflict_count; i++) {
                if (strcmp(conflicts[i], rkey) == 0) {
                    free(conflicts[i]);
                    conflicts[i] = conflicts[--conflict_count];
                    break;
                }
            }
            if (conflict_count > 0) {
                wf_status result = create_record_with_backlink_cleanup(
                    s, collection, rkey, record_json, conflicts, conflict_count,
                    out_uri, out_cid);
                free_backlink_conflicts(conflicts, conflict_count);
                return result;
            }
            free_backlink_conflicts(conflicts, conflict_count);
        }
    }

    unsigned char *cbor = NULL;
    size_t cbor_len = 0;
    st = encode_record_json(record_json, &cbor, &cbor_len);
    if (st != WF_OK) return st;

    wf_cid out_commit = {{0}, 0}, out_record = {{0}, 0};
    wf_cid old_head = s->head;
    const wf_cid *prev = s->head.len ? &s->head : NULL;
    st = wf_repo_create_record(&s->car, prev, s->did, collection, rkey, cbor,
                               cbor_len, &s->key, &out_commit, &out_record);
    free(cbor);
    if (st != WF_OK) return st;

    st = commit_persist(s, &out_commit);
    if (st != WF_OK) return st;

    *out_uri = make_uri(s->did, collection, rkey);
    char *cidstr = wf_cid_to_string(&out_record);
    if (!*out_uri || !cidstr) {
        free(*out_uri);
        free(cidstr);
        return WF_ERR_ALLOC;
    }
    *out_cid = cidstr;
    index_upsert_record(s, collection, rkey, cidstr, record_json);
    emit_commit_event(s, &old_head, "create", collection, rkey, &out_record,
                      NULL);
    return WF_OK;
}

wf_status metalbear_repo_store_create_record(metalbear_repo_store *s,
                                             const char *collection,
                                             const char *rkey_or_null,
                                             const char *record_json,
                                             const char *swap_commit_or_null,
                                             char **out_uri, char **out_cid) {
    if (!s || !collection || !*collection || !record_json || !out_uri ||
        !out_cid)
        return WF_ERR_INVALID_ARG;
    *out_uri = NULL;
    *out_cid = NULL;
    pthread_mutex_lock(&s->mutex);
    wf_status st =
        create_record_locked(s, collection, rkey_or_null, record_json,
                             swap_commit_or_null, out_uri, out_cid);
    pthread_mutex_unlock(&s->mutex);
    return st;
}

static wf_status put_record_locked(metalbear_repo_store *s,
                                   const char *collection, const char *rkey,
                                   const char *record_json,
                                   const char *swap_commit_or_null,
                                   const char *swap_record_or_null,
                                   char **out_uri, char **out_cid) {
    if (!s || !collection || !*collection || !rkey || !*rkey || !record_json ||
        !out_uri || !out_cid)
        return WF_ERR_INVALID_ARG;
    *out_uri = NULL;
    *out_cid = NULL;

    /* (c) record-key validation (atproto charset/length rules). */
    if (!wf_syntax_record_key_is_valid(rkey)) return WF_ERR_INVALID_ARG;

    /* (b) $type, when present, must equal the target collection. */
    if (!record_type_matches(record_json, collection))
        return WF_ERR_INVALID_ARG;

    /* Detect whether the record already exists. */
    unsigned char *existing = NULL;
    size_t ex_len = 0;
    wf_cid ex_cid;
    wf_status st =
        get_record_cbor(s, collection, rkey, &existing, &ex_len, &ex_cid);
    int exists = (st == WF_OK);
    free(existing);
    if (st != WF_OK && st != WF_ERR_NOT_FOUND) return st;

    /* (a) CAS: swapCommit against head; swapRecord against current record. */
    char *head = head_cid_string(s);
    st = check_swap(swap_commit_or_null, head);
    free(head);
    if (st != WF_OK) return st;
    if (swap_record_or_null && *swap_record_or_null) {
        /* A swapRecord guard on a record that is not there cannot match. */
        if (!exists) return WF_ERR_CONFLICT;
        char *cur = wf_cid_to_string(&ex_cid);
        st = check_swap(swap_record_or_null, cur);
        free(cur);
        if (st != WF_OK) return st;
    }

    wf_cid out_commit = {{0}, 0}, out_record = {{0}, 0};
    wf_cid old_head = s->head;
    unsigned char *cbor = NULL;
    size_t cbor_len = 0;
    st = encode_record_json(record_json, &cbor, &cbor_len);
    if (st != WF_OK) return st;

    /* Matches the reference (putRecord.ts): putting a record whose new
     * content is byte-identical to what's already there is a genuine no-op,
     * not a content-free commit -- skip the write entirely rather than
     * minting a new rev/firehose event for nothing. */
    if (exists) {
        wf_cid new_cid;
        if (wf_cid_of_block(cbor, cbor_len, &new_cid) == WF_OK &&
            cid_equal(&new_cid, &ex_cid)) {
            free(cbor);
            *out_uri = make_uri(s->did, collection, rkey);
            *out_cid = wf_cid_to_string(&ex_cid);
            if (!*out_uri || !*out_cid) {
                free(*out_uri);
                free(*out_cid);
                *out_uri = NULL;
                *out_cid = NULL;
                return WF_ERR_ALLOC;
            }
            return WF_OK;
        }
    }

    if (exists) {
        st = wf_repo_update_record(&s->car, &s->head, s->did, collection, rkey,
                                   cbor, cbor_len, &s->key, &out_commit,
                                   &out_record);
    } else {
        const wf_cid *prev = s->head.len ? &s->head : NULL;
        st =
            wf_repo_create_record(&s->car, prev, s->did, collection, rkey, cbor,
                                  cbor_len, &s->key, &out_commit, &out_record);
    }
    free(cbor);
    if (st != WF_OK) return st;

    st = commit_persist(s, &out_commit);
    if (st != WF_OK) return st;

    *out_uri = make_uri(s->did, collection, rkey);
    char *cidstr = wf_cid_to_string(&out_record);
    if (!*out_uri || !cidstr) {
        free(*out_uri);
        free(cidstr);
        return WF_ERR_ALLOC;
    }
    *out_cid = cidstr;
    index_upsert_record(s, collection, rkey, cidstr, record_json);
    emit_commit_event(s, &old_head, exists ? "update" : "create", collection,
                      rkey, &out_record, exists ? &ex_cid : NULL);
    return WF_OK;
}

wf_status metalbear_repo_store_put_record(
    metalbear_repo_store *s, const char *collection, const char *rkey,
    const char *record_json, const char *swap_commit_or_null,
    const char *swap_record_or_null, char **out_uri, char **out_cid) {
    if (!s || !collection || !*collection || !rkey || !*rkey || !record_json ||
        !out_uri || !out_cid)
        return WF_ERR_INVALID_ARG;
    *out_uri = NULL;
    *out_cid = NULL;
    pthread_mutex_lock(&s->mutex);
    wf_status st =
        put_record_locked(s, collection, rkey, record_json, swap_commit_or_null,
                          swap_record_or_null, out_uri, out_cid);
    pthread_mutex_unlock(&s->mutex);
    return st;
}

static wf_status delete_record_locked(metalbear_repo_store *s,
                                      const char *collection, const char *rkey,
                                      const char *swap_commit_or_null,
                                      const char *swap_record_or_null) {
    if (!s || !collection || !*collection || !rkey || !*rkey)
        return WF_ERR_INVALID_ARG;

    /* (c) record-key validation (atproto charset/length rules). */
    if (!wf_syntax_record_key_is_valid(rkey)) return WF_ERR_INVALID_ARG;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    unsigned char *existing = NULL;
    size_t ex_len = 0;
    wf_cid ex_cid;
    wf_status st =
        get_record_cbor(s, collection, rkey, &existing, &ex_len, &ex_cid);
    free(existing);
    if (st != WF_OK) return st;

    /* (a) CAS: swapCommit against head; swapRecord against current record. */
    char *head = head_cid_string(s);
    st = check_swap(swap_commit_or_null, head);
    free(head);
    if (st != WF_OK) return st;
    if (swap_record_or_null && *swap_record_or_null) {
        char *cur = wf_cid_to_string(&ex_cid);
        st = check_swap(swap_record_or_null, cur);
        free(cur);
        if (st != WF_OK) return st;
    }

    wf_cid out_commit = {{0}, 0};
    wf_cid old_head = s->head;
    st = wf_repo_delete_record(&s->car, &s->head, s->did, collection, rkey,
                               &s->key, &out_commit);
    if (st != WF_OK) return st;
    st = commit_persist(s, &out_commit);
    if (st != WF_OK) return st;
    index_delete_record(s, collection, rkey);
    emit_commit_event(s, &old_head, "delete", collection, rkey, NULL, &ex_cid);
    return WF_OK;
}

wf_status metalbear_repo_store_delete_record(metalbear_repo_store *s,
                                             const char *collection,
                                             const char *rkey,
                                             const char *swap_commit_or_null,
                                             const char *swap_record_or_null) {
    if (!s || !collection || !*collection || !rkey || !*rkey)
        return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&s->mutex);
    wf_status st = delete_record_locked(
        s, collection, rkey, swap_commit_or_null, swap_record_or_null);
    pthread_mutex_unlock(&s->mutex);
    return st;
}

wf_status metalbear_repo_store_get_record(metalbear_repo_store *s,
                                          const char *collection,
                                          const char *rkey,
                                          char **out_record_json,
                                          char **out_cid) {
    if (!s || !collection || !*collection || !rkey || !*rkey ||
        !out_record_json || !out_cid)
        return WF_ERR_INVALID_ARG;
    *out_record_json = NULL;
    *out_cid = NULL;

    unsigned char *data = NULL;
    size_t len = 0;
    wf_cid rcid;
    pthread_mutex_lock(&s->mutex);
    wf_status st = get_record_cbor(s, collection, rkey, &data, &len, &rcid);
    pthread_mutex_unlock(&s->mutex);
    if (st != WF_OK) return st;

    wf_cbor_item *item = wf_cbor_parse(data, len);
    free(data);
    if (!item) return WF_ERR_PARSE;

    cJSON *j = cbor_to_json(item);
    wf_cbor_free(item);
    if (!j) return WF_ERR_PARSE;

    char *js = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!js) return WF_ERR_ALLOC;

    char *cidstr = wf_cid_to_string(&rcid);
    if (!cidstr) {
        free(js);
        return WF_ERR_ALLOC;
    }

    *out_record_json = js;
    *out_cid = cidstr;
    return WF_OK;
}

static wf_status
apply_writes_locked(metalbear_repo_store *s, const char *writes_json,
                    const char *swap_commit_or_null, char **out_commit_cid,
                    char **out_commit_rev, char **out_results_json) {
    if (!s || !writes_json || !out_commit_cid || !out_commit_rev ||
        !out_results_json)
        return WF_ERR_INVALID_ARG;
    *out_commit_cid = NULL;
    *out_commit_rev = NULL;
    *out_results_json = NULL;

    cJSON *root = cJSON_Parse(writes_json);
    if (!root || !cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return WF_ERR_INVALID_ARG;
    }

    /* (a) CAS: swapCommit must match the current repo head (if supplied). */
    char *head = head_cid_string(s);
    wf_status st = check_swap(swap_commit_or_null, head);
    free(head);
    if (st != WF_OK) {
        cJSON_Delete(root);
        return st;
    }

    /* (g) cap batch size at 200 writes (mirrors atproto's limit). */
    if (cJSON_GetArraySize(root) > 200) {
        cJSON_Delete(root);
        return WF_ERR_INVALID_ARG;
    }

    cJSON *results = cJSON_CreateArray();
    if (!results) {
        cJSON_Delete(root);
        return WF_ERR_ALLOC;
    }

    /* Stage every write, then land the whole batch as ONE signed commit.
     * applyWrites is specified as atomic: the reference PDS runs the batch in
     * a single transaction and sequences a single #commit event carrying all
     * ops. Applying the writes one at a time would emit one commit (and one
     * firehose event) per write, and would leave earlier writes committed when
     * a later one fails. */
    size_t write_count = (size_t)cJSON_GetArraySize(root);
    wf_repo_write *batch =
        write_count ? calloc(write_count, sizeof(*batch)) : NULL;
    /* Parallel bookkeeping: the CBOR bodies and any rkeys we generate must
     * outlive the loop, since `batch` only borrows them. */
    unsigned char **bodies =
        write_count ? calloc(write_count, sizeof(*bodies)) : NULL;
    char **rkeys = write_count ? calloc(write_count, sizeof(*rkeys)) : NULL;
    char **collections =
        write_count ? calloc(write_count, sizeof(*collections)) : NULL;
    char **values = write_count ? calloc(write_count, sizeof(*values)) : NULL;
    if (write_count &&
        (!batch || !bodies || !rkeys || !collections || !values)) {
        st = WF_ERR_ALLOC;
        goto done;
    }

    st = WF_OK;
    size_t staged = 0;
    const cJSON *op;
    cJSON_ArrayForEach(op, root) {
        if (!cJSON_IsObject(op)) {
            st = WF_ERR_INVALID_ARG;
            goto done;
        }
        cJSON *type = cJSON_GetObjectItemCaseSensitive(op, "$type");
        if (!type || !cJSON_IsString(type)) {
            st = WF_ERR_INVALID_ARG;
            goto done;
        }
        const char *t = type->valuestring;

        cJSON *coll = cJSON_GetObjectItemCaseSensitive(op, "collection");
        cJSON *val = cJSON_GetObjectItemCaseSensitive(op, "value");
        cJSON *rk = cJSON_GetObjectItemCaseSensitive(op, "rkey");
        if (!coll || !cJSON_IsString(coll) || !coll->valuestring[0]) {
            st = WF_ERR_INVALID_ARG;
            goto done;
        }

        bool is_create = strcmp(t, "com.atproto.repo.applyWrites#create") == 0;
        bool is_update = strcmp(t, "com.atproto.repo.applyWrites#update") == 0;
        bool is_delete = strcmp(t, "com.atproto.repo.applyWrites#delete") == 0;
        if (!is_create && !is_update && !is_delete) {
            st = WF_ERR_INVALID_ARG;
            goto done;
        }

        /* create may omit rkey (the PDS mints a TID); update/delete may not. */
        const char *rkey = (rk && cJSON_IsString(rk) && rk->valuestring[0])
                               ? rk->valuestring
                               : NULL;
        if (!rkey) {
            if (!is_create) {
                st = WF_ERR_INVALID_ARG;
                goto done;
            }
            char tid[16];
            if (wf_tid_now(tid) != WF_OK) {
                st = WF_ERR_INTERNAL;
                goto done;
            }
            rkeys[staged] = strdup(tid);
        } else {
            if (!wf_syntax_record_key_is_valid(rkey)) {
                st = WF_ERR_INVALID_ARG;
                goto done;
            }
            rkeys[staged] = strdup(rkey);
        }
        collections[staged] = strdup(coll->valuestring);
        if (!rkeys[staged] || !collections[staged]) {
            st = WF_ERR_ALLOC;
            goto done;
        }

        batch[staged].collection = collections[staged];
        batch[staged].rkey = rkeys[staged];
        if (is_delete) {
            batch[staged].action = WF_REPO_WRITE_DELETE;
        } else {
            if (!val) {
                st = WF_ERR_INVALID_ARG;
                goto done;
            }
            char *rec_json = cJSON_PrintUnformatted(val);
            if (!rec_json) {
                st = WF_ERR_ALLOC;
                goto done;
            }
            if (!record_type_matches(rec_json, collections[staged])) {
                free(rec_json);
                st = WF_ERR_INVALID_ARG;
                goto done;
            }
            values[staged] = rec_json;
            size_t body_len = 0;
            st = encode_record_json(rec_json, &bodies[staged], &body_len);
            if (st != WF_OK) goto done;
            batch[staged].action =
                is_create ? WF_REPO_WRITE_CREATE : WF_REPO_WRITE_UPDATE;
            batch[staged].record_cbor = bodies[staged];
            batch[staged].record_cbor_len = body_len;
        }
        staged++;
    }

    wf_cid old_head = s->head;
    wf_cid new_commit = {{0}, 0};
    const wf_cid *prev = s->head.len ? &s->head : NULL;
    st = wf_repo_apply_writes(&s->car, prev, s->did, batch, staged, &s->key,
                              &new_commit);
    if (st != WF_OK) goto done;
    st = commit_persist(s, &new_commit);
    if (st != WF_OK) goto done;

    /* The commit is durable; now bring the record index in line with it and
     * describe the batch to the firehose as a single event. */
    metalbear_repo_store_op *events =
        staged ? calloc(staged, sizeof(*events)) : NULL;
    if (staged && !events) {
        st = WF_ERR_ALLOC;
        goto done;
    }
    for (size_t i = 0; i < staged; i++) {
        char *record_cid = NULL;
        if (batch[i].action == WF_REPO_WRITE_DELETE) {
            index_delete_record(s, batch[i].collection, batch[i].rkey);
        } else {
            record_cid = wf_cid_to_string(&batch[i].out_record);
            index_upsert_record(s, batch[i].collection, batch[i].rkey,
                                record_cid ? record_cid : "", values[i]);
        }
        events[i].action = batch[i].action == WF_REPO_WRITE_CREATE   ? "create"
                           : batch[i].action == WF_REPO_WRITE_UPDATE ? "update"
                                                                     : "delete";
        events[i].collection = batch[i].collection;
        events[i].rkey = batch[i].rkey;
        events[i].cid = batch[i].out_record;
        events[i].has_cid = batch[i].action != WF_REPO_WRITE_DELETE;

        cJSON *r = cJSON_CreateObject();
        /* `results` is a CLOSED union in the lexicon, so each entry must carry
         * the $type that discriminates it; without one a strict client rejects
         * the whole response. */
        if (batch[i].action == WF_REPO_WRITE_DELETE) {
            cJSON_AddStringToObject(
                r, "$type", "com.atproto.repo.applyWrites#deleteResult");
        } else {
            cJSON_AddStringToObject(
                r, "$type",
                batch[i].action == WF_REPO_WRITE_CREATE
                    ? "com.atproto.repo.applyWrites#createResult"
                    : "com.atproto.repo.applyWrites#updateResult");
            char *uri = make_uri(s->did, batch[i].collection, batch[i].rkey);
            cJSON_AddStringToObject(r, "uri", uri ? uri : "");
            free(uri);
            cJSON_AddStringToObject(r, "cid", record_cid ? record_cid : "");
            /* wolfram performs no lexicon validation, so report "unknown"
             * (what atproto reports for an unrecognised $type). */
            cJSON_AddStringToObject(r, "validationStatus", "unknown");
        }
        cJSON_AddItemToArray(results, r);
        free(record_cid);
    }
    emit_commit_event_ops(s, &old_head, events, staged);
    free(events);

done:
    for (size_t i = 0; i < write_count; i++) {
        if (bodies) free(bodies[i]);
        if (rkeys) free(rkeys[i]);
        if (collections) free(collections[i]);
        if (values) free(values[i]);
    }
    free(bodies);
    free(rkeys);
    free(collections);
    free(values);
    free(batch);
    cJSON_Delete(root);
    if (st != WF_OK) {
        cJSON_Delete(results);
        return st;
    }

    char *cidstr = s->head.len ? wf_cid_to_string(&s->head) : strdup("");
    char *rev = NULL;
    if (s->head.len) {
        wf_car_block *blk = wf_car_find_block(&s->car, &s->head);
        if (blk) {
            wf_commit cm;
            if (wf_commit_parse(blk->data, blk->data_len, &cm) == WF_OK)
                rev = strdup(cm.rev);
        }
    }
    char *resjson = cJSON_PrintUnformatted(results);
    cJSON_Delete(results);
    if (!cidstr || !resjson) {
        free(cidstr);
        free(rev);
        free(resjson);
        return WF_ERR_ALLOC;
    }
    *out_commit_cid = cidstr;
    *out_commit_rev = rev;
    *out_results_json = resjson;
    return WF_OK;
}

wf_status metalbear_repo_store_apply_writes(metalbear_repo_store *s,
                                            const char *writes_json,
                                            const char *swap_commit_or_null,
                                            char **out_commit_cid,
                                            char **out_commit_rev,
                                            char **out_results_json) {
    if (!s || !writes_json || !out_commit_cid || !out_commit_rev ||
        !out_results_json)
        return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&s->mutex);
    wf_status st =
        apply_writes_locked(s, writes_json, swap_commit_or_null, out_commit_cid,
                            out_commit_rev, out_results_json);
    pthread_mutex_unlock(&s->mutex);
    return st;
}

/* ------------------------------------------------------------------ */
/* describeRepo + verification                                         */
/* ------------------------------------------------------------------ */

static wf_status walk_mst_collections(metalbear_repo_store *s,
                                      const wf_cid *root, cJSON *cols) {
    if (root->len == 0) return WF_OK;
    wf_car_block *b = wf_car_find_block(&s->car, root);
    if (!b) return WF_OK;

    wf_mst_node node;
    memset(&node, 0, sizeof(node));
    wf_status st = wf_mst_node_parse(b->data, b->data_len, root, &node);
    if (st != WF_OK) return st;

    if (node.left.len) walk_mst_collections(s, &node.left, cols);

    for (size_t i = 0; i < node.count; i++) {
        unsigned char *k = node.entries[i].key;
        size_t kl = node.entries[i].key_len;
        unsigned char *slash = memchr(k, '/', kl);
        if (slash) {
            size_t clen = (size_t)(slash - k);
            int found = 0;
            int sz = cJSON_GetArraySize(cols);
            for (int j = 0; j < sz; j++) {
                cJSON *e = cJSON_GetArrayItem(cols, j);
                if (e && cJSON_IsString(e) &&
                    (int)clen == (int)strlen(e->valuestring) &&
                    memcmp(e->valuestring, k, clen) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                char *tmp = malloc(clen + 1);
                if (tmp) {
                    memcpy(tmp, k, clen);
                    tmp[clen] = '\0';
                    cJSON_AddItemToArray(cols, cJSON_CreateString(tmp));
                    free(tmp);
                }
            }
        }
        if (node.entries[i].subtree.len)
            walk_mst_collections(s, &node.entries[i].subtree, cols);
    }
    wf_mst_node_free(&node);
    return WF_OK;
}

wf_status metalbear_repo_store_describe(metalbear_repo_store *s,
                                        char **out_json) {
    if (!s || !out_json) return WF_ERR_INVALID_ARG;
    *out_json = NULL;

    pthread_mutex_lock(&s->mutex);

    cJSON *obj = cJSON_CreateObject();
    if (!obj) {
        pthread_mutex_unlock(&s->mutex);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(obj, "handle", s->handle ? s->handle : "");
    cJSON_AddStringToObject(obj, "did", s->did ? s->did : "");

    cJSON *cols = cJSON_CreateArray();
    if (cols) {
        if (s->head.len) {
            wf_car_block *blk = wf_car_find_block(&s->car, &s->head);
            if (blk) {
                wf_commit cm;
                if (wf_commit_parse(blk->data, blk->data_len, &cm) == WF_OK)
                    walk_mst_collections(s, &cm.data, cols);
            }
        }
        cJSON_AddItemToObject(obj, "collections", cols);
    }
    if (s->head.len) {
        wf_car_block *blk = wf_car_find_block(&s->car, &s->head);
        if (blk) {
            wf_commit cm;
            if (wf_commit_parse(blk->data, blk->data_len, &cm) == WF_OK)
                cJSON_AddStringToObject(obj, "rev", cm.rev);
        }
    }

    pthread_mutex_unlock(&s->mutex);

    char *js = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (!js) return WF_ERR_ALLOC;
    *out_json = js;
    return WF_OK;
}

wf_status metalbear_repo_store_verify_head(metalbear_repo_store *s,
                                           int *out_verified,
                                           wf_commit *out_commit) {
    if (!s || !out_verified) return WF_ERR_INVALID_ARG;
    *out_verified = 0;
    if (out_commit) memset(out_commit, 0, sizeof(*out_commit));
    if (s->head.len == 0) return WF_OK;

    pthread_mutex_lock(&s->mutex);
    wf_repo_verify_options opts = {s->did, s->signing_key_didkey, NULL};
    wf_commit c;
    wf_status st = wf_repo_verify(&s->car, &opts, &c);
    if (st == WF_OK) *out_verified = 1;
    if (out_commit) *out_commit = c;
    pthread_mutex_unlock(&s->mutex);
    return st;
}

/* ── listRecords (com.atproto.repo.listRecords) ──────────────────────── */

wf_status metalbear_repo_store_list_records(metalbear_repo_store *s,
                                            const char *collection,
                                            const char *cursor, bool reverse,
                                            int limit, char **out_json) {
    if (!s || !collection || !*collection || !out_json)
        return WF_ERR_INVALID_ARG;
    *out_json = NULL;
    if (limit <= 0 || limit > 100) limit = 50; /* lexicon max is 100 */

    const char *cursor_str = cursor && *cursor ? cursor : NULL;

    /* Descending (newest rkey first) by default, ascending when `reverse` —
     * the order the reference PDS returns, and what clients paginating a
     * collection expect. The cursor is the last rkey of the previous page, so
     * it walks the same direction as the sort. */
    char sql[256];
    if (reverse) {
        if (cursor_str)
            snprintf(
                sql, sizeof(sql),
                "SELECT rkey, cid, value FROM records "
                "WHERE collection = ? AND rkey > ? ORDER BY rkey ASC LIMIT ?;");
        else
            snprintf(sql, sizeof(sql),
                     "SELECT rkey, cid, value FROM records "
                     "WHERE collection = ? ORDER BY rkey ASC LIMIT ?;");
    } else {
        if (cursor_str)
            snprintf(sql, sizeof(sql),
                     "SELECT rkey, cid, value FROM records "
                     "WHERE collection = ? AND rkey < ? ORDER BY rkey DESC "
                     "LIMIT ?;");
        else
            snprintf(sql, sizeof(sql),
                     "SELECT rkey, cid, value FROM records "
                     "WHERE collection = ? ORDER BY rkey DESC LIMIT ?;");
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, collection, -1, SQLITE_TRANSIENT);
    if (cursor_str)
        sqlite3_bind_text(stmt, 2, cursor_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, cursor_str ? 3 : 2,
                     limit + 1); /* +1 to detect a next page */

    cJSON *records = cJSON_CreateArray();
    if (!records) {
        sqlite3_finalize(stmt);
        return WF_ERR_ALLOC;
    }
    int count = 0;
    int has_more = 0;
    /* Owned copy: sqlite3_column_text pointers do not survive the next
     * sqlite3_step / sqlite3_finalize, and the cursor is read after both. */
    char *last_rkey = NULL;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= limit) { /* over-fetch: there is a next page */
            has_more = 1;
            break;
        }
        const char *rkey = (const char *)sqlite3_column_text(stmt, 0);
        const char *cid = (const char *)sqlite3_column_text(stmt, 1);
        const char *value = (const char *)sqlite3_column_text(stmt, 2);
        /* The cursor is the last record actually returned. Pointing it at the
         * over-fetched row instead would skip that record on the next page. */
        free(last_rkey);
        last_rkey = rkey ? strdup(rkey) : NULL;
        cJSON *rec = cJSON_CreateObject();
        char *uri = make_uri(s->did, collection, rkey);
        cJSON_AddStringToObject(rec, "uri", uri);
        free(uri);
        cJSON_AddStringToObject(rec, "cid", cid ? cid : "");
        cJSON *val = cJSON_Parse(value ? value : "{}");
        if (val) cJSON_AddItemToObject(rec, "value", val);
        cJSON_AddItemToArray(records, rec);
        count++;
    }
    sqlite3_finalize(stmt);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "records", records);
    if (has_more && last_rkey)
        cJSON_AddStringToObject(out, "cursor", last_rkey);
    free(last_rkey);

    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    *out_json = js;
    return WF_OK;
}

wf_status metalbear_repo_store_records_since_rev(metalbear_repo_store *s,
                                                 const char *rev, int limit,
                                                 char **out_json) {
    if (!s || !rev || !*rev || !out_json) return WF_ERR_INVALID_ARG;
    *out_json = NULL;
    if (limit <= 0 || limit > 100) limit = 10;

    /* Sanity check from the reference: if NOTHING predates the rev the client
     * quoted, that rev is not describing this repo's history at all (an
     * account migration, say). Splicing local records into a response built
     * from someone else's timeline would be worse than showing a stale one. */
    sqlite3_stmt *check = NULL;
    if (sqlite3_prepare_v2(
            s->db,
            "SELECT 1 FROM records WHERE repo_rev IS NOT NULL AND repo_rev <= ?"
            " LIMIT 1;",
            -1, &check, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(check, 1, rev, -1, SQLITE_TRANSIENT);
    bool has_older = sqlite3_step(check) == SQLITE_ROW;
    sqlite3_finalize(check);

    cJSON *root = cJSON_CreateObject();
    cJSON *records = cJSON_CreateArray();
    if (!root || !records) {
        cJSON_Delete(root);
        cJSON_Delete(records);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToObject(root, "records", records);

    if (has_older) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(
                s->db,
                "SELECT collection, rkey, cid, value, repo_rev, indexed_at"
                " FROM records WHERE repo_rev IS NOT NULL AND repo_rev > ?"
                " ORDER BY repo_rev ASC LIMIT ?;",
                -1, &stmt, NULL) != SQLITE_OK) {
            cJSON_Delete(root);
            return WF_ERR_INTERNAL;
        }
        sqlite3_bind_text(stmt, 1, rev, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, limit);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *collection = (const char *)sqlite3_column_text(stmt, 0);
            const char *rkey = (const char *)sqlite3_column_text(stmt, 1);
            const char *cid = (const char *)sqlite3_column_text(stmt, 2);
            const char *value = (const char *)sqlite3_column_text(stmt, 3);
            const char *indexed = (const char *)sqlite3_column_text(stmt, 5);
            cJSON *entry = cJSON_CreateObject();
            if (!entry) break;
            char *uri = make_uri(s->did, collection ? collection : "",
                                 rkey ? rkey : "");
            cJSON_AddStringToObject(entry, "uri", uri ? uri : "");
            free(uri);
            cJSON_AddStringToObject(entry, "cid", cid ? cid : "");
            cJSON_AddStringToObject(entry, "collection",
                                    collection ? collection : "");
            cJSON_AddStringToObject(entry, "indexedAt", indexed ? indexed : "");
            cJSON *val = cJSON_Parse(value ? value : "{}");
            if (val) cJSON_AddItemToObject(entry, "value", val);
            cJSON_AddItemToArray(records, entry);
        }
        sqlite3_finalize(stmt);
    }

    char *js = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!js) return WF_ERR_ALLOC;
    *out_json = js;
    return WF_OK;
}

/* ── record streaming (com.atproto.repo.listMissingBlobs support) ────── */

wf_status metalbear_repo_store_foreach_record(
    metalbear_repo_store *s,
    wf_status (*visit)(const char *collection, const char *rkey,
                       const char *value_json, void *ctx),
    void *ctx) {
    if (!s || !visit) return WF_ERR_INVALID_ARG;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
                           "SELECT collection, rkey, value FROM records "
                           "ORDER BY collection ASC, rkey ASC;",
                           -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    wf_status status = WF_OK;
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const char *collection = (const char *)sqlite3_column_text(stmt, 0);
        const char *rkey = (const char *)sqlite3_column_text(stmt, 1);
        const char *value = (const char *)sqlite3_column_text(stmt, 2);
        status = visit(collection ? collection : "", rkey ? rkey : "",
                       value ? value : "{}", ctx);
    }
    sqlite3_finalize(stmt);
    return status;
}

/* ── getLatestCommit (com.atproto.sync.getLatestCommit) ───────────────── */

wf_status metalbear_repo_store_get_head(metalbear_repo_store *s, char **out_rev,
                                        char **out_cid) {
    if (!s || !out_rev || !out_cid) return WF_ERR_INVALID_ARG;
    *out_rev = NULL;
    *out_cid = NULL;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    pthread_mutex_lock(&s->mutex);
    char *cid = wf_cid_to_string(&s->head);
    char rev[64] = "";
    wf_car_block *blk = wf_car_find_block(&s->car, &s->head);
    if (blk) {
        wf_commit cm;
        if (wf_commit_parse(blk->data, blk->data_len, &cm) == WF_OK)
            snprintf(rev, sizeof(rev), "%s", cm.rev);
    }
    pthread_mutex_unlock(&s->mutex);
    if (!cid) return WF_ERR_ALLOC;
    *out_cid = cid;
    *out_rev = strdup(rev);
    if (!*out_rev) {
        free(cid);
        return WF_ERR_ALLOC;
    }
    return WF_OK;
}

wf_status metalbear_repo_store_export(metalbear_repo_store *s,
                                      const char *since,
                                      unsigned char **out_data,
                                      size_t *out_len) {
    if (!s || !out_data || !out_len) return WF_ERR_INVALID_ARG;
    *out_data = NULL;
    *out_len = 0;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    pthread_mutex_lock(&s->mutex);

    const char *sql =
        since && since[0]
            ? "SELECT cid FROM blocks WHERE repo_rev > ? "
              "ORDER BY repo_rev DESC, cid DESC;"
            : "SELECT cid FROM blocks ORDER BY repo_rev DESC, cid DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    if (since && since[0])
        sqlite3_bind_text(stmt, 1, since, -1, SQLITE_TRANSIENT);

    wf_car export_car = {0};
    export_car.roots = &s->head;
    export_car.root_count = 1;
    wf_status status = WF_OK;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *cid_string = (const char *)sqlite3_column_text(stmt, 0);
        wf_cid cid;
        if (!cid_string || wf_cid_from_string(cid_string, &cid) != WF_OK) {
            status = WF_ERR_PARSE;
            break;
        }
        wf_car_block *source = wf_car_find_block(&s->car, &cid);
        if (!source) {
            status = WF_ERR_NOT_FOUND;
            break;
        }
        wf_car_block *grown = realloc(
            export_car.blocks, (export_car.block_count + 1) * sizeof(*grown));
        if (!grown) {
            status = WF_ERR_ALLOC;
            break;
        }
        export_car.blocks = grown;
        export_car.blocks[export_car.block_count++] = *source;
    }
    sqlite3_finalize(stmt);
    if (status == WF_OK) status = wf_car_write(&export_car, out_data, out_len);
    free(export_car.blocks);
    pthread_mutex_unlock(&s->mutex);
    return status;
}

wf_status metalbear_repo_store_export_commit(metalbear_repo_store *s,
                                             unsigned char **out_data,
                                             size_t *out_len) {
    /*
     * A #sync event carries the commit block and nothing else.
     *
     * The lexicon is explicit — "CAR file containing the commit, as a block"
     * with maxLength 10000 — and the reference builds it from exactly one
     * block (getSyncEventData does getBlocks([root.cid])). Exporting the whole
     * repo here produced a #sync that grew with the account and sailed past
     * the limit after a handful of records, so a validating relay rejects the
     * very event whose job is to recover a broken stream.
     */
    if (!s || !out_data || !out_len) return WF_ERR_INVALID_ARG;
    *out_data = NULL;
    *out_len = 0;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    pthread_mutex_lock(&s->mutex);
    wf_car_block *source = wf_car_find_block(&s->car, &s->head);
    if (!source) {
        pthread_mutex_unlock(&s->mutex);
        return WF_ERR_NOT_FOUND;
    }

    wf_car export_car = {0};
    export_car.roots = &s->head;
    export_car.root_count = 1;
    export_car.blocks = source;
    export_car.block_count = 1;
    wf_status st = wf_car_write(&export_car, out_data, out_len);
    pthread_mutex_unlock(&s->mutex);
    return st;
}

wf_status metalbear_repo_store_get_blocks(metalbear_repo_store *s,
                                          const char *const *cids,
                                          size_t cid_count,
                                          unsigned char **out_data,
                                          size_t *out_len) {
    if (!s || !cids || cid_count == 0 || !out_data || !out_len)
        return WF_ERR_INVALID_ARG;
    *out_data = NULL;
    *out_len = 0;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    pthread_mutex_lock(&s->mutex);
    wf_car selected = {0};
    wf_status status = WF_OK;
    for (size_t i = 0; i < cid_count; i++) {
        wf_cid cid;
        if (!cids[i] || wf_cid_from_string(cids[i], &cid) != WF_OK) {
            status = WF_ERR_INVALID_ARG;
            break;
        }
        int duplicate = 0;
        for (size_t j = 0; j < selected.block_count; j++) {
            if (cid_equal(&selected.blocks[j].cid, &cid)) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) continue;
        wf_car_block *source = wf_car_find_block(&s->car, &cid);
        if (!source) {
            status = WF_ERR_NOT_FOUND;
            break;
        }
        wf_car_block *grown = realloc(
            selected.blocks, (selected.block_count + 1) * sizeof(*grown));
        if (!grown) {
            status = WF_ERR_ALLOC;
            break;
        }
        selected.blocks = grown;
        selected.blocks[selected.block_count++] = *source;
    }
    if (status == WF_OK) status = wf_car_write(&selected, out_data, out_len);
    free(selected.blocks);
    pthread_mutex_unlock(&s->mutex);
    return status;
}

wf_status metalbear_repo_store_get_record_car(metalbear_repo_store *s,
                                              const char *collection,
                                              const char *rkey,
                                              unsigned char **out_data,
                                              size_t *out_len) {
    if (!s || !collection || !rkey || !out_data || !out_len)
        return WF_ERR_INVALID_ARG;
    *out_data = NULL;
    *out_len = 0;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    /* Get the record CID. */
    char *record_json = NULL;
    char *record_cid_str = NULL;
    wf_status status = metalbear_repo_store_get_record(
        s, collection, rkey, &record_json, &record_cid_str);
    if (status != WF_OK) return status;
    free(record_json);

    /* Parse the record CID. */
    wf_cid record_cid;
    if (wf_cid_from_string(record_cid_str, &record_cid) != WF_OK) {
        free(record_cid_str);
        return WF_ERR_INTERNAL;
    }
    free(record_cid_str);

    pthread_mutex_lock(&s->mutex);
    /* Find the record block in the CAR. */
    wf_car_block *record_block = wf_car_find_block(&s->car, &record_cid);
    if (!record_block) {
        pthread_mutex_unlock(&s->mutex);
        return WF_ERR_NOT_FOUND;
    }

    /* Build a CAR with the commit as root and the record block. */
    wf_car out = {0};
    out.roots = &s->head;
    out.root_count = 1;

    /* Add commit block. */
    wf_car_block *commit_block = wf_car_find_block(&s->car, &s->head);
    if (!commit_block) {
        pthread_mutex_unlock(&s->mutex);
        return WF_ERR_NOT_FOUND;
    }
    out.blocks = calloc(2, sizeof(*out.blocks));
    if (!out.blocks) {
        pthread_mutex_unlock(&s->mutex);
        return WF_ERR_ALLOC;
    }
    out.blocks[0] = *commit_block;
    out.blocks[1] = *record_block;
    out.block_count = 2;

    pthread_mutex_unlock(&s->mutex);
    status = wf_car_write(&out, out_data, out_len);
    free(out.blocks);
    return status;
}

wf_status metalbear_repo_store_create_service_auth(metalbear_repo_store *s,
                                                   const char *audience,
                                                   int64_t expiration,
                                                   const char *lxm,
                                                   char **out_token) {
    if (!s || !audience || !out_token) return WF_ERR_INVALID_ARG;
    wf_service_auth_request request = {
        .iss = s->did,
        .aud = audience,
        .exp = expiration,
        .lxm = lxm,
    };
    return wf_server_create_service_auth(&request, &s->key, out_token);
}

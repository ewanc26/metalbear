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

#include "metalbear/repo_store.h"

#include "wolfram/repo/cbor.h"
#include "wolfram/repo/cid.h"
#include "wolfram/repo/car.h"
#include "wolfram/repo/record.h"
#include "wolfram/repo/diff.h"
#include "wolfram/repo/mst.h"
#include "wolfram/syntax.h"
#include "wolfram/server.h"
#include "wolfram/tid.h"
#include "wolfram/xrpc_server.h"
#include "wolfram/crypto.h"

#include <cJSON.h>
#include <sqlite3.h>

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Store handle                                                        */
/* ------------------------------------------------------------------ */

struct metalbear_repo_store {
    char *path;
    char *did;
    char *handle;
    wf_signing_key key;
    char *signing_key_didkey;   /* did:key multibase, for wf_repo_verify */
    sqlite3 *db;
    wf_car car;                 /* accumulated blocks; roots -> &head */
    wf_cid head;                /* current head commit CID (len 0 = empty) */
    size_t persisted_blocks;    /* count of blocks already flushed to db */
    metalbear_repo_store_event_cb event_cb;
    void *event_ctx;
};

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
        if (!isfinite(d) || d != floor(d) ||
            fabs(d) > 9007199254740991.0)
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
        if (!v->string.str) { free(v); return NULL; }
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
        v->children.items = n ? calloc((size_t)n, sizeof(wf_cbor_item *))
                              : NULL;
        if (n && !v->children.items) { free(v); return NULL; }
        int i = 0;
        const cJSON *child;
        cJSON_ArrayForEach(child, (cJSON *)j) {
            v->children.items[i] = cbor_from_json(child);
            if (!v->children.items[i]) { wf_cbor_free(v); return NULL; }
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
                    if (cid.len)
                        memcpy(v->bytes.data, cid.bytes, cid.len);
                    return v;
                }
            } else if (only->string && strcmp(only->string, "$bytes") == 0 &&
                       cJSON_IsString(only)) {
                unsigned char *raw = NULL;
                size_t raw_len = 0;
                if (wf_crypto_base64url_decode(only->valuestring,
                                               &raw, &raw_len) == WF_OK) {
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
        v->map.pairs = count ? calloc((size_t)count, sizeof(wf_cbor_pair))
                              : NULL;
        if (count && !v->map.pairs) { free(v); return NULL; }
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
                    } else { free(k); k = NULL; }
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
            if (!e) { cJSON_Delete(a); return NULL; }
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
                                    unsigned char **out_cbor,
                                    size_t *out_len) {
    if (out_cbor) *out_cbor = NULL;
    if (out_len) *out_len = 0;
    if (!record_json || !out_cbor || !out_len)
        return WF_ERR_INVALID_ARG;

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

static char *make_uri(const char *did, const char *collection,
                      const char *rkey) {
    size_t n = strlen("at://") + strlen(did) + 1 + strlen(collection) +
               1 + strlen(rkey) + 1;
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
static void add_commit_meta(metalbear_repo_store *s, cJSON *parent) {
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
static wf_status get_record_cbor(metalbear_repo_store *s, const char *collection,
                                 const char *rkey, unsigned char **out_data,
                                 size_t *out_len, wf_cid *out_record_cid) {
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;
    return wf_repo_get_record(&s->car, &s->head, collection, rkey, out_data,
                              out_len, out_record_cid);
}

/* Forward declaration (defined in the Persistence section below). */
static wf_status index_upsert_record(metalbear_repo_store *s, const char *collection,
                                      const char *rkey, const char *cid,
                                      const char *value);

/* Current head commit CID as a base32 string ("" when repo is empty). */
static char *head_cid_string(metalbear_repo_store *s) {
    return s->head.len ? wf_cid_to_string(&s->head) : strdup("");
}

/* Compare a requested compare-and-swap CID (may be NULL/empty) against
 * the current value (a base32 string). Returns WF_OK when they match or
 * when no swap was requested; otherwise WF_ERR_INVALID_ARG (atproto
 * returns InvalidSwap — TODO: surface the specific XRPC error here).
 * The error is intentionally generic: the HTTP handler maps it to a
 * 400 InvalidSwap-equivalent response. */
static wf_status check_swap(const char *requested, const char *current) {
    if (!requested || !*requested) return WF_OK;
    if (!current || strcmp(requested, current) != 0)
        return WF_ERR_INVALID_ARG;
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
    int ok = (t && cJSON_IsString(t)) ? (strcmp(t->valuestring, collection) == 0) : 1;
    cJSON_Delete(root);
    return ok;
}

/* Decode a record block (by CID) into canonical record JSON, or NULL. */
static char *decode_record_json(metalbear_repo_store *s, const wf_cid *record_cid) {
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
static wf_status reindex_collect(metalbear_repo_store *s, const wf_cid *node_cid) {
    if (node_cid->len == 0) return WF_OK;
    wf_car_block *b = wf_car_find_block(&s->car, node_cid);
    if (!b) return WF_OK;
    wf_mst_node node;
    memset(&node, 0, sizeof(node));
    wf_status st = wf_mst_node_parse(b->data, b->data_len, node_cid, &node);
    if (st != WF_OK) return st;
    if (node.left.len) {
        st = reindex_collect(s, &node.left);
        if (st != WF_OK) { wf_mst_node_free(&node); return st; }
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
                    memcpy(coll, k, clen); coll[clen] = '\0';
                    memcpy(rk, slash + 1, rlen); rk[rlen] = '\0';
                    char *cidstr = wf_cid_to_string(&node.entries[i].value);
                    if (cidstr) {
                        char *js = decode_record_json(s, &node.entries[i].value);
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
            if (st != WF_OK) { wf_mst_node_free(&node); return st; }
        }
    }
    wf_mst_node_free(&node);
    return WF_OK;
}

static wf_status reindex_all(metalbear_repo_store *s) {
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
        if (wf_commit_parse(head_block->data, head_block->data_len,
                            &commit) == WF_OK)
            snprintf(revision, sizeof(revision), "%s", commit.rev);
    }
    for (size_t i = s->persisted_blocks; i < s->car.block_count; i++) {
        wf_car_block *blk = &s->car.blocks[i];
        char *cidstr = wf_cid_to_string(&blk->cid);
        if (!cidstr) return WF_ERR_ALLOC;
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(s->db,
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
static wf_status index_upsert_record(metalbear_repo_store *s, const char *collection,
                                     const char *rkey, const char *cid,
                                     const char *value) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT OR REPLACE INTO records (collection, rkey, cid, value)"
            " VALUES (?, ?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, collection, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, cid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, value, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

static wf_status index_delete_record(metalbear_repo_store *s, const char *collection,
                                     const char *rkey) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
            "DELETE FROM records WHERE collection = ? AND rkey = ?;",
            -1, &stmt, NULL) != SQLITE_OK)
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
    if (sqlite3_prepare_v2(s->db,
            "INSERT OR REPLACE INTO head (id, cid) VALUES (0, ?);",
            -1, &stmt, NULL) != SQLITE_OK) {
        free(cidstr);
        return WF_ERR_INTERNAL;
    }
    if (cidstr) sqlite3_bind_text(stmt, 1, cidstr, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 1);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(cidstr);
    return rc == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

/* Persist the new head commit (and any new blocks) atomically. */
static wf_status commit_persist(metalbear_repo_store *s, const wf_cid *new_head) {
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
    if (sqlite3_prepare_v2(s->db, "SELECT cid, data FROM blocks;", -1,
                           &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    wf_status st = WF_OK;
    for (;;) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) { st = WF_ERR_INTERNAL; break; }
        wf_cid cid;
        const char *cidstr = (const char *)sqlite3_column_text(stmt, 0);
        if (wf_cid_from_string(cidstr, &cid) != WF_OK) { st = WF_ERR_PARSE; break; }
        const unsigned char *data =
            (const unsigned char *)sqlite3_column_blob(stmt, 1);
        int dlen = sqlite3_column_bytes(stmt, 1);

        wf_car_block *nb = realloc(s->car.blocks,
            (s->car.block_count + 1) * sizeof(wf_car_block));
        if (!nb) { st = WF_ERR_ALLOC; break; }
        s->car.blocks = nb;
        wf_car_block *blk = &s->car.blocks[s->car.block_count];
        blk->cid = cid;
        blk->data_len = (size_t)dlen;
        blk->data = dlen ? malloc((size_t)dlen) : NULL;
        if (dlen && !blk->data) { st = WF_ERR_ALLOC; break; }
        if (dlen) memcpy(blk->data, data, (size_t)dlen);
        s->car.block_count++;
    }
    sqlite3_finalize(stmt);
    return st;
}

static void free_store(metalbear_repo_store *s) {
    if (!s) return;
    if (s->db) sqlite3_close(s->db);
    for (size_t i = 0; i < s->car.block_count; i++)
        free(s->car.blocks[i].data);
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
                             const char *handle, metalbear_repo_store **out) {
    if (!path || !*path || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;

    metalbear_repo_store *s = calloc(1, sizeof(*s));
    if (!s) return WF_ERR_ALLOC;
    s->path = strdup(path);
    if (!s->path) { free(s); return WF_ERR_ALLOC; }

    if (sqlite3_open(path, &s->db) != SQLITE_OK) {
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
    if (!has_repo_rev && sqlite3_exec(s->db,
            "ALTER TABLE blocks ADD COLUMN repo_rev TEXT;", NULL, NULL,
            NULL) != SQLITE_OK) {
        free_store(s);
        return WF_ERR_INTERNAL;
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
            "SELECT did, handle, key_type, key_bytes FROM meta WHERE id=0;",
            -1, &stmt, NULL) != SQLITE_OK) {
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

        s->did = strdup(d ? d : "");
        s->handle = strdup(h ? h : "");
        s->key.type = (wf_key_type)kt;
        if (kbl == (int)sizeof(s->key.bytes))
            memcpy(s->key.bytes, kb, sizeof(s->key.bytes));
        sqlite3_finalize(stmt);

        if (wf_signing_key_public_didkey(&s->key, &s->signing_key_didkey)
                != WF_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }
        st = load_all_blocks(s);
        if (st != WF_OK) { free_store(s); return st; }

        /* Load head commit CID, if any. */
        if (sqlite3_prepare_v2(s->db, "SELECT cid FROM head WHERE id=0;",
                -1, &stmt, NULL) != SQLITE_OK) {
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
        if (!did || !*did) { free_store(s); return WF_ERR_INVALID_ARG; }

        wf_signing_key key;
        if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &key) != WF_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }
        s->did = strdup(did);
        s->handle = strdup(handle ? handle : "");
        s->key = key;
        if (wf_signing_key_public_didkey(&s->key, &s->signing_key_didkey)
                != WF_OK) {
            free_store(s);
            return WF_ERR_INTERNAL;
        }

        if (sqlite3_prepare_v2(s->db,
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
        if (rc != SQLITE_DONE) { free_store(s); return WF_ERR_INTERNAL; }
        set_root(s);
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

wf_status metalbear_repo_store_set_handle(metalbear_repo_store *store, const char *handle) {
    if (!store || !handle || !wf_syntax_handle_is_valid(handle))
        return WF_ERR_INVALID_ARG;
    char *copy = strdup(handle);
    if (!copy) return WF_ERR_ALLOC;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "UPDATE meta SET handle=? WHERE id=0;", -1, &stmt, NULL) !=
            SQLITE_OK) {
        free(copy);
        return WF_ERR_INTERNAL;
    }
    sqlite3_bind_text(stmt, 1, handle, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE || sqlite3_changes(store->db) != 1) {
        free(copy);
        return WF_ERR_INTERNAL;
    }
    free(store->handle);
    store->handle = copy;
    return WF_OK;
}

wf_status metalbear_repo_store_get_stats(metalbear_repo_store *store,
                                  metalbear_repo_store_stats *out_stats) {
    if (!out_stats) return WF_ERR_INVALID_ARG;
    memset(out_stats, 0, sizeof(*out_stats));
    if (!store) return WF_ERR_INVALID_ARG;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT (SELECT COUNT(*) FROM blocks), "
            "(SELECT COUNT(*) FROM records);", -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return WF_ERR_INTERNAL;
    }
    sqlite3_int64 blocks = sqlite3_column_int64(stmt, 0);
    sqlite3_int64 records = sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt);
    if (blocks < 0 || records < 0 ||
        (uint64_t)blocks > (uint64_t)SIZE_MAX ||
        (uint64_t)records > (uint64_t)SIZE_MAX)
        return WF_ERR_INTERNAL;
    out_stats->repo_blocks = (size_t)blocks;
    out_stats->indexed_records = (size_t)records;
    return WF_OK;
}

void metalbear_repo_store_set_event_callback(metalbear_repo_store *store,
                                      metalbear_repo_store_event_cb callback,
                                      void *context) {
    if (!store) return;
    store->event_cb = callback;
    store->event_ctx = context;
}

static int parse_commit_at(metalbear_repo_store *s, const wf_cid *cid,
                           wf_commit *out) {
    if (!s || !cid || !cid->len || !out) return 0;
    const wf_car_block *block = wf_car_find_block(&s->car, cid);
    return block && wf_commit_parse(block->data, block->data_len, out) == WF_OK;
}

static void emit_commit_event(metalbear_repo_store *s, const wf_cid *old_head,
                              const char *action, const char *collection,
                              const char *rkey, const wf_cid *cid,
                              const wf_cid *prev) {
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
        .action = action,
        .collection = collection,
        .rkey = rkey,
        .cid = cid ? *cid : (wf_cid){{0}, 0},
        .has_cid = cid != NULL,
        .prev = prev ? *prev : (wf_cid){{0}, 0},
        .has_prev = prev != NULL,
        .blocks = blocks,
        .blocks_len = blocks_len,
    };
    s->event_cb(&event, s->event_ctx);
    free(blocks);
}

static void emit_sync_event(metalbear_repo_store *s) {
    if (!s || !s->event_cb) return;
    wf_commit current = {0};
    if (!parse_commit_at(s, &s->head, &current)) return;
    unsigned char *blocks = NULL;
    size_t blocks_len = 0;
    if (metalbear_repo_store_export(s, NULL, &blocks, &blocks_len) != WF_OK) return;
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
/* Write / read operations                                             */
/* ------------------------------------------------------------------ */

wf_status metalbear_repo_store_create_record(metalbear_repo_store *s, const char *collection,
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
        return WF_ERR_INVALID_ARG; /* TODO: atproto returns InvalidRecordKey */
    }

    /* (b) $type, when present, must equal the target collection. */
    if (!record_type_matches(record_json, collection))
        return WF_ERR_INVALID_ARG; /* TODO: atproto returns InvalidRecord */

    /* (a) CAS: swapCommit must match the current repo head (if supplied). */
    char *head = head_cid_string(s);
    wf_status st = check_swap(swap_commit_or_null, head);
    free(head);
    if (st != WF_OK) return st;

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
    emit_commit_event(s, &old_head, "create", collection, rkey,
                      &out_record, NULL);
    return WF_OK;
}

wf_status metalbear_repo_store_put_record(metalbear_repo_store *s, const char *collection,
                                    const char *rkey, const char *record_json,
                                    const char *swap_commit_or_null,
                                    const char *swap_record_or_null,
                                    char **out_uri, char **out_cid) {
    if (!s || !collection || !*collection || !rkey || !*rkey ||
        !record_json || !out_uri || !out_cid)
        return WF_ERR_INVALID_ARG;
    *out_uri = NULL;
    *out_cid = NULL;

    /* (c) record-key validation (atproto charset/length rules). */
    if (!wf_syntax_record_key_is_valid(rkey))
        return WF_ERR_INVALID_ARG; /* TODO: atproto returns InvalidRecordKey */

    /* (b) $type, when present, must equal the target collection. */
    if (!record_type_matches(record_json, collection))
        return WF_ERR_INVALID_ARG; /* TODO: atproto returns InvalidRecord */

    /* Detect whether the record already exists. */
    unsigned char *existing = NULL;
    size_t ex_len = 0;
    wf_cid ex_cid;
    wf_status st = get_record_cbor(s, collection, rkey, &existing, &ex_len,
                                    &ex_cid);
    int exists = (st == WF_OK);
    free(existing);
    if (st != WF_OK && st != WF_ERR_NOT_FOUND) return st;

    /* (a) CAS: swapCommit against head; swapRecord against current record. */
    char *head = head_cid_string(s);
    st = check_swap(swap_commit_or_null, head);
    free(head);
    if (st != WF_OK) return st;
    if (swap_record_or_null && *swap_record_or_null) {
        if (!exists) return WF_ERR_INVALID_ARG; /* TODO: atproto InvalidSwap */
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

    if (exists) {
        st = wf_repo_update_record(&s->car, &s->head, s->did, collection,
                                    rkey, cbor, cbor_len, &s->key, &out_commit,
                                    &out_record);
    } else {
        const wf_cid *prev = s->head.len ? &s->head : NULL;
        st = wf_repo_create_record(&s->car, prev, s->did, collection, rkey,
                                    cbor, cbor_len, &s->key, &out_commit,
                                    &out_record);
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
    emit_commit_event(s, &old_head, exists ? "update" : "create",
                      collection, rkey, &out_record,
                      exists ? &ex_cid : NULL);
    return WF_OK;
}

wf_status metalbear_repo_store_delete_record(metalbear_repo_store *s, const char *collection,
                                       const char *rkey,
                                       const char *swap_commit_or_null,
                                       const char *swap_record_or_null) {
    if (!s || !collection || !*collection || !rkey || !*rkey)
        return WF_ERR_INVALID_ARG;

    /* (c) record-key validation (atproto charset/length rules). */
    if (!wf_syntax_record_key_is_valid(rkey))
        return WF_ERR_INVALID_ARG; /* TODO: atproto returns InvalidRecordKey */
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    unsigned char *existing = NULL;
    size_t ex_len = 0;
    wf_cid ex_cid;
    wf_status st = get_record_cbor(s, collection, rkey, &existing, &ex_len,
                                    &ex_cid);
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
    emit_commit_event(s, &old_head, "delete", collection, rkey, NULL,
                      &ex_cid);
    return WF_OK;
}

wf_status metalbear_repo_store_get_record(metalbear_repo_store *s, const char *collection,
                                   const char *rkey, char **out_record_json,
                                   char **out_cid) {
    if (!s || !collection || !*collection || !rkey || !*rkey ||
        !out_record_json || !out_cid)
        return WF_ERR_INVALID_ARG;
    *out_record_json = NULL;
    *out_cid = NULL;

    unsigned char *data = NULL;
    size_t len = 0;
    wf_cid rcid;
    wf_status st = get_record_cbor(s, collection, rkey, &data, &len, &rcid);
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
    if (!cidstr) { free(js); return WF_ERR_ALLOC; }

    *out_record_json = js;
    *out_cid = cidstr;
    return WF_OK;
}

wf_status metalbear_repo_store_apply_writes(metalbear_repo_store *s, const char *writes_json,
                                      const char *swap_commit_or_null,
                                      char **out_commit_cid,
                                      char **out_commit_rev,
                                      char **out_results_json) {
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
    if (st != WF_OK) { cJSON_Delete(root); return st; }

    /* (g) cap batch size at 200 writes (mirrors atproto's limit). */
    if (cJSON_GetArraySize(root) > 200) {
        cJSON_Delete(root);
        return WF_ERR_INVALID_ARG; /* TODO: atproto returns TooManyWrites */
    }

    cJSON *results = cJSON_CreateArray();
    if (!results) { cJSON_Delete(root); return WF_ERR_ALLOC; }

    st = WF_OK;
    const cJSON *op;
    cJSON_ArrayForEach(op, root) {
        if (!cJSON_IsObject(op)) { st = WF_ERR_INVALID_ARG; break; }
        cJSON *type = cJSON_GetObjectItemCaseSensitive(op, "$type");
        if (!type || !cJSON_IsString(type)) { st = WF_ERR_INVALID_ARG; break; }
        const char *t = type->valuestring;

        cJSON *coll = cJSON_GetObjectItemCaseSensitive(op, "collection");
        cJSON *val = cJSON_GetObjectItemCaseSensitive(op, "value");
        cJSON *rk = cJSON_GetObjectItemCaseSensitive(op, "rkey");

        if (strcmp(t, "com.atproto.repo.applyWrites#create") == 0 ||
            strcmp(t, "com.atproto.repo.applyWrites#update") == 0) {
            if (!coll || !cJSON_IsString(coll) || !val) {
                st = WF_ERR_INVALID_ARG;
                break;
            }
            /* (c) record-key validation when a caller-supplied rkey given. */
            const char *rkey = (rk && cJSON_IsString(rk) && rk->valuestring[0])
                                  ? rk->valuestring : NULL;
            if (rkey && !wf_syntax_record_key_is_valid(rkey)) {
                st = WF_ERR_INVALID_ARG; /* TODO: InvalidRecordKey */
                break;
            }
            char *rec_json = cJSON_PrintUnformatted(val);
            if (!rec_json) { st = WF_ERR_ALLOC; break; }
            char *uri = NULL, *cid = NULL;
            if (strcmp(t, "com.atproto.repo.applyWrites#create") == 0) {
                st = metalbear_repo_store_create_record(s, coll->valuestring, rkey,
                                                 rec_json, NULL, &uri, &cid);
            } else {
                if (!rkey) {
                    st = WF_ERR_INVALID_ARG;
                } else {
                    st = metalbear_repo_store_put_record(s, coll->valuestring, rkey,
                                                   rec_json, NULL, NULL, &uri,
                                                   &cid);
                }
            }
            free(rec_json);
            if (st != WF_OK) { free(uri); free(cid); break; }
            cJSON *r = cJSON_CreateObject();
            cJSON_AddStringToObject(r, "uri", uri ? uri : "");
            cJSON_AddStringToObject(r, "cid", cid ? cid : "");
            /* (d)/(g) per-op validationStatus; wolfram does no lexicon
             * validation, so it reports "unknown" (matching atproto's
             * behaviour for an unrecognised $type). */
            cJSON_AddStringToObject(r, "validationStatus", "unknown");
            cJSON_AddItemToArray(results, r);
            free(uri);
            free(cid);
        } else if (strcmp(t, "com.atproto.repo.applyWrites#delete") == 0) {
            if (!coll || !cJSON_IsString(coll) || !rk ||
                !cJSON_IsString(rk) || !rk->valuestring[0]) {
                st = WF_ERR_INVALID_ARG;
                break;
            }
            if (!wf_syntax_record_key_is_valid(rk->valuestring)) {
                st = WF_ERR_INVALID_ARG; /* TODO: InvalidRecordKey */
                break;
            }
            st = metalbear_repo_store_delete_record(s, coll->valuestring,
                                             rk->valuestring, NULL, NULL);
            if (st != WF_OK) break;
            cJSON_AddItemToArray(results, cJSON_CreateObject());
        } else {
            st = WF_ERR_INVALID_ARG;
            break;
        }
    }
    cJSON_Delete(root);
    if (st != WF_OK) { cJSON_Delete(results); return st; }

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

/* ------------------------------------------------------------------ */
/* describeRepo + verification                                         */
/* ------------------------------------------------------------------ */

static wf_status walk_mst_collections(metalbear_repo_store *s, const wf_cid *root,
                                      cJSON *cols) {
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

wf_status metalbear_repo_store_describe(metalbear_repo_store *s, char **out_json) {
    if (!s || !out_json) return WF_ERR_INVALID_ARG;
    *out_json = NULL;

    cJSON *obj = cJSON_CreateObject();
    if (!obj) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(obj, "handle", s->handle ? s->handle : "");
    cJSON_AddStringToObject(obj, "did", s->did ? s->did : "");
    cJSON_AddBoolToObject(obj, "handleIsCorrect", 0);
    cJSON_AddStringToObject(obj, "version", "0");

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

    char *js = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (!js) return WF_ERR_ALLOC;
    *out_json = js;
    return WF_OK;
}

wf_status metalbear_repo_store_verify_head(metalbear_repo_store *s, int *out_verified,
                                    wf_commit *out_commit) {
    if (!s || !out_verified) return WF_ERR_INVALID_ARG;
    *out_verified = 0;
    if (out_commit) memset(out_commit, 0, sizeof(*out_commit));
    if (s->head.len == 0) return WF_OK;

    wf_repo_verify_options opts = { s->did, s->signing_key_didkey, NULL };
    wf_commit c;
    wf_status st = wf_repo_verify(&s->car, &opts, &c);
    if (st == WF_OK) *out_verified = 1;
    if (out_commit) *out_commit = c;
    return st;
}

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
} metalbear_pds_repo_bundle;

/*
 * Resolve the repo store for a request from the registration's bundle.
 * Returns the store to use (never NULL on success) or NULL after writing a
 * 400 RepoNotFound response when the resolver fails / resolves no store.
 * When no resolver is set the single fallback store is returned.
 */
static metalbear_repo_store *resolve_repo(metalbear_pds_repo_bundle *b,
                                   const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    metalbear_repo_store *store = b->fallback_repo;
    if (b->resolver) {
        metalbear_repo_store *out_repo = NULL;
        metalbear_blob_store *out_blobs = NULL;
        if (b->resolver(b->resolver_ctx, req, &out_repo, &out_blobs) != WF_OK ||
            !out_repo) {
            wf_xrpc_response_set_error(resp, 400, "RepoNotFound",
                                        "Repository is not hosted here");
            return NULL;
        }
        store = out_repo;
    }
    return store;
}

static wf_status h_create_record(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
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

    const char *rk = (rkey && cJSON_IsString(rkey)) ? rkey->valuestring : NULL;
    const char *swap_str = (swap && cJSON_IsString(swap)) ? swap->valuestring
                                                         : NULL;
    char *uri = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_create_record(s, collection->valuestring, rk,
                                              rec_json, swap_str, &uri, &cid);
    free(rec_json);
    if (st != WF_OK) {
        /* CAS / validation failures surface as InvalidSwap-equivalent 400s. */
        wf_xrpc_response_set_error(resp, 400, "CreationFailed",
                                    "record creation failed");
        return WF_OK;
    }

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "uri", uri ? uri : "");
    cJSON_AddStringToObject(out, "cid", cid ? cid : "");
    /* (d) wolfram performs no lexicon validation, so report "unknown". */
    cJSON_AddStringToObject(out, "validationStatus", "unknown");
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
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
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

    const char *swap_str = (swap && cJSON_IsString(swap)) ? swap->valuestring
                                                         : NULL;
    const char *swaprec_str = (swapRec && cJSON_IsString(swapRec))
                                  ? swapRec->valuestring : NULL;
    char *uri = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_put_record(s, collection->valuestring,
                                           rkey->valuestring, rec_json,
                                           swap_str, swaprec_str, &uri, &cid);
    free(rec_json);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "PutFailed",
                                    "record put failed");
        return WF_OK;
    }

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "uri", uri ? uri : "");
    cJSON_AddStringToObject(out, "cid", cid ? cid : "");
    /* (d) wolfram performs no lexicon validation, so report "unknown". */
    cJSON_AddStringToObject(out, "validationStatus", "unknown");
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
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
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
    const char *swap_str = (swap && cJSON_IsString(swap)) ? swap->valuestring
                                                         : NULL;
    const char *swaprec_str = (swapRec && cJSON_IsString(swapRec))
                                  ? swapRec->valuestring : NULL;
    wf_status st = metalbear_repo_store_delete_record(s, collection->valuestring,
                                              rkey->valuestring, swap_str,
                                              swaprec_str);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 404, "RecordNotFound",
                                   "record could not be deleted");
        return WF_OK;
    }
    cJSON *out = cJSON_CreateObject();
    add_commit_meta(s, out);
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static wf_status h_get_record(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
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
    char *rec = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_get_record(s, collection->valuestring,
                                            rkey->valuestring, &rec, &cid);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 404, "RecordNotFound",
                                   "record not found");
        return WF_OK;
    }
    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "uri",
                            make_uri(s->did, collection->valuestring,
                                     rkey->valuestring));
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
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
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
    const char *swap_str = (swap && cJSON_IsString(swap)) ? swap->valuestring
                                                         : NULL;
    char *writes_json = cJSON_PrintUnformatted(writes);
    if (!writes_json) return WF_ERR_ALLOC;

    char *cid = NULL, *rev = NULL, *results = NULL;
    wf_status st = metalbear_repo_store_apply_writes(s, writes_json, swap_str, &cid,
                                              &rev, &results);
    free(writes_json);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "ApplyFailed",
                                   "applyWrites failed");
        return WF_OK;
    }

    cJSON *out = cJSON_CreateObject();
    cJSON *commit = cJSON_CreateObject();
    cJSON_AddStringToObject(commit, "cid", cid ? cid : "");
    cJSON_AddStringToObject(commit, "rev", rev ? rev : "");
    cJSON_AddItemToObject(out, "commit", commit);
    cJSON *res = cJSON_Parse(results);
    if (res) cJSON_AddItemToObject(out, "results", res);
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

static wf_status h_describe_repo(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    char *json = NULL;
    wf_status st = metalbear_repo_store_describe(s, &json);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "describeRepo failed");
        return WF_OK;
    }
    wf_xrpc_response_set_body(resp, json, strlen(json));
    free(json);
    return WF_OK;
}

/* ── listRecords (com.atproto.repo.listRecords) ──────────────────────── */

wf_status metalbear_repo_store_list_records(metalbear_repo_store *s, const char *collection,
                                      const char *cursor, bool reverse,
                                      int limit, char **out_json) {
    if (!s || !collection || !*collection || !out_json)
        return WF_ERR_INVALID_ARG;
    *out_json = NULL;
    if (limit <= 0 || limit > 100) limit = 50;  /* lexicon max is 100 */

    const char *cursor_str = cursor && *cursor ? cursor : NULL;

    /* (e) ascending by default; descending when `reverse`. */
    char sql[256];
    if (reverse) {
        if (cursor_str)
            snprintf(sql, sizeof(sql),
                "SELECT rkey, cid, value FROM records "
                "WHERE collection = ? AND rkey < ? ORDER BY rkey DESC LIMIT ?;");
        else
            snprintf(sql, sizeof(sql),
                "SELECT rkey, cid, value FROM records "
                "WHERE collection = ? ORDER BY rkey DESC LIMIT ?;");
    } else {
        if (cursor_str)
            snprintf(sql, sizeof(sql),
                "SELECT rkey, cid, value FROM records "
                "WHERE collection = ? AND rkey > ? ORDER BY rkey ASC LIMIT ?;");
        else
            snprintf(sql, sizeof(sql),
                "SELECT rkey, cid, value FROM records "
                "WHERE collection = ? ORDER BY rkey ASC LIMIT ?;");
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, collection, -1, SQLITE_TRANSIENT);
    if (cursor_str)
        sqlite3_bind_text(stmt, 2, cursor_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, cursor_str ? 3 : 2, limit + 1); /* +1 to detect a next page */

    cJSON *records = cJSON_CreateArray();
    if (!records) { sqlite3_finalize(stmt); return WF_ERR_ALLOC; }
    int count = 0;
    int has_more = 0;
    const char *last_rkey = NULL;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= limit) { /* over-fetch: there is a next page */
            has_more = 1;
            last_rkey = (const char *)sqlite3_column_text(stmt, 0);
            break;
        }
        const char *rkey = (const char *)sqlite3_column_text(stmt, 0);
        const char *cid = (const char *)sqlite3_column_text(stmt, 1);
        const char *value = (const char *)sqlite3_column_text(stmt, 2);
        last_rkey = rkey;
        cJSON *rec = cJSON_CreateObject();
        cJSON_AddStringToObject(rec, "uri",
                                 make_uri(s->did, collection, rkey));
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

    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    *out_json = js;
    return WF_OK;
}

/* ── getLatestCommit (com.atproto.sync.getLatestCommit) ───────────────── */

wf_status metalbear_repo_store_get_head(metalbear_repo_store *s, char **out_rev,
                                  char **out_cid) {
    if (!s || !out_rev || !out_cid) return WF_ERR_INVALID_ARG;
    *out_rev = NULL;
    *out_cid = NULL;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    char *cid = wf_cid_to_string(&s->head);
    char rev[64] = "";
    wf_car_block *blk = wf_car_find_block(&s->car, &s->head);
    if (blk) {
        wf_commit cm;
        if (wf_commit_parse(blk->data, blk->data_len, &cm) == WF_OK)
            snprintf(rev, sizeof(rev), "%s", cm.rev);
    }
    if (!cid) return WF_ERR_ALLOC;
    *out_cid = cid;
    *out_rev = strdup(rev);
    if (!*out_rev) { free(cid); return WF_ERR_ALLOC; }
    return WF_OK;
}

wf_status metalbear_repo_store_export(metalbear_repo_store *s, const char *since,
                               unsigned char **out_data, size_t *out_len) {
    if (!s || !out_data || !out_len) return WF_ERR_INVALID_ARG;
    *out_data = NULL;
    *out_len = 0;
    if (s->head.len == 0) return WF_ERR_NOT_FOUND;

    const char *sql = since && since[0]
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
        wf_car_block *grown = realloc(export_car.blocks,
            (export_car.block_count + 1) * sizeof(*grown));
        if (!grown) {
            status = WF_ERR_ALLOC;
            break;
        }
        export_car.blocks = grown;
        export_car.blocks[export_car.block_count++] = *source;
    }
    sqlite3_finalize(stmt);
    if (status == WF_OK)
        status = wf_car_write(&export_car, out_data, out_len);
    free(export_car.blocks); /* Shallow references into s->car. */
    return status;
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
        wf_car_block *grown = realloc(selected.blocks,
            (selected.block_count + 1) * sizeof(*grown));
        if (!grown) {
            status = WF_ERR_ALLOC;
            break;
        }
        selected.blocks = grown;
        selected.blocks[selected.block_count++] = *source;
    }
    if (status == WF_OK) status = wf_car_write(&selected, out_data, out_len);
    free(selected.blocks); /* Shallow references into s->car. */
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
    wf_status status = metalbear_repo_store_get_record(s, collection, rkey,
                                                       &record_json, &record_cid_str);
    if (status != WF_OK) return status;
    free(record_json);

    /* Parse the record CID. */
    wf_cid record_cid;
    if (wf_cid_from_string(record_cid_str, &record_cid) != WF_OK) {
        free(record_cid_str);
        return WF_ERR_INTERNAL;
    }
    free(record_cid_str);

    /* Find the record block in the CAR. */
    wf_car_block *record_block = wf_car_find_block(&s->car, &record_cid);
    if (!record_block) return WF_ERR_NOT_FOUND;

    /* Build a CAR with the commit as root and the record block. */
    wf_car out = {0};
    out.roots = &s->head;
    out.root_count = 1;

    /* Add commit block. */
    wf_car_block *commit_block = wf_car_find_block(&s->car, &s->head);
    if (!commit_block) return WF_ERR_NOT_FOUND;
    out.blocks = calloc(2, sizeof(*out.blocks));
    if (!out.blocks) return WF_ERR_ALLOC;
    out.blocks[0] = *commit_block;
    out.blocks[1] = *record_block;
    out.block_count = 2;

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

/* ── Route handlers ──────────────────────────────────────────────────── */

static wf_status h_list_records(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    cJSON *p = req->params;
    if (!p || !cJSON_IsObject(p)) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                    "query parameters required");
        return WF_OK;
    }
    cJSON *collection = cJSON_GetObjectItemCaseSensitive(p, "collection");
    if (!collection || !cJSON_IsString(collection) || !collection->valuestring ||
        !*collection->valuestring) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                    "collection required");
        return WF_OK;
    }
    cJSON *cursor = cJSON_GetObjectItemCaseSensitive(p, "cursor");
    cJSON *limit = cJSON_GetObjectItemCaseSensitive(p, "limit");
    cJSON *reverse = cJSON_GetObjectItemCaseSensitive(p, "reverse");
    int lim = (limit && cJSON_IsNumber(limit)) ? limit->valueint : 50;
    int rev = (reverse && cJSON_IsTrue(reverse)) ? 1 : 0;
    const char *cur = (cursor && cJSON_IsString(cursor)) ? cursor->valuestring
                                                          : NULL;
    char *json = NULL;
    wf_status st = metalbear_repo_store_list_records(s, collection->valuestring, cur,
                                              rev, lim, &json);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "ListRecordsFailed",
                                    "failed to list records");
        return WF_OK;
    }
    wf_xrpc_response_set_body(resp, json, strlen(json));
    free(json);
    return WF_OK;
}

static wf_status h_get_latest_commit(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp) {
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    char *rev = NULL, *cid = NULL;
    wf_status st = metalbear_repo_store_get_head(s, &rev, &cid);
    if (st == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(resp, 400, "RepositoryNotFound",
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
    free(rev); free(cid);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

/* ── importRepo (com.atproto.repo.importRepo) ──────────────────────
 * Accept a CAR POST body, verify it as a full repo with the store's
 * signing key (wf_repo_import reuses the SDK commit/MST verification),
 * merge its blocks into the store, make its root the new head, and
 * rebuild the records index. */

static wf_status h_import_repo(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    metalbear_repo_store *s = resolve_repo((metalbear_pds_repo_bundle *)ctx, req, resp);
    if (!s) return WF_OK;
    if (!req->body || req->body_len == 0) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                    "CAR body required");
        return WF_OK;
    }

    wf_repo_verify_options opts = { s->did, s->signing_key_didkey, NULL };
    wf_car imported;
    wf_commit commit;
    wf_status st = wf_repo_import(req->body, req->body_len, &opts,
                                   &imported, &commit);
    if (st != WF_OK) {
        /* A bad/unverifiable CAR fails the import rather than corrupting
         * the existing repo (atproto returns InvalidCAR). */
        wf_xrpc_response_set_error(resp, 400, "InvalidCAR",
                                    "imported CAR failed verification");
        return WF_OK;
    }

    /* Merge blocks that aren't already present into the store's CAR. */
    for (size_t i = 0; i < imported.block_count; i++) {
        if (wf_car_find_block(&s->car, &imported.blocks[i].cid))
            continue;
        wf_car_block *nb = realloc(s->car.blocks,
            (s->car.block_count + 1) * sizeof(*nb));
        if (!nb) { wf_car_free(&imported); return WF_ERR_ALLOC; }
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
    /* Rebuild the records index so listRecords reflects the imported repo.
     * Index rebuild failures are best-effort: persistence already
     * succeeded, but callers should re-list to recover. */
    reindex_all(s);
    emit_sync_event(s);

    cJSON *out = cJSON_CreateObject();
    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

static wf_status register_pds_repo_handlers(wf_xrpc_server *server,
                                            metalbear_pds_repo_bundle *b);

wf_status metalbear_xrpc_server_register_pds_repo(wf_xrpc_server *server,
                                            metalbear_repo_store *store) {
    if (!server || !store) return WF_ERR_INVALID_ARG;
    /* Single-store path: build a resolver-less bundle that always serves
     * `store`. The server owns the bundle and frees it on
     * wf_xrpc_server_free, preserving the caller-owned `store` contract. */
    metalbear_pds_repo_bundle *b = (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->fallback_repo = store;
    wf_xrpc_server_own_ctx(server, b, free);
    return register_pds_repo_handlers(server, b);
}

static wf_status register_pds_repo_handlers(wf_xrpc_server *server,
                                            metalbear_pds_repo_bundle *b) {
    if (!server || !b) return WF_ERR_INVALID_ARG;
    wf_status s;
    s = wf_xrpc_server_register_procedure(server,
            "com.atproto.repo.createRecord", h_create_record, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_procedure(server, "com.atproto.repo.putRecord",
            h_put_record, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_procedure(server,
            "com.atproto.repo.deleteRecord", h_delete_record, b);
    if (s != WF_OK) return s;
    s = wf_xrpc_server_register_procedure(server, "com.atproto.repo.applyWrites",
            h_apply_writes, b);
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
    s = wf_xrpc_server_register_query(server, "com.atproto.sync.getLatestCommit",
            h_get_latest_commit, b);
    if (s != WF_OK) return s;
    /* importRepo (CAR POST body) — see h_import_repo. uploadBlob is
     * registered separately by wf_xrpc_server_register_blob_store. */
    s = wf_xrpc_server_register_procedure(server,
            "com.atproto.repo.importRepo", h_import_repo, b);
    if (s != WF_OK) return s;
    return WF_OK;
}

wf_status metalbear_xrpc_server_register_pds_repo_resolver(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx) {
    if (!server) return WF_ERR_INVALID_ARG;
    metalbear_pds_repo_bundle *b = (metalbear_pds_repo_bundle *)malloc(sizeof(*b));
    if (!b) return WF_ERR_ALLOC;
    *b = (metalbear_pds_repo_bundle){0};
    b->resolver = resolver;
    b->resolver_ctx = ctx;
    wf_xrpc_server_own_ctx(server, b, free);
    return register_pds_repo_handlers(server, b);
}

#define _POSIX_C_SOURCE 200809L

/*
 * blob_lifecycle.c -- host-wide blob lifecycle metadata (issue #253).
 *
 * Kept separate from the per-account blob store so the state survives account
 * cache eviction and the operator can sweep every account from one place.
 * Payload IO is delegated to the caller's callbacks; this module only owns the
 * SQLite truth about which copies are temporary, which are durable, and which
 * record revisions still make them reachable.
 */

#include "metalbear/repo/blob_lifecycle.h"
#include "metalbear/log.h"
#include "metalbear/schema_version.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct metalbear_blob_lifecycle {
    sqlite3 *db;
    pthread_mutex_t mutex;
};

typedef struct blob_state_row {
    char *did;
    char *cid;
    int state;
    int64_t created_at;
    uint64_t size;
} blob_state_row;

typedef struct blob_ref_row {
    char *uri;
    char *rev;
} blob_ref_row;

static void rows_free(blob_state_row *rows, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(rows[i].did);
        free(rows[i].cid);
    }
    free(rows);
}

static void refs_free(blob_ref_row *refs, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(refs[i].uri);
        free(refs[i].rev);
    }
    free(refs);
}

static char *lifecycle_path(const char *dir) {
    size_t n = strlen(dir);
    int sep = n > 0 && dir[n - 1] == '/' ? 0 : 1;
    char *out = malloc(n + sep + strlen("blob_lifecycle.sqlite3") + 1);
    if (!out) return NULL;
    memcpy(out, dir, n);
    if (sep) out[n] = '/';
    strcpy(out + n + sep, "blob_lifecycle.sqlite3");
    return out;
}

metalbear_blob_lifecycle *
metalbear_blob_lifecycle_open(const char *data_directory) {
    if (!data_directory || !*data_directory) return NULL;
    char *path = lifecycle_path(data_directory);
    if (!path) return NULL;

    metalbear_blob_lifecycle *life = calloc(1, sizeof(*life));
    if (!life) {
        free(path);
        return NULL;
    }
    if (pthread_mutex_init(&life->mutex, NULL) != 0) {
        free(life);
        free(path);
        return NULL;
    }
    if (sqlite3_open_v2(path, &life->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        LOG_ERROR("cannot open blob lifecycle store at %s", path);
        pthread_mutex_destroy(&life->mutex);
        free(life);
        free(path);
        return NULL;
    }
    free(path);

    if (metalbear_schema_open(life->db, "blob_lifecycle.sqlite3") != WF_OK) {
        metalbear_blob_lifecycle_free(life);
        return NULL;
    }

    const char *schema =
        "CREATE TABLE IF NOT EXISTS blob_state ("
        "  did TEXT NOT NULL, cid TEXT NOT NULL,"
        "  state INTEGER NOT NULL CHECK(state IN (0,1)),"
        "  created_at INTEGER NOT NULL, size INTEGER NOT NULL,"
        "  PRIMARY KEY (did, cid));"
        "CREATE TABLE IF NOT EXISTS blob_refs ("
        "  did TEXT NOT NULL, cid TEXT NOT NULL,"
        "  uri TEXT NOT NULL, rev TEXT NOT NULL,"
        "  PRIMARY KEY (did, cid, uri, rev));"
        "CREATE INDEX IF NOT EXISTS blob_refs_cid ON blob_refs(cid);"
        "CREATE INDEX IF NOT EXISTS blob_refs_rev ON blob_refs(did, rev);";
    char *errmsg = NULL;
    if (sqlite3_exec(life->db, schema, NULL, NULL, &errmsg) != SQLITE_OK) {
        LOG_ERROR("blob lifecycle schema migration failed: %s",
                  errmsg ? errmsg : "unknown error");
        sqlite3_free(errmsg);
        metalbear_blob_lifecycle_free(life);
        return NULL;
    }
    return life;
}

void metalbear_blob_lifecycle_free(metalbear_blob_lifecycle *life) {
    if (!life) return;
    pthread_mutex_lock(&life->mutex);
    if (life->db) {
        sqlite3_close(life->db);
        life->db = NULL;
    }
    pthread_mutex_unlock(&life->mutex);
    pthread_mutex_destroy(&life->mutex);
    free(life);
}

static bool valid_key(const char *did, const char *cid) {
    return did && did[0] && cid && cid[0];
}

wf_status metalbear_blob_lifecycle_mark_uploaded(metalbear_blob_lifecycle *life,
                                                 const char *did,
                                                 const char *cid, size_t size,
                                                 int64_t now) {
    if (!life || !valid_key(did, cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&life->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status st = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            life->db,
            "INSERT OR IGNORE INTO blob_state"
            " (did,cid,state,created_at,size) VALUES (?,?,0,?,?);",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)size);
        st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (st == WF_OK &&
        sqlite3_prepare_v2(
            life->db, "UPDATE blob_state SET size=? WHERE did=? AND cid=?;", -1,
            &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)size);
        sqlite3_bind_text(stmt, 2, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, cid, -1, SQLITE_TRANSIENT);
        st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&life->mutex);
    return st;
}

wf_status metalbear_blob_lifecycle_promote(metalbear_blob_lifecycle *life,
                                           const char *did, const char *cid,
                                           int *changed) {
    if (changed) *changed = 0;
    if (!life || !valid_key(did, cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&life->mutex);
    sqlite3_stmt *stmt = NULL;
    int state = -1;
    wf_status st = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            life->db, "SELECT state FROM blob_state WHERE did=? AND cid=?;", -1,
            &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            state = sqlite3_column_int(stmt, 0);
            st = WF_OK;
        } else if (rc == SQLITE_DONE) {
            state = -1;
            st = WF_OK;
        }
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    if (st == WF_OK && state == 0) {
        if (sqlite3_prepare_v2(life->db,
                               "UPDATE blob_state SET state=1"
                               " WHERE did=? AND cid=?;",
                               -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
            st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
            if (st == WF_OK && changed) *changed = 1;
        } else {
            st = WF_ERR_INTERNAL;
        }
        sqlite3_finalize(stmt);
    } else if (st == WF_OK && state < 0) {
        stmt = NULL;
        if (sqlite3_prepare_v2(life->db,
                               "INSERT OR IGNORE INTO blob_state"
                               " (did,cid,state,created_at,size)"
                               " VALUES (?,?,1,strftime('%s','now'),0);",
                               -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
            st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
            if (st == WF_OK && changed) *changed = 1;
        } else {
            st = WF_ERR_INTERNAL;
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&life->mutex);
    return st;
}

wf_status metalbear_blob_lifecycle_add_ref(metalbear_blob_lifecycle *life,
                                           const char *did, const char *cid,
                                           const char *uri, const char *rev) {
    if (!life || !valid_key(did, cid) || !uri || !*uri)
        return WF_ERR_INVALID_ARG;
    wf_status st = metalbear_blob_lifecycle_promote(life, did, cid, NULL);
    if (st != WF_OK) return st;
    if (!rev || !*rev) rev = "unknown";

    pthread_mutex_lock(&life->mutex);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(life->db,
                           "INSERT OR REPLACE INTO blob_refs"
                           " (did,cid,uri,rev) VALUES (?,?,?,?);",
                           -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, uri, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, rev, -1, SQLITE_TRANSIENT);
        st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    } else {
        st = WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&life->mutex);
    return st;
}

wf_status metalbear_blob_lifecycle_remove_refs(metalbear_blob_lifecycle *life,
                                               const char *did, const char *cid,
                                               const char *uri) {
    if (!life || !valid_key(did, cid) || !uri || !*uri)
        return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&life->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status st = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(life->db,
                           "DELETE FROM blob_refs"
                           " WHERE did=? AND cid=? AND uri=?;",
                           -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, uri, -1, SQLITE_TRANSIENT);
        st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&life->mutex);
    return st;
}

wf_status metalbear_blob_lifecycle_forget(metalbear_blob_lifecycle *life,
                                          const char *did, const char *cid) {
    if (!life || !valid_key(did, cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&life->mutex);
    const char *sql[] = {"DELETE FROM blob_refs WHERE did=? AND cid=?;",
                         "DELETE FROM blob_state WHERE did=? AND cid=?;"};
    wf_status st = WF_OK;
    for (size_t i = 0; i < 2 && st == WF_OK; i++) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(life->db, sql[i], -1, &stmt, NULL) !=
            SQLITE_OK) {
            st = WF_ERR_INTERNAL;
            break;
        }
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
        st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&life->mutex);
    return st;
}

wf_status metalbear_blob_lifecycle_seed_blob(metalbear_blob_lifecycle *life,
                                             const char *did, const char *cid,
                                             size_t size, int64_t now) {
    if (!life || !valid_key(did, cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&life->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status st = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            life->db,
            "INSERT OR IGNORE INTO blob_state"
            " (did,cid,state,created_at,size) VALUES (?,?,1,?,?);",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)size);
        st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&life->mutex);
    return st;
}

int metalbear_blob_lifecycle_is_durable(metalbear_blob_lifecycle *life,
                                        const char *did, const char *cid) {
    if (!life || !valid_key(did, cid)) return -1;
    pthread_mutex_lock(&life->mutex);
    sqlite3_stmt *stmt = NULL;
    int result = 0; /* untracked uploads stay hidden */
    if (sqlite3_prepare_v2(
            life->db, "SELECT state FROM blob_state WHERE did=? AND cid=?;", -1,
            &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            result = sqlite3_column_int(stmt, 0) == 1 ? 1 : 0;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&life->mutex);
    return result;
}

/* A reference recorded before revision tracking (or by an older binary)
 * cannot be proved stale. Keep it rather than risk deleting live content. */
static bool ref_revision_unknown(const char *rev) {
    return !rev || !*rev || strcmp(rev, "unknown") == 0;
}

/* Forward declarations: the loaders are defined after the stats/sweep entry
 * points because they share the row structs and free helpers above. */
static wf_status load_state_rows(metalbear_blob_lifecycle *life,
                                 blob_state_row **out_rows, size_t *out_count);
static wf_status load_ref_rows(metalbear_blob_lifecycle *life, const char *did,
                               const char *cid, blob_ref_row **out_rows,
                               size_t *out_count);

wf_status metalbear_blob_lifecycle_stats(
    metalbear_blob_lifecycle *life, int64_t now, int64_t temp_seconds,
    metalbear_blob_revision_exists_cb revision_exists, void *ctx,
    metalbear_blob_sweep_summary *out) {
    if (!life || !out) return WF_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (temp_seconds < 0) temp_seconds = 0;

    pthread_mutex_lock(&life->mutex);
    blob_state_row *rows = NULL;
    size_t count = 0;
    wf_status st = load_state_rows(life, &rows, &count);
    pthread_mutex_unlock(&life->mutex);
    if (st != WF_OK) return st;

    for (size_t i = 0; i < count && st == WF_OK; i++) {
        blob_state_row *row = &rows[i];
        if (row->state == 0) {
            out->temporary++;
            out->temporary_bytes += row->size;
            if (now - row->created_at >= temp_seconds) out->expiring++;
            continue;
        }

        pthread_mutex_lock(&life->mutex);
        blob_ref_row *refs = NULL;
        size_t ref_count = 0;
        st = load_ref_rows(life, row->did, row->cid, &refs, &ref_count);
        pthread_mutex_unlock(&life->mutex);
        if (st != WF_OK) break;

        size_t live = 0;
        for (size_t j = 0; j < ref_count; j++) {
            bool keep = true;
            if (revision_exists && !ref_revision_unknown(refs[j].rev)) {
                wf_status ex = revision_exists(row->did, refs[j].rev, ctx);
                if (ex == WF_ERR_NOT_FOUND) keep = false;
                /* WF_OK is live; any other answer is "unknown" and keeps the
                 * ref. Counters never mutate or log secrets from the callback.
                 */
            }
            if (keep) live++;
        }
        refs_free(refs, ref_count);
        if (live == 0) out->unreferenced_durable++;
    }

    rows_free(rows, count);
    return st;
}

static wf_status load_state_rows(metalbear_blob_lifecycle *life,
                                 blob_state_row **out_rows, size_t *out_count) {
    *out_rows = NULL;
    *out_count = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            life->db,
            "SELECT did,cid,state,created_at,size FROM blob_state"
            " ORDER BY did,cid;",
            -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    size_t cap = 0, count = 0;
    blob_state_row *rows = NULL;
    wf_status st = WF_OK;
    for (;;) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            st = WF_ERR_INTERNAL;
            break;
        }
        if (count == cap) {
            size_t new_cap = cap ? cap * 2 : 32;
            blob_state_row *grown = realloc(rows, new_cap * sizeof(*grown));
            if (!grown) {
                st = WF_ERR_ALLOC;
                break;
            }
            rows = grown;
            cap = new_cap;
        }
        blob_state_row *row = &rows[count];
        memset(row, 0, sizeof(*row));
        const unsigned char *did = sqlite3_column_text(stmt, 0);
        const unsigned char *cid = sqlite3_column_text(stmt, 1);
        row->did = did ? strdup((const char *)did) : NULL;
        row->cid = cid ? strdup((const char *)cid) : NULL;
        row->state = sqlite3_column_int(stmt, 2);
        row->created_at = sqlite3_column_int64(stmt, 3);
        row->size = (uint64_t)sqlite3_column_int64(stmt, 4);
        if (!row->did || !row->cid) {
            st = WF_ERR_ALLOC;
            break;
        }
        count++;
    }
    sqlite3_finalize(stmt);
    if (st != WF_OK) {
        rows_free(rows, count);
        return st;
    }
    *out_rows = rows;
    *out_count = count;
    return WF_OK;
}

static wf_status load_ref_rows(metalbear_blob_lifecycle *life, const char *did,
                               const char *cid, blob_ref_row **out_rows,
                               size_t *out_count) {
    *out_rows = NULL;
    *out_count = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(life->db,
                           "SELECT uri,rev FROM blob_refs"
                           " WHERE did=? AND cid=? ORDER BY uri,rev;",
                           -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
    size_t cap = 0, count = 0;
    blob_ref_row *rows = NULL;
    wf_status st = WF_OK;
    for (;;) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            st = WF_ERR_INTERNAL;
            break;
        }
        if (count == cap) {
            size_t new_cap = cap ? cap * 2 : 8;
            blob_ref_row *grown = realloc(rows, new_cap * sizeof(*grown));
            if (!grown) {
                st = WF_ERR_ALLOC;
                break;
            }
            rows = grown;
            cap = new_cap;
        }
        const unsigned char *uri = sqlite3_column_text(stmt, 0);
        const unsigned char *rev = sqlite3_column_text(stmt, 1);
        rows[count].uri = uri ? strdup((const char *)uri) : NULL;
        rows[count].rev = rev ? strdup((const char *)rev) : NULL;
        if (!rows[count].uri || !rows[count].rev) {
            st = WF_ERR_ALLOC;
            break;
        }
        count++;
    }
    sqlite3_finalize(stmt);
    if (st != WF_OK) {
        refs_free(rows, count);
        return st;
    }
    *out_rows = rows;
    *out_count = count;
    return WF_OK;
}

static wf_status delete_ref(metalbear_blob_lifecycle *life, const char *did,
                            const char *cid, const char *uri, const char *rev) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(life->db,
                           "DELETE FROM blob_refs"
                           " WHERE did=? AND cid=? AND uri=? AND rev=?;",
                           -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, uri, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rev, -1, SQLITE_TRANSIENT);
    wf_status st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    sqlite3_finalize(stmt);
    return st;
}

static wf_status delete_state(metalbear_blob_lifecycle *life, const char *did,
                              const char *cid) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(life->db,
                           "DELETE FROM blob_refs WHERE did=? AND cid=?;", -1,
                           &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
    wf_status st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    sqlite3_finalize(stmt);
    if (st != WF_OK) return st;
    stmt = NULL;
    if (sqlite3_prepare_v2(life->db,
                           "DELETE FROM blob_state WHERE did=? AND cid=?;", -1,
                           &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, cid, -1, SQLITE_TRANSIENT);
    st = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    sqlite3_finalize(stmt);
    return st;
}

wf_status metalbear_blob_lifecycle_sweep(
    metalbear_blob_lifecycle *life, int64_t now, int64_t temp_seconds,
    bool dry_run, metalbear_blob_revision_exists_cb revision_exists,
    metalbear_blob_delete_cb delete_blob, void *ctx,
    metalbear_blob_sweep_summary *out) {
    if (!life || !out) return WF_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (temp_seconds < 0) temp_seconds = 0;

    pthread_mutex_lock(&life->mutex);
    blob_state_row *rows = NULL;
    size_t count = 0;
    wf_status st = load_state_rows(life, &rows, &count);
    pthread_mutex_unlock(&life->mutex);
    if (st != WF_OK) return st;

    for (size_t i = 0; i < count; i++) {
        blob_state_row *row = &rows[i];
        bool expired_temp =
            row->state == 0 && (now - row->created_at) >= temp_seconds;
        bool unreferenced_durable = false;

        if (row->state == 0 && expired_temp) out->expiring++;
        out->temporary_bytes += row->state == 0 ? row->size : 0;
        if (row->state == 0) out->temporary++;

        if (row->state == 1) {
            pthread_mutex_lock(&life->mutex);
            blob_ref_row *refs = NULL;
            size_t ref_count = 0;
            wf_status ref_st =
                load_ref_rows(life, row->did, row->cid, &refs, &ref_count);
            pthread_mutex_unlock(&life->mutex);
            if (ref_st != WF_OK) {
                st = ref_st;
                break;
            }

            size_t live = 0;
            for (size_t j = 0; j < ref_count; j++) {
                bool keep = true;
                if (revision_exists && !ref_revision_unknown(refs[j].rev)) {
                    wf_status ex = revision_exists(row->did, refs[j].rev, ctx);
                    if (ex == WF_ERR_NOT_FOUND) {
                        keep = false;
                        if (!dry_run) {
                            pthread_mutex_lock(&life->mutex);
                            wf_status del =
                                delete_ref(life, row->did, row->cid,
                                           refs[j].uri, refs[j].rev);
                            pthread_mutex_unlock(&life->mutex);
                            if (del == WF_OK)
                                out->refs_pruned++;
                            else
                                keep = true; /* transient IO error: retry */
                        }
                    }
                    /* WF_OK is live; any other answer is "unknown" and keeps
                     * the reference. A dry run checks but never mutates. */
                }
                if (keep) live++;
            }
            refs_free(refs, ref_count);
            if (live == 0) {
                unreferenced_durable = true;
                if (dry_run) out->unreferenced_durable++;
            }
        }

        bool remove = expired_temp || unreferenced_durable;
        if (remove && !dry_run && delete_blob) {
            wf_status del = delete_blob(row->did, row->cid, ctx);
            if (del == WF_OK || del == WF_ERR_NOT_FOUND) {
                pthread_mutex_lock(&life->mutex);
                wf_status state_del = delete_state(life, row->did, row->cid);
                pthread_mutex_unlock(&life->mutex);
                if (state_del == WF_OK)
                    out->deleted++;
                else
                    st = state_del;
            }
        }
        if (st != WF_OK) break;
    }

    rows_free(rows, count);
    return st;
}

#define _POSIX_C_SOURCE 200809L

#include "metalbear/label/label_store.h"

#include "metalbear/schema_version.h"

#include <cJSON.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LABEL_DEFAULT_LIMIT 50
#define LABEL_MAX_LIMIT 250

struct metalbear_label_store {
    sqlite3 *db;
    pthread_mutex_t mutex;
};

wf_status metalbear_label_store_open(const char *path,
                                     metalbear_label_store **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_label_store *store = calloc(1, sizeof(*store));
    if (!store) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&store->mutex, NULL) != 0) {
        free(store);
        return WF_ERR_INTERNAL;
    }
    if (sqlite3_open_v2(path, &store->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK ||
        metalbear_schema_open(store->db, path) != WF_OK ||
        sqlite3_exec(
            store->db,
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE IF NOT EXISTS labels("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "src TEXT NOT NULL,"
            "uri TEXT NOT NULL,"
            "val TEXT NOT NULL,"
            "neg INTEGER NOT NULL DEFAULT 0,"
            "cts TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS idx_labels_uri ON labels(uri);"
            "CREATE INDEX IF NOT EXISTS idx_labels_src ON labels(src);",
            NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(store->db);
        pthread_mutex_destroy(&store->mutex);
        free(store);
        return WF_ERR_INTERNAL;
    }
    *out = store;
    return WF_OK;
}

void metalbear_label_store_free(metalbear_label_store *store) {
    if (!store) return;
    sqlite3_close(store->db);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

/* RFC 3339 with millisecond precision, the form the lexicon's datetime uses. */
static char *label_now(void) {
    time_t t = time(NULL);
    struct tm tm;
    if (!gmtime_r(&t, &tm)) return NULL;
    char *buf = malloc(32);
    if (!buf) return NULL;
    strftime(buf, 32, "%Y-%m-%dT%H:%M:%S.000Z", &tm);
    return buf;
}

wf_status metalbear_label_store_insert(metalbear_label_store *store,
                                       const char *src, const char *uri,
                                       const char *val, bool neg,
                                       const char *cts) {
    if (!store || !src || !*src || !uri || !*uri || !val || !*val)
        return WF_ERR_INVALID_ARG;
    char *now = NULL;
    if (!cts || !*cts) {
        now = label_now();
        if (!now) return WF_ERR_ALLOC;
        cts = now;
    }
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status st = WF_OK;
    if (sqlite3_prepare_v2(store->db,
                           "INSERT INTO labels(src, uri, val, neg, cts)"
                           " VALUES(?, ?, ?, ?, ?);",
                           -1, &stmt, NULL) != SQLITE_OK) {
        st = WF_ERR_INTERNAL;
    } else {
        sqlite3_bind_text(stmt, 1, src, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, uri, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, val, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, neg ? 1 : 0);
        sqlite3_bind_text(stmt, 5, cts, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) st = WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    free(now);
    return st;
}

/* A growable SQL buffer, so the query can grow with its pattern list. */
typedef struct sql_buf {
    char *data;
    size_t len;
    size_t cap;
    bool failed;
} sql_buf;

static void sql_append(sql_buf *b, const char *s) {
    if (b->failed) return;
    size_t n = strlen(s);
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (b->len + n + 1 > cap) cap *= 2;
        char *grown = realloc(b->data, cap);
        if (!grown) {
            b->failed = true;
            return;
        }
        b->data = grown;
        b->cap = cap;
    }
    memcpy(b->data + b->len, s, n + 1);
    b->len += n;
}

/* One value to bind, in the order its placeholder appears. */
typedef struct bind_item {
    const char *text;
    int64_t num;
    bool is_num;
    bool owned; /* text is a copy this query must free */
} bind_item;

wf_status metalbear_label_store_query(metalbear_label_store *store,
                                      const metalbear_label_query *query,
                                      char **out_json) {
    if (!store || !query || !out_json) return WF_ERR_INVALID_ARG;
    *out_json = NULL;
    int limit = query->limit;
    if (limit <= 0) limit = LABEL_DEFAULT_LIMIT;
    if (limit > LABEL_MAX_LIMIT) limit = LABEL_MAX_LIMIT;

    size_t bind_cap = 2 + query->uri_pattern_count + query->source_count + 1;
    bind_item *binds = calloc(bind_cap, sizeof(*binds));
    if (!binds) return WF_ERR_ALLOC;
    size_t nb = 0;

    sql_buf sql = {0};
    sql_append(&sql,
               "SELECT id, src, uri, val, neg, cts FROM labels WHERE id > ?");
    binds[nb++] = (bind_item){.num = query->after_id, .is_num = true};

    /* URI patterns: an exact URI, or a prefix ending in '*'. */
    if (query->uri_pattern_count == 0) {
        sql_append(&sql, " AND 0");
    } else {
        sql_append(&sql, " AND (");
        for (size_t i = 0; i < query->uri_pattern_count; i++) {
            const char *pattern = query->uri_patterns[i];
            size_t plen = strlen(pattern);
            if (i) sql_append(&sql, " OR ");
            if (plen > 0 && pattern[plen - 1] == '*') {
                /* instr = 1 is a prefix test that binds the text as-is, so no
                 * LIKE escaping is needed. */
                sql_append(&sql, "instr(uri, ?) = 1");
                char *prefix = strndup(pattern, plen - 1);
                if (!prefix) {
                    sql.failed = true;
                    break;
                }
                binds[nb++] = (bind_item){.text = prefix, .owned = true};
            } else {
                sql_append(&sql, "uri = ?");
                binds[nb++] = (bind_item){.text = pattern};
            }
        }
        sql_append(&sql, ")");
    }

    /* Sources: keep only the labels of the named labelers. Asked for but empty
     * matches nothing. */
    if (query->sources_present) {
        if (query->source_count == 0) {
            sql_append(&sql, " AND 0");
        } else {
            sql_append(&sql, " AND src IN (");
            for (size_t i = 0; i < query->source_count; i++) {
                if (i) sql_append(&sql, ",");
                sql_append(&sql, "?");
                binds[nb++] = (bind_item){.text = query->sources[i]};
            }
            sql_append(&sql, ")");
        }
    }
    sql_append(&sql, " ORDER BY id ASC LIMIT ?;");
    /* One extra row is fetched to learn whether another page follows. */
    binds[nb++] = (bind_item){.num = limit + 1, .is_num = true};

    /* Free the prefix copies whatever happens below. */
    wf_status st = WF_OK;
    if (sql.failed) {
        st = WF_ERR_ALLOC;
        goto cleanup;
    }

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db, sql.data, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&store->mutex);
        st = WF_ERR_INTERNAL;
        goto cleanup;
    }
    for (size_t i = 0; i < nb; i++) {
        int idx = (int)i + 1;
        if (binds[i].is_num)
            sqlite3_bind_int64(stmt, idx, binds[i].num);
        else
            sqlite3_bind_text(stmt, idx, binds[i].text, -1, SQLITE_TRANSIENT);
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *labels = cJSON_CreateArray();
    if (!root || !labels) {
        cJSON_Delete(root);
        cJSON_Delete(labels);
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&store->mutex);
        st = WF_ERR_ALLOC;
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "labels", labels);

    int count = 0;
    bool has_more = false;
    int64_t last_id = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= limit) {
            has_more = true;
            break;
        }
        last_id = sqlite3_column_int64(stmt, 0);
        cJSON *label = cJSON_CreateObject();
        cJSON_AddNumberToObject(label, "ver", 1);
        cJSON_AddStringToObject(label, "src",
                                (const char *)sqlite3_column_text(stmt, 1));
        cJSON_AddStringToObject(label, "uri",
                                (const char *)sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(label, "val",
                                (const char *)sqlite3_column_text(stmt, 3));
        if (sqlite3_column_int(stmt, 4)) cJSON_AddTrueToObject(label, "neg");
        cJSON_AddStringToObject(label, "cts",
                                (const char *)sqlite3_column_text(stmt, 5));
        cJSON_AddItemToArray(labels, label);
        count++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);

    /* The cursor is the last label returned. Pointing it at the extra row
     * would skip that row on the next page. */
    if (has_more) {
        char cursor[32];
        snprintf(cursor, sizeof(cursor), "%lld", (long long)last_id);
        cJSON_AddStringToObject(root, "cursor", cursor);
    }

    char *js = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!js) {
        st = WF_ERR_ALLOC;
        goto cleanup;
    }
    *out_json = js;

cleanup:
    for (size_t i = 0; i < nb; i++) {
        if (binds[i].owned) free((void *)binds[i].text);
    }
    free(binds);
    free(sql.data);
    return st;
}

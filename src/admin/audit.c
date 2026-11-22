#define _POSIX_C_SOURCE 200809L

#include "metalbear/admin/audit.h"
#include "metalbear/log.h"
#include "metalbear/schema_version.h"

#include <cJSON.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct metalbear_admin_audit {
    sqlite3 *db;
    pthread_mutex_t mutex;
};

wf_status metalbear_admin_audit_open(const char *path,
                                     metalbear_admin_audit **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_admin_audit *audit = calloc(1, sizeof(*audit));
    if (!audit) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&audit->mutex, NULL) != 0) {
        free(audit);
        return WF_ERR_INTERNAL;
    }
    if (sqlite3_open_v2(path, &audit->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK ||
        metalbear_schema_open(audit->db, path) != WF_OK ||
        sqlite3_exec(audit->db,
                     "PRAGMA journal_mode=WAL;"
                     "CREATE TABLE IF NOT EXISTS admin_audit("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                     "time TEXT NOT NULL,"
                     "admin TEXT NOT NULL,"
                     "action TEXT NOT NULL,"
                     "target_did TEXT,"
                     "outcome TEXT NOT NULL);"
                     "CREATE INDEX IF NOT EXISTS idx_admin_audit_id ON "
                     "admin_audit(id DESC);",
                     NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(audit->db);
        pthread_mutex_destroy(&audit->mutex);
        free(audit);
        return WF_ERR_INTERNAL;
    }
    *out = audit;
    return WF_OK;
}

void metalbear_admin_audit_free(metalbear_admin_audit *audit) {
    if (!audit) return;
    sqlite3_close(audit->db);
    pthread_mutex_destroy(&audit->mutex);
    free(audit);
}

static void audit_time(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm tm;
#if defined(_WIN32)
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    if (strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        snprintf(buf, size, "1970-01-01T00:00:00Z");
}

wf_status metalbear_admin_audit_append(metalbear_admin_audit *audit,
                                       const char *time, const char *admin,
                                       const char *action,
                                       const char *target_did,
                                       const char *outcome, int64_t *out_id) {
    if (!audit || !admin || !action || !outcome) return WF_ERR_INVALID_ARG;
    if (out_id) *out_id = 0;
    char generated[40];
    if (!time) {
        audit_time(generated, sizeof(generated));
        time = generated;
    }

    pthread_mutex_lock(&audit->mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO admin_audit(time,admin,action,target_did,outcome) "
        "VALUES(?,?,?,?,?)";
    wf_status st = WF_OK;
    if (sqlite3_prepare_v2(audit->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&audit->mutex);
        return WF_ERR_INTERNAL;
    }
    sqlite3_bind_text(stmt, 1, time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, admin, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, target_did && target_did[0] ? target_did : NULL,
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, outcome, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        st = WF_ERR_INTERNAL;
    } else if (out_id) {
        *out_id = (int64_t)sqlite3_last_insert_rowid(audit->db);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&audit->mutex);
    return st;
}

void metalbear_admin_audit_entries_free(metalbear_admin_audit_entry *entries,
                                        size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        free(entries[i].time);
        free(entries[i].admin);
        free(entries[i].action);
        free(entries[i].target_did);
        free(entries[i].outcome);
    }
    free(entries);
}

static char *column_copy(sqlite3_stmt *stmt, int column) {
    const unsigned char *text = sqlite3_column_text(stmt, column);
    return text ? strdup((const char *)text) : NULL;
}

wf_status metalbear_admin_audit_list(metalbear_admin_audit *audit,
                                     int64_t before_id, size_t limit,
                                     metalbear_admin_audit_entry **out,
                                     size_t *out_count) {
    if (!audit || !out || !out_count || limit == 0) return WF_ERR_INVALID_ARG;
    *out = NULL;
    *out_count = 0;

    pthread_mutex_lock(&audit->mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql = before_id > 0
                          ? "SELECT id,time,admin,action,target_did,outcome "
                            "FROM admin_audit WHERE id<? ORDER BY id DESC "
                            "LIMIT ?;"
                          : "SELECT id,time,admin,action,target_did,outcome "
                            "FROM admin_audit ORDER BY id DESC LIMIT ?;";
    if (sqlite3_prepare_v2(audit->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&audit->mutex);
        return WF_ERR_INTERNAL;
    }
    int index = 1;
    if (before_id > 0) sqlite3_bind_int64(stmt, index++, before_id);
    sqlite3_bind_int64(stmt, index, (sqlite3_int64)limit);

    metalbear_admin_audit_entry *rows = calloc(limit, sizeof(*rows));
    if (!rows) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&audit->mutex);
        return WF_ERR_ALLOC;
    }
    size_t count = 0;
    wf_status st = WF_OK;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < limit) {
        metalbear_admin_audit_entry *row = &rows[count];
        row->id = sqlite3_column_int64(stmt, 0);
        row->time = column_copy(stmt, 1);
        row->admin = column_copy(stmt, 2);
        row->action = column_copy(stmt, 3);
        row->target_did = column_copy(stmt, 4);
        row->outcome = column_copy(stmt, 5);
        if (!row->time || !row->admin || !row->action || !row->outcome) {
            st = WF_ERR_ALLOC;
            break;
        }
        count++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&audit->mutex);
    if (st != WF_OK) {
        metalbear_admin_audit_entries_free(rows, count);
        return st;
    }
    *out = rows;
    *out_count = count;
    return WF_OK;
}

size_t metalbear_admin_audit_count(metalbear_admin_audit *audit) {
    if (!audit) return 0;
    pthread_mutex_lock(&audit->mutex);
    sqlite3_stmt *stmt = NULL;
    size_t count = 0;
    if (sqlite3_prepare_v2(audit->db, "SELECT COUNT(*) FROM admin_audit;", -1,
                           &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            count = (size_t)sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&audit->mutex);
    return count;
}

bool metalbear_admin_audit_target_did(const wf_xrpc_request *req, char *out,
                                      size_t out_size) {
    if (!req || !req->params || !out || out_size == 0) return false;
    static const char *keys[] = {"did", "subject", "recipientDid", "repo"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const cJSON *item =
            cJSON_GetObjectItemCaseSensitive(req->params, keys[i]);
        if (!item) continue;
        const char *value = NULL;
        if (cJSON_IsString(item))
            value = item->valuestring;
        else if (cJSON_IsObject(item)) {
            const cJSON *did = cJSON_GetObjectItemCaseSensitive(item, "did");
            if (cJSON_IsString(did)) value = did->valuestring;
        }
        if (value && strncmp(value, "did:", 4) == 0) {
            snprintf(out, out_size, "%s", value);
            return true;
        }
    }
    const cJSON *dids = cJSON_GetObjectItemCaseSensitive(req->params, "dids");
    if (cJSON_IsArray(dids)) {
        const cJSON *first = cJSON_GetArrayItem(dids, 0);
        if (cJSON_IsString(first) &&
            strncmp(first->valuestring, "did:", 4) == 0) {
            snprintf(out, out_size, "%s", first->valuestring);
            return true;
        }
    }
    return false;
}

#define _POSIX_C_SOURCE 200809L

#include "metalbear/report.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct metalbear_report_store {
    sqlite3 *db;
    pthread_mutex_t mutex;
};

wf_status metalbear_report_store_open(const char *path,
                                      metalbear_report_store **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_report_store *store = calloc(1, sizeof(*store));
    if (!store) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&store->mutex, NULL) != 0) {
        free(store);
        return WF_ERR_INTERNAL;
    }
    if (sqlite3_open(path, &store->db) != SQLITE_OK ||
        sqlite3_exec(store->db,
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE IF NOT EXISTS reports("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "did TEXT NOT NULL,"
            "reason_type TEXT NOT NULL,"
            "reason TEXT,"
            "subject_type TEXT NOT NULL,"
            "subject_uri TEXT NOT NULL,"
            "subject_cid TEXT,"
            "mod_tool_name TEXT,"
            "mod_tool_meta TEXT,"
            "reported_by TEXT NOT NULL,"
            "created_at TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS idx_reports_did ON reports(did);"
            "CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);",
            NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(store->db);
        pthread_mutex_destroy(&store->mutex);
        free(store);
        return WF_ERR_INTERNAL;
    }
    *out = store;
    return WF_OK;
}

void metalbear_report_store_free(metalbear_report_store *store) {
    if (!store) return;
    sqlite3_close(store->db);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

wf_status metalbear_report_store_create(metalbear_report_store *store,
                                        const char *reporter_did,
                                        const char *reason_type,
                                        const char *reason,
                                        const char *subject_type,
                                        const char *subject_uri,
                                        const char *subject_cid,
                                        const char *mod_tool_name,
                                        const char *mod_tool_meta,
                                        int64_t *out_id) {
    if (!store || !reporter_did || !reason_type || !subject_type ||
        !subject_uri || !out_id)
        return WF_ERR_INVALID_ARG;
    *out_id = 0;

    char created_at[64];
    time_t now = time(NULL);
    if (strftime(created_at, sizeof(created_at), "%Y-%m-%dT%H:%M:%SZ",
                 gmtime(&now)) == 0)
        return WF_ERR_INTERNAL;

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO reports(did,reason_type,reason,subject_type,"
        "subject_uri,subject_cid,mod_tool_name,mod_tool_meta,reported_by,"
        "created_at) VALUES(?,?,?,?,?,?,?,?,?,?)";
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_INTERNAL;
    }
    sqlite3_bind_text(stmt, 1, reporter_did, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, reason_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, reason ? reason : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, subject_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, subject_uri, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, subject_cid ? subject_cid : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, mod_tool_name ? mod_tool_name : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, mod_tool_meta ? mod_tool_meta : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, reporter_did, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, created_at, -1, SQLITE_STATIC);

    wf_status st = WF_OK;
    if (sqlite3_step(stmt) != SQLITE_DONE)
        st = WF_ERR_INTERNAL;
    else
        *out_id = (int64_t)sqlite3_last_insert_rowid(store->db);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return st;
}

wf_status metalbear_report_store_get(metalbear_report_store *store,
                                     int64_t id, metalbear_report **out) {
    if (!store || !out || id <= 0) return WF_ERR_INVALID_ARG;
    *out = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT id,did,reason_type,reason,subject_type,subject_uri,"
        "subject_cid,mod_tool_name,mod_tool_meta,reported_by,created_at"
        " FROM reports WHERE id=?";
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return WF_ERR_NOT_FOUND;
    }
    metalbear_report *r = calloc(1, sizeof(*r));
    if (!r) {
        sqlite3_finalize(stmt);
        return WF_ERR_ALLOC;
    }
    r->id = sqlite3_column_int64(stmt, 0);
    r->did = strdup((const char *)sqlite3_column_text(stmt, 1));
    r->reason_type = strdup((const char *)sqlite3_column_text(stmt, 2));
    r->reason = strdup((const char *)sqlite3_column_text(stmt, 3));
    r->subject_type = strdup((const char *)sqlite3_column_text(stmt, 4));
    r->subject_uri = strdup((const char *)sqlite3_column_text(stmt, 5));
    r->subject_cid = strdup((const char *)sqlite3_column_text(stmt, 6));
    r->mod_tool_name = strdup((const char *)sqlite3_column_text(stmt, 7));
    r->mod_tool_meta = strdup((const char *)sqlite3_column_text(stmt, 8));
    r->reported_by = strdup((const char *)sqlite3_column_text(stmt, 9));
    r->created_at = strdup((const char *)sqlite3_column_text(stmt, 10));
    sqlite3_finalize(stmt);
    if (!r->did || !r->reason_type || !r->subject_type || !r->subject_uri ||
        !r->reported_by || !r->created_at) {
        metalbear_report_free(r);
        return WF_ERR_ALLOC;
    }
    *out = r;
    return WF_OK;
}

void metalbear_report_free(metalbear_report *report) {
    if (!report) return;
    free(report->did);
    free(report->reason_type);
    free(report->reason);
    free(report->subject_type);
    free(report->subject_uri);
    free(report->subject_cid);
    free(report->mod_tool_name);
    free(report->mod_tool_meta);
    free(report->reported_by);
    free(report->created_at);
    free(report);
}

void metalbear_report_list_free(metalbear_report *reports, size_t count) {
    if (!reports) return;
    for (size_t i = 0; i < count; i++)
        metalbear_report_free(&reports[i]);
    free(reports);
}

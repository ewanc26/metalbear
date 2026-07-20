#define _POSIX_C_SOURCE 200809L

#include "metalbear/account_registry.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct metalbear_account_registry {
    sqlite3 *db;
    pthread_mutex_t mutex;
};

static wf_status execute(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? WF_OK :
                                                                  WF_ERR_INTERNAL;
}

wf_status metalbear_account_registry_open(const char *path,
                                          metalbear_account_registry **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_account_registry *reg = calloc(1, sizeof(*reg));
    if (!reg) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&reg->mutex, NULL) != 0) {
        free(reg);
        return WF_ERR_INTERNAL;
    }
    if (sqlite3_open(path, &reg->db) != SQLITE_OK ||
        execute(reg->db,
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE IF NOT EXISTS accounts("
            "did TEXT PRIMARY KEY,"
            "handle TEXT UNIQUE NOT NULL,"
            "password_hash TEXT NOT NULL,"
            "data_directory TEXT NOT NULL,"
            "active INTEGER NOT NULL DEFAULT 1);") != WF_OK) {
        metalbear_account_registry_free(reg);
        return WF_ERR_INTERNAL;
    }
    *out = reg;
    return WF_OK;
}

void metalbear_account_registry_free(metalbear_account_registry *reg) {
    if (!reg) return;
    if (reg->db) sqlite3_close(reg->db);
    pthread_mutex_destroy(&reg->mutex);
    free(reg);
}

void metalbear_account_entry_free(metalbear_account_entry *entry) {
    if (!entry) return;
    free(entry->did);
    free(entry->handle);
    free(entry->password_hash);
    free(entry->data_directory);
    free(entry);
}

void metalbear_account_entries_free(metalbear_account_entry *entries,
                                    size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        free(entries[i].did);
        free(entries[i].handle);
        free(entries[i].password_hash);
        free(entries[i].data_directory);
    }
    free(entries);
}

static wf_status read_entry(sqlite3_stmt *stmt, metalbear_account_entry *out) {
    const char *did = (const char *)sqlite3_column_text(stmt, 0);
    const char *handle = (const char *)sqlite3_column_text(stmt, 1);
    const char *pw = (const char *)sqlite3_column_text(stmt, 2);
    const char *dir = (const char *)sqlite3_column_text(stmt, 3);
    if (!did || !handle || !pw || !dir) return WF_ERR_INTERNAL;
    out->did = strdup(did);
    out->handle = strdup(handle);
    out->password_hash = strdup(pw);
    out->data_directory = strdup(dir);
    out->active = sqlite3_column_int(stmt, 4);
    if (!out->did || !out->handle || !out->password_hash ||
        !out->data_directory) {
        free(out->did);
        free(out->handle);
        free(out->password_hash);
        free(out->data_directory);
        return WF_ERR_ALLOC;
    }
    return WF_OK;
}

wf_status metalbear_account_registry_add(
    metalbear_account_registry *registry,
    const char *did, const char *handle,
    const char *password_hash, const char *data_directory) {
    if (!registry || !did || !handle || !password_hash || !data_directory)
        return WF_ERR_INVALID_ARG;

    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(registry->db,
            "INSERT INTO accounts(did,handle,password_hash,data_directory) "
            "VALUES(?,?,?,?);", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, handle, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, password_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, data_directory, -1, SQLITE_TRANSIENT);
        int result = sqlite3_step(stmt);
        status = result == SQLITE_DONE ? WF_OK :
                 result == SQLITE_CONSTRAINT ? WF_ERR_CONFLICT :
                                               WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_find_by_handle(
    metalbear_account_registry *registry,
    const char *handle, metalbear_account_entry **out) {
    if (!registry || !handle || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(registry->db,
            "SELECT did,handle,password_hash,data_directory,active "
            "FROM accounts WHERE handle=?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, handle, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *out = calloc(1, sizeof(**out));
            if (*out) status = read_entry(stmt, *out);
            else status = WF_ERR_ALLOC;
        } else {
            status = WF_ERR_NOT_FOUND;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_find_by_did(
    metalbear_account_registry *registry,
    const char *did, metalbear_account_entry **out) {
    if (!registry || !did || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(registry->db,
            "SELECT did,handle,password_hash,data_directory,active "
            "FROM accounts WHERE did=?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *out = calloc(1, sizeof(**out));
            if (*out) status = read_entry(stmt, *out);
            else status = WF_ERR_ALLOC;
        } else {
            status = WF_ERR_NOT_FOUND;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_list(
    metalbear_account_registry *registry,
    metalbear_account_entry **out_entries, size_t *out_count) {
    if (!registry || !out_entries || !out_count) return WF_ERR_INVALID_ARG;
    *out_entries = NULL;
    *out_count = 0;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_OK;
    size_t capacity = 0;
    if (sqlite3_prepare_v2(registry->db,
            "SELECT did,handle,password_hash,data_directory,active "
            "FROM accounts ORDER BY handle;", -1, &stmt, NULL) != SQLITE_OK) {
        status = WF_ERR_INTERNAL;
    }
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized = realloc(*out_entries,
                                    next * sizeof(**out_entries));
            if (!resized) { status = WF_ERR_ALLOC; break; }
            *out_entries = resized;
            memset(*out_entries + capacity, 0,
                   (next - capacity) * sizeof(**out_entries));
            capacity = next;
        }
        metalbear_account_entry *item = &(*out_entries)[*out_count];
        status = read_entry(stmt, item);
        if (status == WF_OK) (*out_count)++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    if (status != WF_OK) {
        metalbear_account_entries_free(*out_entries, *out_count);
        *out_entries = NULL;
        *out_count = 0;
    }
    return status;
}

wf_status metalbear_account_registry_remove(
    metalbear_account_registry *registry,
    const char *did) {
    if (!registry || !did) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(registry->db,
            "DELETE FROM accounts WHERE did=?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        int result = sqlite3_step(stmt);
        status = result == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

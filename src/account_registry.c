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

/* Join root + encoded-did name into a heap buffer (caller frees). */
static char *account_dir_join(const char *root, const char *enc_did) {
    size_t rlen = strlen(root);
    size_t nlen = strlen(enc_did);
    int sep = (rlen > 0 && root[rlen - 1] == '/') ? 0 : 1;
    char *out = malloc(rlen + nlen + 1 + sep);
    if (!out) return NULL;
    memcpy(out, root, rlen);
    if (sep) out[rlen] = '/';
    memcpy(out + rlen + sep, enc_did, nlen);
    out[rlen + sep + nlen] = '\0';
    return out;
}

wf_status metalbear_account_dir_for_did(const char *root, const char *did,
                                        char **out) {
    if (!root || !did || !did[0] || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    /* Encode ':' as '_' for a filesystem-safe, deterministic directory name. */
    size_t need = 1;
    for (const char *p = did; *p; p++) need += (*p == ':') ? 1 : 1;
    char *enc = malloc(need);
    if (!enc) return WF_ERR_ALLOC;
    size_t j = 0;
    for (const char *p = did; *p; p++) enc[j++] = (*p == ':') ? '_' : *p;
    enc[j] = '\0';
    char *path = account_dir_join(root, enc);
    free(enc);
    if (!path) return WF_ERR_ALLOC;
    *out = path;
    return WF_OK;
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
            "active INTEGER NOT NULL DEFAULT 1);"
            "CREATE TABLE IF NOT EXISTS invite_code("
            "code TEXT PRIMARY KEY,"
            "for_account TEXT NOT NULL,"
            "uses_remaining INTEGER NOT NULL,"
            "disabled INTEGER NOT NULL DEFAULT 0,"
            "created_by TEXT,"
            "created_at TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS invite_code_use("
            "code TEXT NOT NULL,"
            "used_by TEXT NOT NULL,"
            "used_at TEXT NOT NULL);") != WF_OK) {
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

wf_status metalbear_account_registry_update_handle(
    metalbear_account_registry *registry,
    const char *did, const char *new_handle) {
    if (!registry || !did || !new_handle) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(registry->db,
            "UPDATE accounts SET handle=? WHERE did=?;", -1, &stmt,
            NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, new_handle, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, did, -1, SQLITE_TRANSIENT);
        int result = sqlite3_step(stmt);
        status = result == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_create_invite_codes(
    metalbear_account_registry *registry,
    const char *for_account,
    const char **codes, size_t code_count,
    int use_count) {
    if (!registry || !for_account || !codes || code_count == 0 ||
        use_count < 1)
        return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    wf_status status = WF_OK;
    for (size_t i = 0; i < code_count && status == WF_OK; i++) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(registry->db,
                "INSERT INTO invite_code(code,for_account,uses_remaining,"
                "created_at) VALUES(?,?,?,datetime('now'));",
                -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, codes[i], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, for_account, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 3, use_count);
            int r = sqlite3_step(stmt);
            status = (r == SQLITE_DONE) ? WF_OK : WF_ERR_INTERNAL;
        } else {
            status = WF_ERR_INTERNAL;
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_consume_invite_code(
    metalbear_account_registry *registry,
    const char *code, const char *used_by) {
    if (!registry || !code || !used_by) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    wf_status status = WF_ERR_NOT_FOUND;

    /* Check code exists, is not disabled, and has remaining uses. */
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(registry->db,
            "SELECT uses_remaining,disabled FROM invite_code "
            "WHERE code=?;", -1, &sel, NULL) == SQLITE_OK) {
        sqlite3_bind_text(sel, 1, code, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(sel) == SQLITE_ROW) {
            int remaining = sqlite3_column_int(sel, 0);
            int disabled  = sqlite3_column_int(sel, 1);
            if (disabled) {
                status = WF_ERR_CONFLICT;
            } else if (remaining > 0) {
                status = WF_OK;
            }
        }
    }
    sqlite3_finalize(sel);

    if (status != WF_OK) {
        pthread_mutex_unlock(&registry->mutex);
        return status;
    }

    /* Decrement uses_remaining. */
    sqlite3_stmt *upd = NULL;
    if (sqlite3_prepare_v2(registry->db,
            "UPDATE invite_code SET uses_remaining = uses_remaining - 1 "
            "WHERE code=? AND uses_remaining > 0;", -1, &upd, NULL) ==
            SQLITE_OK) {
        sqlite3_bind_text(upd, 1, code, -1, SQLITE_TRANSIENT);
        sqlite3_step(upd);
    }
    sqlite3_finalize(upd);

    /* Record usage. */
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(registry->db,
            "INSERT INTO invite_code_use(code,used_by,used_at) "
            "VALUES(?,?,datetime('now'));", -1, &ins, NULL) == SQLITE_OK) {
        sqlite3_bind_text(ins, 1, code, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 2, used_by, -1, SQLITE_TRANSIENT);
        sqlite3_step(ins);
    }
    sqlite3_finalize(ins);

    pthread_mutex_unlock(&registry->mutex);
    return WF_OK;
}

wf_status metalbear_account_registry_get_invite_codes(
    metalbear_account_registry *registry,
    const char *did,
    metalbear_invite_code_entry **out, size_t *out_count) {
    if (!registry || !did || !out || !out_count) return WF_ERR_INVALID_ARG;
    *out = NULL;
    *out_count = 0;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_OK;
    size_t capacity = 0;
    if (sqlite3_prepare_v2(registry->db,
            "SELECT code,for_account,uses_remaining,disabled,"
            "created_by,created_at FROM invite_code "
            "WHERE for_account=? OR created_by=? "
            "ORDER BY created_at DESC;",
            -1, &stmt, NULL) != SQLITE_OK) {
        status = WF_ERR_INTERNAL;
    } else {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, did, -1, SQLITE_TRANSIENT);
    }
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized = realloc(*out,
                                    next * sizeof(**out));
            if (!resized) { status = WF_ERR_ALLOC; break; }
            *out = resized;
            memset(*out + capacity, 0,
                   (next - capacity) * sizeof(**out));
            capacity = next;
        }
        metalbear_invite_code_entry *item = &(*out)[*out_count];
        const char *c0 = (const char *)sqlite3_column_text(stmt, 0);
        const char *c1 = (const char *)sqlite3_column_text(stmt, 1);
        const char *c4 = (const char *)sqlite3_column_text(stmt, 4);
        const char *c5 = (const char *)sqlite3_column_text(stmt, 5);
        item->code           = c0 ? strdup(c0) : NULL;
        item->for_account    = c1 ? strdup(c1) : NULL;
        item->uses_remaining = sqlite3_column_int(stmt, 2);
        item->disabled       = sqlite3_column_int(stmt, 3);
        item->created_by     = c4 ? strdup(c4) : NULL;
        item->created_at     = c5 ? strdup(c5) : NULL;
        if (!item->code || !item->for_account) {
            status = WF_ERR_ALLOC;
        } else {
            (*out_count)++;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    if (status != WF_OK) {
        metalbear_invite_code_entries_free(*out, *out_count);
        *out = NULL;
        *out_count = 0;
    }
    return status;
}

void metalbear_invite_code_entries_free(metalbear_invite_code_entry *entries,
                                       size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        free(entries[i].code);
        free(entries[i].for_account);
        free(entries[i].created_by);
        free(entries[i].created_at);
    }
    free(entries);
}

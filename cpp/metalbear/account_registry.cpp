#include "metalbear/account/account_registry.h"

#include <pthread.h>
#include <sqlite3.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

struct sqlite3_deleter {
    void operator()(sqlite3 *db) const noexcept {
        sqlite3_close(db);
    }
};

using sqlite3_ptr = std::unique_ptr<sqlite3, sqlite3_deleter>;

struct metalbear_account_registry {
    sqlite3_ptr db;
    pthread_mutex_t mutex;
};

extern "C" {

wf_status metalbear_account_dir_for_did(const char *root, const char *did,
                                        char **out) {
    if (!root || !did || !did[0] || !out) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    size_t need = 1;
    for (const char *p = did; *p; p++) need += (*p == ':') ? 1 : 1;
    char *enc = static_cast<char *>(std::malloc(need));
    if (!enc) return WF_ERR_ALLOC;
    size_t j = 0;
    for (const char *p = did; *p; p++) enc[j++] = (*p == ':') ? '_' : *p;
    enc[j] = '\0';
    size_t rlen = std::strlen(root);
    size_t nlen = std::strlen(enc);
    int sep = (rlen > 0 && root[rlen - 1] == '/') ? 0 : 1;
    char *path = static_cast<char *>(std::malloc(rlen + nlen + 1 + sep));
    if (!path) {
        std::free(enc);
        return WF_ERR_ALLOC;
    }
    std::memcpy(path, root, rlen);
    if (sep) path[rlen] = '/';
    std::memcpy(path + rlen + sep, enc, nlen);
    path[rlen + sep + nlen] = '\0';
    std::free(enc);
    *out = path;
    return WF_OK;
}

wf_status metalbear_account_registry_open(const char *path,
                                          metalbear_account_registry **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    auto *reg = static_cast<metalbear_account_registry *>(
        std::calloc(1, sizeof(metalbear_account_registry)));
    if (!reg) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&reg->mutex, nullptr) != 0) {
        std::free(reg);
        return WF_ERR_INTERNAL;
    }
    sqlite3 *raw_db = nullptr;
    if (sqlite3_open(path, &raw_db) != SQLITE_OK) {
        pthread_mutex_destroy(&reg->mutex);
        std::free(reg);
        return WF_ERR_INTERNAL;
    }
    reg->db.reset(raw_db);
    if (sqlite3_exec(reg->db.get(),
                     "PRAGMA journal_mode=WAL;"
                     "CREATE TABLE IF NOT EXISTS accounts("
                     "did TEXT PRIMARY KEY,"
                     "handle TEXT UNIQUE NOT NULL,"
                     "password_hash TEXT NOT NULL,"
                     "data_directory TEXT NOT NULL,"
                     "active INTEGER NOT NULL DEFAULT 1,"
                     "created_at TEXT NOT NULL DEFAULT '');"
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
                     "used_at TEXT NOT NULL);"
                     "CREATE TABLE IF NOT EXISTS subject_takedown("
                     "did TEXT,"
                     "uri TEXT,"
                     "blob_cid TEXT,"
                     "takedown_ref TEXT NOT NULL,"
                     "created_at TEXT NOT NULL);",
                     nullptr, nullptr, nullptr) != SQLITE_OK) {
        metalbear_account_registry_free(reg);
        return WF_ERR_INTERNAL;
    }
    /* Migrate registries that predate the created_at column. A fresh
     * database already carries it (the CREATE TABLE above), so "duplicate
     * column name" is the expected case; any other failure leaves the store
     * unable to read a column the new queries depend on, so fail the open
     * rather than limp on -- same pattern as account.cpp's invites_enabled
     * migration. Existing rows get stamped with the migration time itself:
     * their true creation time was never recorded, and that is an honest
     * lower bound rather than a fabricated one. */
    {
        char *err = nullptr;
        sqlite3_exec(reg->db.get(),
                     "ALTER TABLE accounts ADD COLUMN created_at TEXT NOT "
                     "NULL DEFAULT '';"
                     "UPDATE accounts SET "
                     "created_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE "
                     "created_at='';",
                     nullptr, nullptr, &err);
        if (err && !std::strstr(err, "duplicate column name")) {
            sqlite3_free(err);
            metalbear_account_registry_free(reg);
            return WF_ERR_INTERNAL;
        }
        if (err) sqlite3_free(err);
    }
    /* Migrate registries that predate the email column. Same duplicate-column
     * tolerance as the created_at migration above; a fresh database already
     * carries the column, and existing rows (which were created before email
     * was tracked) legitimately read back as NULL/empty. */
    {
        char *err = nullptr;
        sqlite3_exec(reg->db.get(),
                     "ALTER TABLE accounts ADD COLUMN email TEXT;",
                     nullptr, nullptr, &err);
        if (err && !std::strstr(err, "duplicate column name")) {
            sqlite3_free(err);
            metalbear_account_registry_free(reg);
            return WF_ERR_INTERNAL;
        }
        if (err) sqlite3_free(err);
    }
    /* Correct timestamps written with SQLite's own datetime('now') shape
     * ("2026-08-07 00:53:26": space-separated, no timezone) instead of the
     * RFC 3339 the datetime lexicon format requires
     * ("2026-08-07T00:53:26.000Z") -- every writer in this file used the
     * wrong one until now. Detected by "has a space, has no T": swap the
     * space for T and append the missing fractional-seconds+Z suffix,
     * across every column any writer here ever stamped that way. A row
     * already in the correct shape has no space to match, so this is a
     * no-op on a clean database. */
    sqlite3_exec(reg->db.get(),
                 "UPDATE accounts SET created_at="
                 "REPLACE(created_at,' ','T')||'.000Z' "
                 "WHERE created_at LIKE '% %' AND created_at NOT LIKE '%T%';"
                 "UPDATE invite_code SET created_at="
                 "REPLACE(created_at,' ','T')||'.000Z' "
                 "WHERE created_at LIKE '% %' AND created_at NOT LIKE '%T%';"
                 "UPDATE invite_code_use SET used_at="
                 "REPLACE(used_at,' ','T')||'.000Z' "
                 "WHERE used_at LIKE '% %' AND used_at NOT LIKE '%T%';"
                 "UPDATE subject_takedown SET created_at="
                 "REPLACE(created_at,' ','T')||'.000Z' "
                 "WHERE created_at LIKE '% %' AND created_at NOT LIKE '%T%';",
                 nullptr, nullptr, nullptr);
    *out = reg;
    return WF_OK;
}

void metalbear_account_registry_free(metalbear_account_registry *reg) {
    if (!reg) return;
    reg->db.reset();
    pthread_mutex_destroy(&reg->mutex);
    std::free(reg);
}

void metalbear_account_entry_free(metalbear_account_entry *entry) {
    if (!entry) return;
    std::free(entry->did);
    std::free(entry->handle);
    std::free(entry->password_hash);
    std::free(entry->data_directory);
    std::free(entry->email);
    std::free(entry->created_at);
    std::free(entry);
}

void metalbear_account_entries_free(metalbear_account_entry *entries,
                                    size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        std::free(entries[i].did);
        std::free(entries[i].handle);
        std::free(entries[i].password_hash);
        std::free(entries[i].data_directory);
        std::free(entries[i].email);
        std::free(entries[i].created_at);
    }
    std::free(entries);
}

static wf_status read_entry(sqlite3_stmt *stmt, metalbear_account_entry *out) {
    const char *did =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    const char *handle =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
    const char *pw =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
    const char *dir =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
    const char *email =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
    const char *created_at =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
    if (!did || !handle || !pw || !dir) return WF_ERR_INTERNAL;
    out->did = strdup(did);
    out->handle = strdup(handle);
    out->password_hash = strdup(pw);
    out->data_directory = strdup(dir);
    out->email = strdup(email ? email : "");
    out->created_at = strdup(created_at ? created_at : "");
    out->active = sqlite3_column_int(stmt, 4);
    if (!out->did || !out->handle || !out->password_hash ||
        !out->data_directory || !out->email || !out->created_at) {
        std::free(out->did);
        std::free(out->handle);
        std::free(out->password_hash);
        std::free(out->data_directory);
        std::free(out->email);
        std::free(out->created_at);
        return WF_ERR_ALLOC;
    }
    return WF_OK;
}

wf_status metalbear_account_registry_add(metalbear_account_registry *registry,
                                         const char *did, const char *handle,
                                         const char *password_hash,
                                         const char *data_directory) {
    return metalbear_account_registry_add_with_email(
        registry, did, handle, password_hash, data_directory, nullptr, 1);
}

wf_status metalbear_account_registry_add_with_email(
    metalbear_account_registry *registry, const char *did, const char *handle,
    const char *password_hash, const char *data_directory, const char *email,
    int active) {
    if (!registry || !did || !handle || !password_hash || !data_directory)
        return WF_ERR_INVALID_ARG;

    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "INSERT INTO accounts(did,handle,password_hash,data_directory,"
            "active,email,created_at) "
            "VALUES(?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, handle, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, password_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, data_directory, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, active ? 1 : 0);
        if (email && email[0])
            sqlite3_bind_text(stmt, 6, email, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(stmt, 6);
        int result = sqlite3_step(stmt);
        status = result == SQLITE_DONE         ? WF_OK
                 : result == SQLITE_CONSTRAINT ? WF_ERR_CONFLICT
                                               : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status
metalbear_account_registry_find_by_handle(metalbear_account_registry *registry,
                                          const char *handle,
                                          metalbear_account_entry **out) {
    if (!registry || !handle || !out) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "SELECT did,handle,password_hash,data_directory,active,email,"
            "created_at "
            "FROM accounts WHERE handle=?;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, handle, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *out = static_cast<metalbear_account_entry *>(
                std::calloc(1, sizeof(**out)));
            if (*out)
                status = read_entry(stmt, *out);
            else
                status = WF_ERR_ALLOC;
        } else {
            status = WF_ERR_NOT_FOUND;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status
metalbear_account_registry_find_by_did(metalbear_account_registry *registry,
                                       const char *did,
                                       metalbear_account_entry **out) {
    if (!registry || !did || !out) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "SELECT did,handle,password_hash,data_directory,active,email,"
            "created_at "
            "FROM accounts WHERE did=?;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *out = static_cast<metalbear_account_entry *>(
                std::calloc(1, sizeof(**out)));
            if (*out)
                status = read_entry(stmt, *out);
            else
                status = WF_ERR_ALLOC;
        } else {
            status = WF_ERR_NOT_FOUND;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status
metalbear_account_registry_find_by_email(metalbear_account_registry *registry,
                                         const char *email,
                                         metalbear_account_entry **out) {
    if (!registry || !email || !email[0] || !out) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "SELECT did,handle,password_hash,data_directory,active,email,"
            "created_at "
            "FROM accounts WHERE email=?;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *out = static_cast<metalbear_account_entry *>(
                std::calloc(1, sizeof(**out)));
            if (*out)
                status = read_entry(stmt, *out);
            else
                status = WF_ERR_ALLOC;
        } else {
            status = WF_ERR_NOT_FOUND;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_list(metalbear_account_registry *registry,
                                          metalbear_account_entry **out_entries,
                                          size_t *out_count) {
    if (!registry || !out_entries || !out_count) return WF_ERR_INVALID_ARG;
    *out_entries = nullptr;
    *out_count = 0;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_OK;
    size_t capacity = 0;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "SELECT did,handle,password_hash,data_directory,active,email,"
            "created_at "
            "FROM accounts ORDER BY handle;",
            -1, &stmt, nullptr) != SQLITE_OK) {
        status = WF_ERR_INTERNAL;
    }
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized =
                std::realloc(*out_entries, next * sizeof(**out_entries));
            if (!resized) {
                status = WF_ERR_ALLOC;
                break;
            }
            *out_entries = static_cast<metalbear_account_entry *>(resized);
            std::memset(*out_entries + capacity, 0,
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
        *out_entries = nullptr;
        *out_count = 0;
    }
    return status;
}

wf_status metalbear_account_registry_list_after(
    metalbear_account_registry *registry, const char *after, size_t limit,
    metalbear_account_entry **out_entries, size_t *out_count) {
    if (!registry || !out_entries || !out_count || limit == 0)
        return WF_ERR_INVALID_ARG;
    *out_entries = nullptr;
    *out_count = 0;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_OK;
    size_t capacity = 0;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "SELECT did,handle,password_hash,data_directory,active,email,"
            "created_at "
            "FROM accounts WHERE did > ? ORDER BY did LIMIT ?;",
            -1, &stmt, nullptr) != SQLITE_OK) {
        status = WF_ERR_INTERNAL;
    } else {
        sqlite3_bind_text(stmt, 1, after ? after : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(limit));
    }
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized =
                std::realloc(*out_entries, next * sizeof(**out_entries));
            if (!resized) {
                status = WF_ERR_ALLOC;
                break;
            }
            *out_entries = static_cast<metalbear_account_entry *>(resized);
            std::memset(*out_entries + capacity, 0,
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
        *out_entries = nullptr;
        *out_count = 0;
    }
    return status;
}

wf_status
metalbear_account_registry_remove(metalbear_account_registry *registry,
                                  const char *did) {
    if (!registry || !did) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "DELETE FROM accounts WHERE did=?;", -1, &stmt,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        int result = sqlite3_step(stmt);
        status = result == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status
metalbear_account_registry_update_handle(metalbear_account_registry *registry,
                                         const char *did,
                                         const char *new_handle) {
    if (!registry || !did || !new_handle) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "UPDATE accounts SET handle=? WHERE did=?;", -1,
                           &stmt, nullptr) == SQLITE_OK) {
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
    metalbear_account_registry *registry, const char *for_account,
    const char **codes, size_t code_count, int use_count) {
    if (!registry || !for_account || !codes || code_count == 0 || use_count < 1)
        return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    wf_status status = WF_OK;
    for (size_t i = 0; i < code_count && status == WF_OK; i++) {
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(
                registry->db.get(),
                "INSERT INTO invite_code(code,for_account,uses_remaining,"
                "created_at) "
                "VALUES(?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
                -1, &stmt, nullptr) == SQLITE_OK) {
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
    metalbear_account_registry *registry, const char *code,
    const char *used_by) {
    if (!registry || !code || !used_by) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    wf_status status = WF_ERR_NOT_FOUND;

    sqlite3_stmt *sel = nullptr;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "SELECT uses_remaining,disabled FROM invite_code "
                           "WHERE code=?;",
                           -1, &sel, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(sel, 1, code, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(sel) == SQLITE_ROW) {
            int remaining = sqlite3_column_int(sel, 0);
            int disabled = sqlite3_column_int(sel, 1);
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

    sqlite3_stmt *upd = nullptr;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "UPDATE invite_code SET uses_remaining = uses_remaining - 1 "
            "WHERE code=? AND uses_remaining > 0;",
            -1, &upd, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(upd, 1, code, -1, SQLITE_TRANSIENT);
        sqlite3_step(upd);
    }
    sqlite3_finalize(upd);

    sqlite3_stmt *ins = nullptr;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "INSERT INTO invite_code_use(code,used_by,used_at) "
                           "VALUES(?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
                           -1, &ins, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(ins, 1, code, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 2, used_by, -1, SQLITE_TRANSIENT);
        sqlite3_step(ins);
    }
    sqlite3_finalize(ins);

    pthread_mutex_unlock(&registry->mutex);
    return WF_OK;
}

wf_status metalbear_account_registry_get_invite_codes(
    metalbear_account_registry *registry, const char *did,
    metalbear_invite_code_entry **out, size_t *out_count) {
    if (!registry || !did || !out || !out_count) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    *out_count = 0;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_OK;
    size_t capacity = 0;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "SELECT code,for_account,uses_remaining,disabled,"
                           "created_by,created_at FROM invite_code "
                           "WHERE for_account=? OR created_by=? "
                           "ORDER BY created_at DESC;",
                           -1, &stmt, nullptr) != SQLITE_OK) {
        status = WF_ERR_INTERNAL;
    } else {
        sqlite3_bind_text(stmt, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, did, -1, SQLITE_TRANSIENT);
    }
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized = std::realloc(*out, next * sizeof(**out));
            if (!resized) {
                status = WF_ERR_ALLOC;
                break;
            }
            *out = static_cast<metalbear_invite_code_entry *>(resized);
            std::memset(*out + capacity, 0, (next - capacity) * sizeof(**out));
            capacity = next;
        }
        metalbear_invite_code_entry *item = &(*out)[*out_count];
        const char *c0 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        const char *c1 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        const char *c4 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        const char *c5 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
        item->code = c0 ? strdup(c0) : nullptr;
        item->for_account = c1 ? strdup(c1) : nullptr;
        item->uses_remaining = sqlite3_column_int(stmt, 2);
        item->disabled = sqlite3_column_int(stmt, 3);
        item->created_by = c4 ? strdup(c4) : nullptr;
        item->created_at = c5 ? strdup(c5) : nullptr;
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
        *out = nullptr;
        *out_count = 0;
    }
    return status;
}

void metalbear_invite_code_entries_free(metalbear_invite_code_entry *entries,
                                        size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        std::free(entries[i].code);
        std::free(entries[i].for_account);
        std::free(entries[i].created_by);
        std::free(entries[i].created_at);
    }
    std::free(entries);
}

wf_status metalbear_account_registry_list_invite_codes(
    metalbear_account_registry *registry, const char *after_created_at,
    const char *after_code, size_t limit, metalbear_invite_code_entry **out,
    size_t *out_count) {
    if (!registry || !out || !out_count || limit == 0)
        return WF_ERR_INVALID_ARG;
    *out = nullptr;
    *out_count = 0;
    bool has_cursor =
        after_created_at && after_created_at[0] && after_code && after_code[0];
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_OK;
    size_t capacity = 0;
    const char *sql =
        has_cursor
            ? "SELECT code,for_account,uses_remaining,disabled,created_by,"
              "created_at FROM invite_code WHERE created_at<? OR "
              "(created_at=? AND code<?) ORDER BY created_at DESC,code DESC "
              "LIMIT ?;"
            : "SELECT code,for_account,uses_remaining,disabled,created_by,"
              "created_at FROM invite_code ORDER BY created_at DESC,code "
              "DESC LIMIT ?;";
    if (sqlite3_prepare_v2(registry->db.get(), sql, -1, &stmt, nullptr) !=
        SQLITE_OK) {
        status = WF_ERR_INTERNAL;
    } else if (has_cursor) {
        sqlite3_bind_text(stmt, 1, after_created_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, after_created_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, after_code, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(limit));
    } else {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(limit));
    }
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized = std::realloc(*out, next * sizeof(**out));
            if (!resized) {
                status = WF_ERR_ALLOC;
                break;
            }
            *out = static_cast<metalbear_invite_code_entry *>(resized);
            std::memset(*out + capacity, 0, (next - capacity) * sizeof(**out));
            capacity = next;
        }
        metalbear_invite_code_entry *item = &(*out)[*out_count];
        const char *c0 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        const char *c1 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        const char *c4 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        const char *c5 =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
        item->code = c0 ? strdup(c0) : nullptr;
        item->for_account = c1 ? strdup(c1) : nullptr;
        item->uses_remaining = sqlite3_column_int(stmt, 2);
        item->disabled = sqlite3_column_int(stmt, 3);
        item->created_by = c4 ? strdup(c4) : nullptr;
        item->created_at = c5 ? strdup(c5) : nullptr;
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
        *out = nullptr;
        *out_count = 0;
    }
    return status;
}

wf_status metalbear_account_registry_get_invite_code_for_account(
    metalbear_account_registry *registry, const char *did, const char *handle,
    metalbear_invite_code_entry **out) {
    if (!registry || (!did && !handle) || !out) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_NOT_FOUND;
    if (sqlite3_prepare_v2(
            registry->db.get(),
            "SELECT ic.code,ic.for_account,ic.uses_remaining,ic.disabled,"
            "ic.created_by,ic.created_at FROM invite_code_use icu "
            "JOIN invite_code ic ON ic.code=icu.code "
            "WHERE icu.used_by=? OR icu.used_by=? "
            "ORDER BY icu.used_at ASC LIMIT 1;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, did ? did : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, handle ? handle : "", -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            auto *entry = static_cast<metalbear_invite_code_entry *>(
                std::calloc(1, sizeof(metalbear_invite_code_entry)));
            if (!entry) {
                status = WF_ERR_ALLOC;
            } else {
                const char *c0 = reinterpret_cast<const char *>(
                    sqlite3_column_text(stmt, 0));
                const char *c1 = reinterpret_cast<const char *>(
                    sqlite3_column_text(stmt, 1));
                const char *c4 = reinterpret_cast<const char *>(
                    sqlite3_column_text(stmt, 4));
                const char *c5 = reinterpret_cast<const char *>(
                    sqlite3_column_text(stmt, 5));
                entry->code = c0 ? strdup(c0) : nullptr;
                entry->for_account = c1 ? strdup(c1) : nullptr;
                entry->uses_remaining = sqlite3_column_int(stmt, 2);
                entry->disabled = sqlite3_column_int(stmt, 3);
                entry->created_by = c4 ? strdup(c4) : nullptr;
                entry->created_at = c5 ? strdup(c5) : nullptr;
                if (!entry->code || !entry->for_account) {
                    metalbear_invite_code_entries_free(entry, 1);
                    status = WF_ERR_ALLOC;
                } else {
                    *out = entry;
                    status = WF_OK;
                }
            }
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_get_invite_code_uses(
    metalbear_account_registry *registry, const char *code,
    metalbear_invite_code_use_entry **out, size_t *out_count) {
    if (!registry || !code || !out || !out_count) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    *out_count = 0;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_OK;
    size_t capacity = 0;
    /* used_at has millisecond precision but two redemptions can still land
     * in the same millisecond; rowid as a secondary key keeps insertion
     * order deterministic instead of leaving ties to SQLite's whim. */
    if (sqlite3_prepare_v2(registry->db.get(),
                           "SELECT used_by,used_at FROM invite_code_use "
                           "WHERE code=? ORDER BY used_at ASC, rowid ASC;",
                           -1, &stmt, nullptr) != SQLITE_OK) {
        status = WF_ERR_INTERNAL;
    } else {
        sqlite3_bind_text(stmt, 1, code, -1, SQLITE_TRANSIENT);
    }
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized = std::realloc(*out, next * sizeof(**out));
            if (!resized) {
                status = WF_ERR_ALLOC;
                break;
            }
            *out = static_cast<metalbear_invite_code_use_entry *>(resized);
            std::memset(*out + capacity, 0, (next - capacity) * sizeof(**out));
            capacity = next;
        }
        metalbear_invite_code_use_entry *item = &(*out)[*out_count];
        const char *used_by =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        const char *used_at =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        item->used_by = used_by ? strdup(used_by) : nullptr;
        item->used_at = used_at ? strdup(used_at) : nullptr;
        if (!item->used_by || !item->used_at) {
            status = WF_ERR_ALLOC;
        } else {
            (*out_count)++;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&registry->mutex);
    if (status != WF_OK) {
        metalbear_invite_code_use_entries_free(*out, *out_count);
        *out = nullptr;
        *out_count = 0;
    }
    return status;
}

void metalbear_invite_code_use_entries_free(
    metalbear_invite_code_use_entry *entries, size_t count) {
    if (!entries) return;
    for (size_t i = 0; i < count; i++) {
        std::free(entries[i].used_by);
        std::free(entries[i].used_at);
    }
    std::free(entries);
}

wf_status metalbear_account_registry_disable_invite_codes(
    metalbear_account_registry *registry, const char **codes, size_t code_count,
    const char **accounts, size_t account_count) {
    if (!registry) return WF_ERR_INVALID_ARG;
    if ((!codes || code_count == 0) && (!accounts || account_count == 0))
        return WF_ERR_INVALID_ARG;

    pthread_mutex_lock(&registry->mutex);
    int touched = 0;

    if (codes && code_count > 0) {
        for (size_t i = 0; i < code_count; i++) {
            if (!codes[i] || !codes[i][0]) continue;
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(
                    registry->db.get(),
                    "UPDATE invite_code SET disabled=1 WHERE code=?;", -1,
                    &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, codes[i], -1, SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                if (rc == SQLITE_DONE)
                    touched += sqlite3_changes(registry->db.get());
            }
            sqlite3_finalize(stmt);
        }
    }

    if (accounts && account_count > 0) {
        for (size_t i = 0; i < account_count; i++) {
            if (!accounts[i] || !accounts[i][0]) continue;
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(
                    registry->db.get(),
                    "UPDATE invite_code SET disabled=1 WHERE for_account=?;",
                    -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, accounts[i], -1, SQLITE_TRANSIENT);
                int rc = sqlite3_step(stmt);
                if (rc == SQLITE_DONE)
                    touched += sqlite3_changes(registry->db.get());
            }
            sqlite3_finalize(stmt);
        }
    }

    pthread_mutex_unlock(&registry->mutex);
    return touched > 0 ? WF_OK : WF_ERR_NOT_FOUND;
}

static bool takedown_subject_valid(const char *did, const char *uri,
                                   const char *blob_cid) {
    bool has_did = did && did[0];
    bool has_uri = uri && uri[0];
    bool has_cid = blob_cid && blob_cid[0];
    if (has_uri) return !has_did && !has_cid;
    if (has_cid) return has_did;
    return has_did;
}

static void bind_text_or_null(sqlite3_stmt *stmt, int index,
                              const char *value) {
    if (value && value[0])
        sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, index);
}

wf_status
metalbear_account_registry_set_takedown(metalbear_account_registry *registry,
                                        const char *did, const char *uri,
                                        const char *blob_cid, const char *ref) {
    if (!registry) return WF_ERR_INVALID_ARG;
    if (!takedown_subject_valid(did, uri, blob_cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *del = nullptr;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "DELETE FROM subject_takedown WHERE "
                           "did IS ? AND uri IS ? AND blob_cid IS ?;",
                           -1, &del, nullptr) == SQLITE_OK) {
        bind_text_or_null(del, 1, did);
        bind_text_or_null(del, 2, uri);
        bind_text_or_null(del, 3, blob_cid);
        sqlite3_step(del);
    }
    sqlite3_finalize(del);
    if (ref && ref[0]) {
        sqlite3_stmt *ins = nullptr;
        if (sqlite3_prepare_v2(
                registry->db.get(),
                "INSERT INTO subject_takedown(did,uri,blob_cid,"
                "takedown_ref,created_at) "
                "VALUES(?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
                -1, &ins, nullptr) == SQLITE_OK) {
            bind_text_or_null(ins, 1, did);
            bind_text_or_null(ins, 2, uri);
            bind_text_or_null(ins, 3, blob_cid);
            sqlite3_bind_text(ins, 4, ref, -1, SQLITE_TRANSIENT);
            sqlite3_step(ins);
        }
        sqlite3_finalize(ins);
    }
    pthread_mutex_unlock(&registry->mutex);
    return WF_OK;
}

wf_status
metalbear_account_registry_get_takedown(metalbear_account_registry *registry,
                                        const char *did, const char *uri,
                                        const char *blob_cid, char **out_ref) {
    if (!registry || !out_ref) return WF_ERR_INVALID_ARG;
    *out_ref = nullptr;
    if (!takedown_subject_valid(did, uri, blob_cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *sel = nullptr;
    wf_status status = WF_OK;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "SELECT takedown_ref FROM subject_takedown WHERE "
                           "did IS ? AND uri IS ? AND blob_cid IS ? LIMIT 1;",
                           -1, &sel, nullptr) == SQLITE_OK) {
        bind_text_or_null(sel, 1, did);
        bind_text_or_null(sel, 2, uri);
        bind_text_or_null(sel, 3, blob_cid);
        if (sqlite3_step(sel) == SQLITE_ROW) {
            const char *ref =
                reinterpret_cast<const char *>(sqlite3_column_text(sel, 0));
            *out_ref = ref ? strdup(ref) : nullptr;
        }
    } else {
        status = WF_ERR_INTERNAL;
    }
    sqlite3_finalize(sel);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

wf_status metalbear_account_registry_clear_takedowns_for_did(
    metalbear_account_registry *registry, const char *did) {
    if (!registry || !did || !did[0]) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&registry->mutex);
    sqlite3_stmt *del = nullptr;
    wf_status status = WF_OK;
    if (sqlite3_prepare_v2(registry->db.get(),
                           "DELETE FROM subject_takedown WHERE did IS ? "
                           "OR substr(uri, 1, ?) = ?;",
                           -1, &del, nullptr) == SQLITE_OK) {
        char prefix[512];
        int len = std::snprintf(prefix, sizeof(prefix), "at://%s/", did);
        sqlite3_bind_text(del, 1, did, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(del, 2, len);
        sqlite3_bind_text(del, 3, prefix, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(del) != SQLITE_DONE) status = WF_ERR_INTERNAL;
    } else {
        status = WF_ERR_INTERNAL;
    }
    sqlite3_finalize(del);
    pthread_mutex_unlock(&registry->mutex);
    return status;
}

} // extern "C"
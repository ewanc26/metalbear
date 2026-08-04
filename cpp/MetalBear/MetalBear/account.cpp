#include "metalbear/account.h"

#define _POSIX_C_SOURCE 200809L

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <memory>

#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

struct sqlite3_deleter {
    void operator()(sqlite3 *db) const noexcept { sqlite3_close(db); }
};

using sqlite3_ptr = std::unique_ptr<sqlite3, sqlite3_deleter>;

struct metalbear_account_store {
    sqlite3_ptr db;
    pthread_mutex_t mutex;
};

static wf_status derive_password(const char *password,
                                    const unsigned char salt[16],
                                    unsigned char hash[32]) {
    if (!password || EVP_PBE_scrypt(password, std::strlen(password), salt, 16,
                                        16384, 8, 1, 32 * 1024 * 1024,
                                        hash, 32) != 1)
        return WF_ERR_INTERNAL;
    return WF_OK;
}

static wf_status current_datetime(char output[32]) {
    std::time_t now = std::time(nullptr);
    std::tm utc;
    if (now == static_cast<std::time_t>(-1) || !gmtime_r(&now, &utc) ||
        std::strftime(output, 32, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0)
        return WF_ERR_INTERNAL;
    return WF_OK;
}

extern "C" {

wf_status metalbear_account_store_open(const char *path,
                                           const char *bootstrap_password,
                                           metalbear_account_store **out) {
    if (!path || !bootstrap_password || !out)
        return WF_ERR_INVALID_ARG;
    *out = nullptr;
    auto *store = static_cast<metalbear_account_store *>(std::calloc(1, sizeof(metalbear_account_store)));
    if (!store) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&store->mutex, nullptr) != 0) {
        std::free(store);
        return WF_ERR_INTERNAL;
    }
    sqlite3 *raw_db = nullptr;
    if (sqlite3_open(path, &raw_db) != SQLITE_OK) {
        pthread_mutex_destroy(&store->mutex);
        std::free(store);
        return WF_ERR_INTERNAL;
    }
    store->db.reset(raw_db);
    const char *sql =
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS account_state("
        "id INTEGER PRIMARY KEY CHECK(id=0),"
        "active INTEGER NOT NULL CHECK(active IN(0,1)),"
        "email TEXT,email_confirmed INTEGER NOT NULL DEFAULT 0,"
        "deactivated_at TEXT,delete_after TEXT,"
        "invites_enabled INTEGER NOT NULL DEFAULT 1);"
        "INSERT OR IGNORE INTO account_state(id,active) VALUES(0,1);"
        "CREATE TABLE IF NOT EXISTS credentials("
        "id INTEGER PRIMARY KEY CHECK(id=0),salt BLOB NOT NULL,"
        "password_hash BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS app_password("
        "name TEXT PRIMARY KEY,salt BLOB NOT NULL,password_hash BLOB NOT NULL,"
        "created_at TEXT NOT NULL,privileged INTEGER NOT NULL DEFAULT 0 "
        "CHECK(privileged IN(0,1)));"
        "CREATE TABLE IF NOT EXISTS email_token("
        "token TEXT PRIMARY KEY,kind TEXT NOT NULL,"
        "created_at TEXT NOT NULL,expires_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS preferences("
        "id INTEGER PRIMARY KEY CHECK(id=0),"
        "data TEXT NOT NULL);";
    if (sqlite3_exec(store->db.get(), sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
        metalbear_account_store_free(store);
        return WF_ERR_INTERNAL;
    }
    /* Migrate existing databases that predate the invites_enabled column. A
     * fresh database already carries the column, so "duplicate column name" is
     * the expected case; any other failure leaves the store unable to read the
     * flag the new queries depend on, so fail the open rather than limp on. */
    char *err = nullptr;
    sqlite3_exec(store->db.get(),
        "ALTER TABLE account_state ADD COLUMN invites_enabled INTEGER NOT NULL DEFAULT 1;",
        nullptr, nullptr, &err);
    if (err && !std::strstr(err, "duplicate column name")) {
        sqlite3_free(err);
        metalbear_account_store_free(store);
        return WF_ERR_INTERNAL;
    }
    if (err) sqlite3_free(err);
    sqlite3_stmt *stmt = nullptr;
    int has_credentials = 0;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT 1 FROM credentials WHERE id=0;", -1, &stmt, nullptr) ==
            SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
        has_credentials = 1;
    sqlite3_finalize(stmt);
    if (!has_credentials) {
        if (!bootstrap_password[0]) {
            metalbear_account_store_free(store);
            return WF_ERR_INVALID_ARG;
        }
        unsigned char salt[16], hash[32];
        if (RAND_bytes(salt, sizeof(salt)) != 1 ||
            derive_password(bootstrap_password, salt, hash) != WF_OK) {
            metalbear_account_store_free(store);
            return WF_ERR_INTERNAL;
        }
        if (sqlite3_prepare_v2(store->db.get(),
                "INSERT INTO credentials(id,salt,password_hash) VALUES(0,?,?);",
                -1, &stmt, nullptr) != SQLITE_OK) {
            metalbear_account_store_free(store);
            return WF_ERR_INTERNAL;
        }
        sqlite3_bind_blob(stmt, 1, salt, sizeof(salt), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, hash, sizeof(hash), SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            metalbear_account_store_free(store);
            return WF_ERR_INTERNAL;
        }
        sqlite3_finalize(stmt);
        OPENSSL_cleanse(hash, sizeof(hash));
    }
    *out = store;
    return WF_OK;
}

int metalbear_account_verify_password(metalbear_account_store *store,
                                           const char *password) {
    if (!store || !password) return 0;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    int valid = 0;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT salt,password_hash FROM credentials WHERE id=0;",
            -1, &stmt, nullptr) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *salt = static_cast<const unsigned char *>(sqlite3_column_blob(stmt, 0));
        const unsigned char *expected = static_cast<const unsigned char *>(sqlite3_column_blob(stmt, 1));
        int salt_len = sqlite3_column_bytes(stmt, 0);
        int hash_len = sqlite3_column_bytes(stmt, 1);
        unsigned char actual[32];
        if (salt && expected && salt_len == 16 && hash_len == 32 &&
            derive_password(password, salt, actual) == WF_OK)
            valid = CRYPTO_memcmp(actual, expected, sizeof(actual)) == 0;
        OPENSSL_cleanse(actual, sizeof(actual));
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return valid;
}

metalbear_credential_kind metalbear_account_verify_credential(
    metalbear_account_store *store, const char *password,
    char **out_app_password_name) {
    if (out_app_password_name) *out_app_password_name = nullptr;
    if (!store || !password) return METALBEAR_CREDENTIAL_INVALID;
    if (metalbear_account_verify_password(store, password))
        return METALBEAR_CREDENTIAL_ACCOUNT;

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    metalbear_credential_kind kind = METALBEAR_CREDENTIAL_INVALID;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT name,salt,password_hash,privileged FROM app_password;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            const unsigned char *salt = static_cast<const unsigned char *>(sqlite3_column_blob(stmt, 1));
            const unsigned char *expected = static_cast<const unsigned char *>(sqlite3_column_blob(stmt, 2));
            unsigned char actual[32] = {0};
            bool match = name && salt && expected &&
                sqlite3_column_bytes(stmt, 1) == 16 &&
                sqlite3_column_bytes(stmt, 2) == 32 &&
                derive_password(password, salt, actual) == WF_OK &&
                CRYPTO_memcmp(actual, expected, sizeof(actual)) == 0;
            OPENSSL_cleanse(actual, sizeof(actual));
            if (!match) continue;
            if (out_app_password_name) {
                *out_app_password_name = strdup(name);
                if (!*out_app_password_name) break;
            }
            kind = sqlite3_column_int(stmt, 3)
                ? METALBEAR_CREDENTIAL_APP_PASSWORD_PRIVILEGED
                : METALBEAR_CREDENTIAL_APP_PASSWORD;
            break;
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return kind;
}

wf_status metalbear_account_create_app_password(
    metalbear_account_store *store, const char *name, bool privileged,
    char **out_password, char **out_created_at) {
    if (!store || !name || !name[0] || std::strlen(name) > 256 || !out_password ||
        !out_created_at)
        return WF_ERR_INVALID_ARG;
    *out_password = nullptr;
    *out_created_at = nullptr;
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
    unsigned char random[16], salt[16], hash[32];
    char compact[17], formatted[20], created_at[32];
    if (RAND_bytes(random, sizeof(random)) != 1 ||
        RAND_bytes(salt, sizeof(salt)) != 1 ||
        current_datetime(created_at) != WF_OK)
        return WF_ERR_CRYPTO;
    for (size_t i = 0; i < sizeof(random); i++)
        compact[i] = alphabet[random[i] & 31];
    compact[16] = '\0';
    std::snprintf(formatted, sizeof(formatted), "%.4s-%.4s-%.4s-%.4s", compact,
                 compact + 4, compact + 8, compact + 12);
    if (derive_password(formatted, salt, hash) != WF_OK)
        return WF_ERR_INTERNAL;
    char *password_copy = strdup(formatted);
    char *created_copy = strdup(created_at);
    if (!password_copy || !created_copy) {
        std::free(password_copy);
        std::free(created_copy);
        OPENSSL_cleanse(hash, sizeof(hash));
        return WF_ERR_ALLOC;
    }

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "INSERT INTO app_password(name,salt,password_hash,created_at,"
            "privileged) VALUES(?,?,?,?,?);", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, salt, sizeof(salt), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 3, hash, sizeof(hash), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, created_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, privileged ? 1 : 0);
        int result = sqlite3_step(stmt);
        status = result == SQLITE_DONE ? WF_OK :
                 result == SQLITE_CONSTRAINT ? WF_ERR_CONFLICT :
                                               WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    OPENSSL_cleanse(hash, sizeof(hash));
    pthread_mutex_unlock(&store->mutex);
    if (status != WF_OK) {
        std::free(password_copy);
        std::free(created_copy);
        return status;
    }
    *out_password = password_copy;
    *out_created_at = created_copy;
    return WF_OK;
}

wf_status metalbear_account_list_app_passwords(
    metalbear_account_store *store, metalbear_app_password **out_passwords,
    size_t *out_count) {
    if (!store || !out_passwords || !out_count) return WF_ERR_INVALID_ARG;
    *out_passwords = nullptr;
    *out_count = 0;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_OK;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT name,created_at,privileged FROM app_password "
            "ORDER BY created_at DESC,name ASC;", -1, &stmt, nullptr) != SQLITE_OK)
        status = WF_ERR_INTERNAL;
    size_t capacity = 0;
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized = std::realloc(*out_passwords,
                                            next * sizeof(**out_passwords));
            if (!resized) { status = WF_ERR_ALLOC; break; }
            *out_passwords = static_cast<metalbear_app_password *>(resized);
            std::memset(*out_passwords + capacity, 0,
                       (next - capacity) * sizeof(**out_passwords));
            capacity = next;
        }
        metalbear_app_password *item = &(*out_passwords)[*out_count];
        const char *name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        const char *created = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        item->name = name ? strdup(name) : nullptr;
        item->created_at = created ? strdup(created) : nullptr;
        item->privileged = sqlite3_column_int(stmt, 2) != 0;
        if (!item->name || !item->created_at) {
            std::free(item->name);
            std::free(item->created_at);
            item->name = nullptr;
            item->created_at = nullptr;
            status = WF_ERR_ALLOC;
            break;
        }
        (*out_count)++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    if (status != WF_OK) {
        metalbear_app_passwords_free(*out_passwords, *out_count);
        *out_passwords = nullptr;
        *out_count = 0;
    }
    return status;
}

void metalbear_app_passwords_free(metalbear_app_password *passwords,
                                       size_t count) {
    if (!passwords) return;
    for (size_t i = 0; i < count; i++) {
        std::free(passwords[i].name);
        std::free(passwords[i].created_at);
    }
    std::free(passwords);
}

wf_status metalbear_account_revoke_app_password(
    metalbear_account_store *store, const char *name) {
    if (!store || !name || !name[0]) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "DELETE FROM app_password WHERE name=?;", -1, &stmt, nullptr) ==
            SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        status = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

int metalbear_account_is_active(metalbear_account_store *store) {
    if (!store) return 0;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    int active = 0;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT active FROM account_state WHERE id=0;", -1, &stmt,
            nullptr) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
        active = sqlite3_column_int(stmt, 0) != 0;
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return active;
}

wf_status metalbear_account_deactivate(metalbear_account_store *store,
                                           const char *delete_after) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "UPDATE account_state SET active=0,"
            "deactivated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),"
            "delete_after=? WHERE id=0;", -1, &stmt, nullptr) == SQLITE_OK) {
        if (delete_after)
            sqlite3_bind_text(stmt, 1, delete_after, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(stmt, 1);
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

wf_status metalbear_account_activate(metalbear_account_store *store) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    int result = sqlite3_exec(store->db.get(),
        "UPDATE account_state SET active=1,deactivated_at=NULL,"
        "delete_after=NULL WHERE id=0;", nullptr, nullptr, nullptr);
    pthread_mutex_unlock(&store->mutex);
    return result == SQLITE_OK ? WF_OK : WF_ERR_INTERNAL;
}

wf_status metalbear_account_store_email(metalbear_account_store *store,
                                         const char *email) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "UPDATE account_state SET email=?,email_confirmed=0 WHERE id=0;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        if (email)
            sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(stmt, 1);
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

wf_status metalbear_account_get_email(metalbear_account_store *store,
                                           char **out_email,
                                           int *out_confirmed) {
    if (!store || !out_email) return WF_ERR_INVALID_ARG;
    *out_email = nullptr;
    if (out_confirmed) *out_confirmed = 0;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT email,email_confirmed FROM account_state WHERE id=0;",
            -1, &stmt, nullptr) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const char *email = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        if (email) *out_email = strdup(email);
        if (out_confirmed) *out_confirmed = sqlite3_column_int(stmt, 1);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return *out_email ? WF_OK : WF_ERR_ALLOC;
}

wf_status metalbear_account_create_email_token(metalbear_account_store *store,
                                                    const char *kind,
                                                    char *out_token,
                                                    size_t token_len) {
    if (!store || !kind || !out_token || token_len < 33)
        return WF_ERR_INVALID_ARG;
    unsigned char random_bytes[16];
    static const char hex[] = "0123456789abcdef";
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1)
        return WF_ERR_CRYPTO;
    for (size_t i = 0; i < sizeof(random_bytes) && i * 2 + 1 < token_len;
         i++) {
        out_token[i * 2] = hex[random_bytes[i] >> 4];
        out_token[i * 2 + 1] = hex[random_bytes[i] & 15];
    }
    out_token[32] = '\0';
    char created_at[32];
    if (current_datetime(created_at) != WF_OK)
        return WF_ERR_INTERNAL;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "INSERT INTO email_token(token,kind,created_at,expires_at) "
            "VALUES(?,?,?,?);",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, out_token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, created_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, static_cast<int64_t>(std::time(nullptr)) + 3600);
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

wf_status metalbear_account_verify_email_token(metalbear_account_store *store,
                                                    const char *kind,
                                                    const char *token) {
    if (!store || !kind || !token) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "DELETE FROM email_token WHERE token=? AND kind=? AND expires_at>?;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(std::time(nullptr)));
        sqlite3_step(stmt);
        int changes = sqlite3_changes(store->db.get());
        status = changes > 0 ? WF_OK : WF_ERR_PERMISSION;
    }
    if (status == WF_OK && std::strcmp(kind, "confirm") == 0) {
        sqlite3_stmt *stmt2 = nullptr;
        if (sqlite3_prepare_v2(store->db.get(),
                "UPDATE account_state SET email_confirmed=1 WHERE id=0;",
                -1, &stmt2, nullptr) == SQLITE_OK) {
            sqlite3_step(stmt2);
        }
        sqlite3_finalize(stmt2);
    }
    pthread_mutex_unlock(&store->mutex);
    return status;
}

wf_status metalbear_account_delete(metalbear_account_store *store) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "DELETE FROM app_password;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    if (sqlite3_prepare_v2(store->db.get(),
            "DELETE FROM credentials;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    if (sqlite3_prepare_v2(store->db.get(),
            "UPDATE account_state SET active=0 WHERE id=0;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

void metalbear_account_store_free(metalbear_account_store *store) {
    if (!store) return;
    store->db.reset(); /* closes sqlite3 db via deleter */
    pthread_mutex_destroy(&store->mutex);
    std::free(store);
}

wf_status metalbear_account_reset_password(metalbear_account_store *store,
                                                const char *new_password) {
    if (!store || !new_password || !new_password[0]) return WF_ERR_INVALID_ARG;
    unsigned char salt[16], hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        derive_password(new_password, salt, hash) != WF_OK)
        return WF_ERR_INTERNAL;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "UPDATE credentials SET salt=?,password_hash=? WHERE id=0;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, salt, sizeof(salt), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, hash, sizeof(hash), SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        status = sqlite3_changes(store->db.get()) > 0 ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    OPENSSL_cleanse(hash, sizeof(hash));
    pthread_mutex_unlock(&store->mutex);
    return status;
}

char *metalbear_account_hash_password(const char *password) {
    if (!password || !password[0]) return nullptr;
    unsigned char salt[16], hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) return nullptr;
    if (derive_password(password, salt, hash) != WF_OK) return nullptr;
    static const char hex[] = "0123456789abcdef";
    char *result = static_cast<char *>(std::calloc(97, 1));
    if (!result) { OPENSSL_cleanse(hash, sizeof(hash)); return nullptr; }
    for (size_t i = 0; i < 16; i++) {
        result[i * 2]     = hex[salt[i] >> 4];
        result[i * 2 + 1] = hex[salt[i] & 15];
    }
    for (size_t i = 0; i < 32; i++) {
        result[32 + i * 2]     = hex[hash[i] >> 4];
        result[32 + i * 2 + 1] = hex[hash[i] & 15];
    }
    result[96] = '\0';
    OPENSSL_cleanse(hash, sizeof(hash));
    return result;
}

wf_status metalbear_account_store_prefs_get(metalbear_account_store *store,
                                                 char **out_json) {
    if (!store || !out_json) return WF_ERR_INVALID_ARG;
    *out_json = nullptr;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT data FROM preferences WHERE id=0;", -1, &stmt, nullptr) !=
            SQLITE_OK || sqlite3_step(stmt) != SQLITE_ROW) {
        *out_json = strdup("{\"preferences\":[]}");
        pthread_mutex_unlock(&store->mutex);
        return *out_json ? WF_OK : WF_ERR_ALLOC;
    }
    const char *data = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    *out_json = data ? strdup(data) : strdup("{\"preferences\":[]}");
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return *out_json ? WF_OK : WF_ERR_ALLOC;
}

wf_status metalbear_account_store_prefs_put(metalbear_account_store *store,
                                                 const char *json) {
    if (!store || !json) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "REPLACE INTO preferences(id, data) VALUES(0, ?);",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, json, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

bool metalbear_account_invites_enabled(metalbear_account_store *store) {
    if (!store) return false;
    pthread_mutex_lock(&store->mutex);
    int enabled = 1;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(store->db.get(),
            "SELECT invites_enabled FROM account_state WHERE id=0;",
            -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        enabled = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return enabled != 0;
}

wf_status metalbear_account_set_invites_enabled(metalbear_account_store *store,
                                                bool enabled) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db.get(),
            "UPDATE account_state SET invites_enabled=? WHERE id=0;",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

} // extern "C"

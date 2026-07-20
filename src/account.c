#define _POSIX_C_SOURCE 200809L

#include "metalbear/account.h"

#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct metalbear_account_store {
    sqlite3 *db;
    pthread_mutex_t mutex;
};

static wf_status derive_password(const char *password,
                                 const unsigned char salt[16],
                                 unsigned char hash[32]) {
    if (!password || EVP_PBE_scrypt(password, strlen(password), salt, 16,
                                    16384, 8, 1, 32 * 1024 * 1024,
                                    hash, 32) != 1)
        return WF_ERR_INTERNAL;
    return WF_OK;
}

wf_status metalbear_account_store_open(const char *path,
                                       const char *bootstrap_password,
                                       metalbear_account_store **out) {
    if (!path || !bootstrap_password || !bootstrap_password[0] || !out)
        return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_account_store *store = calloc(1, sizeof(*store));
    if (!store) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&store->mutex, NULL) != 0) {
        free(store);
        return WF_ERR_INTERNAL;
    }
    if (sqlite3_open(path, &store->db) != SQLITE_OK ||
        sqlite3_exec(store->db,
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE IF NOT EXISTS account_state("
            "id INTEGER PRIMARY KEY CHECK(id=0),"
            "active INTEGER NOT NULL CHECK(active IN(0,1)),"
            "email TEXT,email_confirmed INTEGER NOT NULL DEFAULT 0,"
            "deactivated_at TEXT,delete_after TEXT);"
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
            "created_at TEXT NOT NULL,expires_at INTEGER NOT NULL);",
            NULL, NULL, NULL) != SQLITE_OK) {
        metalbear_account_store_free(store);
        return WF_ERR_INTERNAL;
    }
    sqlite3_stmt *stmt = NULL;
    int has_credentials = 0;
    if (sqlite3_prepare_v2(store->db,
            "SELECT 1 FROM credentials WHERE id=0;", -1, &stmt, NULL) ==
            SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
        has_credentials = 1;
    sqlite3_finalize(stmt);
    if (!has_credentials) {
        unsigned char salt[16], hash[32];
        if (RAND_bytes(salt, sizeof(salt)) != 1 ||
            derive_password(bootstrap_password, salt, hash) != WF_OK ||
            sqlite3_prepare_v2(store->db,
                "INSERT INTO credentials(id,salt,password_hash) VALUES(0,?,?);",
                -1, &stmt, NULL) != SQLITE_OK) {
            metalbear_account_store_free(store);
            return WF_ERR_INTERNAL;
        }
        sqlite3_bind_blob(stmt, 1, salt, sizeof(salt), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, hash, sizeof(hash), SQLITE_TRANSIENT);
        int result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        OPENSSL_cleanse(hash, sizeof(hash));
        if (result != SQLITE_DONE) {
            metalbear_account_store_free(store);
            return WF_ERR_INTERNAL;
        }
    }
    *out = store;
    return WF_OK;
}

int metalbear_account_verify_password(metalbear_account_store *store,
                                      const char *password) {
    if (!store || !password) return 0;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    int valid = 0;
    if (sqlite3_prepare_v2(store->db,
            "SELECT salt,password_hash FROM credentials WHERE id=0;",
            -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *salt = sqlite3_column_blob(stmt, 0);
        const unsigned char *expected = sqlite3_column_blob(stmt, 1);
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
    if (out_app_password_name) *out_app_password_name = NULL;
    if (!store || !password) return METALBEAR_CREDENTIAL_INVALID;
    if (metalbear_account_verify_password(store, password))
        return METALBEAR_CREDENTIAL_ACCOUNT;

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    metalbear_credential_kind kind = METALBEAR_CREDENTIAL_INVALID;
    if (sqlite3_prepare_v2(store->db,
            "SELECT name,salt,password_hash,privileged FROM app_password;",
            -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(stmt, 0);
            const unsigned char *salt = sqlite3_column_blob(stmt, 1);
            const unsigned char *expected = sqlite3_column_blob(stmt, 2);
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

static wf_status current_datetime(char output[32]) {
    time_t now = time(NULL);
    struct tm utc;
    if (now == (time_t)-1 || !gmtime_r(&now, &utc) ||
        strftime(output, 32, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0)
        return WF_ERR_INTERNAL;
    return WF_OK;
}

wf_status metalbear_account_create_app_password(
    metalbear_account_store *store, const char *name, bool privileged,
    char **out_password, char **out_created_at) {
    if (!store || !name || !name[0] || strlen(name) > 256 || !out_password ||
        !out_created_at)
        return WF_ERR_INVALID_ARG;
    *out_password = NULL;
    *out_created_at = NULL;
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
    snprintf(formatted, sizeof(formatted), "%.4s-%.4s-%.4s-%.4s", compact,
             compact + 4, compact + 8, compact + 12);
    if (derive_password(formatted, salt, hash) != WF_OK)
        return WF_ERR_INTERNAL;
    char *password_copy = strdup(formatted);
    char *created_copy = strdup(created_at);
    if (!password_copy || !created_copy) {
        free(password_copy);
        free(created_copy);
        OPENSSL_cleanse(hash, sizeof(hash));
        return WF_ERR_ALLOC;
    }

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "INSERT INTO app_password(name,salt,password_hash,created_at,"
            "privileged) VALUES(?,?,?,?,?);", -1, &stmt, NULL) == SQLITE_OK) {
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
    pthread_mutex_unlock(&store->mutex);
    OPENSSL_cleanse(hash, sizeof(hash));
    if (status != WF_OK) {
        free(password_copy);
        free(created_copy);
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
    *out_passwords = NULL;
    *out_count = 0;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_OK;
    if (sqlite3_prepare_v2(store->db,
            "SELECT name,created_at,privileged FROM app_password "
            "ORDER BY created_at DESC,name ASC;", -1, &stmt, NULL) != SQLITE_OK)
        status = WF_ERR_INTERNAL;
    size_t capacity = 0;
    while (status == WF_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        if (*out_count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *resized = realloc(*out_passwords,
                                    next * sizeof(**out_passwords));
            if (!resized) { status = WF_ERR_ALLOC; break; }
            *out_passwords = resized;
            memset(*out_passwords + capacity, 0,
                   (next - capacity) * sizeof(**out_passwords));
            capacity = next;
        }
        metalbear_app_password *item = &(*out_passwords)[*out_count];
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        const char *created = (const char *)sqlite3_column_text(stmt, 1);
        item->name = name ? strdup(name) : NULL;
        item->created_at = created ? strdup(created) : NULL;
        item->privileged = sqlite3_column_int(stmt, 2) != 0;
        if (!item->name || !item->created_at) {
            free(item->name);
            free(item->created_at);
            item->name = NULL;
            item->created_at = NULL;
            status = WF_ERR_ALLOC;
            break;
        }
        (*out_count)++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    if (status != WF_OK) {
        metalbear_app_passwords_free(*out_passwords, *out_count);
        *out_passwords = NULL;
        *out_count = 0;
    }
    return status;
}

void metalbear_app_passwords_free(metalbear_app_password *passwords,
                                  size_t count) {
    if (!passwords) return;
    for (size_t i = 0; i < count; i++) {
        free(passwords[i].name);
        free(passwords[i].created_at);
    }
    free(passwords);
}

wf_status metalbear_account_revoke_app_password(
    metalbear_account_store *store, const char *name) {
    if (!store || !name || !name[0]) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "DELETE FROM app_password WHERE name=?;", -1, &stmt, NULL) ==
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
    sqlite3_stmt *stmt = NULL;
    int active = 0;
    if (sqlite3_prepare_v2(store->db,
            "SELECT active FROM account_state WHERE id=0;", -1, &stmt,
            NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
        active = sqlite3_column_int(stmt, 0) != 0;
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return active;
}

wf_status metalbear_account_deactivate(metalbear_account_store *store,
                                       const char *delete_after) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "UPDATE account_state SET active=0,"
            "deactivated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),"
            "delete_after=? WHERE id=0;", -1, &stmt, NULL) == SQLITE_OK) {
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
    int result = sqlite3_exec(store->db,
        "UPDATE account_state SET active=1,deactivated_at=NULL,"
        "delete_after=NULL WHERE id=0;", NULL, NULL, NULL);
    pthread_mutex_unlock(&store->mutex);
    return result == SQLITE_OK ? WF_OK : WF_ERR_INTERNAL;
}

wf_status metalbear_account_store_email(metalbear_account_store *store,
                                        const char *email) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "UPDATE account_state SET email=?,email_confirmed=0 WHERE id=0;",
            -1, &stmt, NULL) == SQLITE_OK) {
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
    *out_email = NULL;
    if (out_confirmed) *out_confirmed = 0;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT email,email_confirmed FROM account_state WHERE id=0;",
            -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const char *email = (const char *)sqlite3_column_text(stmt, 0);
        if (email) *out_email = strdup(email);
        if (out_confirmed) *out_confirmed = sqlite3_column_int(stmt, 1);
        status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
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
    time_t now = time(NULL);
    struct tm utc;
    char created_at[32];
    if (now == (time_t)-1 || !gmtime_r(&now, &utc) ||
        strftime(created_at, 32, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0)
        return WF_ERR_INTERNAL;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "INSERT INTO email_token(token,kind,created_at,expires_at) "
            "VALUES(?,?,?,?);",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, out_token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, created_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, (int64_t)now + 3600);
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
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "DELETE FROM email_token WHERE token=? AND kind=? AND expires_at>?;",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));
        sqlite3_step(stmt);
        int changes = sqlite3_changes(store->db);
        status = changes > 0 ? WF_OK : WF_ERR_PERMISSION;
    }
    sqlite3_finalize(stmt);
    if (status == WF_OK && strcmp(kind, "confirm") == 0) {
        if (sqlite3_prepare_v2(store->db,
                "UPDATE account_state SET email_confirmed=1 WHERE id=0;",
                -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_step(stmt);
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&store->mutex);
    return status;
}

wf_status metalbear_account_delete(metalbear_account_store *store) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "DELETE FROM app_password;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (sqlite3_prepare_v2(store->db,
            "DELETE FROM credentials;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (sqlite3_prepare_v2(store->db,
            "UPDATE account_state SET active=0 WHERE id=0;",
            -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

void metalbear_account_store_free(metalbear_account_store *store) {
    if (!store) return;
    if (store->db) sqlite3_close(store->db);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

wf_status metalbear_account_reset_password(metalbear_account_store *store,
                                           const char *new_password) {
    if (!store || !new_password || !new_password[0]) return WF_ERR_INVALID_ARG;
    unsigned char salt[16], hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        derive_password(new_password, salt, hash) != WF_OK)
        return WF_ERR_INTERNAL;
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "UPDATE credentials SET salt=?,password_hash=? WHERE id=0;",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, salt, sizeof(salt), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, hash, sizeof(hash), SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        status = sqlite3_changes(store->db) > 0 ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    OPENSSL_cleanse(hash, sizeof(hash));
    pthread_mutex_unlock(&store->mutex);
    return status;
}

char *metalbear_account_hash_password(const char *password) {
    if (!password || !password[0]) return NULL;
    unsigned char salt[16], hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) return NULL;
    if (derive_password(password, salt, hash) != WF_OK) return NULL;
    /* Encode as hex: 16-byte salt + 32-byte hash = 48 bytes = 96 hex chars */
    static const char hex[] = "0123456789abcdef";
    char *result = calloc(97, 1);
    if (!result) { OPENSSL_cleanse(hash, sizeof(hash)); return NULL; }
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

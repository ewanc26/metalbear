#include "metalbear/repo/key_rotation.h"

#include "wolfram/crypto.h"

#include <openssl/rand.h>
#include <pthread.h>
#include <sqlite3.h>
#include <cstdlib>
#include <cstring>
#include <memory>

struct sqlite3_deleter {
    void operator()(sqlite3 *db) const noexcept {
        sqlite3_close(db);
    }
};

using sqlite3_ptr = std::unique_ptr<sqlite3, sqlite3_deleter>;

struct metalbear_key_rotation {
    sqlite3_ptr db;
    pthread_mutex_t mutex;
};

extern "C" {

wf_status metalbear_key_rotation_open(const char *path,
                                      metalbear_key_rotation **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
    *out = nullptr;
    auto *store = static_cast<metalbear_key_rotation *>(
        std::calloc(1, sizeof(metalbear_key_rotation)));
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
    if (sqlite3_exec(store->db.get(),
                     "PRAGMA journal_mode=WAL;"
                     "CREATE TABLE IF NOT EXISTS signing_keys("
                     "id INTEGER PRIMARY KEY CHECK(id=0),"
                     "key_bytes BLOB NOT NULL,"
                     "created_at TEXT NOT NULL);",
                     nullptr, nullptr, nullptr) != SQLITE_OK) {
        metalbear_key_rotation_free(store);
        return WF_ERR_INTERNAL;
    }
    *out = store;
    return WF_OK;
}

void metalbear_key_rotation_free(metalbear_key_rotation *store) {
    if (!store) return;
    store->db.reset();
    pthread_mutex_destroy(&store->mutex);
    std::free(store);
}

wf_status metalbear_key_rotation_current_key(metalbear_key_rotation *store,
                                             wf_signing_key *out) {
    if (!store || !out) return WF_ERR_INVALID_ARG;
    std::memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&store->mutex);

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(store->db.get(),
                           "SELECT key_bytes FROM signing_keys WHERE id=0;", -1,
                           &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *bytes =
            static_cast<const unsigned char *>(sqlite3_column_blob(stmt, 0));
        int length = sqlite3_column_bytes(stmt, 0);
        if (bytes && length == 32) {
            std::memcpy(out->bytes, bytes, 32);
            out->type = WF_KEY_TYPE_SECP256K1;
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&store->mutex);
            return WF_OK;
        }
    }
    sqlite3_finalize(stmt);

    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, out) != WF_OK) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_CRYPTO;
    }

    if (sqlite3_prepare_v2(
            store->db.get(),
            "INSERT OR REPLACE INTO signing_keys(id,key_bytes,created_at) "
            "VALUES(0,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, out->bytes, 32, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return WF_OK;
}

wf_status metalbear_key_rotation_import(metalbear_key_rotation *store,
                                        const wf_signing_key *key) {
    if (!store || !key || key->type != WF_KEY_TYPE_SECP256K1)
        return WF_ERR_INVALID_ARG;

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(
            store->db.get(),
            "INSERT OR REPLACE INTO signing_keys(id,key_bytes,created_at) "
            "VALUES(0,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, key->bytes, 32, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE) status = WF_OK;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return status;
}

wf_status metalbear_key_rotation_rotate(metalbear_key_rotation *store,
                                        wf_signing_key *out_new_key,
                                        char **out_didkey) {
    if (!store || !out_new_key) return WF_ERR_INVALID_ARG;
    std::memset(out_new_key, 0, sizeof(*out_new_key));
    if (out_didkey) *out_didkey = nullptr;

    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, out_new_key) != WF_OK)
        return WF_ERR_CRYPTO;

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(
            store->db.get(),
            "INSERT OR REPLACE INTO signing_keys(id,key_bytes,created_at) "
            "VALUES(0,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, out_new_key->bytes, 32, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);

    if (out_didkey)
        return wf_signing_key_public_didkey(out_new_key, out_didkey);
    return WF_OK;
}

wf_status metalbear_key_rotation_reserve(metalbear_key_rotation *store,
                                         char **out_didkey) {
    if (!store || !out_didkey) return WF_ERR_INVALID_ARG;
    *out_didkey = nullptr;

    wf_signing_key key;
    std::memset(&key, 0, sizeof(key));
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &key) != WF_OK)
        return WF_ERR_CRYPTO;

    return wf_signing_key_public_didkey(&key, out_didkey);
}

} // extern "C"
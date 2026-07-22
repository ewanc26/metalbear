#define _POSIX_C_SOURCE 200809L

#include "metalbear/key_rotation.h"

#include "wolfram/crypto.h"

#include <openssl/rand.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct metalbear_key_rotation {
    sqlite3 *db;
    pthread_mutex_t mutex;
};

static wf_status execute(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? WF_OK :
                                                                  WF_ERR_INTERNAL;
}

wf_status metalbear_key_rotation_open(const char *path,
                                      metalbear_key_rotation **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_key_rotation *store = calloc(1, sizeof(*store));
    if (!store) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&store->mutex, NULL) != 0) {
        free(store);
        return WF_ERR_INTERNAL;
    }
    if (sqlite3_open(path, &store->db) != SQLITE_OK ||
        execute(store->db,
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE IF NOT EXISTS signing_keys("
            "id INTEGER PRIMARY KEY CHECK(id=0),"
            "key_bytes BLOB NOT NULL,"
            "created_at TEXT NOT NULL);") != WF_OK) {
        metalbear_key_rotation_free(store);
        return WF_ERR_INTERNAL;
    }
    *out = store;
    return WF_OK;
}

void metalbear_key_rotation_free(metalbear_key_rotation *store) {
    if (!store) return;
    if (store->db) sqlite3_close(store->db);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

wf_status metalbear_key_rotation_current_key(
    metalbear_key_rotation *store, wf_signing_key *out) {
    if (!store || !out) return WF_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&store->mutex);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT key_bytes FROM signing_keys WHERE id=0;", -1, &stmt,
            NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const void *bytes = sqlite3_column_blob(stmt, 0);
        int length = sqlite3_column_bytes(stmt, 0);
        if (bytes && length == 32) {
            memcpy(out->bytes, bytes, 32);
            out->type = WF_KEY_TYPE_SECP256K1;
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&store->mutex);
            return WF_OK;
        }
    }
    sqlite3_finalize(stmt);

    /* Generate new key (secp256k1 for PLC compatibility) */
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, out) != WF_OK) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_CRYPTO;
    }

    if (sqlite3_prepare_v2(store->db,
            "INSERT OR REPLACE INTO signing_keys(id,key_bytes,created_at) "
            "VALUES(0,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, out->bytes, 32, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    return WF_OK;
}

wf_status metalbear_key_rotation_rotate(metalbear_key_rotation *store,
                                        wf_signing_key *out_new_key,
                                        char **out_didkey) {
    if (!store || !out_new_key) return WF_ERR_INVALID_ARG;
    memset(out_new_key, 0, sizeof(*out_new_key));
    if (out_didkey) *out_didkey = NULL;

    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, out_new_key) != WF_OK)
        return WF_ERR_CRYPTO;

    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "INSERT OR REPLACE INTO signing_keys(id,key_bytes,created_at) "
            "VALUES(0,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
            -1, &stmt, NULL) == SQLITE_OK) {
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
    *out_didkey = NULL;

    wf_signing_key key;
    memset(&key, 0, sizeof(key));
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &key) != WF_OK)
        return WF_ERR_CRYPTO;

    return wf_signing_key_public_didkey(&key, out_didkey);
}

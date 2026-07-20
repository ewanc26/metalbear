#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth.h"

#include "wolfram/crypto.h"

#include <cJSON.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define PAR_LIFETIME_SECONDS 300
#define CODE_LIFETIME_SECONDS 300
#define ACCESS_LIFETIME_SECONDS 3600
#define REFRESH_LIFETIME_SECONDS (90 * 24 * 60 * 60)

struct metalbear_oauth_store {
    sqlite3 *db;
    pthread_mutex_t mutex;
    wf_signing_key key;
    char *issuer;
    char *subject;
    wf_oauth_trusted_keys *trusted_keys;
    wf_oauth_dpop_replay_cache *replay;
};

static wf_status execute(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? WF_OK :
                                                                  WF_ERR_INTERNAL;
}

static wf_status random_value(size_t bytes, char **out) {
    unsigned char *raw = malloc(bytes);
    if (!raw) return WF_ERR_ALLOC;
    wf_status status = RAND_bytes(raw, (int)bytes) == 1
        ? wf_crypto_base64url_encode(raw, bytes, out) : WF_ERR_CRYPTO;
    OPENSSL_cleanse(raw, bytes);
    free(raw);
    return status;
}

static wf_status token_hash(const char *token, unsigned char out[32]) {
    return token ? wf_crypto_sha256((const unsigned char *)token,
                                    strlen(token), out) : WF_ERR_INVALID_ARG;
}

static void prune(metalbear_oauth_store *store, int64_t now) {
    sqlite3_stmt *stmt = NULL;
    static const char *const tables[] = {"oauth_par", "oauth_code",
                                         "oauth_refresh"};
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char sql[96];
        int length = snprintf(sql, sizeof(sql),
                              "DELETE FROM %s WHERE expires_at<=?;", tables[i]);
        if (length <= 0 || (size_t)length >= sizeof(sql) ||
            sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            continue;
        sqlite3_bind_int64(stmt, 1, now);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
}

static wf_status load_or_create_key(metalbear_oauth_store *store) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT value FROM oauth_meta WHERE key='signing_key';", -1,
            &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    int result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        const void *bytes = sqlite3_column_blob(stmt, 0);
        int length = sqlite3_column_bytes(stmt, 0);
        if (bytes && length == 32) memcpy(store->key.bytes, bytes, 32);
        sqlite3_finalize(stmt);
        store->key.type = WF_KEY_TYPE_P256;
        return bytes && length == 32 ? WF_OK : WF_ERR_CONFIG;
    }
    sqlite3_finalize(stmt);
    if (result != SQLITE_DONE ||
        wf_signing_key_generate(WF_KEY_TYPE_P256, &store->key) != WF_OK)
        return WF_ERR_CRYPTO;
    if (sqlite3_prepare_v2(store->db,
            "INSERT INTO oauth_meta(key,value) VALUES('signing_key',?);", -1,
            &stmt, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_blob(stmt, 1, store->key.bytes, 32, SQLITE_TRANSIENT);
    result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return result == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

wf_status metalbear_oauth_public_jwk(metalbear_oauth_store *store,
                                     char **out_jwk) {
    if (!store || !out_jwk) return WF_ERR_INVALID_ARG;
    *out_jwk = NULL;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *private_key = BN_bin2bn(store->key.bytes, 32, NULL);
    EC_POINT *public_key = ec ? EC_POINT_new(EC_KEY_get0_group(ec)) : NULL;
    BIGNUM *x = BN_new(), *y = BN_new();
    unsigned char x_raw[32], y_raw[32];
    char *x_b64 = NULL, *y_b64 = NULL, *json = NULL;
    cJSON *root = NULL;
    wf_status status = WF_ERR_CRYPTO;
    if (!ec || !private_key || !public_key || !x || !y ||
        EC_POINT_mul(EC_KEY_get0_group(ec), public_key, private_key, NULL, NULL,
                     NULL) != 1 ||
        EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ec), public_key, x, y,
                                        NULL) != 1 ||
        BN_bn2binpad(x, x_raw, sizeof(x_raw)) != (int)sizeof(x_raw) ||
        BN_bn2binpad(y, y_raw, sizeof(y_raw)) != (int)sizeof(y_raw))
        goto done;
    status = wf_crypto_base64url_encode(x_raw, sizeof(x_raw), &x_b64);
    if (status == WF_OK)
        status = wf_crypto_base64url_encode(y_raw, sizeof(y_raw), &y_b64);
    root = cJSON_CreateObject();
    if (status != WF_OK || !root ||
        !cJSON_AddStringToObject(root, "kty", "EC") ||
        !cJSON_AddStringToObject(root, "crv", "P-256") ||
        !cJSON_AddStringToObject(root, "x", x_b64) ||
        !cJSON_AddStringToObject(root, "y", y_b64) ||
        !cJSON_AddStringToObject(root, "use", "sig") ||
        !cJSON_AddStringToObject(root, "alg", "ES256") ||
        !cJSON_AddStringToObject(root, "kid", "metalbear-oauth")) {
        status = status == WF_OK ? WF_ERR_ALLOC : status;
        goto done;
    }
    json = cJSON_PrintUnformatted(root);
    if (!json) { status = WF_ERR_ALLOC; goto done; }
    *out_jwk = json;
    json = NULL;
    status = WF_OK;
done:
    cJSON_Delete(root);
    free(json);
    free(x_b64);
    free(y_b64);
    BN_clear_free(private_key);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(public_key);
    EC_KEY_free(ec);
    return status;
}

wf_status metalbear_oauth_jwks(metalbear_oauth_store *store, char **out_jwks) {
    if (!store || !out_jwks) return WF_ERR_INVALID_ARG;
    *out_jwks = NULL;
    char *jwk_json = NULL;
    wf_status status = metalbear_oauth_public_jwk(store, &jwk_json);
    cJSON *jwk = status == WF_OK ? cJSON_Parse(jwk_json) : NULL;
    cJSON *root = cJSON_CreateObject(), *keys = cJSON_CreateArray();
    if (status != WF_OK || !jwk || !root || !keys) {
        status = status == WF_OK ? WF_ERR_ALLOC : status;
        cJSON_Delete(jwk); cJSON_Delete(root); cJSON_Delete(keys);
        free(jwk_json);
        return status;
    }
    cJSON_AddItemToArray(keys, jwk);
    cJSON_AddItemToObject(root, "keys", keys);
    *out_jwks = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(jwk_json);
    return *out_jwks ? WF_OK : WF_ERR_ALLOC;
}

wf_status metalbear_oauth_store_open(const char *path, const char *issuer,
                                     const char *subject,
                                     metalbear_oauth_store **out) {
    if (!path || !issuer || !subject || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_oauth_store *store = calloc(1, sizeof(*store));
    if (!store) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&store->mutex, NULL) != 0) { free(store); return WF_ERR_INTERNAL; }
    store->issuer = strdup(issuer);
    store->subject = strdup(subject);
    if (!store->issuer || !store->subject ||
        sqlite3_open_v2(path, &store->db, SQLITE_OPEN_READWRITE |
                        SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK)
        goto fail;
    chmod(path, 0600);
    if (execute(store->db, "PRAGMA journal_mode=WAL;") != WF_OK ||
        execute(store->db,
            "CREATE TABLE IF NOT EXISTS oauth_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS oauth_par("
            "request_uri TEXT PRIMARY KEY,client_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,"
            "scope TEXT NOT NULL,state TEXT,code_challenge TEXT NOT NULL,dpop_jkt TEXT NOT NULL,"
            "expires_at INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS oauth_code("
            "code_hash BLOB PRIMARY KEY,client_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,"
            "scope TEXT NOT NULL,code_challenge TEXT NOT NULL,dpop_jkt TEXT NOT NULL,"
            "expires_at INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS oauth_refresh("
            "token_hash BLOB PRIMARY KEY,client_id TEXT NOT NULL,scope TEXT NOT NULL,"
            "dpop_jkt TEXT NOT NULL,expires_at INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS oauth_par_expiry ON oauth_par(expires_at);"
            "CREATE INDEX IF NOT EXISTS oauth_code_expiry ON oauth_code(expires_at);"
            "CREATE INDEX IF NOT EXISTS oauth_refresh_expiry ON oauth_refresh(expires_at);") != WF_OK ||
        load_or_create_key(store) != WF_OK ||
        wf_oauth_trusted_keys_new(&store->trusted_keys) != WF_OK ||
        wf_oauth_dpop_replay_cache_new(&store->replay) != WF_OK)
        goto fail;
    char *jwk = NULL;
    if (metalbear_oauth_public_jwk(store, &jwk) != WF_OK ||
        wf_oauth_trusted_keys_add_jwk(store->trusted_keys, jwk) != WF_OK) {
        free(jwk);
        goto fail;
    }
    free(jwk);
    *out = store;
    return WF_OK;
fail:
    metalbear_oauth_store_free(store);
    return WF_ERR_INTERNAL;
}

void metalbear_oauth_store_free(metalbear_oauth_store *store) {
    if (!store) return;
    sqlite3_close(store->db);
    wf_oauth_trusted_keys_free(store->trusted_keys);
    wf_oauth_dpop_replay_cache_free(store->replay);
    OPENSSL_cleanse(store->key.bytes, sizeof(store->key.bytes));
    free(store->issuer);
    free(store->subject);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

void metalbear_oauth_grant_free(metalbear_oauth_grant *grant) {
    if (!grant) return;
    free(grant->access_token);
    free(grant->refresh_token);
    memset(grant, 0, sizeof(*grant));
}

static bool valid_request(const metalbear_oauth_request *request) {
    return request && request->client_id && request->client_id[0] &&
           request->redirect_uri && request->redirect_uri[0] &&
           request->scope && strstr(request->scope, "atproto") &&
           request->code_challenge && strlen(request->code_challenge) == 43 &&
           request->dpop_jkt && strlen(request->dpop_jkt) == 43;
}

wf_status metalbear_oauth_create_par(metalbear_oauth_store *store,
                                     const metalbear_oauth_request *request,
                                     char **out_request_uri,
                                     int64_t *out_expires_in) {
    if (!store || !valid_request(request) || !out_request_uri ||
        !out_expires_in)
        return WF_ERR_INVALID_ARG;
    *out_request_uri = NULL;
    char *random = NULL;
    wf_status status = random_value(32, &random);
    if (status != WF_OK) return status;
    static const char prefix[] = "urn:ietf:params:oauth:request_uri:";
    size_t size = sizeof(prefix) + strlen(random);
    char *uri = malloc(size);
    if (!uri) { free(random); return WF_ERR_ALLOC; }
    snprintf(uri, size, "%s%s", prefix, random);
    free(random);
    int64_t now = (int64_t)time(NULL);
    pthread_mutex_lock(&store->mutex);
    prune(store, now);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "INSERT INTO oauth_par(request_uri,client_id,redirect_uri,scope,state,"
            "code_challenge,dpop_jkt,expires_at) VALUES(?,?,?,?,?,?,?,?);",
            -1, &stmt, NULL) != SQLITE_OK) status = WF_ERR_INTERNAL;
    if (status == WF_OK) {
        sqlite3_bind_text(stmt, 1, uri, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, request->client_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, request->redirect_uri, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, request->scope, -1, SQLITE_TRANSIENT);
        if (request->state) sqlite3_bind_text(stmt, 5, request->state, -1, SQLITE_TRANSIENT);
        else sqlite3_bind_null(stmt, 5);
        sqlite3_bind_text(stmt, 6, request->code_challenge, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, request->dpop_jkt, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 8, now + PAR_LIFETIME_SECONDS);
        if (sqlite3_step(stmt) != SQLITE_DONE) status = WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    if (status != WF_OK) { free(uri); return status; }
    *out_request_uri = uri;
    *out_expires_in = PAR_LIFETIME_SECONDS;
    return WF_OK;
}

static char *column_copy(sqlite3_stmt *stmt, int column) {
    const char *value = (const char *)sqlite3_column_text(stmt, column);
    return value ? strdup(value) : NULL;
}

wf_status metalbear_oauth_authorize(metalbear_oauth_store *store,
                                    const char *request_uri,
                                    const char *client_id,
                                    char **out_code,
                                    char **out_redirect_uri,
                                    char **out_state) {
    if (!store || !request_uri || !client_id || !out_code ||
        !out_redirect_uri || !out_state)
        return WF_ERR_INVALID_ARG;
    *out_code = NULL; *out_redirect_uri = NULL; *out_state = NULL;
    char *code = NULL;
    wf_status status = random_value(32, &code);
    if (status != WF_OK) return status;
    unsigned char hash[32];
    token_hash(code, hash);
    int64_t now = (int64_t)time(NULL);
    pthread_mutex_lock(&store->mutex);
    prune(store, now);
    sqlite3_stmt *stmt = NULL;
    char *stored_client = NULL, *redirect = NULL, *scope = NULL;
    char *state = NULL, *challenge = NULL, *jkt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT client_id,redirect_uri,scope,state,code_challenge,dpop_jkt "
            "FROM oauth_par WHERE request_uri=? AND expires_at>?;", -1,
            &stmt, NULL) != SQLITE_OK) status = WF_ERR_INTERNAL;
    if (status == WF_OK) {
        sqlite3_bind_text(stmt, 1, request_uri, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, now);
        if (sqlite3_step(stmt) != SQLITE_ROW) status = WF_ERR_NOT_FOUND;
    }
    if (status == WF_OK) {
        stored_client = column_copy(stmt, 0); redirect = column_copy(stmt, 1);
        scope = column_copy(stmt, 2); state = column_copy(stmt, 3);
        challenge = column_copy(stmt, 4); jkt = column_copy(stmt, 5);
        if (!stored_client || !redirect || !scope || !challenge || !jkt)
            status = WF_ERR_ALLOC;
        else if (strcmp(stored_client, client_id) != 0)
            status = WF_ERR_PERMISSION;
    }
    sqlite3_finalize(stmt); stmt = NULL;
    if (status == WF_OK && execute(store->db, "BEGIN IMMEDIATE;") != WF_OK)
        status = WF_ERR_INTERNAL;
    if (status == WF_OK && sqlite3_prepare_v2(store->db,
            "DELETE FROM oauth_par WHERE request_uri=?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, request_uri, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE || sqlite3_changes(store->db) != 1)
            status = WF_ERR_CONFLICT;
    } else if (status == WF_OK) status = WF_ERR_INTERNAL;
    sqlite3_finalize(stmt); stmt = NULL;
    if (status == WF_OK && sqlite3_prepare_v2(store->db,
            "INSERT INTO oauth_code(code_hash,client_id,redirect_uri,scope,"
            "code_challenge,dpop_jkt,expires_at) VALUES(?,?,?,?,?,?,?);", -1,
            &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, stored_client, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, redirect, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, scope, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, challenge, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, jkt, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 7, now + CODE_LIFETIME_SECONDS);
        if (sqlite3_step(stmt) != SQLITE_DONE) status = WF_ERR_INTERNAL;
    } else if (status == WF_OK) status = WF_ERR_INTERNAL;
    sqlite3_finalize(stmt);
    if (status == WF_OK && execute(store->db, "COMMIT;") != WF_OK)
        status = WF_ERR_INTERNAL;
    if (status != WF_OK) execute(store->db, "ROLLBACK;");
    pthread_mutex_unlock(&store->mutex);
    free(stored_client); free(scope); free(challenge); free(jkt);
    OPENSSL_cleanse(hash, sizeof(hash));
    if (status != WF_OK) { free(code); free(redirect); free(state); return status; }
    *out_code = code; *out_redirect_uri = redirect; *out_state = state;
    return WF_OK;
}

static char *create_access_jwt(metalbear_oauth_store *store,
                               const char *client_id, const char *scope,
                               const char *dpop_jkt, int64_t expires_at) {
    cJSON *header = cJSON_CreateObject(), *payload = cJSON_CreateObject();
    cJSON *cnf = cJSON_CreateObject();
    char *header_json = NULL, *payload_json = NULL, *header_b64 = NULL;
    char *payload_b64 = NULL, *signature_b64 = NULL, *input = NULL, *jwt = NULL;
    unsigned char signature[64];
    char *jti = NULL;
    int64_t now = (int64_t)time(NULL);
    if (!header || !payload || !cnf || random_value(16, &jti) != WF_OK) goto done;
    cJSON_AddStringToObject(header, "typ", "at+jwt");
    cJSON_AddStringToObject(header, "alg", "ES256");
    cJSON_AddStringToObject(header, "kid", "metalbear-oauth");
    cJSON_AddStringToObject(payload, "iss", store->issuer);
    cJSON_AddStringToObject(payload, "sub", store->subject);
    cJSON_AddStringToObject(payload, "aud", store->issuer);
    cJSON_AddStringToObject(payload, "scope", scope);
    cJSON_AddStringToObject(payload, "client_id", client_id);
    cJSON_AddStringToObject(payload, "jti", jti);
    cJSON_AddNumberToObject(payload, "iat", (double)now);
    cJSON_AddNumberToObject(payload, "exp", (double)expires_at);
    cJSON_AddStringToObject(cnf, "jkt", dpop_jkt);
    cJSON_AddItemToObject(payload, "cnf", cnf); cnf = NULL;
    header_json = cJSON_PrintUnformatted(header);
    payload_json = cJSON_PrintUnformatted(payload);
    if (!header_json || !payload_json ||
        wf_crypto_base64url_encode((const unsigned char *)header_json,
                                   strlen(header_json), &header_b64) != WF_OK ||
        wf_crypto_base64url_encode((const unsigned char *)payload_json,
                                   strlen(payload_json), &payload_b64) != WF_OK)
        goto done;
    size_t input_len = strlen(header_b64) + strlen(payload_b64) + 1;
    input = malloc(input_len + 1);
    if (!input) goto done;
    snprintf(input, input_len + 1, "%s.%s", header_b64, payload_b64);
    if (wf_sign(&store->key, (const unsigned char *)input, input_len,
                signature, sizeof(signature)) != WF_OK ||
        wf_crypto_base64url_encode(signature, sizeof(signature),
                                   &signature_b64) != WF_OK)
        goto done;
    size_t jwt_len = input_len + strlen(signature_b64) + 1;
    jwt = malloc(jwt_len + 1);
    if (jwt) snprintf(jwt, jwt_len + 1, "%s.%s", input, signature_b64);
done:
    OPENSSL_cleanse(signature, sizeof(signature));
    cJSON_Delete(header); cJSON_Delete(payload); cJSON_Delete(cnf);
    free(header_json); free(payload_json); free(header_b64); free(payload_b64);
    free(signature_b64); free(input); free(jti);
    return jwt;
}

static wf_status persist_refresh(metalbear_oauth_store *store,
                                 const char *token, const char *client_id,
                                 const char *scope, const char *jkt,
                                 int64_t expires_at) {
    unsigned char hash[32];
    if (token_hash(token, hash) != WF_OK) return WF_ERR_CRYPTO;
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "INSERT INTO oauth_refresh(token_hash,client_id,scope,dpop_jkt,"
            "expires_at) VALUES(?,?,?,?,?);", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, client_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, scope, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, jkt, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, expires_at);
        status = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    OPENSSL_cleanse(hash, sizeof(hash));
    return status;
}

static wf_status issue_grant(metalbear_oauth_store *store,
                             const char *client_id, const char *scope,
                             const char *jkt, metalbear_oauth_grant *out) {
    memset(out, 0, sizeof(*out));
    int64_t now = (int64_t)time(NULL);
    out->access_token = create_access_jwt(store, client_id, scope, jkt,
                                          now + ACCESS_LIFETIME_SECONDS);
    wf_status status = out->access_token
        ? random_value(32, &out->refresh_token) : WF_ERR_CRYPTO;
    if (status == WF_OK)
        status = persist_refresh(store, out->refresh_token, client_id, scope,
                                 jkt, now + REFRESH_LIFETIME_SECONDS);
    if (status != WF_OK) { metalbear_oauth_grant_free(out); return status; }
    out->expires_in = ACCESS_LIFETIME_SECONDS;
    return WF_OK;
}

wf_status metalbear_oauth_exchange_code(metalbear_oauth_store *store,
                                        const char *code,
                                        const char *client_id,
                                        const char *redirect_uri,
                                        const char *code_verifier,
                                        const char *dpop_jkt,
                                        metalbear_oauth_grant *out) {
    if (!store || !code || !client_id || !redirect_uri || !code_verifier ||
        !dpop_jkt || !out) return WF_ERR_INVALID_ARG;
    unsigned char hash[32];
    token_hash(code, hash);
    wf_oauth_pkce pkce;
    wf_status status = wf_oauth_pkce_from_verifier(code_verifier, &pkce);
    char *stored_client = NULL, *stored_redirect = NULL, *scope = NULL;
    char *challenge = NULL, *jkt = NULL;
    int64_t now = (int64_t)time(NULL);
    pthread_mutex_lock(&store->mutex);
    prune(store, now);
    sqlite3_stmt *stmt = NULL;
    if (status == WF_OK && sqlite3_prepare_v2(store->db,
            "SELECT client_id,redirect_uri,scope,code_challenge,dpop_jkt FROM "
            "oauth_code WHERE code_hash=? AND expires_at>?;", -1, &stmt,
            NULL) != SQLITE_OK) status = WF_ERR_INTERNAL;
    if (status == WF_OK) {
        sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, now);
        if (sqlite3_step(stmt) != SQLITE_ROW) status = WF_ERR_PERMISSION;
    }
    if (status == WF_OK) {
        stored_client = column_copy(stmt, 0); stored_redirect = column_copy(stmt, 1);
        scope = column_copy(stmt, 2); challenge = column_copy(stmt, 3);
        jkt = column_copy(stmt, 4);
        if (!stored_client || !stored_redirect || !scope || !challenge || !jkt)
            status = WF_ERR_ALLOC;
        else if (strcmp(stored_client, client_id) ||
                 strcmp(stored_redirect, redirect_uri) ||
                 strcmp(challenge, pkce.challenge) || strcmp(jkt, dpop_jkt))
            status = WF_ERR_PERMISSION;
    }
    sqlite3_finalize(stmt); stmt = NULL;
    if (status == WF_OK && sqlite3_prepare_v2(store->db,
            "DELETE FROM oauth_code WHERE code_hash=?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE || sqlite3_changes(store->db) != 1)
            status = WF_ERR_PERMISSION;
    } else if (status == WF_OK) status = WF_ERR_INTERNAL;
    sqlite3_finalize(stmt);
    if (status == WF_OK) status = issue_grant(store, client_id, scope, jkt, out);
    pthread_mutex_unlock(&store->mutex);
    OPENSSL_cleanse(hash, sizeof(hash));
    free(stored_client); free(stored_redirect); free(scope); free(challenge); free(jkt);
    return status;
}

wf_status metalbear_oauth_refresh(metalbear_oauth_store *store,
                                  const char *refresh_token,
                                  const char *client_id,
                                  const char *dpop_jkt,
                                  metalbear_oauth_grant *out) {
    if (!store || !refresh_token || !client_id || !dpop_jkt || !out)
        return WF_ERR_INVALID_ARG;
    unsigned char hash[32]; token_hash(refresh_token, hash);
    int64_t now = (int64_t)time(NULL);
    char *stored_client = NULL, *scope = NULL, *jkt = NULL;
    wf_status status = WF_OK;
    pthread_mutex_lock(&store->mutex);
    prune(store, now);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT client_id,scope,dpop_jkt FROM oauth_refresh WHERE "
            "token_hash=? AND expires_at>?;", -1, &stmt, NULL) != SQLITE_OK)
        status = WF_ERR_INTERNAL;
    if (status == WF_OK) {
        sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, now);
        if (sqlite3_step(stmt) != SQLITE_ROW) status = WF_ERR_PERMISSION;
    }
    if (status == WF_OK) {
        stored_client = column_copy(stmt, 0); scope = column_copy(stmt, 1);
        jkt = column_copy(stmt, 2);
        if (!stored_client || !scope || !jkt) status = WF_ERR_ALLOC;
        else if (strcmp(stored_client, client_id) || strcmp(jkt, dpop_jkt))
            status = WF_ERR_PERMISSION;
    }
    sqlite3_finalize(stmt); stmt = NULL;
    if (status == WF_OK && sqlite3_prepare_v2(store->db,
            "DELETE FROM oauth_refresh WHERE token_hash=?;", -1, &stmt,
            NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE || sqlite3_changes(store->db) != 1)
            status = WF_ERR_PERMISSION;
    } else if (status == WF_OK) status = WF_ERR_INTERNAL;
    sqlite3_finalize(stmt);
    if (status == WF_OK) status = issue_grant(store, client_id, scope, jkt, out);
    pthread_mutex_unlock(&store->mutex);
    OPENSSL_cleanse(hash, sizeof(hash));
    free(stored_client); free(scope); free(jkt);
    return status;
}

wf_status metalbear_oauth_revoke(metalbear_oauth_store *store,
                                 const char *token) {
    if (!store || !token) return WF_ERR_INVALID_ARG;
    unsigned char hash[32]; token_hash(token, hash);
    pthread_mutex_lock(&store->mutex);
    sqlite3_stmt *stmt = NULL;
    wf_status status = WF_ERR_INTERNAL;
    if (sqlite3_prepare_v2(store->db,
            "DELETE FROM oauth_refresh WHERE token_hash=?;", -1, &stmt,
            NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
        status = sqlite3_step(stmt) == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&store->mutex);
    OPENSSL_cleanse(hash, sizeof(hash));
    return status;
}

wf_status metalbear_oauth_verify_request(
    metalbear_oauth_store *store, const char *authorization,
    const char *dpop_proof, const char *method, const char *uri,
    wf_oauth_verified_token **out) {
    if (!store) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    wf_status status = wf_oauth_verify_request(
        authorization, dpop_proof, method, uri, store->trusted_keys,
        store->replay, out);
    pthread_mutex_unlock(&store->mutex);
    if (status != WF_OK) return status;
    if (!(*out)->sub || strcmp((*out)->sub, store->subject) ||
        !(*out)->iss || strcmp((*out)->iss, store->issuer) ||
        !(*out)->aud || strcmp((*out)->aud, store->issuer) ||
        !(*out)->scope || !strstr((*out)->scope, "atproto") ||
        !(*out)->dpop_bound) {
        wf_oauth_verified_token_free(*out);
        *out = NULL;
        return WF_ERR_PERMISSION;
    }
    return WF_OK;
}

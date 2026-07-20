#define _POSIX_C_SOURCE 200809L

#include "metalbear/auth.h"

#include <cJSON.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define ACCESS_LIFETIME_SECONDS (2 * 60 * 60)
#define REFRESH_LIFETIME_SECONDS (90 * 24 * 60 * 60)
#define REFRESH_GRACE_SECONDS (2 * 60 * 60)
#define JWT_KEY_BYTES 32
#define JWT_MAX_BYTES 8192

typedef enum token_kind {
    TOKEN_ACCESS,
    TOKEN_REFRESH,
} token_kind;

struct metalbear_auth_store {
    sqlite3 *db;
    unsigned char key[JWT_KEY_BYTES];
    char *service_did;
    char *account_did;
};

static const char b64url_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *base64url_encode(const unsigned char *input, size_t length) {
    size_t capacity = (length + 2) / 3 * 4;
    char *output = malloc(capacity + 1);
    if (!output) return NULL;
    size_t i = 0, o = 0;
    while (i + 3 <= length) {
        uint32_t n = ((uint32_t)input[i] << 16) |
                     ((uint32_t)input[i + 1] << 8) | input[i + 2];
        output[o++] = b64url_alphabet[(n >> 18) & 63];
        output[o++] = b64url_alphabet[(n >> 12) & 63];
        output[o++] = b64url_alphabet[(n >> 6) & 63];
        output[o++] = b64url_alphabet[n & 63];
        i += 3;
    }
    if (length - i == 1) {
        uint32_t n = (uint32_t)input[i] << 16;
        output[o++] = b64url_alphabet[(n >> 18) & 63];
        output[o++] = b64url_alphabet[(n >> 12) & 63];
    } else if (length - i == 2) {
        uint32_t n = ((uint32_t)input[i] << 16) |
                     ((uint32_t)input[i + 1] << 8);
        output[o++] = b64url_alphabet[(n >> 18) & 63];
        output[o++] = b64url_alphabet[(n >> 12) & 63];
        output[o++] = b64url_alphabet[(n >> 6) & 63];
    }
    output[o] = '\0';
    return output;
}

static int base64url_value(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-') return 62;
    if (value == '_') return 63;
    return -1;
}

static unsigned char *base64url_decode(const char *input, size_t length,
                                       size_t *out_length) {
    if (!input || !out_length || length % 4 == 1) return NULL;
    unsigned char *output = malloc(length / 4 * 3 + 3);
    if (!output) return NULL;
    size_t i = 0, o = 0;
    while (length - i >= 4) {
        int a = base64url_value(input[i]);
        int b = base64url_value(input[i + 1]);
        int c = base64url_value(input[i + 2]);
        int d = base64url_value(input[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) goto malformed;
        uint32_t n = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                     ((uint32_t)c << 6) | (uint32_t)d;
        output[o++] = (unsigned char)(n >> 16);
        output[o++] = (unsigned char)(n >> 8);
        output[o++] = (unsigned char)n;
        i += 4;
    }
    if (length - i == 2) {
        int a = base64url_value(input[i]), b = base64url_value(input[i + 1]);
        if (a < 0 || b < 0 || (b & 0x0f) != 0) goto malformed;
        output[o++] = (unsigned char)(((a << 18) | (b << 12)) >> 16);
    } else if (length - i == 3) {
        int a = base64url_value(input[i]), b = base64url_value(input[i + 1]);
        int c = base64url_value(input[i + 2]);
        if (a < 0 || b < 0 || c < 0 || (c & 0x03) != 0) goto malformed;
        uint32_t n = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                     ((uint32_t)c << 6);
        output[o++] = (unsigned char)(n >> 16);
        output[o++] = (unsigned char)(n >> 8);
    }
    *out_length = o;
    return output;

malformed:
    free(output);
    return NULL;
}

static wf_status random_jti(char output[33]) {
    unsigned char random[16];
    static const char hex[] = "0123456789abcdef";
    if (RAND_bytes(random, sizeof(random)) != 1) return WF_ERR_CRYPTO;
    for (size_t i = 0; i < sizeof(random); i++) {
        output[i * 2] = hex[random[i] >> 4];
        output[i * 2 + 1] = hex[random[i] & 15];
    }
    output[32] = '\0';
    return WF_OK;
}

static wf_status sign_hs256(const metalbear_auth_store *store,
                            const char *input, unsigned char output[32]) {
    unsigned int output_length = 0;
    if (!HMAC(EVP_sha256(), store->key, sizeof(store->key),
              (const unsigned char *)input, strlen(input), output,
              &output_length) || output_length != 32)
        return WF_ERR_CRYPTO;
    return WF_OK;
}

static const char *access_scope_name(metalbear_access_scope scope) {
    switch (scope) {
    case METALBEAR_ACCESS_APP_PASSWORD:
        return "com.atproto.appPass";
    case METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED:
        return "com.atproto.appPassPrivileged";
    default:
        return "com.atproto.access";
    }
}

static bool valid_access_scope(metalbear_access_scope scope) {
    return scope == METALBEAR_ACCESS_FULL ||
           scope == METALBEAR_ACCESS_APP_PASSWORD ||
           scope == METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED;
}

static bool parse_access_scope(const char *value,
                               metalbear_access_scope *out) {
    if (!value) return false;
    if (strcmp(value, "com.atproto.access") == 0) {
        if (out) *out = METALBEAR_ACCESS_FULL;
        return true;
    }
    if (strcmp(value, "com.atproto.appPass") == 0) {
        if (out) *out = METALBEAR_ACCESS_APP_PASSWORD;
        return true;
    }
    if (strcmp(value, "com.atproto.appPassPrivileged") == 0) {
        if (out) *out = METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED;
        return true;
    }
    return false;
}

static char *create_jwt(metalbear_auth_store *store, token_kind kind,
                        metalbear_access_scope access_scope, const char *jti,
                        int64_t expires_at) {
    int64_t now = (int64_t)time(NULL);
    const char *type = kind == TOKEN_ACCESS ? "at+jwt" : "refresh+jwt";
    const char *scope = kind == TOKEN_ACCESS ? access_scope_name(access_scope) :
                                               "com.atproto.refresh";
    cJSON *header = cJSON_CreateObject();
    cJSON *payload = cJSON_CreateObject();
    char *header_json = NULL, *payload_json = NULL;
    char *header_b64 = NULL, *payload_b64 = NULL, *signature_b64 = NULL;
    char *signing_input = NULL, *token = NULL;
    unsigned char signature[32];
    if (!header || !payload) goto done;
    cJSON_AddStringToObject(header, "typ", type);
    cJSON_AddStringToObject(header, "alg", "HS256");
    cJSON_AddStringToObject(payload, "scope", scope);
    cJSON_AddStringToObject(payload, "aud", store->service_did);
    cJSON_AddStringToObject(payload, "sub", store->account_did);
    if (kind == TOKEN_REFRESH) cJSON_AddStringToObject(payload, "jti", jti);
    cJSON_AddNumberToObject(payload, "iat", (double)now);
    cJSON_AddNumberToObject(payload, "exp", (double)expires_at);
    header_json = cJSON_PrintUnformatted(header);
    payload_json = cJSON_PrintUnformatted(payload);
    if (!header_json || !payload_json) goto done;
    header_b64 = base64url_encode((const unsigned char *)header_json,
                                  strlen(header_json));
    payload_b64 = base64url_encode((const unsigned char *)payload_json,
                                   strlen(payload_json));
    if (!header_b64 || !payload_b64) goto done;
    size_t input_size = strlen(header_b64) + strlen(payload_b64) + 2;
    signing_input = malloc(input_size);
    if (!signing_input) goto done;
    snprintf(signing_input, input_size, "%s.%s", header_b64, payload_b64);
    if (sign_hs256(store, signing_input, signature) != WF_OK) goto done;
    signature_b64 = base64url_encode(signature, sizeof(signature));
    if (!signature_b64) goto done;
    size_t token_size = strlen(signing_input) + strlen(signature_b64) + 2;
    token = malloc(token_size);
    if (token) snprintf(token, token_size, "%s.%s", signing_input, signature_b64);

done:
    cJSON_Delete(header);
    cJSON_Delete(payload);
    free(header_json);
    free(payload_json);
    free(header_b64);
    free(payload_b64);
    free(signature_b64);
    free(signing_input);
    return token;
}

static wf_status verify_jwt(metalbear_auth_store *store, const char *token,
                            token_kind kind, bool allow_expired,
                            char **out_jti, int64_t *out_exp,
                            metalbear_access_scope *out_scope) {
    if (out_jti) *out_jti = NULL;
    if (out_exp) *out_exp = 0;
    if (!store || !token || !token[0] || strlen(token) > JWT_MAX_BYTES)
        return WF_ERR_INVALID_ARG;
    const char *first_dot = strchr(token, '.');
    const char *second_dot = first_dot ? strchr(first_dot + 1, '.') : NULL;
    if (!first_dot || !second_dot || strchr(second_dot + 1, '.'))
        return WF_ERR_PERMISSION;

    size_t signing_length = (size_t)(second_dot - token);
    char *signing_input = strndup(token, signing_length);
    size_t signature_length = 0;
    unsigned char *signature = base64url_decode(second_dot + 1,
                                                strlen(second_dot + 1),
                                                &signature_length);
    unsigned char expected[32];
    if (!signing_input || !signature || signature_length != sizeof(expected) ||
        sign_hs256(store, signing_input, expected) != WF_OK ||
        CRYPTO_memcmp(signature, expected, sizeof(expected)) != 0) {
        free(signing_input);
        free(signature);
        return WF_ERR_PERMISSION;
    }
    free(signature);

    size_t header_length = 0, payload_length = 0;
    unsigned char *header_raw = base64url_decode(
        token, (size_t)(first_dot - token), &header_length);
    unsigned char *payload_raw = base64url_decode(
        first_dot + 1, (size_t)(second_dot - first_dot - 1), &payload_length);
    cJSON *header = header_raw ? cJSON_ParseWithLength((char *)header_raw,
                                                       header_length) : NULL;
    cJSON *payload = payload_raw ? cJSON_ParseWithLength((char *)payload_raw,
                                                         payload_length) : NULL;
    free(signing_input);
    free(header_raw);
    free(payload_raw);
    if (!header || !payload) {
        cJSON_Delete(header);
        cJSON_Delete(payload);
        return WF_ERR_PERMISSION;
    }

    const char *required_type = kind == TOKEN_ACCESS ? "at+jwt" : "refresh+jwt";
    cJSON *alg = cJSON_GetObjectItemCaseSensitive(header, "alg");
    cJSON *typ = cJSON_GetObjectItemCaseSensitive(header, "typ");
    cJSON *scope = cJSON_GetObjectItemCaseSensitive(payload, "scope");
    cJSON *aud = cJSON_GetObjectItemCaseSensitive(payload, "aud");
    cJSON *sub = cJSON_GetObjectItemCaseSensitive(payload, "sub");
    cJSON *iat = cJSON_GetObjectItemCaseSensitive(payload, "iat");
    cJSON *exp = cJSON_GetObjectItemCaseSensitive(payload, "exp");
    cJSON *jti = cJSON_GetObjectItemCaseSensitive(payload, "jti");
    int64_t now = (int64_t)time(NULL);
    metalbear_access_scope parsed_scope = METALBEAR_ACCESS_FULL;
    bool scope_valid = cJSON_IsString(scope) &&
        (kind == TOKEN_ACCESS ? parse_access_scope(scope->valuestring,
                                                   &parsed_scope) :
         strcmp(scope->valuestring, "com.atproto.refresh") == 0);
    bool valid = cJSON_IsString(alg) && strcmp(alg->valuestring, "HS256") == 0 &&
        cJSON_IsString(typ) && strcmp(typ->valuestring, required_type) == 0 &&
        scope_valid &&
        cJSON_IsString(aud) && strcmp(aud->valuestring, store->service_did) == 0 &&
        cJSON_IsString(sub) && strcmp(sub->valuestring, store->account_did) == 0 &&
        cJSON_IsNumber(iat) && iat->valuedouble <= (double)(now + 60) &&
        cJSON_IsNumber(exp) && (allow_expired || exp->valuedouble > (double)now) &&
        (kind == TOKEN_ACCESS || cJSON_IsString(jti));
    char *jti_copy = valid && kind == TOKEN_REFRESH ? strdup(jti->valuestring) : NULL;
    if (valid && kind == TOKEN_REFRESH && !jti_copy) valid = false;
    if (valid && out_exp) *out_exp = (int64_t)exp->valuedouble;
    if (valid && out_scope) *out_scope = parsed_scope;
    cJSON_Delete(header);
    cJSON_Delete(payload);
    if (!valid) {
        free(jti_copy);
        return WF_ERR_PERMISSION;
    }
    if (out_jti) *out_jti = jti_copy; else free(jti_copy);
    return WF_OK;
}

static wf_status execute(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? WF_OK :
                                                                  WF_ERR_INTERNAL;
}

static wf_status load_or_create_key(metalbear_auth_store *store) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT value FROM auth_meta WHERE key='jwt_key';", -1,
            &statement, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    int result = sqlite3_step(statement);
    if (result == SQLITE_ROW) {
        const void *key = sqlite3_column_blob(statement, 0);
        int length = sqlite3_column_bytes(statement, 0);
        if (length == JWT_KEY_BYTES) memcpy(store->key, key, JWT_KEY_BYTES);
        sqlite3_finalize(statement);
        return length == JWT_KEY_BYTES ? WF_OK : WF_ERR_CONFIG;
    }
    sqlite3_finalize(statement);
    if (result != SQLITE_DONE || RAND_bytes(store->key, sizeof(store->key)) != 1)
        return WF_ERR_CRYPTO;
    if (sqlite3_prepare_v2(store->db,
            "INSERT INTO auth_meta(key,value) VALUES('jwt_key',?);", -1,
            &statement, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_blob(statement, 1, store->key, sizeof(store->key),
                      SQLITE_TRANSIENT);
    result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return result == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

wf_status metalbear_auth_store_open(const char *path, const char *service_did,
                                    const char *account_did,
                                    metalbear_auth_store **out) {
    if (!path || !service_did || !account_did || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_auth_store *store = calloc(1, sizeof(*store));
    if (!store) return WF_ERR_ALLOC;
    store->service_did = strdup(service_did);
    store->account_did = strdup(account_did);
    if (!store->service_did || !store->account_did ||
        sqlite3_open_v2(path, &store->db, SQLITE_OPEN_READWRITE |
                        SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK)
        goto fail;
    chmod(path, 0600);
    if (execute(store->db, "PRAGMA journal_mode=WAL;") != WF_OK ||
        execute(store->db, "PRAGMA foreign_keys=ON;") != WF_OK ||
        execute(store->db,
            "CREATE TABLE IF NOT EXISTS auth_meta("
            "key TEXT PRIMARY KEY,value BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS refresh_token("
            "jti TEXT PRIMARY KEY,did TEXT NOT NULL,expires_at INTEGER NOT NULL,"
            "next_jti TEXT,grace_expires_at INTEGER,revoked INTEGER NOT NULL DEFAULT 0,"
            "access_scope INTEGER NOT NULL DEFAULT 0,app_password_name TEXT);"
            "CREATE INDEX IF NOT EXISTS refresh_expiry_idx ON refresh_token(expires_at);") != WF_OK ||
        load_or_create_key(store) != WF_OK)
        goto fail;
    sqlite3_exec(store->db,
        "ALTER TABLE refresh_token ADD COLUMN access_scope INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);
    sqlite3_exec(store->db,
        "ALTER TABLE refresh_token ADD COLUMN app_password_name TEXT;",
        NULL, NULL, NULL);
    *out = store;
    return WF_OK;

fail:
    metalbear_auth_store_free(store);
    return WF_ERR_INTERNAL;
}

void metalbear_auth_store_free(metalbear_auth_store *store) {
    if (!store) return;
    sqlite3_close(store->db);
    OPENSSL_cleanse(store->key, sizeof(store->key));
    free(store->service_did);
    free(store->account_did);
    free(store);
}

void metalbear_session_tokens_free(metalbear_session_tokens *tokens) {
    if (!tokens) return;
    free(tokens->access_jwt);
    free(tokens->refresh_jwt);
    memset(tokens, 0, sizeof(*tokens));
}

static wf_status persist_refresh(metalbear_auth_store *store, const char *jti,
                                 int64_t expires_at,
                                 metalbear_access_scope scope,
                                 const char *app_password_name) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(store->db,
            "INSERT INTO refresh_token(jti,did,expires_at,access_scope,"
            "app_password_name) VALUES(?,?,?,?,?);",
            -1, &statement, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(statement, 1, jti, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, store->account_did, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 3, expires_at);
    sqlite3_bind_int(statement, 4, (int)scope);
    if (app_password_name)
        sqlite3_bind_text(statement, 5, app_password_name, -1,
                          SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(statement, 5);
    int result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return result == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

static void prune_expired_refreshes(metalbear_auth_store *store, int64_t now) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(store->db,
            "DELETE FROM refresh_token WHERE expires_at<=? OR "
            "(next_jti IS NOT NULL AND grace_expires_at<=?);", -1,
            &statement, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int64(statement, 1, now);
    sqlite3_bind_int64(statement, 2, now);
    sqlite3_step(statement);
    sqlite3_finalize(statement);
}

static wf_status issue_pair(metalbear_auth_store *store, const char *jti,
                            int64_t refresh_expiry,
                            metalbear_access_scope scope,
                            metalbear_session_tokens *out) {
    memset(out, 0, sizeof(*out));
    int64_t now = (int64_t)time(NULL);
    out->access_jwt = create_jwt(store, TOKEN_ACCESS, scope, NULL,
                                 now + ACCESS_LIFETIME_SECONDS);
    out->refresh_jwt = create_jwt(store, TOKEN_REFRESH, scope, jti,
                                  refresh_expiry);
    if (!out->access_jwt || !out->refresh_jwt) {
        metalbear_session_tokens_free(out);
        return WF_ERR_CRYPTO;
    }
    return WF_OK;
}

wf_status metalbear_auth_create_session(metalbear_auth_store *store,
                                        metalbear_session_tokens *out) {
    return metalbear_auth_create_scoped_session(store, METALBEAR_ACCESS_FULL,
                                                NULL, out);
}

wf_status metalbear_auth_create_scoped_session(
    metalbear_auth_store *store, metalbear_access_scope scope,
    const char *app_password_name, metalbear_session_tokens *out) {
    if (!store || !out) return WF_ERR_INVALID_ARG;
    if (!valid_access_scope(scope) ||
        (scope != METALBEAR_ACCESS_FULL &&
         (!app_password_name || !app_password_name[0])))
        return WF_ERR_INVALID_ARG;
    char jti[33];
    int64_t now = (int64_t)time(NULL);
    int64_t expiry = now + REFRESH_LIFETIME_SECONDS;
    prune_expired_refreshes(store, now);
    wf_status status = random_jti(jti);
    if (status == WF_OK)
        status = persist_refresh(store, jti, expiry, scope, app_password_name);
    if (status == WF_OK) status = issue_pair(store, jti, expiry, scope, out);
    return status;
}

wf_status metalbear_auth_verify_access(metalbear_auth_store *store,
                                       const char *token) {
    return verify_jwt(store, token, TOKEN_ACCESS, false, NULL, NULL, NULL);
}

wf_status metalbear_auth_verify_access_scope(metalbear_auth_store *store,
                                             const char *token,
                                             metalbear_access_scope *out_scope) {
    if (!out_scope) return WF_ERR_INVALID_ARG;
    return verify_jwt(store, token, TOKEN_ACCESS, false, NULL, NULL,
                      out_scope);
}

wf_status metalbear_auth_rotate_refresh(metalbear_auth_store *store,
                                        const char *refresh_token,
                                        metalbear_session_tokens *out) {
    if (!store || !refresh_token || !out) return WF_ERR_INVALID_ARG;
    char *jti = NULL;
    int64_t token_expiry = 0;
    wf_status status = verify_jwt(store, refresh_token, TOKEN_REFRESH, false,
                                  &jti, &token_expiry, NULL);
    if (status != WF_OK) return status;
    prune_expired_refreshes(store, (int64_t)time(NULL));

    sqlite3_stmt *statement = NULL;
    const char *next = NULL;
    char *next_copy = NULL;
    char *app_password_name = NULL;
    int64_t stored_expiry = 0, grace_expiry = 0;
    int revoked = 0;
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    if (sqlite3_prepare_v2(store->db,
            "SELECT expires_at,next_jti,grace_expires_at,revoked,access_scope,"
            "app_password_name FROM refresh_token "
            "WHERE jti=? AND did=?;", -1, &statement, NULL) != SQLITE_OK)
        status = WF_ERR_INTERNAL;
    if (status == WF_OK) {
        sqlite3_bind_text(statement, 1, jti, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, store->account_did, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) != SQLITE_ROW) status = WF_ERR_PERMISSION;
    }
    if (status == WF_OK) {
        stored_expiry = sqlite3_column_int64(statement, 0);
        next = (const char *)sqlite3_column_text(statement, 1);
        grace_expiry = sqlite3_column_type(statement, 2) == SQLITE_NULL ? 0 :
                       sqlite3_column_int64(statement, 2);
        revoked = sqlite3_column_int(statement, 3);
        scope = (metalbear_access_scope)sqlite3_column_int(statement, 4);
        if (!valid_access_scope(scope)) status = WF_ERR_PERMISSION;
        const char *name = (const char *)sqlite3_column_text(statement, 5);
        if (name) {
            app_password_name = strdup(name);
            if (!app_password_name) status = WF_ERR_ALLOC;
        }
        if (next) {
            next_copy = strdup(next);
            if (!next_copy) status = WF_ERR_ALLOC;
        }
    }
    sqlite3_finalize(statement);
    int64_t now = (int64_t)time(NULL);
    if (status != WF_OK || revoked || stored_expiry <= now ||
        (next_copy && grace_expiry <= now)) {
        free(jti);
        free(next_copy);
        free(app_password_name);
        return status == WF_OK ? WF_ERR_PERMISSION : status;
    }

    char generated[33];
    if (!next_copy) {
        if (random_jti(generated) != WF_OK) {
            free(jti);
            free(app_password_name);
            return WF_ERR_CRYPTO;
        }
        next_copy = strdup(generated);
        int64_t grace = now + REFRESH_GRACE_SECONDS;
        if (grace > stored_expiry) grace = stored_expiry;
        int64_t next_expiry = now + REFRESH_LIFETIME_SECONDS;
        if (execute(store->db, "BEGIN IMMEDIATE;") != WF_OK ||
            sqlite3_prepare_v2(store->db,
                "UPDATE refresh_token SET next_jti=?,grace_expires_at=? "
                "WHERE jti=? AND next_jti IS NULL AND revoked=0;", -1,
                &statement, NULL) != SQLITE_OK) {
            execute(store->db, "ROLLBACK;");
            free(jti); free(next_copy); free(app_password_name);
            return WF_ERR_INTERNAL;
        }
        sqlite3_bind_text(statement, 1, next_copy, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 2, grace);
        sqlite3_bind_text(statement, 3, jti, -1, SQLITE_TRANSIENT);
        int result = sqlite3_step(statement);
        int changes = sqlite3_changes(store->db);
        sqlite3_finalize(statement);
        if (result == SQLITE_DONE && changes == 0) {
            /* A concurrent refresh established the successor after our first
             * read. Roll back the stale attempt and reuse that successor. */
            execute(store->db, "ROLLBACK;");
            free(jti);
            free(next_copy);
            free(app_password_name);
            return metalbear_auth_rotate_refresh(store, refresh_token, out);
        }
        if (result != SQLITE_DONE ||
            persist_refresh(store, next_copy, next_expiry, scope,
                            app_password_name) != WF_OK ||
            execute(store->db, "COMMIT;") != WF_OK) {
            execute(store->db, "ROLLBACK;");
            free(jti); free(next_copy); free(app_password_name);
            return WF_ERR_INTERNAL;
        }
        token_expiry = next_expiry;
    } else {
        if (sqlite3_prepare_v2(store->db,
                "SELECT expires_at,access_scope FROM refresh_token WHERE "
                "jti=? AND revoked=0;",
                -1, &statement, NULL) != SQLITE_OK) {
            free(jti); free(next_copy); free(app_password_name);
            return WF_ERR_INTERNAL;
        }
        sqlite3_bind_text(statement, 1, next_copy, -1, SQLITE_TRANSIENT);
        status = sqlite3_step(statement) == SQLITE_ROW ? WF_OK : WF_ERR_PERMISSION;
        if (status == WF_OK) {
            token_expiry = sqlite3_column_int64(statement, 0);
            scope = (metalbear_access_scope)sqlite3_column_int(statement, 1);
            if (!valid_access_scope(scope)) status = WF_ERR_PERMISSION;
        }
        sqlite3_finalize(statement);
    }
    if (status == WF_OK)
        status = issue_pair(store, next_copy, token_expiry, scope, out);
    free(jti);
    free(next_copy);
    free(app_password_name);
    return status;
}

wf_status metalbear_auth_revoke_refresh(metalbear_auth_store *store,
                                        const char *refresh_token) {
    if (!store || !refresh_token) return WF_ERR_INVALID_ARG;
    char *jti = NULL;
    wf_status status = verify_jwt(store, refresh_token, TOKEN_REFRESH, true,
                                  &jti, NULL, NULL);
    if (status != WF_OK) return status;
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(store->db,
            "UPDATE refresh_token SET revoked=1 WHERE jti=? AND did=?;", -1,
            &statement, NULL) != SQLITE_OK) {
        free(jti);
        return WF_ERR_INTERNAL;
    }
    sqlite3_bind_text(statement, 1, jti, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, store->account_did, -1, SQLITE_TRANSIENT);
    int result = sqlite3_step(statement);
    int changes = sqlite3_changes(store->db);
    sqlite3_finalize(statement);
    free(jti);
    return result == SQLITE_DONE && changes == 1 ? WF_OK : WF_ERR_PERMISSION;
}

wf_status metalbear_auth_revoke_app_password_sessions(
    metalbear_auth_store *store, const char *app_password_name) {
    if (!store || !app_password_name || !app_password_name[0])
        return WF_ERR_INVALID_ARG;
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(store->db,
            "UPDATE refresh_token SET revoked=1 WHERE did=? AND "
            "app_password_name=?;", -1, &statement, NULL) != SQLITE_OK)
        return WF_ERR_INTERNAL;
    sqlite3_bind_text(statement, 1, store->account_did, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, app_password_name, -1, SQLITE_TRANSIENT);
    int result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return result == SQLITE_DONE ? WF_OK : WF_ERR_INTERNAL;
}

wf_status metalbear_auth_delete_all(metalbear_auth_store *store) {
    if (!store) return WF_ERR_INVALID_ARG;
    return execute(store->db,
                   "DELETE FROM refresh_token;"
                   "DELETE FROM auth_meta;");
}

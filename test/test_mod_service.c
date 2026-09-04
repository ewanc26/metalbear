/* test_mod_service.c — app.bsky.actor.getPreferences moderator-service
 * support (the reference's authorizationOrModService) and the hasAccessFull
 * preference partition.
 *
 * The server is configured with a mod_service_did (a did:key derived from a
 * freshly generated P-256 keypair, so the inbound service JWT verifies
 * offline — did:key issuers are verified without DID-document resolution).
 * Covers:
 *   - a valid service JWT reads another account's full preference set via the
 *     undocumented `did` query parameter (moderator => hasAccessFull);
 *   - missing/invalid `did` => 400 InvalidRequest, unknown account => 400
 *     NotFound;
 *   - a service JWT never authenticates a write (putPreferences answers like
 *     any other non-mod_service route);
 *   - a tampered token, a wrong-lxm token, and a wrong-aud token fall through
 *     to ordinary user-token auth and are refused (401), not mis-accepted;
 *   - a standard-scope (app-password) session cannot read or write the
 *     full-access-only personalDetailsPref, while a full session can.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "metalbear/server.h"
#include "wolfram/crypto.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

/* Case-sensitive substring search over a length-delimited body. */
static bool body_contains(const wf_response *response, const char *needle) {
    if (!response || !response->body || !needle) return false;
    size_t nlen = strlen(needle);
    if (nlen == 0) return true;
    if (response->body_len < nlen) return false;
    for (size_t i = 0; i + nlen <= response->body_len; i++) {
        if (memcmp(response->body + i, needle, nlen) == 0) return true;
    }
    return false;
}

/* base64url(self/containing) helpers for building test JWTs. */
static char *b64url(const unsigned char *in, size_t len) {
    char *out = NULL;
    if (wf_crypto_base64url_encode(in, len, &out) != WF_OK) return NULL;
    return out;
}

/* Mint an ES256 service JWT signed by `key` (P-256). exp is
 * now_seconds + exp_offset; lxm may be NULL to omit the claim (the reference
 * verifier rejects a missing lxm, so that is a valid negative test). */
static char *mint_service_jwt(const wf_signing_key *key, const char *iss,
                              const char *aud, const char *lxm,
                              int exp_offset) {
    char *token = NULL;
    cJSON *payload = cJSON_CreateObject();
    if (!payload) return NULL;
    cJSON_AddStringToObject(payload, "iss", iss);
    cJSON_AddStringToObject(payload, "aud", aud);
    cJSON_AddNumberToObject(payload, "exp",
                            (double)time(NULL) + (double)exp_offset);
    if (lxm) cJSON_AddStringToObject(payload, "lxm", lxm);
    char *pl = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);
    if (!pl) return NULL;
    const char *header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
    char *h64 = b64url((const unsigned char *)header, strlen(header));
    char *p64 = b64url((const unsigned char *)pl, strlen(pl));
    free(pl);
    if (!h64 || !p64) goto done;
    size_t ilen = strlen(h64) + 1 + strlen(p64);
    char *input = malloc(ilen + 1);
    if (!input) goto done;
    snprintf(input, ilen + 1, "%s.%s", h64, p64);
    unsigned char sig[64];
    if (wf_sign(key, (const unsigned char *)input, ilen, sig, sizeof sig) !=
        WF_OK) {
        free(input);
        goto done;
    }
    char *s64 = b64url(sig, sizeof sig);
    if (!s64) {
        free(input);
        goto done;
    }
    size_t tlen = ilen + 1 + strlen(s64);
    token = malloc(tlen + 1);
    if (token) snprintf(token, tlen + 1, "%s.%s", input, s64);
    free(input);
    free(s64);
done:
    free(h64);
    free(p64);
    return token;
}

static int rmtree_remove_cb(const char *path, const struct stat *sb, int type,
                            struct FTW *ftwbuf) {
    (void)sb;
    (void)type;
    (void)ftwbuf;
    return remove(path);
}
static void rmtree(const char *path) {
    nftw(path, rmtree_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

#define PREFS_FULL                                                             \
    "{\"preferences\":[{\"$type\":\"app.bsky.actor.defs."                      \
    "personalDetailsPref\","                                                   \
    "\"birthDate\":\"2000-01-01\"},"                                           \
    "{\"$type\":\"app.bsky.actor.defs.feedViewPref\","                         \
    "\"feed\":\"home\",\"itemsPerPage\":25}]}"
#define PREFS_PERSONAL_ONLY                                                    \
    "{\"preferences\":[{\"$type\":\"app.bsky.actor.defs."                      \
    "personalDetailsPref\","                                                   \
    "\"birthDate\":\"1990-05-05\"}]}"

int main(void) {
    wf_signing_key mod_key = {0};
    CHECK(wf_signing_key_generate(WF_KEY_TYPE_P256, &mod_key) == WF_OK);
    char *mod_did = NULL;
    CHECK(wf_signing_key_public_didkey(&mod_key, &mod_did) == WF_OK);
    if (!mod_did) return 1;

    char directory[] = "/tmp/metalbear-modtest-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .invite_required = false,
        .rate_limit = 10000,
        .mod_service_did = mod_did,
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) return 1;

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);
    wf_response response = {0};

    /* The account whose preferences the mod service will read. */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                            "{\"handle\":\"bob.example.com\","
                            "\"password\":\"bobsecret\","
                            "\"email\":\"bob@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    char bob_did[128] = "";
    cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
    if (cJSON_IsString(did) && did->valuestring)
        snprintf(bob_did, sizeof(bob_did), "%s", did->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    CHECK(bob_did[0] != '\0');

    /* Full-access session: can write and read the full-access-only pref. */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                            "{\"identifier\":\"bob.example.com\","
                            "\"password\":\"bobsecret\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *full_token =
        cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    CHECK(full_token != NULL);
    wf_xrpc_client_set_auth(client, full_token);

    CHECK(wf_xrpc_procedure(client, "app.bsky.actor.putPreferences", PREFS_FULL,
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    CHECK(wf_xrpc_query(client, "app.bsky.actor.getPreferences", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *prefs = cJSON_GetObjectItemCaseSensitive(json, "preferences");
    CHECK(cJSON_IsArray(prefs));
    CHECK(cJSON_GetArraySize(prefs) == 2);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* --- Mod-service read: valid service JWT, target via `did` param --- */
    char *svc = mint_service_jwt(&mod_key, mod_did, config.service_did,
                                 "app.bsky.actor.getPreferences", 600);
    CHECK(svc != NULL);
    wf_xrpc_client_set_auth(client, svc);
    wf_xrpc_param did_params[] = {{"did", bob_did}};
    CHECK(wf_xrpc_query_params(client, "app.bsky.actor.getPreferences",
                               did_params, 1, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    prefs = cJSON_GetObjectItemCaseSensitive(json, "preferences");
    CHECK(cJSON_IsArray(prefs));
    CHECK(cJSON_GetArraySize(prefs) == 2); /* moderator sees personalDetails */
    cJSON_Delete(json);
    wf_response_free(&response);

    /* Missing / invalid / unknown `did` target. */
    CHECK(wf_xrpc_query(client, "app.bsky.actor.getPreferences", NULL,
                        &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidRequest") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_param bad_did_params[] = {{"did", "bob.example.com"}};
    CHECK(wf_xrpc_query_params(client, "app.bsky.actor.getPreferences",
                               bad_did_params, 1, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidRequest") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_param unknown_did_params[] = {
        {"did", "did:plc:aaaaaaaaaaaaaaaaaaaaaa"}};
    CHECK(wf_xrpc_query_params(client, "app.bsky.actor.getPreferences",
                               unknown_did_params, 1,
                               &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "NotFound") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* A service JWT does not authenticate putPreferences (plain
     * authorization, like every other route): refused as invalid. */
    CHECK(wf_xrpc_procedure(client, "app.bsky.actor.putPreferences",
                            PREFS_PERSONAL_ONLY, &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);

    /* --- Negative verification: tampered / wrong-lxm / wrong-aud fall
     * through to user-token auth and are rejected --- */
    CHECK(svc != NULL && strlen(svc) > 8);
    char *tampered = strdup(svc);
    tampered[strlen(tampered) - 3] =
        tampered[strlen(tampered) - 3] == 'A' ? 'B' : 'A';
    wf_xrpc_client_set_auth(client, tampered);
    wf_xrpc_query_params(client, "app.bsky.actor.getPreferences", did_params, 1,
                         &response);
    CHECK(response.status == 401);
    wf_response_free(&response);
    free(tampered);

    char *wrong_lxm = mint_service_jwt(&mod_key, mod_did, config.service_did,
                                       "app.bsky.actor.getProfile", 600);
    CHECK(wrong_lxm != NULL);
    wf_xrpc_client_set_auth(client, wrong_lxm);
    wf_xrpc_query_params(client, "app.bsky.actor.getPreferences", did_params, 1,
                         &response);
    CHECK(response.status == 401);
    wf_response_free(&response);
    free(wrong_lxm);

    char *wrong_aud =
        mint_service_jwt(&mod_key, mod_did, "did:web:evil.example",
                         "app.bsky.actor.getPreferences", 600);
    CHECK(wrong_aud != NULL);
    wf_xrpc_client_set_auth(client, wrong_aud);
    wf_xrpc_query_params(client, "app.bsky.actor.getPreferences", did_params, 1,
                         &response);
    CHECK(response.status == 401);
    wf_response_free(&response);
    free(wrong_aud);

    char *expired = mint_service_jwt(&mod_key, mod_did, config.service_did,
                                     "app.bsky.actor.getPreferences", -600);
    CHECK(expired != NULL);
    wf_xrpc_client_set_auth(client, expired);
    wf_xrpc_query_params(client, "app.bsky.actor.getPreferences", did_params, 1,
                         &response);
    CHECK(response.status == 401);
    wf_response_free(&response);
    free(expired);

    /* --- hasAccessFull partition: an app password lacks full access --- */
    wf_xrpc_client_set_auth(client, full_token);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAppPassword",
                            "{\"name\":\"mod-test\"}", &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *pw = cJSON_GetObjectItemCaseSensitive(json, "password");
    char *app_password = cJSON_IsString(pw) ? strdup(pw->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    CHECK(app_password != NULL);

    char *app_body = malloc(strlen(bob_did) + strlen(app_password) + 96);
    snprintf(app_body, strlen(bob_did) + strlen(app_password) + 96,
             "{\"identifier\":\"bob.example.com\",\"password\":\"%s\"}",
             app_password);
    wf_xrpc_client_set_auth(client, NULL);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                            app_body, &response) == WF_OK);
    free(app_body);
    CHECK(response.status == 200);
    json = json_response(&response);
    access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *app_token =
        cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    free(app_password);
    CHECK(app_token != NULL);
    wf_xrpc_client_set_auth(client, app_token);

    /* Reads hide the full-access-only pref. */
    CHECK(wf_xrpc_query(client, "app.bsky.actor.getPreferences", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    prefs = cJSON_GetObjectItemCaseSensitive(json, "preferences");
    CHECK(cJSON_IsArray(prefs));
    CHECK(cJSON_GetArraySize(prefs) == 1);
    CHECK(!body_contains(&response, "personalDetailsPref"));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* Writes refuse the full-access-only pref. */
    CHECK(wf_xrpc_procedure(client, "app.bsky.actor.putPreferences",
                            PREFS_PERSONAL_ONLY, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidRequest") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* A declaredAgePref is never persisted (read-only, computed server-side).
     */
    CHECK(
        wf_xrpc_procedure(client, "app.bsky.actor.putPreferences",
                          "{\"preferences\":[{\"$type\":\"app.bsky.actor.defs."
                          "declaredAgePref\",\"isOverAge13\":true}]}",
                          &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);
    CHECK(wf_xrpc_query(client, "app.bsky.actor.getPreferences", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    CHECK(!body_contains(&response, "declaredAgePref"));
    wf_response_free(&response);

    free(app_token);
    free(full_token);
    free(svc);
    wf_xrpc_client_set_auth(client, NULL);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    free(mod_did);

    rmtree(directory);
    if (failures) fprintf(stderr, "%d test(s) failed\n", failures);
    return failures ? 1 : 0;
}
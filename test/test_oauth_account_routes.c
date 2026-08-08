#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_oauth_account_routes.c — offline coverage for the account-management
 * listings added for issue #26 item 4: com.metalbear.oauth.listDevices /
 * revokeDevice and .listGrants / revokeGrant.
 *
 * Unlike oauth_routes.c's /oauth/ routes (device-session cookie auth),
 * these are ordinary JWT-authenticated XRPC procedures/queries -- "manage
 * my own account", reached the same way listAppPasswords is. This file
 * drives the full HTTP flow to seed real state (a device session via
 * /oauth/signin, a real OAuth grant via PAR -> authorize -> token exchange)
 * rather than reaching into internal structures, so it exercises exactly
 * what the frontend's account pages will call.
 *
 * Covers: listing an account's own device sessions and connected apps;
 * revoking one of each and confirming it disappears (and, for a device
 * session, that its cookie stops authenticating); and that revoking by a
 * sessionId scoped to a DIFFERENT account is refused (404), not merely
 * "not found" by accident -- one account must never be able to sign
 * another one's device out by guessing or reusing an id.
 */

#include "metalbear/server.h"
#include "wolfram/oauth.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <curl/curl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

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

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *password) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\",\"email\":\"%s@example.com\"}",
             handle, password, handle);
    wf_response response = {0};
    if (wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                          &response) != WF_OK ||
        response.status != 200) {
        wf_response_free(&response);
        return NULL;
    }
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

static wf_status oauth_post(wf_xrpc_client *client, const char *base,
                            const char *path, const char *body,
                            const wf_http_header *extra, size_t extra_count,
                            wf_response *out) {
    char url[256];
    snprintf(url, sizeof(url), "%s%s", base, path);
    return wf_http_post(client, url, "application/json", body, extra,
                        extra_count, out);
}

static wf_status oauth_form_post(wf_xrpc_client *client, const char *base,
                                 const char *path, const char *body,
                                 wf_response *out) {
    char url[256];
    snprintf(url, sizeof(url), "%s%s", base, path);
    return wf_http_post(client, url, "application/x-www-form-urlencoded", body,
                        NULL, 0, out);
}

static char *extract_cookie_pair(const char *set_cookie) {
    if (!set_cookie) return NULL;
    const char *semi = strchr(set_cookie, ';');
    size_t len = semi ? (size_t)(semi - set_cookie) : strlen(set_cookie);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, set_cookie, len);
    out[len] = '\0';
    return out;
}

/* Sign in via /oauth/signin, returning the device-session cookie pair. */
static char *sign_in_device(wf_xrpc_client *client, const char *base,
                            const char *handle, const char *password) {
    char body[256];
    snprintf(body, sizeof(body), "{\"identifier\":\"%s\",\"password\":\"%s\"}",
             handle, password);
    wf_response response = {0};
    CHECK(oauth_post(client, base, "/oauth/signin", body, NULL, 0, &response) ==
          WF_OK);
    CHECK(response.status == 200);
    char *cookie = extract_cookie_pair(response.set_cookie);
    wf_response_free(&response);
    return cookie;
}

/* Full PAR -> authorize -> code exchange, seeding a real oauth_refresh row
 * (a "connected app") for `handle`'s account under `client_id`. */
static bool seed_grant(wf_xrpc_client *client, const char *base,
                       const char *handle, const char *device_cookie,
                       const char *client_id, const char *seed) {
    char verifier[128];
    snprintf(verifier, sizeof(verifier),
             "v3ry-long-test-verifier-with-enough-entropy-%s", seed);
    wf_oauth_pkce pkce = {0};
    if (wf_oauth_pkce_from_verifier(verifier, &pkce) != WF_OK) return false;

    char *enc_cid = curl_easy_escape(NULL, client_id, 0);
    char *enc_redir =
        curl_easy_escape(NULL, "https://client.example/callback", 0);
    char par_body[1024];
    snprintf(par_body, sizeof(par_body),
             "client_id=%s&redirect_uri=%s&scope=atproto&state=xyz&"
             "code_challenge=%s&"
             "dpop_jkt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
             enc_cid, enc_redir, pkce.challenge);
    wf_response response = {0};
    if (oauth_form_post(client, base, "/oauth/par", par_body, &response) !=
            WF_OK ||
        response.status != 201) {
        wf_response_free(&response);
        curl_free(enc_cid);
        curl_free(enc_redir);
        return false;
    }
    cJSON *par_json = json_response(&response);
    cJSON *ru = cJSON_GetObjectItemCaseSensitive(par_json, "request_uri");
    char request_uri[256] = "";
    if (cJSON_IsString(ru))
        snprintf(request_uri, sizeof(request_uri), "%s", ru->valuestring);
    cJSON_Delete(par_json);
    wf_response_free(&response);
    if (!request_uri[0]) {
        curl_free(enc_cid);
        curl_free(enc_redir);
        return false;
    }

    char *enc_ru = curl_easy_escape(NULL, request_uri, 0);
    char *enc_hint = curl_easy_escape(NULL, handle, 0);
    char authorize_url[768];
    snprintf(authorize_url, sizeof(authorize_url),
             "%s/oauth/authorize?request_uri=%s&client_id=%s&login_hint=%s",
             base, enc_ru, enc_cid, enc_hint);
    curl_free(enc_ru);
    curl_free(enc_hint);

    wf_http_header hdr = {"Cookie", device_cookie};
    wf_status s =
        wf_http_get_with_headers(client, authorize_url, &hdr, 1, &response);
    bool authorized = s == WF_ERR_HTTP && response.status == 302 &&
                      response.location && strstr(response.location, "code=");
    char code[256] = "";
    if (authorized) {
        const char *c = strstr(response.location, "code=");
        c += 5;
        const char *end = strchr(c, '&');
        size_t len = end ? (size_t)(end - c) : strlen(c);
        if (len < sizeof(code)) {
            memcpy(code, c, len);
            code[len] = '\0';
        }
    }
    wf_response_free(&response);
    if (!code[0]) {
        curl_free(enc_cid);
        curl_free(enc_redir);
        return false;
    }

    char token_body[1024];
    snprintf(token_body, sizeof(token_body),
             "grant_type=authorization_code&code=%s&client_id=%s&"
             "redirect_uri=%s&code_verifier=%s&"
             "dpop_jkt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
             code, enc_cid, enc_redir, pkce.verifier);
    curl_free(enc_cid);
    curl_free(enc_redir);
    bool ok = oauth_form_post(client, base, "/oauth/token", token_body,
                              &response) == WF_OK &&
              response.status == 200;
    if (ok) {
        cJSON *tj = json_response(&response);
        ok = cJSON_GetObjectItemCaseSensitive(tj, "refresh_token") != NULL;
        cJSON_Delete(tj);
    }
    wf_response_free(&response);
    return ok;
}

int main(void) {
    char directory[] = "/tmp/metalbear-oauth-account-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .admin_password = "secret-admin",
        .invite_required = false,
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) {
        rmtree(directory);
        return 1;
    }

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);

    char *alice_tok = create_account(client, "alice.example.com",
                                     "alice-secret-pw");
    char *bob_tok = create_account(client, "bob.example.com", "bob-secret-pw");
    CHECK(alice_tok != NULL);
    CHECK(bob_tok != NULL);

    char *alice_device =
        sign_in_device(client, base, "alice.example.com", "alice-secret-pw");
    char *bob_device =
        sign_in_device(client, base, "bob.example.com", "bob-secret-pw");
    CHECK(alice_device != NULL);
    CHECK(bob_device != NULL);

    CHECK(seed_grant(client, base, "alice.example.com", alice_device,
                     "https://client.example/metadata.json", "grant1"));

    /* ---- listDevices: Alice sees her own device session ----------------*/
    wf_xrpc_client_set_auth(client, alice_tok);
    wf_response response = {0};
    CHECK(wf_xrpc_query_params(client, "com.metalbear.oauth.listDevices", NULL,
                               0, &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    cJSON *devices = cJSON_GetObjectItemCaseSensitive(json, "devices");
    CHECK(cJSON_IsArray(devices) && cJSON_GetArraySize(devices) == 1);
    char session_id[256] = "";
    if (cJSON_IsArray(devices) && cJSON_GetArraySize(devices) == 1) {
        cJSON *item = cJSON_GetArrayItem(devices, 0);
        cJSON *sid = cJSON_GetObjectItemCaseSensitive(item, "sessionId");
        CHECK(cJSON_IsString(sid));
        if (cJSON_IsString(sid))
            snprintf(session_id, sizeof(session_id), "%s", sid->valuestring);
        CHECK(cJSON_GetObjectItemCaseSensitive(item, "expiresAt") != NULL);
    }
    cJSON_Delete(json);
    wf_response_free(&response);
    CHECK(session_id[0] != '\0');

    /* ---- listGrants: Alice sees the connected app -----------------------*/
    CHECK(wf_xrpc_query_params(client, "com.metalbear.oauth.listGrants", NULL,
                               0, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *grants = cJSON_GetObjectItemCaseSensitive(json, "grants");
    CHECK(cJSON_IsArray(grants) && cJSON_GetArraySize(grants) == 1);
    if (cJSON_IsArray(grants) && cJSON_GetArraySize(grants) == 1) {
        cJSON *item = cJSON_GetArrayItem(grants, 0);
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(item, "clientId");
        CHECK(cJSON_IsString(cid) &&
              strcmp(cid->valuestring,
                     "https://client.example/metadata.json") == 0);
        cJSON *scope = cJSON_GetObjectItemCaseSensitive(item, "scope");
        CHECK(cJSON_IsString(scope));
    }
    cJSON_Delete(json);
    wf_response_free(&response);

    /* ---- Cross-account isolation: Bob cannot revoke Alice's device ------*/
    wf_xrpc_client_set_auth(client, bob_tok);
    char body[300];
    snprintf(body, sizeof(body), "{\"sessionId\":\"%s\"}", session_id);
    CHECK(wf_xrpc_procedure(client, "com.metalbear.oauth.revokeDevice", body,
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 404);
    wf_response_free(&response);
    /* ... and Alice's device session is still perfectly valid. */
    {
        wf_http_header hdr = {"Cookie", alice_device};
        char url[128];
        snprintf(url, sizeof(url), "%s/oauth/session", base);
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &response) ==
              WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }

    /* ---- Alice revokes her own device session ---------------------------*/
    wf_xrpc_client_set_auth(client, alice_tok);
    CHECK(wf_xrpc_procedure(client, "com.metalbear.oauth.revokeDevice", body,
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* Revoking the same sessionId again is refused: it's already gone. */
    CHECK(wf_xrpc_procedure(client, "com.metalbear.oauth.revokeDevice", body,
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 404);
    wf_response_free(&response);

    /* The device cookie itself no longer authenticates. */
    {
        wf_http_header hdr = {"Cookie", alice_device};
        char url[128];
        snprintf(url, sizeof(url), "%s/oauth/session", base);
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &response) ==
              WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);
    }

    /* listDevices now shows none. */
    CHECK(wf_xrpc_query_params(client, "com.metalbear.oauth.listDevices", NULL,
                               0, &response) == WF_OK);
    json = json_response(&response);
    devices = cJSON_GetObjectItemCaseSensitive(json, "devices");
    CHECK(cJSON_IsArray(devices) && cJSON_GetArraySize(devices) == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* ---- Alice revokes the connected app ---------------------------------*/
    const char *grant_body =
        "{\"clientId\":\"https://client.example/metadata.json\"}";
    CHECK(wf_xrpc_procedure(client, "com.metalbear.oauth.revokeGrant",
                            grant_body, &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    CHECK(wf_xrpc_query_params(client, "com.metalbear.oauth.listGrants", NULL,
                               0, &response) == WF_OK);
    json = json_response(&response);
    grants = cJSON_GetObjectItemCaseSensitive(json, "grants");
    CHECK(cJSON_IsArray(grants) && cJSON_GetArraySize(grants) == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    free(alice_device);
    free(bob_device);
    free(alice_tok);
    free(bob_tok);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_oauth_account_routes: OK\n");
    return 0;
}

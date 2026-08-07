#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_oauth_authorize_info.c — offline coverage for the distinct error
 * codes GET /oauth/authorize/info returns (issue #26 item 3).
 *
 * Before this, every failure here -- an unknown/expired request_uri, a
 * client_id that doesn't match the pushed request, and a genuine server
 * error building the response -- collapsed into the same generic
 * "invalid_request" error, and the consent page showed one message for all
 * three ("unknown, expired, or no longer valid") even though only one of
 * them ("expired") is actually fixable by going back and trying again.
 *
 * Covers: missing params, an unknown request_uri, a request_uri that
 * exists but names a different client_id, and the success path.
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

static wf_status oauth_form_post(wf_xrpc_client *client, const char *base,
                                 const char *path, const char *body,
                                 wf_response *out) {
    char url[256];
    snprintf(url, sizeof(url), "%s%s", base, path);
    return wf_http_post(client, url, "application/x-www-form-urlencoded", body,
                        NULL, 0, out);
}

/* Push a real PAR for `client_id`, returning its request_uri. */
static bool push_par(wf_xrpc_client *client, const char *base,
                     const char *client_id, char *out_request_uri,
                     size_t out_len) {
    wf_oauth_pkce pkce = {0};
    if (wf_oauth_pkce_from_verifier(
            "v3ry-long-test-verifier-with-enough-entropy-0123456789", &pkce) !=
        WF_OK)
        return false;
    char *enc_cid = curl_easy_escape(NULL, client_id, 0);
    char par_body[1024];
    snprintf(par_body, sizeof(par_body),
             "client_id=%s&redirect_uri=https%%3A%%2F%%2Fclient.example%%2F"
             "callback&scope=atproto&state=xyz&code_challenge=%s&"
             "dpop_jkt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
             enc_cid, pkce.challenge);
    curl_free(enc_cid);
    wf_response response = {0};
    bool ok = oauth_form_post(client, base, "/oauth/par", par_body,
                              &response) == WF_OK &&
              response.status == 201;
    if (ok) {
        cJSON *json = json_response(&response);
        cJSON *ru = cJSON_GetObjectItemCaseSensitive(json, "request_uri");
        ok = cJSON_IsString(ru);
        if (ok) snprintf(out_request_uri, out_len, "%s", ru->valuestring);
        cJSON_Delete(json);
    }
    wf_response_free(&response);
    return ok;
}

static wf_status info_request(wf_xrpc_client *client, const char *base,
                              const char *request_uri, const char *client_id,
                              wf_response *out) {
    char *enc_ru = request_uri ? curl_easy_escape(NULL, request_uri, 0) : NULL;
    char *enc_cid = client_id ? curl_easy_escape(NULL, client_id, 0) : NULL;
    char url[768];
    snprintf(url, sizeof(url), "%s/oauth/authorize/info?%s%s%s%s", base,
             enc_ru ? "request_uri=" : "", enc_ru ? enc_ru : "",
             enc_cid ? "&client_id=" : "", enc_cid ? enc_cid : "");
    curl_free(enc_ru);
    curl_free(enc_cid);
    return wf_http_get_with_headers(client, url, NULL, 0, out);
}

int main(void) {
    char directory[] = "/tmp/metalbear-authinfo-XXXXXX";
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

    const char *client_id = "https://client.example/metadata.json";
    wf_response response = {0};

    /* ---- missing params -------------------------------------------------*/
    CHECK(info_request(client, base, NULL, NULL, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    cJSON *json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "invalid_request") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* ---- unknown/expired request_uri --------------------------------------*/
    CHECK(info_request(client, base,
                       "urn:ietf:params:oauth:request_uri:nonexistent",
                       client_id, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "expired") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* ---- client_id mismatch: a real request_uri, wrong client -----------*/
    char request_uri[256] = "";
    CHECK(push_par(client, base, client_id, request_uri, sizeof(request_uri)));
    CHECK(request_uri[0] != '\0');
    CHECK(info_request(client, base, request_uri,
                       "https://other-client.example/metadata.json",
                       &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "client_mismatch") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* ---- success: the SAME request_uri with the matching client_id ------*/
    CHECK(info_request(client, base, request_uri, client_id, &response) ==
          WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *cid = cJSON_GetObjectItemCaseSensitive(json, "client_id");
    CHECK(cJSON_IsString(cid) && strcmp(cid->valuestring, client_id) == 0);
    cJSON *scope = cJSON_GetObjectItemCaseSensitive(json, "scope");
    CHECK(cJSON_IsString(scope));
    cJSON_Delete(json);
    wf_response_free(&response);

    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_oauth_authorize_info: OK\n");
    return 0;
}

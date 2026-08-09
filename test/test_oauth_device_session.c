#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_oauth_device_session.c — offline end-to-end coverage for the
 * device-session gate on GET /oauth/authorize.
 *
 * `/oauth/authorize` used to mint an authorization code for whichever
 * account `login_hint` named, with no check that the browser asking for it
 * actually controlled that account — and a handle is a public identifier,
 * not a secret, so this was an unauthenticated path to a valid OAuth token
 * for any account on the host. This file proves that path is closed and
 * that the legitimate flow around it still works:
 *
 *   (a) an authorize request naming a real account, with no device-session
 *       cookie, is refused a code and redirected to sign in instead,
 *   (b) /oauth/signin refuses a wrong password,
 *   (c) /oauth/signin refuses an app password, even a correct one — a
 *       device session is full account control (including creating further
 *       app passwords), and an app password is meant to carry restricted
 *       scope to one client; accepting one here would let a scoped
 *       credential escalate itself,
 *   (d) /oauth/signin accepts the account's own password and sets a
 *       device-session cookie,
 *   (e) authorize now succeeds with that cookie: it redirects to the
 *       CLIENT's redirect_uri carrying a code and the original state,
 *   (f) the same cookie does not authorize a DIFFERENT account,
 *   (g) /oauth/signout revokes the session, and the same cookie value is
 *       refused afterward.
 *
 * Cleanup removes the whole data directory.
 */

#include "metalbear/server.h"
#include "wolfram/oauth.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static bool body_has(const wf_response *response, const char *needle) {
    if (!response || !response->body || !needle) return false;
    size_t nlen = strlen(needle);
    if (response->body_len < nlen) return false;
    for (size_t i = 0; i + nlen <= response->body_len; i++)
        if (memcmp(response->body + i, needle, nlen) == 0) return true;
    return false;
}

static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *password, char *out_did,
                            size_t out_did_len) {
    char body[512];
    snprintf(
        body, sizeof(body),
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
    cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
    if (out_did && out_did_len && cJSON_IsString(did))
        snprintf(out_did, out_did_len, "%s", did->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* Create an app password for the currently-authenticated account. */
static char *create_app_password(wf_xrpc_client *client, const char *name) {
    char body[128];
    snprintf(body, sizeof(body), "{\"name\":\"%s\"}", name);
    wf_response response = {0};
    if (wf_xrpc_procedure(client, "com.atproto.server.createAppPassword", body,
                          &response) != WF_OK ||
        response.status != 200) {
        wf_response_free(&response);
        return NULL;
    }
    cJSON *json = json_response(&response);
    cJSON *password = cJSON_GetObjectItemCaseSensitive(json, "password");
    char *out = cJSON_IsString(password) ? strdup(password->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    return out;
}

/* POST a JSON body with no Authorization header — every oauth route
 * authenticates itself rather than going through the XRPC auth callback. */
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

/*
 * Pull just `mb_device=<token>` out of a Set-Cookie value, discarding the
 * `; Path=/; HttpOnly; ...` attributes — those are instructions to a real
 * browser's cookie jar, not part of what a Cookie request header carries.
 */
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

int main(void) {
    char directory[] = "/tmp/metalbear-oauth-device-XXXXXX";
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

    char victim_did[128] = "";
    char other_did[128] = "";
    char *victim_token =
        create_account(client, "victim.example.com", "victim-secret-pw",
                       victim_did, sizeof(victim_did));
    char *other_token =
        create_account(client, "other.example.com", "other-secret-pw",
                       other_did, sizeof(other_did));
    CHECK(victim_token != NULL);
    CHECK(other_token != NULL);
    if (!victim_token || !other_token) goto done;

    /* An app password for the privilege-escalation check, created through a
     * real authenticated session — the same way a legitimate client would
     * get one. */
    wf_xrpc_client_set_auth(client, victim_token);
    char *victim_app_password = create_app_password(client, "test-app");
    CHECK(victim_app_password != NULL);
    wf_xrpc_client_set_auth(client, NULL);

    /* A PAR, exactly as a real OAuth client would push one. */
    wf_oauth_pkce pkce = {0};
    CHECK(wf_oauth_pkce_from_verifier(
              "v3ry-long-test-verifier-with-enough-entropy-0123456789",
              &pkce) == WF_OK);
    char par_body[1024];
    snprintf(par_body, sizeof(par_body),
             "client_id=https%%3A%%2F%%2Fclient.example%%2Fmetadata.json&"
             "redirect_uri=https%%3A%%2F%%2Fclient.example%%2Fcallback%%3Ffrom%"
             "%3Doauth&"
             "scope=atproto+transition%%3Ageneric&state=state+%%26+value&"
             "code_challenge=%s&"
             "dpop_jkt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
             pkce.challenge);
    wf_response response = {0};
    CHECK(oauth_form_post(client, base, "/oauth/par", par_body, &response) ==
          WF_OK);
    CHECK(response.status == 201);
    cJSON *par_json = json_response(&response);
    cJSON *request_uri_j =
        par_json ? cJSON_GetObjectItemCaseSensitive(par_json, "request_uri")
                 : NULL;
    char request_uri[256] = "";
    if (cJSON_IsString(request_uri_j))
        snprintf(request_uri, sizeof(request_uri), "%s",
                 request_uri_j->valuestring);
    CHECK(request_uri[0] != '\0');
    cJSON_Delete(par_json);
    wf_response_free(&response);

    char authorize_url[512];
    snprintf(authorize_url, sizeof(authorize_url),
             "%s/oauth/authorize?request_uri=%s&client_id=https%%3A%%2F%%2F"
             "client.example%%2Fmetadata.json&login_hint=victim.example.com",
             base, request_uri);

    /* ---- (a) unauthenticated: the vulnerability, now closed ------------ */
    {
        wf_status s =
            wf_http_get_with_headers(client, authorize_url, NULL, 0, &response);
        CHECK(s == WF_ERR_HTTP);
        CHECK(response.status == 302);
        /* Sent to sign in, not handed a code. */
        CHECK(response.location != NULL);
        CHECK(response.location && strncmp(response.location, "/oauth/consent?",
                                           strlen("/oauth/consent?")) == 0);
        CHECK(response.location && strstr(response.location, "login_hint="));
        /* The one thing that must never appear here: a live authorization
         * code for an account nobody has proven they control. */
        CHECK(!(response.location && strstr(response.location, "code=")));
        wf_response_free(&response);
    }

    /* ---- (b) wrong password ---------------------------------------------*/
    {
        const char *body =
            "{\"identifier\":\"victim.example.com\",\"password\":\"wrong\"}";
        CHECK(oauth_post(client, base, "/oauth/signin", body, NULL, 0,
                         &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        CHECK(response.set_cookie == NULL);
        wf_response_free(&response);
    }

    /* ---- (c) an app password must not open a device session ------------ */
    if (victim_app_password) {
        char body[256];
        snprintf(body, sizeof(body),
                 "{\"identifier\":\"victim.example.com\",\"password\":\"%s\"}",
                 victim_app_password);
        wf_status s =
            oauth_post(client, base, "/oauth/signin", body, NULL, 0, &response);
        CHECK(s == WF_ERR_HTTP);
        CHECK(response.status == 401);
        CHECK(response.set_cookie == NULL);
        wf_response_free(&response);
    }

    /* ---- (d) the account's own password succeeds ------------------------*/
    char *device_cookie = NULL;
    {
        const char *body = "{\"identifier\":\"victim.example.com\","
                           "\"password\":\"victim-secret-pw\"}";
        CHECK(oauth_post(client, base, "/oauth/signin", body, NULL, 0,
                         &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(response.set_cookie != NULL);
        CHECK(response.set_cookie && strstr(response.set_cookie, "mb_device="));
        CHECK(response.set_cookie && strstr(response.set_cookie, "HttpOnly"));
        CHECK(body_has(&response, victim_did));
        device_cookie = extract_cookie_pair(response.set_cookie);
        wf_response_free(&response);
    }
    CHECK(device_cookie != NULL);

    /* ---- (e) authorize now succeeds, cookie now set ---------------------*/
    if (device_cookie) {
        wf_http_header hdr = {"Cookie", device_cookie};
        wf_status s =
            wf_http_get_with_headers(client, authorize_url, &hdr, 1, &response);
        CHECK(s == WF_ERR_HTTP);
        CHECK(response.status == 302);
        CHECK(response.location != NULL);
        CHECK(response.location &&
              strncmp(
                  response.location,
                  "https://client.example/callback?from=oauth&code=",
                  strlen("https://client.example/callback?from=oauth&code=")) ==
                  0);
        CHECK(response.location && strstr(response.location, "code="));
        CHECK(response.location &&
              strstr(response.location, "state=state%20%26%20value"));
        CHECK(response.location &&
              strstr(response.location, "iss=https%3A%2F%2Fpds.example.com"));
        wf_response_free(&response);
    }

    /* ---- (f) the same cookie does not authorize a different account -----*/
    if (device_cookie) {
        char other_url[512];
        snprintf(other_url, sizeof(other_url),
                 "%s/oauth/authorize?request_uri=%s&client_id=https%%3A%%2F%%2F"
                 "client.example%%2Fmetadata.json&login_hint=other.example.com",
                 base, request_uri);
        wf_http_header hdr = {"Cookie", device_cookie};
        wf_status s =
            wf_http_get_with_headers(client, other_url, &hdr, 1, &response);
        CHECK(s == WF_ERR_HTTP);
        CHECK(response.status == 302);
        CHECK(response.location != NULL);
        CHECK(response.location && strncmp(response.location, "/oauth/consent?",
                                           strlen("/oauth/consent?")) == 0);
        CHECK(!(response.location && strstr(response.location, "code=")));
        wf_response_free(&response);
    }

    /* ---- (g) signout revokes it ------------------------------------------*/
    if (device_cookie) {
        wf_http_header hdr = {"Cookie", device_cookie};
        CHECK(oauth_post(client, base, "/oauth/signout", "{}", &hdr, 1,
                         &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(response.set_cookie != NULL);
        CHECK(response.set_cookie && strstr(response.set_cookie, "Max-Age=0"));
        wf_response_free(&response);

        /* The old cookie value, now revoked, must be refused just like no
         * cookie at all — not merely rejected by Max-Age on a browser that
         * has already stopped sending it. */
        wf_status s =
            wf_http_get_with_headers(client, authorize_url, &hdr, 1, &response);
        CHECK(s == WF_ERR_HTTP);
        CHECK(response.status == 302);
        CHECK(response.location != NULL);
        CHECK(response.location && strncmp(response.location, "/oauth/consent?",
                                           strlen("/oauth/consent?")) == 0);
        wf_response_free(&response);
    }

done:
    free(device_cookie);
    free(victim_app_password);
    free(victim_token);
    free(other_token);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_oauth_device_session: OK\n");
    return 0;
}

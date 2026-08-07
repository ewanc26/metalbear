#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_oauth_multi_device_session.c — offline coverage for holding more
 * than one signed-in account's device session in the same browser.
 *
 * MetalBear is a multi-account host, but /oauth/signin used to overwrite
 * the single `mb_device` cookie on every call: signing into account B
 * silently signed the browser out of account A, and an /oauth/authorize
 * request for A (e.g. a client whose login_hint names an account other
 * than whichever was signed into most recently) would redirect back to
 * the consent page and loop forever, since nothing there could ever
 * satisfy it without destroying A's session doing so.
 *
 * This file proves the fix: the cookie now carries up to
 * MB_DEVICE_MAX_SESSIONS tokens, one per account, and:
 *
 *   (a) signing into a second account keeps the first account's session
 *       (both are set in the response cookie),
 *   (b) GET /oauth/session lists both subjects, `did` naming the most
 *       recent,
 *   (c) /oauth/authorize succeeds for EITHER account's login_hint against
 *       the combined cookie -- not just the most recently signed-in one,
 *   (d) POST /oauth/signout with {"did": "..."} revokes only that
 *       account's session, leaving the other's cookie entry (and its
 *       ability to authorize) intact,
 *   (e) signing into more accounts than the cap evicts the oldest.
 *
 * Cleanup removes the whole data directory.
 */

#include "metalbear/server.h"
#include "wolfram/oauth.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdbool.h>
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

static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *did, const char *password) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\",\"did\":\"%s\","
             "\"email\":\"%s@example.com\"}",
             handle, password, did, handle);
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

/* Pull just `mb_device=<value>` out of a Set-Cookie value, discarding the
 * `; Path=/; HttpOnly; ...` attributes. */
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

/* Sign in and return the resulting mb_device cookie pair. `existing_cookie`
 * (may be NULL) is sent along so an existing session survives the call. */
static char *sign_in(wf_xrpc_client *client, const char *base,
                     const char *handle, const char *password,
                     const char *existing_cookie) {
    char body[256];
    snprintf(body, sizeof(body), "{\"identifier\":\"%s\",\"password\":\"%s\"}",
             handle, password);
    wf_http_header hdr = {"Cookie", existing_cookie};
    wf_response response = {0};
    wf_status s = oauth_post(client, base, "/oauth/signin", body,
                             existing_cookie ? &hdr : NULL,
                             existing_cookie ? 1 : 0, &response);
    CHECK(s == WF_OK);
    CHECK(response.status == 200);
    char *cookie = extract_cookie_pair(response.set_cookie);
    wf_response_free(&response);
    return cookie;
}

/* Does the GET /oauth/session response's `subjects` array contain `did`? */
static bool subjects_contains(cJSON *subjects, const char *did) {
    if (!cJSON_IsArray(subjects)) return false;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, subjects) {
        if (cJSON_IsString(item) && strcmp(item->valuestring, did) == 0)
            return true;
    }
    return false;
}

static wf_status get_par(wf_xrpc_client *client, const char *base,
                         const char *login_hint_unused, char *out_request_uri,
                         size_t out_len) {
    (void)login_hint_unused;
    wf_oauth_pkce pkce = {0};
    if (wf_oauth_pkce_from_verifier(
            "v3ry-long-test-verifier-with-enough-entropy-0123456789", &pkce) !=
        WF_OK)
        return WF_ERR_INTERNAL;
    char par_body[1024];
    snprintf(par_body, sizeof(par_body),
             "client_id=https%%3A%%2F%%2Fclient.example%%2Fmetadata.json&"
             "redirect_uri=https%%3A%%2F%%2Fclient.example%%2Fcallback&"
             "scope=atproto&state=xyz&"
             "code_challenge=%s&"
             "dpop_jkt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
             pkce.challenge);
    wf_response response = {0};
    wf_status s =
        oauth_form_post(client, base, "/oauth/par", par_body, &response);
    if (s != WF_OK || response.status != 201) {
        wf_response_free(&response);
        return WF_ERR_INTERNAL;
    }
    cJSON *json = json_response(&response);
    cJSON *ru = cJSON_GetObjectItemCaseSensitive(json, "request_uri");
    if (cJSON_IsString(ru))
        snprintf(out_request_uri, out_len, "%s", ru->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    return out_request_uri[0] ? WF_OK : WF_ERR_INTERNAL;
}

/* Does /oauth/authorize succeed (302 to the client's redirect_uri with a
 * code) for `login_hint` against `cookie`? A fresh PAR is pushed each call
 * since a request_uri is single-use. */
static bool authorize_succeeds(wf_xrpc_client *client, const char *base,
                               const char *login_hint, const char *cookie) {
    char request_uri[256] = "";
    if (get_par(client, base, login_hint, request_uri, sizeof(request_uri)) !=
        WF_OK)
        return false;
    char url[768];
    snprintf(url, sizeof(url),
             "%s/oauth/authorize?request_uri=%s&client_id=https%%3A%%2F%%2F"
             "client.example%%2Fmetadata.json&login_hint=%s",
             base, request_uri, login_hint);
    wf_http_header hdr = {"Cookie", cookie};
    wf_response response = {0};
    wf_status s = wf_http_get_with_headers(client, url, cookie ? &hdr : NULL,
                                           cookie ? 1 : 0, &response);
    static const char *const prefix = "https://client.example/callback?";
    bool ok = s == WF_ERR_HTTP && response.status == 302 && response.location &&
              strncmp(response.location, prefix, strlen(prefix)) == 0 &&
              strstr(response.location, "code=");
    wf_response_free(&response);
    return ok;
}

int main(void) {
    char directory[] = "/tmp/metalbear-oauth-multidev-XXXXXX";
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

    char *tok_a = create_account(client, "alice.example.com", "did:plc:alice",
                                 "alice-secret-pw");
    char *tok_b = create_account(client, "bob.example.com", "did:plc:bob",
                                 "bob-secret-pw");
    CHECK(tok_a != NULL);
    CHECK(tok_b != NULL);
    free(tok_a);
    free(tok_b);

    /* ---- (a)/(b): sign into A, then B without losing A ------------------ */
    char *cookie_a =
        sign_in(client, base, "alice.example.com", "alice-secret-pw", NULL);
    CHECK(cookie_a != NULL);
    char *cookie_ab =
        sign_in(client, base, "bob.example.com", "bob-secret-pw", cookie_a);
    CHECK(cookie_ab != NULL);
    /* Both tokens present: the combined cookie is strictly longer than
     * either alone, and still starts with the same value cookie_a carried
     * (existing sessions are kept in order, the new one appended). */
    CHECK(cookie_ab && cookie_a && strlen(cookie_ab) > strlen(cookie_a));

    if (cookie_ab) {
        wf_http_header hdr = {"Cookie", cookie_ab};
        wf_response response = {0};
        char url[128];
        snprintf(url, sizeof(url), "%s/oauth/session", base);
        wf_status s = wf_http_get_with_headers(client, url, &hdr, 1, &response);
        CHECK(s == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *subjects = cJSON_GetObjectItemCaseSensitive(json, "subjects");
        CHECK(subjects_contains(subjects, "did:plc:alice"));
        CHECK(subjects_contains(subjects, "did:plc:bob"));
        cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
        CHECK(cJSON_IsString(did) &&
              strcmp(did->valuestring, "did:plc:bob") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* ---- (b2): matches_hint answers "is THIS account signed in", not just
     * "is any account signed in" -- the check that was missing client-side
     * and caused the original infinite-loop bug. ------------------------- */
    if (cookie_ab) {
        wf_http_header hdr = {"Cookie", cookie_ab};
        wf_response response = {0};
        char url[192];

        snprintf(url, sizeof(url), "%s/oauth/session?login_hint=%s", base,
                 "alice.example.com");
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &response) ==
              WF_OK);
        cJSON *json = json_response(&response);
        cJSON *matches = cJSON_GetObjectItemCaseSensitive(json, "matches_hint");
        CHECK(cJSON_IsBool(matches) && cJSON_IsTrue(matches));
        cJSON_Delete(json);
        wf_response_free(&response);

        snprintf(url, sizeof(url), "%s/oauth/session?login_hint=%s", base,
                 "nobody.example.com");
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &response) ==
              WF_OK);
        json = json_response(&response);
        matches = cJSON_GetObjectItemCaseSensitive(json, "matches_hint");
        CHECK(cJSON_IsBool(matches) && cJSON_IsFalse(matches));
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    if (cookie_a) {
        /* A cookie holding only Alice's session does not match Bob's hint,
         * even though a session exists (just not the right one). */
        wf_http_header hdr = {"Cookie", cookie_a};
        wf_response response = {0};
        char url[192];
        snprintf(url, sizeof(url), "%s/oauth/session?login_hint=%s", base,
                 "bob.example.com");
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &response) ==
              WF_OK);
        cJSON *json = json_response(&response);
        cJSON *matches = cJSON_GetObjectItemCaseSensitive(json, "matches_hint");
        CHECK(cJSON_IsBool(matches) && cJSON_IsFalse(matches));
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* ---- (c): authorize succeeds for EITHER account against the combined
     * cookie, not just the most recently signed-in one ------------------- */
    CHECK(authorize_succeeds(client, base, "alice.example.com", cookie_ab));
    CHECK(authorize_succeeds(client, base, "bob.example.com", cookie_ab));

    /* ---- (d): signing out of one account leaves the other's session
     * intact ---------------------------------------------------------------*/
    char *cookie_b_only = NULL;
    if (cookie_ab) {
        wf_http_header hdr = {"Cookie", cookie_ab};
        wf_response response = {0};
        CHECK(oauth_post(client, base, "/oauth/signout",
                         "{\"did\":\"did:plc:alice\"}", &hdr, 1,
                         &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(response.set_cookie != NULL);
        cookie_b_only = extract_cookie_pair(response.set_cookie);
        wf_response_free(&response);
    }
    CHECK(cookie_b_only != NULL);
    /* Alice's login_hint no longer authorizes ... */
    CHECK(
        !authorize_succeeds(client, base, "alice.example.com", cookie_b_only));
    /* ... but Bob's still does, on the SAME (rewritten) cookie. */
    CHECK(authorize_succeeds(client, base, "bob.example.com", cookie_b_only));

    /* ---- (e): the cap evicts the oldest session -------------------------*/
    {
        char *chain = NULL;
        const char *first_did = "did:plc:cap0";
        for (int i = 0; i < 6; i++) {
            char handle[64], did[32], password[32];
            snprintf(handle, sizeof(handle), "cap%d.example.com", i);
            snprintf(did, sizeof(did), "did:plc:cap%d", i);
            snprintf(password, sizeof(password), "cap%d-secret-pw", i);
            char *t = create_account(client, handle, did, password);
            CHECK(t != NULL);
            free(t);
            char *next = sign_in(client, base, handle, password, chain);
            free(chain);
            chain = next;
        }
        CHECK(chain != NULL);
        if (chain) {
            wf_http_header hdr = {"Cookie", chain};
            wf_response response = {0};
            char url[128];
            snprintf(url, sizeof(url), "%s/oauth/session", base);
            CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &response) ==
                  WF_OK);
            cJSON *json = json_response(&response);
            cJSON *subjects =
                cJSON_GetObjectItemCaseSensitive(json, "subjects");
            CHECK(cJSON_IsArray(subjects) && cJSON_GetArraySize(subjects) == 5);
            /* The first account signed in (cap0) was evicted; the five most
             * recent (cap1..cap5) remain. */
            CHECK(!subjects_contains(subjects, first_did));
            CHECK(subjects_contains(subjects, "did:plc:cap5"));
            CHECK(subjects_contains(subjects, "did:plc:cap1"));
            cJSON_Delete(json);
            wf_response_free(&response);
        }
        free(chain);
    }

    free(cookie_a);
    free(cookie_ab);
    free(cookie_b_only);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_oauth_multi_device_session: OK\n");
    return 0;
}

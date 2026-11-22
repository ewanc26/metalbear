/*
 * test_admin_signing_key.c — coverage for
 * com.atproto.admin.updateAccountSigningKey.
 *
 * A mock PLC directory stands in for the real one: GET .../log/last serves a
 * canned current operation, and the operation submission POST is captured so
 * the test can prove the new verification method was actually published. The
 * route must publish to PLC before writing local state, so stopping the mock
 * mid-test must leave both the DID document and the stored key unchanged.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "metalbear/server.h"
#include "wolfram/crypto.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <errno.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pthread.h>
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

static const char *g_canned_last_op =
    "{\"type\":\"plc_operation\",\"rotationKeys\":[\"did:key:"
    "zQ3shMockRotationKey\"],\"verificationMethods\":{\"atproto\":\"did:key:"
    "zQ3shOldAtprotoKey\",\"other\":\"did:key:zQ3shOtherKey\"},\"services\":"
    "{\"atproto_pds\":{\"type\":\"AtprotoPersonalDataServer\",\"endpoint\":"
    "\"https://old.example.com\"}},\"alsoKnownAs\":[\"at://"
    "alice.example.com\"],"
    "\"prev\":null,\"sig\":\"mockSigValue\"}";

static struct {
    int listen_fd;
    unsigned short port;
    pthread_t thread;
    bool running;
    int requests_seen;
    char last_post[8192];
} mock_plc;

static void *mock_plc_serve(void *arg) {
    (void)arg;
    while (mock_plc.running) {
        struct pollfd pfd = {.fd = mock_plc.listen_fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 50);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0 || !mock_plc.running) continue;

        int fd = accept(mock_plc.listen_fd, NULL, NULL);
        if (fd < 0) break;

        char buf[8192];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            mock_plc.requests_seen++;
            if (strncmp(buf, "GET ", 4) == 0 &&
                strstr(buf, "/log/last") != NULL) {
                char resp[1024];
                int body_len = snprintf(NULL, 0, "%s", g_canned_last_op);
                snprintf(
                    resp, sizeof(resp),
                    "HTTP/1.1 200 OK\r\nContent-Type: "
                    "application/json\r\nContent-Length: %d\r\nConnection: "
                    "close\r\n\r\n%s",
                    body_len, g_canned_last_op);
                send(fd, resp, strlen(resp), 0);
            } else {
                const char *body = strchr(buf, '\n');
                if (body) {
                    body++;
                    snprintf(mock_plc.last_post, sizeof(mock_plc.last_post),
                             "%s", body);
                }
                const char *resp =
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: "
                    "close\r\n\r\n";
                send(fd, resp, strlen(resp), 0);
            }
        }
        close(fd);
    }
    return NULL;
}

static bool start_mock_plc(unsigned short *out_port) {
    mock_plc.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (mock_plc.listen_fd < 0) return false;
    int one = 1;
    setsockopt(mock_plc.listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(mock_plc.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(mock_plc.listen_fd);
        return false;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(mock_plc.listen_fd, (struct sockaddr *)&addr, &len) != 0) {
        close(mock_plc.listen_fd);
        return false;
    }
    *out_port = ntohs(addr.sin_port);
    if (listen(mock_plc.listen_fd, 4) != 0) {
        close(mock_plc.listen_fd);
        return false;
    }
    mock_plc.running = true;
    mock_plc.requests_seen = 0;
    mock_plc.last_post[0] = '\0';
    if (pthread_create(&mock_plc.thread, NULL, mock_plc_serve, NULL) != 0) {
        close(mock_plc.listen_fd);
        return false;
    }
    return true;
}

static void stop_mock_plc(void) {
    mock_plc.running = false;
    close(mock_plc.listen_fd);
    pthread_join(mock_plc.thread, NULL);
}

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

/* POST an admin-gated XRPC method with HTTP Basic `admin:<password>`. */
static wf_status admin_post(wf_xrpc_client *client, const char *base,
                            const char *nsid, const char *body,
                            wf_response *out) {
    char cred[64];
    int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
    char b64[128];
    int len =
        EVP_EncodeBlock((unsigned char *)b64, (const unsigned char *)cred, n);
    b64[len] = '\0';
    char auth[160];
    snprintf(auth, sizeof(auth), "Basic %s", b64);
    wf_http_header hdr = {"Authorization", auth};
    char url[256];
    snprintf(url, sizeof(url), "%s/xrpc/%s", base, nsid);
    return wf_http_post(client, url, "application/json", body, &hdr, 1, out);
}

/* Read the #atproto verification method from getSession's didDoc. */
static bool session_key_is(wf_xrpc_client *client, const char *expected) {
    wf_response response = {0};
    if (wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                      &response) != WF_OK ||
        response.status != 200) {
        wf_response_free(&response);
        return false;
    }
    cJSON *json = json_response(&response);
    cJSON *doc = json ? cJSON_GetObjectItemCaseSensitive(json, "didDoc") : NULL;
    const char *multibase = NULL;
    if (doc) {
        cJSON *methods =
            cJSON_GetObjectItemCaseSensitive(doc, "verificationMethod");
        cJSON *method = NULL;
        cJSON_ArrayForEach(method, methods) {
            cJSON *id = cJSON_GetObjectItemCaseSensitive(method, "id");
            if (cJSON_IsString(id) && strstr(id->valuestring, "#atproto")) {
                cJSON *key = cJSON_GetObjectItemCaseSensitive(
                    method, "publicKeyMultibase");
                if (cJSON_IsString(key)) multibase = key->valuestring;
                break;
            }
        }
    }
    bool matches = multibase && expected &&
                   strcmp(multibase, expected + strlen("did:key:")) == 0;
    cJSON_Delete(json);
    wf_response_free(&response);
    return matches;
}

int main(void) {
    printf("Admin Signing Key Tests\n");
    printf("=======================\n\n");

    char directory[] = "/tmp/metalbear-adminsigningkey-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);

    unsigned short mock_plc_port = 0;
    if (!start_mock_plc(&mock_plc_port)) {
        fprintf(stderr, "could not start mock PLC server\n");
        rmtree(directory);
        return 1;
    }
    char plc_url[64];
    snprintf(plc_url, sizeof(plc_url), "http://127.0.0.1:%u",
             (unsigned)mock_plc_port);

    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .invite_required = false,
        .rate_limit = 10000,
        .admin_password = "secret-admin",
        .plc_url = plc_url,
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) {
        stop_mock_plc();
        rmtree(directory);
        return 1;
    }

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    wf_response response = {0};

    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                            "{\"handle\":\"alice.example.com\","
                            "\"password\":\"correct horse battery staple\","
                            "\"email\":\"alice@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    char alice_did[128] = "";
    cJSON *did_item = cJSON_GetObjectItemCaseSensitive(json, "did");
    if (cJSON_IsString(did_item))
        snprintf(alice_did, sizeof(alice_did), "%s", did_item->valuestring);
    char *access_token = strdup(
        cJSON_GetObjectItemCaseSensitive(json, "accessJwt")->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    CHECK(alice_did[0] != '\0');
    CHECK(strncmp(alice_did, "did:plc:", 8) == 0);
    wf_xrpc_client_set_auth(client, access_token);

    wf_signing_key new_key;
    memset(&new_key, 0, sizeof(new_key));
    CHECK(wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &new_key) == WF_OK);
    char *new_didkey = NULL;
    CHECK(wf_signing_key_public_didkey(&new_key, &new_didkey) == WF_OK);
    CHECK(new_didkey != NULL);

    /* --- happy path: admin publishes a new key --- */
    {
        mock_plc.requests_seen = 0;
        mock_plc.last_post[0] = '\0';
        char body[512];
        snprintf(body, sizeof(body), "{\"did\":\"%s\",\"signingKey\":\"%s\"}",
                 alice_did, new_didkey);
        wf_xrpc_client_set_auth(client, NULL);
        CHECK(admin_post(client, base,
                         "com.atproto.admin.updateAccountSigningKey", body,
                         &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, access_token);
        /* A real PLC round trip happened: the log/last GET and the operation
         * submission POST, rather than a silent local-only key change. */
        CHECK(mock_plc.requests_seen >= 2);
        CHECK(strstr(mock_plc.last_post, new_didkey) != NULL);
        CHECK(session_key_is(client, new_didkey));
    }

    /* --- non-admin request is refused without changing the key --- */
    {
        wf_signing_key other;
        memset(&other, 0, sizeof(other));
        CHECK(wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &other) == WF_OK);
        char *other_key = NULL;
        CHECK(wf_signing_key_public_didkey(&other, &other_key) == WF_OK);
        char body[512];
        snprintf(body, sizeof(body), "{\"did\":\"%s\",\"signingKey\":\"%s\"}",
                 alice_did, other_key);
        wf_xrpc_client_set_auth(client, access_token); /* bearer, not admin */
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.admin.updateAccountSigningKey",
                                body, &response) != WF_OK);
        CHECK(response.status == 401);
        wf_response_free(&response);
        CHECK(session_key_is(client, new_didkey));
        free(other_key);
    }

    /* --- invalid DID and invalid did:key are rejected as 400 --- */
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"did\":\"not-a-did\",\"signingKey\":\"%s\"}", new_didkey);
        wf_xrpc_client_set_auth(client, NULL);
        admin_post(client, base, "com.atproto.admin.updateAccountSigningKey",
                   body, &response);
        CHECK(response.status == 400);
        wf_response_free(&response);

        snprintf(body, sizeof(body),
                 "{\"did\":\"%s\",\"signingKey\":\"did:key:not-a-key\"}",
                 alice_did);
        admin_post(client, base, "com.atproto.admin.updateAccountSigningKey",
                   body, &response);
        CHECK(response.status == 400);
        wf_response_free(&response);
    }

    /* --- PLC failure: the local key must stay as it was --- */
    {
        wf_signing_key third;
        memset(&third, 0, sizeof(third));
        CHECK(wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &third) == WF_OK);
        char *third_key = NULL;
        CHECK(wf_signing_key_public_didkey(&third, &third_key) == WF_OK);
        char body[512];
        snprintf(body, sizeof(body), "{\"did\":\"%s\",\"signingKey\":\"%s\"}",
                 alice_did, third_key);
        stop_mock_plc();
        admin_post(client, base, "com.atproto.admin.updateAccountSigningKey",
                   body, &response);
        CHECK(response.status == 500);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, access_token);
        CHECK(session_key_is(client, new_didkey));
        free(third_key);
    }

    free(new_didkey);
    free(access_token);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);

    printf("\n");
    if (failures)
        fprintf(stderr, "%d admin signing-key test(s) failed\n", failures);
    else
        printf("All admin signing-key tests passed\n");
    return failures ? 1 : 0;
}

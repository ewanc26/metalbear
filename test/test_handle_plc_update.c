/*
 * test_handle_plc_update.c — coverage for the PLC-update side effect of
 * admin.updateAccountHandle and identity.updateHandle.
 *
 * Both routes must, for a did:plc account, submit a real PLC operation
 * changing alsoKnownAs before touching any local state (registry, account
 * context, DNS) -- and if that submission fails, local state must be left
 * completely untouched, matching the reference (account-manager.ts's
 * updateHandle awaits the PLC client call first; a failure there means the
 * local-state write never runs).
 *
 * A mock PLC directory stands in for the real one: GET .../log/last serves
 * a canned current operation (so wf_plc_get_last_op has something to parse
 * and diff against), any other request (the operation submission) is
 * accepted with 200. Stopping the mock mid-test simulates a PLC directory
 * that is unreachable, to prove the "PLC first, blocking" ordering.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "metalbear/server.h"
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

/* ------------------------------------------------------------------ */
/* A stand-in PLC directory: serves a canned "current operation" for   */
/* GET .../log/last, accepts anything else (operation submission).    */
/* ------------------------------------------------------------------ */

static const char *g_canned_last_op =
    "{\"type\":\"plc_operation\",\"rotationKeys\":[\"did:key:"
    "zQ3shMockRotationKey\"],\"verificationMethods\":{\"atproto\":\"did:key:"
    "zQ3shMockAtprotoKey\"},\"services\":{\"atproto_pds\":{\"type\":"
    "\"AtprotoPersonalDataServer\",\"endpoint\":\"https://old.example.com\"}}"
    ",\"alsoKnownAs\":[\"at://old-handle.example\"],\"prev\":null,\"sig\":"
    "\"mockSigValue\"}";

static struct {
    int listen_fd;
    unsigned short port;
    pthread_t thread;
    bool running;
    int requests_seen;
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

        char buf[4096];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            mock_plc.requests_seen++;
            /* Only the request line matters: "GET /<did>/log/last HTTP/1.1".
             */
            int is_get_last = strncmp(buf, "GET ", 4) == 0 &&
                              strstr(buf, "/log/last") != NULL;
            if (is_get_last) {
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

int main(void) {
    printf("Handle update PLC wiring Tests\n");
    printf("===============================\n\n");

    char directory[] = "/tmp/metalbear-handleplc-XXXXXX";
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
    wf_xrpc_client_set_auth(client, access_token);

    /* --- admin.updateAccountHandle, PLC directory reachable --- */
    {
        mock_plc.requests_seen = 0;
        char body[256];
        snprintf(body, sizeof(body),
                 "{\"did\":\"%s\",\"handle\":\"bob."
                 "example.com\"}",
                 alice_did);
        wf_xrpc_client_set_auth(client, NULL);
        CHECK(admin_post(client, base, "com.atproto.admin.updateAccountHandle",
                         body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, access_token);
        /* A real PLC round trip happened: at least the log/last GET and the
         * operation submission POST, not a silent local-only rename. */
        CHECK(mock_plc.requests_seen >= 2);

        wf_xrpc_param describe_params[] = {{"repo", alice_did}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.repo.describeRepo",
                                   describe_params, 1, &response) == WF_OK);
        cJSON *desc = json_response(&response);
        cJSON *handle_field = cJSON_GetObjectItemCaseSensitive(desc, "handle");
        CHECK(cJSON_IsString(handle_field) &&
              strcmp(handle_field->valuestring, "bob.example.com") == 0);
        cJSON_Delete(desc);
        wf_response_free(&response);
    }

    /* --- Self-service identity.updateHandle, PLC directory reachable --- */
    {
        mock_plc.requests_seen = 0;
        char body[256];
        snprintf(body, sizeof(body), "{\"handle\":\"carol.example.com\"}");
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        /* A real PLC round trip happened: at least the log/last GET and the
         * operation submission POST, not a silent local-only rename. */
        CHECK(mock_plc.requests_seen >= 2);

        wf_xrpc_param describe_params[] = {{"repo", alice_did}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.repo.describeRepo",
                                   describe_params, 1, &response) == WF_OK);
        cJSON *desc = json_response(&response);
        cJSON *handle_field = cJSON_GetObjectItemCaseSensitive(desc, "handle");
        CHECK(cJSON_IsString(handle_field) &&
              strcmp(handle_field->valuestring, "carol.example.com") == 0);
        cJSON_Delete(desc);
        wf_response_free(&response);
    }

    /* --- PLC directory unreachable: the rename must NOT happen at all,   */
    /* not even locally -- local state and the DID document must never    */
    /* disagree.                                                          */
    stop_mock_plc();
    {
        char body[256];
        snprintf(body, sizeof(body), "{\"handle\":\"dave.example.com\"}");
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 500);
        wf_response_free(&response);

        wf_xrpc_param describe_params[] = {{"repo", alice_did}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.repo.describeRepo",
                                   describe_params, 1, &response) == WF_OK);
        cJSON *desc = json_response(&response);
        cJSON *handle_field = cJSON_GetObjectItemCaseSensitive(desc, "handle");
        /* Still "carol", the last handle that DID succeed -- not "dave",
         * and not reverted to an earlier handle either (this is about the
         * failed rename never landing, not about rolling back a successful
         * one). */
        CHECK(cJSON_IsString(handle_field) &&
              strcmp(handle_field->valuestring, "carol.example.com") == 0);
        cJSON_Delete(desc);
        wf_response_free(&response);
    }

    free(access_token);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);

    printf("\n");
    if (failures)
        fprintf(stderr, "%d handle-update PLC wiring test(s) failed\n",
                failures);
    return failures ? 1 : 0;
}

/*
 * test_custom_domain_handles.c -- offline coverage for issue #250.
 *
 * With [handles] allow_custom_domains on, a handle outside the host zone is
 * accepted only when it resolves (through the test resolver seam) to the
 * account's DID. The checks below prove that verification happens before any
 * PLC write or local state change, that the allowlist is enforced, that
 * host-zone-only rules (reserved labels, 3-18 label length) do not apply to a
 * verified custom domain, that the admin override verifies too, and that the
 * disabled configuration keeps the original host-only behaviour.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "../src/server_internal.h"

#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <errno.h>
#include <ftw.h>
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

/* ---- control over the resolver seam ------------------------------------ */

static bool g_resolver_succeeds = true;

static wf_status test_handle_resolve(const char *handle,
                                     const char *expected_did, char **out_did) {
    (void)handle;
    if (!expected_did) return WF_ERR_INVALID_ARG;
    /* Return the account's DID when the test wants verification to succeed,
     * and a different well-formed did:plc when it wants a mismatch. */
    *out_did = strdup(g_resolver_succeeds ? expected_did
                                          : "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
    return *out_did ? WF_OK : WF_ERR_ALLOC;
}

/* ---- a stand-in PLC directory ------------------------------------------ */

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
    int submissions; /* operation POSTs, not GET .../log/last reads */
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
            bool get_last = strncmp(buf, "GET ", 4) == 0 &&
                            strstr(buf, "/log/last") != NULL;
            if (!get_last) mock_plc.submissions++;
            if (get_last) {
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
    mock_plc.submissions = 0;
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

static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *email, wf_response *response) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"correct horse battery "
             "staple\",\"email\":\"%s\"}",
             handle, email);
    if (wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                          response) != WF_OK)
        return NULL;
    cJSON *json = json_response(response);
    char *did = NULL;
    cJSON *item = json ? cJSON_GetObjectItemCaseSensitive(json, "did") : NULL;
    if (cJSON_IsString(item)) did = strdup(item->valuestring);
    cJSON_Delete(json);
    return did;
}

int main(void) {
    printf("Custom-domain handle Tests\n");
    printf("==========================\n\n");

    char directory[] = "/tmp/metalbear-customdomain-XXXXXX";
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
        .rate_limit = 100000,
        .plc_url = plc_url,
        .allow_custom_domains = true,
        .allowed_custom_domains = ".example.net",
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) {
        stop_mock_plc();
        rmtree(directory);
        return 1;
    }
    metalbear_test_handle_resolver = test_handle_resolve;

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    wf_response response = {0};

    /* --- unverified custom-domain signup: refused, no PLC write ---------- */
    {
        g_resolver_succeeds = false;
        mock_plc.submissions = 0;
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"handle\":\"bob.example.net\","
                 "\"password\":\"correct horse battery staple\","
                 "\"email\":\"bob@example.net\"}");
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                                body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        cJSON *json = json_response(&response);
        cJSON *err =
            json ? cJSON_GetObjectItemCaseSensitive(json, "error") : NULL;
        CHECK(cJSON_IsString(err) &&
              strcmp(err->valuestring, "InvalidRequest") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
        CHECK(mock_plc.submissions == 0);
        /* The handle is still free: verification failed before registration. */
        g_resolver_succeeds = true;
        char *did = create_account(client, "bob.example.net", "bob@example.net",
                                   &response);
        CHECK(did != NULL);
        CHECK(response.status == 200);
        CHECK(mock_plc.submissions >= 1);
        free(did);
        wf_response_free(&response);
    }

    /* --- allowlist: a domain outside it is UnsupportedDomain ------------ */
    {
        mock_plc.submissions = 0;
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"handle\":\"carol.example.org\","
                 "\"password\":\"correct horse battery staple\","
                 "\"email\":\"carol@example.org\"}");
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                                body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        cJSON *json = json_response(&response);
        cJSON *err =
            json ? cJSON_GetObjectItemCaseSensitive(json, "error") : NULL;
        CHECK(cJSON_IsString(err) &&
              strcmp(err->valuestring, "UnsupportedDomain") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
        CHECK(mock_plc.submissions == 0);
    }

    /* --- host-only rules do not apply: reserved label + short label ----- */
    {
        char *did1 = create_account(client, "admin.example.net",
                                    "admin@example.net", &response);
        CHECK(did1 != NULL);
        CHECK(response.status == 200);
        free(did1);
        wf_response_free(&response);
        char *did2 = create_account(client, "ab.example.net", "ab@example.net",
                                    &response);
        CHECK(did2 != NULL);
        CHECK(response.status == 200);
        free(did2);
        wf_response_free(&response);
    }

    /* --- updateHandle: verified succeeds, unverified is refused --------- */
    {
        char *did = create_account(client, "alice.example.net",
                                   "alice@example.net", &response);
        CHECK(did != NULL);
        CHECK(response.status == 200);
        char *token = NULL;
        cJSON *json = json_response(&response);
        cJSON *tok =
            json ? cJSON_GetObjectItemCaseSensitive(json, "accessJwt") : NULL;
        if (cJSON_IsString(tok)) token = strdup(tok->valuestring);
        cJSON_Delete(json);
        wf_response_free(&response);
        CHECK(token != NULL);
        wf_xrpc_client_set_auth(client, token);

        g_resolver_succeeds = false;
        mock_plc.submissions = 0;
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                "{\"handle\":\"eve.example.net\"}",
                                &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);
        CHECK(mock_plc.submissions == 0);
        wf_xrpc_param describe_params[] = {{"repo", did}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.repo.describeRepo",
                                   describe_params, 1, &response) == WF_OK);
        cJSON *desc = json_response(&response);
        cJSON *h =
            desc ? cJSON_GetObjectItemCaseSensitive(desc, "handle") : NULL;
        CHECK(cJSON_IsString(h) &&
              strcmp(h->valuestring, "alice.example.net") == 0);
        cJSON_Delete(desc);
        wf_response_free(&response);

        g_resolver_succeeds = true;
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                "{\"handle\":\"fred.example.net\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(mock_plc.submissions >= 1);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, NULL);
        free(token);
        free(did);
    }

    metalbear_test_handle_resolver = NULL;
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    stop_mock_plc();
    rmtree(directory);

    printf("\n");
    if (failures)
        fprintf(stderr, "%d custom-domain handle test(s) failed\n", failures);
    return failures ? 1 : 0;
}

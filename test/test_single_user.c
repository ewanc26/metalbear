#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_single_user.c -- offline end-to-end coverage for server.single_user
 * (issue #264): exactly one bootstrap account, no signup/invite/admin surface,
 * federation unchanged, and a hard refusal to start over a data directory that
 * already holds two accounts.
 *
 * The bootstrap createAccount runs with invite_required and a closed
 * admission_default. A 200 there is the proof that the one permitted account
 * bypasses normal admission; the second createAccount must not get that far.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ftw.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

/* Like CHECK, but names the route/assertion and shows the status we got. */
#define CHECK_HTTP(what, actual, expected)                                     \
    do {                                                                       \
        long actual_ = (long)(actual);                                         \
        long expected_ = (long)(expected);                                     \
        if (actual_ != expected_) {                                            \
            fprintf(stderr, "FAIL %s:%d: %s: expected HTTP %ld, got %ld\n",    \
                    __FILE__, __LINE__, (what), expected_, actual_);           \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Recursively remove a directory tree (used for test cleanup). */
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

static cJSON *json_response(const wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

/* Create an account. The access token is caller-owned; the server-minted DID
 * is copied to out_did. Never logs either credential-bearing value. */
static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *password, char *out_did,
                            size_t out_did_len, long *out_status) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\","
             "\"email\":\"%s@example.com\"}",
             handle, password, handle);
    wf_response response = {0};
    wf_status status = wf_xrpc_procedure(
        client, "com.atproto.server.createAccount", body, &response);
    if (out_status) *out_status = response.status;
    if (status != WF_OK || response.status != 200) {
        wf_response_free(&response);
        return NULL;
    }
    cJSON *json = json_response(&response);
    cJSON *access =
        json ? cJSON_GetObjectItemCaseSensitive(json, "accessJwt") : NULL;
    cJSON *did = json ? cJSON_GetObjectItemCaseSensitive(json, "did") : NULL;
    char *token = cJSON_IsString(access) && access->valuestring[0]
                      ? strdup(access->valuestring)
                      : NULL;
    if (cJSON_IsString(did) && did->valuestring[0] && out_did && out_did_len)
        snprintf(out_did, out_did_len, "%s", did->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* Log in as the one account and check the session names the same DID/handle.
 * Returns the access token (caller frees), or NULL. */
static char *create_session(wf_xrpc_client *client, const char *identifier,
                            const char *password, const char *expected_handle,
                            const char *expected_did, long *out_status) {
    char body[512];
    snprintf(body, sizeof(body), "{\"identifier\":\"%s\",\"password\":\"%s\"}",
             identifier, password);
    wf_response response = {0};
    wf_status status = wf_xrpc_procedure(
        client, "com.atproto.server.createSession", body, &response);
    if (out_status) *out_status = response.status;
    if (status != WF_OK || response.status != 200) {
        wf_response_free(&response);
        return NULL;
    }
    cJSON *json = json_response(&response);
    cJSON *access =
        json ? cJSON_GetObjectItemCaseSensitive(json, "accessJwt") : NULL;
    cJSON *handle =
        json ? cJSON_GetObjectItemCaseSensitive(json, "handle") : NULL;
    cJSON *did = json ? cJSON_GetObjectItemCaseSensitive(json, "did") : NULL;
    bool valid = cJSON_IsString(access) && access->valuestring[0] &&
                 cJSON_IsString(handle) &&
                 strcmp(handle->valuestring, expected_handle) == 0 &&
                 cJSON_IsString(did) &&
                 strcmp(did->valuestring, expected_did) == 0;
    char *token = valid ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* A repo needs a head before listRepos will enumerate it. */
static long create_record(wf_xrpc_client *client, const char *repo) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
             "\"rkey\":\"single-user\",\"record\":{"
             "\"$type\":\"app.bsky.feed.post\","
             "\"text\":\"single user repo check\","
             "\"createdAt\":\"2026-11-25T00:00:00.000Z\"}}",
             repo);
    wf_response response = {0};
    (void)wf_xrpc_procedure(client, "com.atproto.repo.createRecord", body,
                            &response);
    long status = response.status;
    wf_response_free(&response);
    return status;
}

/* Each disabled XRPC surface must answer with a real 404, not Wolfram's 501
 * for an unregistered NSID or a 401 from the admin auth gate. */
static void expect_disabled_query(wf_xrpc_client *client, const char *label,
                                  const char *nsid, const wf_xrpc_param *params,
                                  size_t param_count) {
    wf_response response = {0};
    if (param_count)
        (void)wf_xrpc_query_params(client, nsid, params, param_count,
                                   &response);
    else
        (void)wf_xrpc_query(client, nsid, NULL, &response);
    CHECK_HTTP(label, response.status, 404);
    wf_response_free(&response);
}

static void expect_disabled_procedure(wf_xrpc_client *client, const char *label,
                                      const char *nsid, const char *body) {
    wf_response response = {0};
    (void)wf_xrpc_procedure(client, nsid, body, &response);
    CHECK_HTTP(label, response.status, 404);
    wf_response_free(&response);
}

/* Small raw HTTP/1.1 GET like test_frontend_static.c, so disabled non-XRPC
 * paths are checked on the wire rather than through the XRPC client. */
static int http_get(unsigned short port, const char *path, char *body,
                    size_t body_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    char request[512];
    int req_len = snprintf(request, sizeof(request),
                           "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                           "Connection: close\r\n\r\n",
                           path, (unsigned)port);
    if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
        close(fd);
        return -1;
    }
    size_t sent = 0;
    while (sent < (size_t)req_len) {
        ssize_t n = send(fd, request + sent, (size_t)req_len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) break;
        sent += (size_t)n;
    }
    size_t cap = 65536, used = 0;
    char *raw = malloc(cap);
    if (!raw) {
        close(fd);
        return -1;
    }
    for (;;) {
        if (used == cap) {
            char *grown = realloc(raw, cap * 2);
            if (!grown) break;
            raw = grown;
            cap *= 2;
        }
        ssize_t n = recv(fd, raw + used, cap - used, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);

    int status = -1;
    if (used >= 12 && strncmp(raw, "HTTP/1.", 7) == 0) status = atoi(raw + 9);
    if (body && body_len) {
        body[0] = '\0';
        char *sep = NULL;
        for (size_t i = 0; i + 3 < used; i++) {
            if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' &&
                raw[i + 3] == '\n') {
                sep = raw + i;
                break;
            }
        }
        if (sep) {
            size_t n = (size_t)((raw + used) - (sep + 4));
            if (n >= body_len) n = body_len - 1;
            memcpy(body, sep + 4, n);
            body[n] = '\0';
        }
    }
    free(raw);
    return status;
}

static void check_operator_json(unsigned short port) {
    char body[65536];
    int status = http_get(port, "/operator.json", body, sizeof(body));
    CHECK_HTTP("GET /operator.json", status, 200);
    if (status != 200) return;

    cJSON *json = cJSON_Parse(body);
    CHECK(json != NULL);
    if (!json) return;
    cJSON *capabilities =
        cJSON_GetObjectItemCaseSensitive(json, "capabilities");
    cJSON *single =
        cJSON_GetObjectItemCaseSensitive(capabilities, "singleUser");
    CHECK(cJSON_IsTrue(single));
    cJSON *registration =
        cJSON_GetObjectItemCaseSensitive(json, "registration");
    cJSON *mode = cJSON_GetObjectItemCaseSensitive(registration, "mode");
    CHECK(cJSON_IsString(mode));
    CHECK(cJSON_IsString(mode) && strcmp(mode->valuestring, "closed") == 0);
    cJSON *closed = cJSON_GetObjectItemCaseSensitive(registration, "closed");
    CHECK(cJSON_IsTrue(closed));
    cJSON_Delete(json);
}

/* Federation is not part of the restriction: the one account still shows up
 * in listRepos (after it has a repo head). */
static void check_single_repo(wf_xrpc_client *client,
                              const char *expected_did) {
    wf_response response = {0};
    CHECK(wf_xrpc_query(client, "com.atproto.sync.listRepos", NULL,
                        &response) == WF_OK);
    CHECK_HTTP("com.atproto.sync.listRepos", response.status, 200);
    if (response.status == 200) {
        cJSON *json = json_response(&response);
        CHECK(json != NULL);
        if (json) {
            cJSON *repos = cJSON_GetObjectItemCaseSensitive(json, "repos");
            CHECK(cJSON_IsArray(repos));
            CHECK(cJSON_IsArray(repos) && cJSON_GetArraySize(repos) == 1);
            cJSON *repo =
                cJSON_IsArray(repos) ? cJSON_GetArrayItem(repos, 0) : NULL;
            cJSON *did = cJSON_GetObjectItemCaseSensitive(repo, "did");
            CHECK(cJSON_IsString(did));
            CHECK(cJSON_IsString(did) &&
                  strcmp(did->valuestring, expected_did) == 0);
            cJSON_Delete(json);
        }
    }
    wf_response_free(&response);
}

static void test_single_user_server(void) {
    char directory[] = "/tmp/metalbear-single-user-XXXXXX";
    char *made = mkdtemp(directory);
    CHECK(made != NULL);
    if (!made) return;

    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 1,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        /* The one bootstrap must work even though signup is otherwise shut. */
        .single_user = true,
        .invite_required = true,
        .admission_default = "closed",
        .admin_password = "secret-admin",
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) {
        rmtree(directory);
        return;
    }
    unsigned short port = metalbear_server_port(server);
    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u", (unsigned)port);
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);
    if (!client) {
        metalbear_server_free(server);
        rmtree(directory);
        return;
    }

    char did[256] = {0};
    long status = 0;
    char *token = create_account(client, "solo.example.com", "solo-secret", did,
                                 sizeof(did), &status);
    CHECK_HTTP("first createAccount with invite_required and closed admission",
               status, 200);
    CHECK(token != NULL);
    CHECK(did[0] != '\0');

    char other_did[256] = {0};
    status = 0;
    char *second = create_account(client, "second.example.com", "second-secret",
                                  other_did, sizeof(other_did), &status);
    CHECK_HTTP("second createAccount", status, 404);
    CHECK(second == NULL);
    CHECK(other_did[0] == '\0');
    free(second);

    {
        wf_xrpc_param did_params[] = {{"did", did}};
        wf_xrpc_param handle_params[] = {{"handle", "spare.example.com"}};
        wf_xrpc_param search_params[] = {{"limit", "1"}};
        expect_disabled_query(client, "server.getAccountInviteCodes (query)",
                              "com.atproto.server.getAccountInviteCodes", NULL,
                              0);
        expect_disabled_procedure(client, "server.createInviteCode (procedure)",
                                  "com.atproto.server.createInviteCode", "{}");
        expect_disabled_procedure(
            client, "server.createInviteCodes (procedure)",
            "com.atproto.server.createInviteCodes", "{\"codes\":1}");
        expect_disabled_query(client, "admin.getAccountInfo (query)",
                              "com.atproto.admin.getAccountInfo", did_params,
                              1);
        expect_disabled_query(client, "admin.searchAccounts (query)",
                              "com.atproto.admin.searchAccounts", search_params,
                              1);
        expect_disabled_procedure(
            client, "admin.updateSubjectStatus (procedure)",
            "com.atproto.admin.updateSubjectStatus", "{}");
        expect_disabled_procedure(client, "admin.deleteAccount (procedure)",
                                  "com.atproto.admin.deleteAccount", "{}");
        expect_disabled_query(client, "temp.checkHandleAvailability (query)",
                              "com.atproto.temp.checkHandleAvailability",
                              handle_params, 1);
        expect_disabled_procedure(client, "temp.addReservedHandle (procedure)",
                                  "com.atproto.temp.addReservedHandle",
                                  "{\"handle\":\"reserved.example.com\"}");
        expect_disabled_query(client, "temp.checkSignupQueue (query)",
                              "com.atproto.temp.checkSignupQueue", NULL, 0);
        expect_disabled_query(client, "temp.exportAccountBundle (query)",
                              "com.atproto.temp.exportAccountBundle",
                              did_params, 1);
    }

    {
        const char *paths[] = {"/admin", "/admin.html", "/signup",
                               "/signup.html", "/_ops/audit"};
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            int raw_status = http_get(port, paths[i], NULL, 0);
            CHECK_HTTP(paths[i], raw_status, 404);
        }
    }
    check_operator_json(port);

    char *login = NULL;
    status = 0;
    login = create_session(client, "solo.example.com", "solo-secret",
                           "solo.example.com", did, &status);
    CHECK_HTTP("createSession for the one account", status, 200);
    CHECK(login != NULL);
    if (login) {
        wf_xrpc_client_set_auth(client, login);
        CHECK_HTTP("createRecord for the one account",
                   create_record(client, did), 200);
        wf_xrpc_client_set_auth(client, NULL);
    }
    check_single_repo(client, did);

    free(login);
    free(token);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
}

/* A separate fixture: single-user must not silently hide extra accounts on a
 * data directory that was already used as a normal multi-account host. */
static void test_existing_multi_account_refusal(void) {
    char directory[] = "/tmp/metalbear-multi-to-single-XXXXXX";
    char *made = mkdtemp(directory);
    CHECK(made != NULL);
    if (!made) return;

    metalbear_config multi = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 1,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .admission_default = "open",
        .admin_password = "secret-admin",
    };
    metalbear_server *server = metalbear_server_start(&multi);
    CHECK(server != NULL);
    if (!server) {
        rmtree(directory);
        return;
    }
    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);
    if (client) {
        char did_one[256] = {0};
        char did_two[256] = {0};
        long status = 0;
        char *one = create_account(client, "one.example.com", "one-secret",
                                   did_one, sizeof(did_one), &status);
        CHECK_HTTP("multi-account fixture first createAccount", status, 200);
        CHECK(one != NULL);
        status = 0;
        char *two = create_account(client, "two.example.com", "two-secret",
                                   did_two, sizeof(did_two), &status);
        CHECK_HTTP("multi-account fixture second createAccount", status, 200);
        CHECK(two != NULL);
        CHECK(did_one[0] != '\0');
        CHECK(did_two[0] != '\0');
        free(one);
        free(two);
        wf_xrpc_client_free(client);
    }
    metalbear_server_free(server);

    metalbear_config single = multi;
    single.single_user = true;
    metalbear_server *refused = metalbear_server_start(&single);
    CHECK(refused == NULL);
    if (refused) metalbear_server_free(refused);
    rmtree(directory);
}

int main(void) {
    test_single_user_server();
    test_existing_multi_account_refusal();
    if (failures == 0) {
        printf("test_single_user: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_single_user: %d checks failed\n", failures);
    return 1;
}

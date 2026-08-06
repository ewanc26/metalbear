#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include "metalbear/server.h"
#include "metalbear/account/account_registry.h"
#include "wolfram/repo/car.h"
#include "wolfram/sync_subscribe.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ftw.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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

static int write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 0;
        cursor += written;
        length -= (size_t)written;
    }
    return 1;
}

static int read_exact(int fd, void *data, size_t length) {
    unsigned char *cursor = data;
    while (length > 0) {
        struct pollfd poll_fd = {fd, POLLIN, 0};
        if (poll(&poll_fd, 1, 5000) <= 0) return 0;
        ssize_t received = read(fd, cursor, length);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return 0;
        cursor += received;
        length -= (size_t)received;
    }
    return 1;
}

static int firehose_connect(uint16_t port, int64_t cursor) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (fd < 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    char request[512];
    int length = snprintf(
        request, sizeof(request),
        "GET /xrpc/com.atproto.sync.subscribeRepos?cursor=%lld HTTP/1.1\r\n"
        "Host: 127.0.0.1:%u\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        (long long)cursor, (unsigned)port);
    if (!write_all(fd, request, (size_t)length)) {
        close(fd);
        return -1;
    }
    char header[2048] = {0};
    size_t used = 0;
    while (used + 1 < sizeof(header) && !strstr(header, "\r\n\r\n")) {
        if (!read_exact(fd, header + used, 1)) break;
        used++;
        header[used] = '\0';
    }
    if (!strstr(header, " 101 ") && strncmp(header, "HTTP/1.1 101", 12) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int firehose_read(int fd, wf_subscribe_event *event) {
    unsigned char header[10];
    if (!read_exact(fd, header, 2) || (header[0] & 0x0f) != 0x2 ||
        (header[1] & 0x80))
        return 0;
    uint64_t length = header[1] & 0x7f;
    if (length == 126) {
        if (!read_exact(fd, header + 2, 2)) return 0;
        length = ((uint64_t)header[2] << 8) | header[3];
    } else if (length == 127) {
        if (!read_exact(fd, header + 2, 8)) return 0;
        length = 0;
        for (int i = 0; i < 8; i++) length = (length << 8) | header[2 + i];
    }
    if (length > 16 * 1024 * 1024) return 0;
    unsigned char *payload = malloc(length ? (size_t)length : 1);
    if (!payload || !read_exact(fd, payload, (size_t)length)) {
        free(payload);
        return 0;
    }
    wf_status status =
        wf_subscribe_decode_frame(payload, (size_t)length, event);
    free(payload);
    return status == WF_OK;
}

/*
 * Read forward until an event of `type` arrives, discarding the rest.
 *
 * Assertions here used to pin absolute sequence numbers (seq_base + 3, + 4,
 * …), which made every one of them break whenever the number of events the
 * server emits changed — as it did when account creation began announcing
 * #identity/#account/#sync on the host log. What these tests actually care
 * about is that a given event appears, in order, after the write that caused
 * it; the exact ordinal is an implementation detail of everything that ran
 * before. Bounded so a missing event fails rather than hangs.
 */
static int firehose_read_until(int fd, int type, wf_subscribe_event *event) {
    for (int i = 0; i < 32; i++) {
        memset(event, 0, sizeof(*event));
        if (!firehose_read(fd, event)) return 0;
        if (event->type == type) return 1;
        wf_subscribe_event_free(event);
    }
    return 0;
}

/* POST an admin-gated XRPC method with HTTP Basic `admin:<password>`, which
 * is how the reference authenticates these. */
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
    char directory[] = "/tmp/metalbear-test-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .admin_password = "secret-admin",
        /* No account exists until one is created below: the server has no
         * configured account to be "the" account any more. */
        .invite_required = false,
        /* The rate limiter is not under test here; the suite issues more than
         * the 100-request default within the first window, which later starves
         * unrelated endpoints (resolveHandle) into 429s. */
        .rate_limit = 10000,
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

    /*
     * Create the account this test acts as. The server starts with an empty
     * registry, so nothing exists until createAccount says so — the same path
     * every other account takes.
     */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                            "{\"handle\":\"alice.example.com\","
                            "\"password\":\"correct horse battery staple\","
                            "\"did\":\"did:plc:metalbeartest\","
                            "\"email\":\"alice@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /*
     * Sequence numbers are not guaranteed to start at 1 — a fresh event log is
     * seeded above any value this host may already have issued, so a rebuilt
     * PDS never re-hands-out cursors (see seed_sequence_floor). Read the base
     * from the events the account creation above emitted and express every
     * cursor below relative to it, rather than hard-coding absolutes that are
     * an implementation detail.
     */
    int64_t seq_base = 0;
    {
        int probe = firehose_connect(metalbear_server_port(server), 0);
        CHECK(probe >= 0);
        wf_subscribe_event first = {0};
        CHECK(probe >= 0 && firehose_read(probe, &first));
        seq_base = first.seq - 1; /* seq of the first event, minus one */
        CHECK(seq_base >= 0);
        wf_subscribe_event_free(&first);
        if (probe >= 0) close(probe);
    }

    int firehose =
        firehose_connect(metalbear_server_port(server), seq_base + 2);
    CHECK(firehose >= 0);

    CHECK(wf_xrpc_query(client, "_health", NULL, &response) == WF_OK);
    cJSON *health_json = json_response(&response);
    CHECK(cJSON_IsString(
        cJSON_GetObjectItemCaseSensitive(health_json, "version")));
    cJSON_Delete(health_json);
    wf_response_free(&response);

    /* Test createAccount: register a second account in the registry */
    CHECK(wf_xrpc_procedure(
              client, "com.atproto.server.createAccount",
              "{\"handle\":\"bob.example.com\",\"password\":\"bobsecret\","
              "\"did\":\"did:plc:bob\",\"email\":\"bob@example.com\"}",
              &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *create_json = json_response(&response);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(create_json, "did")));
    CHECK(strcmp(
              cJSON_GetObjectItemCaseSensitive(create_json, "did")->valuestring,
              "did:plc:bob") == 0);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(create_json, "handle")
                     ->valuestring,
                 "bob.example.com") == 0);
    CHECK(cJSON_IsString(
        cJSON_GetObjectItemCaseSensitive(create_json, "accessJwt")));
    CHECK(cJSON_IsString(
        cJSON_GetObjectItemCaseSensitive(create_json, "refreshJwt")));
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* Missing email should return InvalidEmail */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                            "{\"handle\":\"x.example.com\",\"password\":"
                            "\"test\",\"did\":\"did:plc:x\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    create_json = json_response(&response);
    CHECK(
        strcmp(
            cJSON_GetObjectItemCaseSensitive(create_json, "error")->valuestring,
            "InvalidEmail") == 0);
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* Missing handle should return InvalidHandle */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                            "{\"email\":\"x@example.com\",\"password\":"
                            "\"test\",\"did\":\"did:plc:x\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    create_json = json_response(&response);
    CHECK(
        strcmp(
            cJSON_GetObjectItemCaseSensitive(create_json, "error")->valuestring,
            "InvalidHandle") == 0);
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* Duplicate handle should return HandleNotAvailable */
    CHECK(wf_xrpc_procedure(
              client, "com.atproto.server.createAccount",
              "{\"handle\":\"bob.example.com\",\"password\":\"other\","
              "\"did\":\"did:plc:bob2\",\"email\":\"other@example.com\"}",
              &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    create_json = json_response(&response);
    CHECK(
        strcmp(
            cJSON_GetObjectItemCaseSensitive(create_json, "error")->valuestring,
            "HandleNotAvailable") == 0);
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* createAccount must provision a real, filesystem-isolated account: a
     * dedicated subdirectory holding the account's own repo/account/auth
     * stores, not just a registry entry. */
    char *bob_dir = NULL;
    CHECK(metalbear_account_dir_for_did(directory, "did:plc:bob", &bob_dir) ==
              WF_OK &&
          bob_dir);
    struct stat st;
    CHECK(stat(bob_dir, &st) == 0 && S_ISDIR(st.st_mode));
    char probe[1024];
    snprintf(probe, sizeof(probe), "%s/repo.sqlite3", bob_dir);
    CHECK(stat(probe, &st) == 0 && S_ISREG(st.st_mode));
    snprintf(probe, sizeof(probe), "%s/account.sqlite3", bob_dir);
    CHECK(stat(probe, &st) == 0 && S_ISREG(st.st_mode));
    snprintf(probe, sizeof(probe), "%s/auth.sqlite3", bob_dir);
    CHECK(stat(probe, &st) == 0 && S_ISREG(st.st_mode));
    snprintf(probe, sizeof(probe), "%s/blobs", bob_dir);
    CHECK(stat(probe, &st) == 0 && S_ISDIR(st.st_mode));
    free(bob_dir);

    /* A second, distinct account gets its own separate directory. */
    CHECK(wf_xrpc_procedure(
              client, "com.atproto.server.createAccount",
              "{\"handle\":\"dave.example.com\",\"password\":\"davesecret\","
              "\"did\":\"did:plc:dave\",\"email\":\"dave@example.com\"}",
              &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *dave_json = json_response(&response);
    CHECK(
        strcmp(cJSON_GetObjectItemCaseSensitive(dave_json, "did")->valuestring,
               "did:plc:dave") == 0);
    cJSON_Delete(dave_json);
    wf_response_free(&response);

    char *dave_dir = NULL;
    CHECK(metalbear_account_dir_for_did(directory, "did:plc:dave", &dave_dir) ==
              WF_OK &&
          dave_dir);
    CHECK(stat(dave_dir, &st) == 0 && S_ISDIR(st.st_mode));
    snprintf(probe, sizeof(probe), "%s/repo.sqlite3", dave_dir);
    CHECK(stat(probe, &st) == 0 && S_ISREG(st.st_mode));
    char *bob_dir_again = NULL;
    CHECK(metalbear_account_dir_for_did(directory, "did:plc:bob",
                                        &bob_dir_again) == WF_OK &&
          bob_dir_again);
    CHECK(strcmp(bob_dir_again, dave_dir) != 0);
    free(bob_dir_again);
    free(dave_dir);

    /* Test requestPasswordReset: accepts email, not identifier */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestPasswordReset",
                            "{\"email\":\"alice@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* Missing email should fail */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestPasswordReset",
                            "{}", &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    create_json = json_response(&response);
    CHECK(
        strcmp(
            cJSON_GetObjectItemCaseSensitive(create_json, "error")->valuestring,
            "InvalidRequest") == 0);
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* Landing page (GET /) must be dynamic HTML listing hosted accounts. */
    CHECK(wf_http_get(client, base, &response) == WF_OK);
    CHECK(response.status == 200);
    CHECK(response.body_len > 0);
    CHECK(strncmp(response.body, "<!DOCTYPE html>", 15) == 0);
    /* The bootstrap account (alice) must appear. */
    CHECK(body_contains(&response, "alice.example.com"));
    CHECK(body_contains(&response, "did:plc:metalbeartest"));
    /* A created account (bob) must also appear once it is hosted. */
    CHECK(body_contains(&response, "bob.example.com"));
    CHECK(body_contains(&response, "did:plc:bob"));
    /* The heading must announce the Wolfram SDK version it is built on,
     * not just MetalBear's own. */
    CHECK(body_contains(&response, "Wolfram " WOLFRAM_VERSION_STRING));
    wf_response_free(&response);

    /* === GET /_debug/health (admin-gated) ===
     * Like /metrics: no/wrong Basic auth -> 401, correct -> a JSON dump of
     * build versions, uptime, identity/config, accounts, the firehose cursor,
     * capabilities and the request counters. */
    {
        char debug_url[160];
        snprintf(debug_url, sizeof(debug_url), "%s/_debug/health", base);
        /* No Authorization header -> 401 */
        CHECK(wf_http_get_with_headers(client, debug_url, NULL, 0, &response) ==
              WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);
        /* Wrong Basic credential -> 401 */
        {
            char wrong[64];
            int wn = snprintf(wrong, sizeof(wrong), "admin:%s", "wrong");
            char wrong_b64[128];
            int wlen = EVP_EncodeBlock((unsigned char *)wrong_b64,
                                       (const unsigned char *)wrong, wn);
            wrong_b64[wlen] = '\0';
            char wrong_hdr[160];
            snprintf(wrong_hdr, sizeof(wrong_hdr), "Basic %s", wrong_b64);
            wf_http_header hdr = {"Authorization", wrong_hdr};
            CHECK(wf_http_get_with_headers(client, debug_url, &hdr, 1,
                                           &response) == WF_ERR_HTTP);
            CHECK(response.status == 401);
            wf_response_free(&response);
        }
        /* Correct Basic credential -> 200 with the debug JSON. */
        {
            char right[64];
            int rn = snprintf(right, sizeof(right), "admin:%s", "secret-admin");
            char right_b64[128];
            int rlen = EVP_EncodeBlock((unsigned char *)right_b64,
                                       (const unsigned char *)right, rn);
            right_b64[rlen] = '\0';
            char right_hdr[160];
            snprintf(right_hdr, sizeof(right_hdr), "Basic %s", right_b64);
            wf_http_header hdr = {"Authorization", right_hdr};
            CHECK(wf_http_get_with_headers(client, debug_url, &hdr, 1,
                                           &response) == WF_OK);
            CHECK(response.status == 200);
            cJSON *dbg = json_response(&response);
            CHECK(dbg != NULL);
            cJSON *build = cJSON_GetObjectItemCaseSensitive(dbg, "build");
            CHECK(cJSON_IsObject(build));
            CHECK(cJSON_GetObjectItemCaseSensitive(build, "metalbearVersion") &&
                  strcmp(cJSON_GetObjectItemCaseSensitive(build,
                                                          "metalbearVersion")
                             ->valuestring,
                         METALBEAR_VERSION) == 0);
            CHECK(
                cJSON_GetObjectItemCaseSensitive(build, "wolframVersion") &&
                strcmp(cJSON_GetObjectItemCaseSensitive(build, "wolframVersion")
                           ->valuestring,
                       WOLFRAM_VERSION_STRING) == 0);
            CHECK(cJSON_GetObjectItemCaseSensitive(build, "commit") &&
                  strcmp(cJSON_GetObjectItemCaseSensitive(build, "commit")
                             ->valuestring,
                         METALBEAR_BUILD_COMMIT) == 0);
            CHECK(cJSON_GetObjectItemCaseSensitive(build, "builtAt") &&
                  strcmp(cJSON_GetObjectItemCaseSensitive(build, "builtAt")
                             ->valuestring,
                         METALBEAR_BUILD_TIME) == 0);
            cJSON *proc = cJSON_GetObjectItemCaseSensitive(dbg, "process");
            CHECK(cJSON_IsObject(proc));
            CHECK(cJSON_IsNumber(
                cJSON_GetObjectItemCaseSensitive(proc, "uptimeSeconds")));
            cJSON *ident = cJSON_GetObjectItemCaseSensitive(dbg, "identity");
            CHECK(cJSON_IsObject(ident));
            CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(ident, "serviceDid")
                             ->valuestring,
                         "did:web:pds.example.com") == 0);
            CHECK(cJSON_IsTrue(
                cJSON_GetObjectItemCaseSensitive(ident, "adminConfigured")));
            cJSON *accts = cJSON_GetObjectItemCaseSensitive(dbg, "accounts");
            CHECK(cJSON_IsObject(accts));
            CHECK((int)cJSON_GetObjectItemCaseSensitive(accts, "total")
                      ->valuedouble == 3);
            cJSON *fire = cJSON_GetObjectItemCaseSensitive(dbg, "firehose");
            CHECK(cJSON_IsObject(fire));
            CHECK(cJSON_IsNumber(
                cJSON_GetObjectItemCaseSensitive(fire, "sequence")));
            CHECK(cJSON_IsObject(
                cJSON_GetObjectItemCaseSensitive(dbg, "capabilities")));
            CHECK(cJSON_IsObject(
                cJSON_GetObjectItemCaseSensitive(dbg, "metrics")));
            cJSON *rl = cJSON_GetObjectItemCaseSensitive(dbg, "rateLimits");
            CHECK(cJSON_IsObject(rl));
            CHECK(cJSON_IsObject(
                cJSON_GetObjectItemCaseSensitive(rl, "createSessionDay")));
            cJSON_Delete(dbg);
            wf_response_free(&response);
        }
    }

    /* === GET /operator.json ===
     * Public operator metadata; the software section must name the exact
     * versions the build links, MetalBear and Wolfram alike, so the landing
     * page can show the pair without a second admin-gated call. */
    {
        char op_url[160];
        snprintf(op_url, sizeof(op_url), "%s/operator.json", base);
        CHECK(wf_http_get(client, op_url, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *op = json_response(&response);
        CHECK(op != NULL);
        cJSON *software = cJSON_GetObjectItemCaseSensitive(op, "software");
        CHECK(cJSON_IsObject(software));
        cJSON *mver = cJSON_GetObjectItemCaseSensitive(software, "version");
        CHECK(cJSON_IsString(mver) &&
              strcmp(mver->valuestring, METALBEAR_VERSION) == 0);
        cJSON *wver =
            cJSON_GetObjectItemCaseSensitive(software, "wolframVersion");
        CHECK(cJSON_IsString(wver) &&
              strcmp(wver->valuestring, WOLFRAM_VERSION_STRING) == 0);
        cJSON *commit = cJSON_GetObjectItemCaseSensitive(software, "commit");
        CHECK(cJSON_IsString(commit) &&
              strcmp(commit->valuestring, METALBEAR_BUILD_COMMIT) == 0);
        cJSON *built_at = cJSON_GetObjectItemCaseSensitive(software, "builtAt");
        CHECK(cJSON_IsString(built_at) &&
              strcmp(built_at->valuestring, METALBEAR_BUILD_TIME) == 0);
        cJSON_Delete(op);
        wf_response_free(&response);
    }

    char well_known_url[160];
    snprintf(well_known_url, sizeof(well_known_url),
             "%s/.well-known/atproto-did", base);
    /*
     * The request arrives with Host: 127.0.0.1, which hosts no account. That
     * must be a miss, not somebody's DID: this used to fall back to the
     * configured account, so every unknown hostname was answered with that
     * account's identity — a wrong answer rather than a missing one.
     */
    CHECK(wf_http_get(client, well_known_url, &response) == WF_ERR_HTTP);
    CHECK(response.status == 404);
    wf_response_free(&response);

    snprintf(well_known_url, sizeof(well_known_url), "%s/.well-known/did.json",
             base);
    /* Same for the DID document: an unknown hostname is neither the service
     * identity nor an account here. */
    CHECK(wf_http_get(client, well_known_url, &response) == WF_ERR_HTTP);
    CHECK(response.status == 404);
    wf_response_free(&response);

    CHECK(wf_xrpc_query(client, "com.atproto.server.describeServer", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "did")));
    CHECK(cJSON_IsArray(
        cJSON_GetObjectItemCaseSensitive(json, "availableUserDomains")));
    CHECK(cJSON_IsBool(
        cJSON_GetObjectItemCaseSensitive(json, "inviteCodeRequired")));
    CHECK(cJSON_IsBool(
        cJSON_GetObjectItemCaseSensitive(json, "phoneVerificationRequired")));
    cJSON *blob_lim = cJSON_GetObjectItemCaseSensitive(json, "blobUploadLimit");
    if (blob_lim) CHECK(cJSON_IsNumber(blob_lim));
    CHECK(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(json, "contact")));
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_param handle_params[] = {{"handle", "alice.example.com"}};
    CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveHandle",
                               handle_params, 1, &response) == WF_OK);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "did")->valuestring,
                 "did:plc:metalbeartest") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    CHECK(wf_xrpc_procedure(
              client, "com.atproto.server.createSession",
              "{\"identifier\":\"alice.example.com\",\"password\":\"wrong\"}",
              &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);

    /* Matches the reference's OLD_PASSWORD_MAX_LENGTH (512) check: an
     * implausibly long password is rejected before it is ever hashed. */
    {
        char long_password_body[700];
        char *p = long_password_body;
        p +=
            sprintf(p, "{\"identifier\":\"alice.example.com\",\"password\":\"");
        for (int i = 0; i < 513; i++) *p++ = 'a';
        strcpy(p, "\"}");
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                                long_password_body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        cJSON *long_pw_json = json_response(&response);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(long_pw_json, "error")
                         ->valuestring,
                     "AuthenticationRequired") == 0);
        cJSON_Delete(long_pw_json);
        wf_response_free(&response);
    }

    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                            "{\"identifier\":\"alice.example.com\","
                            "\"password\":\"correct horse battery staple\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    cJSON *refresh = cJSON_GetObjectItemCaseSensitive(json, "refreshJwt");
    CHECK(cJSON_IsString(access) && strchr(access->valuestring, '.') != NULL);
    CHECK(cJSON_IsString(refresh) && strchr(refresh->valuestring, '.') != NULL);
    cJSON *did_doc = cJSON_GetObjectItemCaseSensitive(json, "didDoc");
    CHECK(cJSON_IsObject(did_doc));
    if (did_doc) {
        cJSON *dd_id = cJSON_GetObjectItemCaseSensitive(did_doc, "id");
        CHECK(cJSON_IsString(dd_id) && dd_id->valuestring[0] != '\0');
        cJSON *dd_svc = cJSON_GetObjectItemCaseSensitive(did_doc, "service");
        CHECK(cJSON_IsArray(dd_svc));
        if (dd_svc && cJSON_GetArraySize(dd_svc) > 0) {
            cJSON *svc0 = cJSON_GetArrayItem(dd_svc, 0);
            cJSON *svc_ep =
                cJSON_GetObjectItemCaseSensitive(svc0, "serviceEndpoint");
            CHECK(cJSON_IsString(svc_ep));
        }
    }
    char *access_token =
        cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    char *refresh_token =
        cJSON_IsString(refresh) ? strdup(refresh->valuestring) : NULL;
    char *privileged_password = NULL;
    cJSON_Delete(json);
    wf_response_free(&response);

    /* Test lexicon conformance for auth-required email/invite endpoints */
    wf_xrpc_client_set_auth(client, access_token);

    /* getAccountInviteCodes: uses 'codes' field name per lexicon */
    CHECK(wf_xrpc_query(client, "com.atproto.server.getAccountInviteCodes",
                        NULL, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(cJSON_GetObjectItemCaseSensitive(json, "codes") != NULL);
    CHECK(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(json, "codes")));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* updateEmail: requires 'email' per lexicon */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.updateEmail", "{}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);

    /* updateEmail: succeeds with email (no token needed when unconfirmed) */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.updateEmail",
                            "{\"email\":\"new@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* requestEmailUpdate: takes no input per lexicon, returns tokenRequired */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestEmailUpdate",
                            "{}", &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "tokenRequired")));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* getSession now includes email and emailConfirmed per lexicon */
    CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "email")->valuestring,
                 "new@example.com") == 0);
    CHECK(
        cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(json, "emailConfirmed")));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* checkAccountStatus: auth-required, lexicon-conformant output */
    CHECK(wf_xrpc_query(client, "com.atproto.server.checkAccountStatus", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(json, "activated")));
    CHECK(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(json, "validDid")));
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "repoCommit")));
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "repoRev")));
    CHECK(cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(json, "repoBlocks")));
    CHECK(cJSON_IsNumber(
        cJSON_GetObjectItemCaseSensitive(json, "indexedRecords")));
    CHECK(cJSON_IsNumber(
        cJSON_GetObjectItemCaseSensitive(json, "privateStateValues")));
    CHECK(cJSON_IsNumber(
        cJSON_GetObjectItemCaseSensitive(json, "expectedBlobs")));
    CHECK(cJSON_IsNumber(
        cJSON_GetObjectItemCaseSensitive(json, "importedBlobs")));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* checkAccountStatus without auth is rejected */
    wf_xrpc_client_set_auth(client, NULL);
    CHECK(wf_xrpc_query(client, "com.atproto.server.checkAccountStatus", NULL,
                        &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, access_token);

    /* reserveSigningKey: public, returns a did:key */
    wf_xrpc_client_set_auth(client, NULL);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.reserveSigningKey",
                            "{\"did\":\"did:plc:metalbeartest\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *signing_key = cJSON_GetObjectItemCaseSensitive(json, "signingKey");
    CHECK(cJSON_IsString(signing_key) &&
          strncmp(signing_key->valuestring, "did:key:", 8) == 0);
    cJSON_Delete(json);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, access_token);

    /*
     * createInviteCode is admin-gated, matching the reference's
     * authVerifier.adminToken. A bearer token must not work: when invite codes
     * are required, an endpoint reachable only with an account token could
     * never issue the code a first account needs.
     */
    {
        char admin_cred[64];
        int an = snprintf(admin_cred, sizeof(admin_cred), "admin:%s",
                          "secret-admin");
        char admin_b64[128];
        int alen = EVP_EncodeBlock((unsigned char *)admin_b64,
                                   (const unsigned char *)admin_cred, an);
        admin_b64[alen] = '\0';
        char admin_auth[160];
        snprintf(admin_auth, sizeof(admin_auth), "Basic %s", admin_b64);
        wf_http_header admin_hdr = {"Authorization", admin_auth};
        char invite_url[256];
        snprintf(invite_url, sizeof(invite_url),
                 "%s/xrpc/com.atproto.server.createInviteCode", base);

        /* A bearer token is refused. */
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createInviteCode",
                                "{\"useCount\":5}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);

        /* Admin Basic auth returns a real code. */
        CHECK(wf_http_post(client, invite_url, "application/json",
                           "{\"useCount\":5}", &admin_hdr, 1,
                           &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *code = cJSON_GetObjectItemCaseSensitive(json, "code");
        CHECK(cJSON_IsString(code) && strlen(code->valuestring) > 0);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* createInviteCode without useCount fails */
        CHECK(wf_http_post(client, invite_url, "application/json", "{}",
                           &admin_hdr, 1, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);
    }

    /* createInviteCodes: returns per-account code lists */
    CHECK(admin_post(client, base, "com.atproto.server.createInviteCodes",
                     "{\"codeCount\":3,\"useCount\":2,"
                     "\"forAccounts\":[\"did:plc:metalbeartest\"]}",
                     &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *codes = cJSON_GetObjectItemCaseSensitive(json, "codes");
    CHECK(cJSON_IsArray(codes) && cJSON_GetArraySize(codes) == 1);
    cJSON *acct = cJSON_GetArrayItem(codes, 0);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(acct, "account")->valuestring,
                 "did:plc:metalbeartest") == 0);
    cJSON *acct_codes = cJSON_GetObjectItemCaseSensitive(acct, "codes");
    CHECK(cJSON_IsArray(acct_codes) && cJSON_GetArraySize(acct_codes) == 3);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* createInviteCodes without codeCount fails validation (admin-authed, so
     * this tests the input check rather than the auth gate). */
    CHECK(admin_post(client, base, "com.atproto.server.createInviteCodes",
                     "{\"useCount\":2}", &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);

    /* === com.atproto.sync.requestCrawl (no crawlers configured) ===
     * Mirrors refpds: when METALBEAR_CRAWLERS is empty the PDS must
     * return an honest error, never a fabricated success. */
    CHECK(wf_xrpc_procedure(client, "com.atproto.sync.requestCrawl",
                            "{\"hostname\":\"example.com\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "NoCrawlersConfigured") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* === com.atproto.admin.getAccountInfo (admin-gated) ===
     * The test server sets METALBEAR_ADMIN_PASSWORD. Without/with-wrong
     * Basic auth the endpoint is rejected (401); with the right
     * credential it returns the account's did/handle/active. */
    wf_xrpc_client_set_auth(client, NULL);
    char admin_url[160];
    snprintf(admin_url, sizeof(admin_url),
             "%s/xrpc/com.atproto.admin.getAccountInfo?did=%s", base,
             "did:plc:bob");
    /* No Authorization header -> 401 */
    CHECK(wf_http_get_with_headers(client, admin_url, NULL, 0, &response) ==
          WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    /* Wrong Basic credential -> 401 */
    {
        char wrong[64];
        int wn = snprintf(wrong, sizeof(wrong), "admin:%s", "wrong");
        char wrong_b64[128];
        int wlen = EVP_EncodeBlock((unsigned char *)wrong_b64,
                                   (const unsigned char *)wrong, wn);
        wrong_b64[wlen] = '\0';
        char wrong_hdr[160];
        snprintf(wrong_hdr, sizeof(wrong_hdr), "Basic %s", wrong_b64);
        wf_http_header hdr = {"Authorization", wrong_hdr};
        CHECK(wf_http_get_with_headers(client, admin_url, &hdr, 1, &response) ==
              WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);
    }
    /* Correct Basic credential -> 200 with did/handle/active */
    {
        char right[64];
        int rn = snprintf(right, sizeof(right), "admin:%s", "secret-admin");
        char right_b64[128];
        int rlen = EVP_EncodeBlock((unsigned char *)right_b64,
                                   (const unsigned char *)right, rn);
        right_b64[rlen] = '\0';
        char right_hdr[160];
        snprintf(right_hdr, sizeof(right_hdr), "Basic %s", right_b64);
        wf_http_header hdr = {"Authorization", right_hdr};
        CHECK(wf_http_get_with_headers(client, admin_url, &hdr, 1, &response) ==
              WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "did")->valuestring,
                     "did:plc:bob") == 0);
        CHECK(strcmp(
                  cJSON_GetObjectItemCaseSensitive(json, "handle")->valuestring,
                  "bob.example.com") == 0);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "active")));
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    /* Unknown DID -> AccountNotFound (404), never a fabricated account */
    {
        char unknown_url[160];
        snprintf(unknown_url, sizeof(unknown_url),
                 "%s/xrpc/com.atproto.admin.getAccountInfo?did=%s", base,
                 "did:plc:ghost");
        char right[64];
        int rn = snprintf(right, sizeof(right), "admin:%s", "secret-admin");
        char right_b64[128];
        int rlen = EVP_EncodeBlock((unsigned char *)right_b64,
                                   (const unsigned char *)right, rn);
        right_b64[rlen] = '\0';
        char right_hdr[160];
        snprintf(right_hdr, sizeof(right_hdr), "Basic %s", right_b64);
        wf_http_header hdr = {"Authorization", right_hdr};
        CHECK(wf_http_get_with_headers(client, unknown_url, &hdr, 1,
                                       &response) == WF_ERR_HTTP);
        CHECK(response.status == 404);
        json = json_response(&response);
        CHECK(
            strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                   "AccountNotFound") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    /* === com.atproto.admin.disableInviteCodes (admin-gated) === */
    {
        char admin_hdr[160];
        char right[64];
        int rn = snprintf(right, sizeof(right), "admin:%s", "secret-admin");
        char right_b64[128];
        int rlen = EVP_EncodeBlock((unsigned char *)right_b64,
                                   (const unsigned char *)right, rn);
        right_b64[rlen] = '\0';
        snprintf(admin_hdr, sizeof(admin_hdr), "Basic %s", right_b64);

        /* Create invite codes for bob so we have something to disable. */
        wf_xrpc_client_set_auth(client, access_token);
        CHECK(admin_post(
                  client, base, "com.atproto.server.createInviteCodes",
                  "{\"codeCount\":2,\"useCount\":1,\"forAccounts\":[\"bob\"]}",
                  &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *codes_arr = cJSON_GetObjectItemCaseSensitive(json, "codes");
        cJSON *bob_codes = cJSON_GetArrayItem(codes_arr, 0);
        cJSON *bob_code_list =
            cJSON_GetObjectItemCaseSensitive(bob_codes, "codes");
        cJSON *first_code = cJSON_GetArrayItem(bob_code_list, 0);
        char *code_to_disable =
            cJSON_IsString(first_code) ? strdup(first_code->valuestring) : NULL;
        cJSON_Delete(json);
        wf_response_free(&response);
        CHECK(code_to_disable != NULL);

        /* Disable by exact code string. */
        char disable_body[512];
        snprintf(disable_body, sizeof(disable_body), "{\"codes\":[\"%s\"]}",
                 code_to_disable);
        wf_http_header hdr = {"Authorization", admin_hdr};
        char disable_url[256];
        snprintf(disable_url, sizeof(disable_url),
                 "%s/xrpc/com.atproto.admin.disableInviteCodes", base);
        CHECK(wf_http_post(client, disable_url, "application/json",
                           disable_body, &hdr, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "disabled")));
        cJSON_Delete(json);
        wf_response_free(&response);

        /* Disable by account should also work. */
        snprintf(disable_body, sizeof(disable_body),
                 "{\"accounts\":[\"bob\"]}");
        CHECK(wf_http_post(client, disable_url, "application/json",
                           disable_body, &hdr, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "disabled")));
        cJSON_Delete(json);
        wf_response_free(&response);

        /* Cannot disable admin codes. */
        snprintf(disable_body, sizeof(disable_body),
                 "{\"accounts\":[\"admin\"]}");
        CHECK(wf_http_post(client, disable_url, "application/json",
                           disable_body, &hdr, 1, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);

        free(code_to_disable);
        wf_xrpc_client_set_auth(client, access_token);
    }

    /* === com.atproto.admin.disableAccountInvites / enableAccountInvites ===
     * The flag lives in the account's own store; disabling must be visible in
     * getAccountInfo and — matching the reference, which only disables an
     * account's self-granted routine codes — must not touch admin-minted
     * codes (existing or newly gifted). */
    {
        const char *alice_did = "did:plc:metalbeartest";

        /* admin Basic header for the GET checks below; the client's bearer
         * auth must be cleared first or the server sees two Authorization
         * headers and rejects the request. */
        wf_xrpc_client_set_auth(client, NULL);

        /* Unknown DID -> AccountNotFound (404), never a fabricated success. */
        CHECK(admin_post(
                  client, base, "com.atproto.admin.disableAccountInvites",
                  "{\"account\":\"did:plc:ghost\"}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 404);
        json = json_response(&response);
        CHECK(
            strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                   "AccountNotFound") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* Missing account param -> 400. */
        CHECK(admin_post(client, base,
                         "com.atproto.admin.disableAccountInvites", "{}",
                         &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);

        /* Disable invites for the hosted account. */
        {
            char body[256];
            snprintf(body, sizeof(body),
                     "{\"account\":\"%s\",\"note\":\"spam\"}", alice_did);
            CHECK(admin_post(client, base,
                             "com.atproto.admin.disableAccountInvites", body,
                             &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);
        }

        /* getAccountInfo reflects invitesDisabled=true. */
        {
            char url[192];
            snprintf(url, sizeof(url),
                     "%s/xrpc/com.atproto.admin.getAccountInfo?did=%s", base,
                     alice_did);
            char hdr[160];
            char cred[64];
            int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
            char b64[128];
            int len = EVP_EncodeBlock((unsigned char *)b64,
                                      (const unsigned char *)cred, n);
            b64[len] = '\0';
            snprintf(hdr, sizeof(hdr), "Basic %s", b64);
            wf_http_header auth_hdr = {"Authorization", hdr};
            CHECK(wf_http_get_with_headers(client, url, &auth_hdr, 1,
                                           &response) == WF_OK);
            CHECK(response.status == 200);
            json = json_response(&response);
            CHECK(cJSON_IsTrue(
                cJSON_GetObjectItemCaseSensitive(json, "invitesDisabled")));
            cJSON_Delete(json);
            wf_response_free(&response);
        }

        /* A code minted for the disabled account stays usable: the reference
         * only disables the account's self-granted routine codes, and admin
         * minting is never gated on invitesDisabled. */
        {
            char body[192];
            snprintf(body, sizeof(body),
                     "{\"useCount\":2,\"forAccount\":\"%s\"}", alice_did);
            CHECK(admin_post(client, base,
                             "com.atproto.server.createInviteCode", body,
                             &response) == WF_OK);
            CHECK(response.status == 200);
            json = json_response(&response);
            cJSON *code_item = cJSON_GetObjectItemCaseSensitive(json, "code");
            char *gifted_code = cJSON_IsString(code_item)
                                    ? strdup(code_item->valuestring)
                                    : NULL;
            cJSON_Delete(json);
            wf_response_free(&response);
            CHECK(gifted_code != NULL);

            /* admin.getInviteCodes lists it without a disabled flag. */
            {
                char list_url[256];
                snprintf(list_url, sizeof(list_url),
                         "%s/xrpc/com.atproto.admin.getInviteCodes", base);
                char hdr[160];
                char cred[64];
                int n =
                    snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
                char b64[128];
                int len = EVP_EncodeBlock((unsigned char *)b64,
                                          (const unsigned char *)cred, n);
                b64[len] = '\0';
                snprintf(hdr, sizeof(hdr), "Basic %s", b64);
                wf_http_header auth_hdr = {"Authorization", hdr};
                CHECK(wf_http_get_with_headers(client, list_url, &auth_hdr, 1,
                                               &response) == WF_OK);
                CHECK(response.status == 200);
                json = json_response(&response);
                cJSON *all_codes =
                    cJSON_GetObjectItemCaseSensitive(json, "codes");
                int found = 0;
                int found_disabled = 0;
                for (int i = 0; cJSON_IsArray(all_codes) &&
                                i < cJSON_GetArraySize(all_codes);
                     i++) {
                    cJSON *c = cJSON_GetArrayItem(all_codes, i);
                    cJSON *code_str =
                        cJSON_GetObjectItemCaseSensitive(c, "code");
                    if (code_str && code_str->valuestring &&
                        strcmp(code_str->valuestring, gifted_code) == 0) {
                        found = 1;
                        found_disabled = cJSON_IsTrue(
                            cJSON_GetObjectItemCaseSensitive(c, "disabled"));
                    }
                }
                cJSON_Delete(json);
                wf_response_free(&response);
                CHECK(found);
                CHECK(!found_disabled);
            }
            free(gifted_code);
        }

        /* Re-enable invites; the account's codes stay usable. */
        {
            char body[256];
            snprintf(body, sizeof(body), "{\"account\":\"%s\"}", alice_did);
            CHECK(admin_post(client, base,
                             "com.atproto.admin.enableAccountInvites", body,
                             &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);
        }

        /* getAccountInfo reflects invitesDisabled=false again. */
        {
            char url[192];
            snprintf(url, sizeof(url),
                     "%s/xrpc/com.atproto.admin.getAccountInfo?did=%s", base,
                     alice_did);
            char hdr[160];
            char cred[64];
            int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
            char b64[128];
            int len = EVP_EncodeBlock((unsigned char *)b64,
                                      (const unsigned char *)cred, n);
            b64[len] = '\0';
            snprintf(hdr, sizeof(hdr), "Basic %s", b64);
            wf_http_header auth_hdr = {"Authorization", hdr};
            CHECK(wf_http_get_with_headers(client, url, &auth_hdr, 1,
                                           &response) == WF_OK);
            CHECK(response.status == 200);
            json = json_response(&response);
            CHECK(cJSON_IsFalse(
                cJSON_GetObjectItemCaseSensitive(json, "invitesDisabled")));
            cJSON_Delete(json);
            wf_response_free(&response);
        }
    }

    /* === com.atproto.admin.deleteAccount (admin-gated) === */
    {
        char admin_hdr[160];
        char right[64];
        int rn = snprintf(right, sizeof(right), "admin:%s", "secret-admin");
        char right_b64[128];
        int rlen = EVP_EncodeBlock((unsigned char *)right_b64,
                                   (const unsigned char *)right, rn);
        right_b64[rlen] = '\0';
        snprintf(admin_hdr, sizeof(admin_hdr), "Basic %s", right_b64);

        /* Create a throwaway account to delete. */
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                                "{\"handle\":\"charlie.example.com\","
                                "\"password\":\"charliepw\","
                                "\"did\":\"did:plc:charlie\",\"email\":"
                                "\"charlie@example.com\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON_Delete(json_response(&response));
        wf_response_free(&response);

        /* Admin delete the account. */
        char del_body[256];
        snprintf(del_body, sizeof(del_body), "{\"did\":\"did:plc:charlie\"}");
        wf_http_header hdr = {"Authorization", admin_hdr};
        char del_url[256];
        snprintf(del_url, sizeof(del_url),
                 "%s/xrpc/com.atproto.admin.deleteAccount", base);
        CHECK(wf_http_post(client, del_url, "application/json", del_body, &hdr,
                           1, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON_Delete(json_response(&response));
        wf_response_free(&response);

        /* Account should no longer be resolvable. */
        wf_xrpc_client_set_auth(client, NULL);
        CHECK(wf_xrpc_query_params(
                  client, "com.atproto.identity.resolveHandle",
                  (wf_xrpc_param[]){{"handle", "charlie.example.com"}}, 1,
                  &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);

        wf_xrpc_client_set_auth(client, access_token);
    }

    /* getRecommendedDidCredentials: auth-required, lexicon-shaped output */
    CHECK(wf_xrpc_query(client,
                        "com.atproto.identity.getRecommendedDidCredentials",
                        NULL, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(json, "alsoKnownAs")));
    cJSON *vms = cJSON_GetObjectItemCaseSensitive(json, "verificationMethods");
    CHECK(cJSON_IsObject(vms) &&
          cJSON_IsString(cJSON_GetObjectItemCaseSensitive(vms, "atproto")));
    CHECK(
        cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(json, "rotationKeys")));
    cJSON *svcs = cJSON_GetObjectItemCaseSensitive(json, "services");
    CHECK(cJSON_IsObject(svcs));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* updateHandle: adopt a handle under the configured domain */
    CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                            "{\"handle\":\"carol.example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* The new handle now resolves */
    wf_xrpc_param new_handle_params[] = {{"handle", "carol.example.com"}};
    CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveHandle",
                               new_handle_params, 1, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "did")->valuestring,
                 "did:plc:metalbeartest") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* updateHandle: handle outside the domain is rejected */
    CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                            "{\"handle\":\"evil.com\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidHandle") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* updateHandle: malformed handle is rejected */
    CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                            "{\"handle\":\"not a handle\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);

    /* restore the original handle for later tests */
    CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                            "{\"handle\":\"alice.example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* confirmEmail: requires email field per lexicon */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.confirmEmail",
                            "{\"token\":\"faketoken\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidEmail") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* confirmEmail with both email and bad token returns InvalidToken */
    CHECK(wf_xrpc_procedure(
              client, "com.atproto.server.confirmEmail",
              "{\"email\":\"alice@example.com\",\"token\":\"bogus\"}",
              &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidToken") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, access_token);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAppPassword",
                            "{\"name\":\"desktop\"}", &response) == WF_OK);
    json = json_response(&response);
    cJSON *app_password = cJSON_GetObjectItemCaseSensitive(json, "password");
    char *desktop_password =
        cJSON_IsString(app_password) ? strdup(app_password->valuestring) : NULL;
    CHECK(desktop_password && strlen(desktop_password) == 19);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "createdAt")));
    CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(json, "privileged")));
    cJSON_Delete(json);
    wf_response_free(&response);

    CHECK(wf_xrpc_query(client, "com.atproto.server.listAppPasswords", NULL,
                        &response) == WF_OK);
    json = json_response(&response);
    cJSON *passwords = cJSON_GetObjectItemCaseSensitive(json, "passwords");
    cJSON *listed_password = cJSON_GetArrayItem(passwords, 0);
    CHECK(cJSON_GetArraySize(passwords) == 1);
    CHECK(cJSON_IsString(
        cJSON_GetObjectItemCaseSensitive(listed_password, "name")));
    CHECK(!cJSON_GetObjectItemCaseSensitive(listed_password, "password"));
    cJSON_Delete(json);
    wf_response_free(&response);

    char login_body[256];
    snprintf(login_body, sizeof(login_body),
             "{\"identifier\":\"alice.example.com\",\"password\":\"%s\"}",
             desktop_password ? desktop_password : "");
    wf_xrpc_client_set_auth(client, NULL);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                            login_body, &response) == WF_OK);
    json = json_response(&response);
    access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    refresh = cJSON_GetObjectItemCaseSensitive(json, "refreshJwt");
    char *desktop_access =
        cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    char *desktop_refresh =
        cJSON_IsString(refresh) ? strdup(refresh->valuestring) : NULL;
    CHECK(desktop_access && desktop_refresh);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "email")));
    CHECK(
        cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(json, "emailConfirmed")));
    CHECK(cJSON_IsBool(
        cJSON_GetObjectItemCaseSensitive(json, "emailAuthFactor")));
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, desktop_access);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAppPassword",
                            "{\"name\":\"forbidden\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    CHECK(wf_xrpc_query(client, "com.atproto.server.listAppPasswords", NULL,
                        &response) == WF_OK);
    wf_response_free(&response);
    wf_xrpc_param privileged_service_params[] = {
        {"aud", "did:web:chat.example.com"},
        {"lxm", "chat.bsky.convo.sendMessage"},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.server.getServiceAuth",
                               privileged_service_params, 2,
                               &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);
    /* requestPlcOperationSignature/signPlcOperation require ACCESS_FULL in
     * the reference (identity.ts) -- an app password, privileged or not,
     * must never reach a PLC identity operation. */
    CHECK(wf_xrpc_procedure(client,
                            "com.atproto.identity.requestPlcOperationSignature",
                            "{}", &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    CHECK(wf_xrpc_procedure(client, "com.atproto.identity.signPlcOperation",
                            "{\"token\":\"whatever\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    /* requestAccountDelete, requestEmailUpdate, getAccountInviteCodes: also
     * ACCESS_FULL-only in the reference, no takendown exception. */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestAccountDelete",
                            "{}", &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestEmailUpdate",
                            "{}", &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    CHECK(wf_xrpc_query(client, "com.atproto.server.getAccountInviteCodes",
                        NULL, &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, access_token);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAppPassword",
                            "{\"name\":\"trusted\",\"privileged\":true}",
                            &response) == WF_OK);
    json = json_response(&response);
    app_password = cJSON_GetObjectItemCaseSensitive(json, "password");
    privileged_password =
        cJSON_IsString(app_password) ? strdup(app_password->valuestring) : NULL;
    CHECK(privileged_password != NULL);
    cJSON_Delete(json);
    wf_response_free(&response);

    snprintf(login_body, sizeof(login_body),
             "{\"identifier\":\"alice.example.com\",\"password\":\"%s\"}",
             privileged_password ? privileged_password : "");
    wf_xrpc_client_set_auth(client, NULL);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                            login_body, &response) == WF_OK);
    json = json_response(&response);
    access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *privileged_access =
        cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, privileged_access);
    CHECK(wf_xrpc_query_params(client, "com.atproto.server.getServiceAuth",
                               privileged_service_params, 2,
                               &response) == WF_OK);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, desktop_access);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.revokeAppPassword",
                            "{\"name\":\"desktop\"}", &response) == WF_OK);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, NULL);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                            login_body, &response) == WF_OK);
    wf_response_free(&response);
    snprintf(login_body, sizeof(login_body),
             "{\"identifier\":\"alice.example.com\",\"password\":\"%s\"}",
             desktop_password ? desktop_password : "");
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                            login_body, &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, desktop_refresh);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession", "{}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    free(desktop_password);
    free(desktop_access);
    free(desktop_refresh);
    free(privileged_access);

    const unsigned char blob_data[] = {0x89, 'P', 'N', 'G'};
    wf_xrpc_client_set_auth(client, access_token);
    wf_status upload_status =
        wf_xrpc_upload_blob(client, "com.atproto.repo.uploadBlob", blob_data,
                            sizeof(blob_data), "image/png", &response);
    CHECK(upload_status == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *blob = cJSON_GetObjectItemCaseSensitive(json, "blob");
    cJSON *ref = cJSON_GetObjectItemCaseSensitive(blob, "ref");
    cJSON *link = cJSON_GetObjectItemCaseSensitive(ref, "$link");
    CHECK(cJSON_IsString(link));
    char *blob_cid = cJSON_IsString(link) ? strdup(link->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, NULL);
    wf_xrpc_param blob_params[] = {
        {"did", "did:plc:metalbeartest"},
        {"cid", blob_cid ? blob_cid : ""},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getBlob", blob_params,
                               2, &response) == WF_OK);
    CHECK(response.status == 200 && response.body_len == sizeof(blob_data));
    CHECK(response.body_len == sizeof(blob_data) &&
          memcmp(response.body, blob_data, sizeof(blob_data)) == 0);
    wf_response_free(&response);

    const char *create_body =
        "{\"repo\":\"did:plc:metalbeartest\","
        "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"first\","
        "\"record\":{\"$type\":\"app.bsky.feed.post\","
        "\"text\":\"hello from MetalBear\","
        "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}";
    CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                            create_body, &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, access_token);
    CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);
    CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                            create_body, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "cid")));
    cJSON *commit = cJSON_GetObjectItemCaseSensitive(json, "commit");
    cJSON *commit_cid_json = cJSON_GetObjectItemCaseSensitive(commit, "cid");
    cJSON *commit_rev_json = cJSON_GetObjectItemCaseSensitive(commit, "rev");
    char *commit_cid = cJSON_IsString(commit_cid_json)
                           ? strdup(commit_cid_json->valuestring)
                           : NULL;
    char *commit_rev = cJSON_IsString(commit_rev_json)
                           ? strdup(commit_rev_json->valuestring)
                           : NULL;
    CHECK(commit_cid && commit_rev);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* queryLabels: MetalBear is a PDS with no label storage. The reference
     * PDS does not serve this endpoint at all -- it is an AppView
     * responsibility, fed by a labeler's own subscribeLabels firehose.
     * Confirm the honest MethodNotImplemented rather than a fabricated
     * empty result. */
    wf_xrpc_param query_labels_params[] = {
        {"uriPatterns", "at://did:plc:metalbeartest/app.bsky.feed.post/first"},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.label.queryLabels",
                               query_labels_params, 1,
                               &response) == WF_ERR_HTTP);
    CHECK(response.status == 501);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "MethodNotImplemented") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_subscribe_event live_event = {0};
    CHECK(
        firehose >= 0 &&
        firehose_read_until(firehose, WF_SUBSCRIBE_EVENT_COMMIT, &live_event));
    CHECK(live_event.type == WF_SUBSCRIBE_EVENT_COMMIT);
    /* Anchor the later assertions to where this commit actually landed. */
    int64_t commit_seq = live_event.seq;
    CHECK(commit_seq > seq_base);
    CHECK(strcmp(live_event.data.commit.did, "did:plc:metalbeartest") == 0);
    CHECK(live_event.data.commit.ops_count == 1);
    if (live_event.data.commit.ops_count == 1) {
        CHECK(strcmp(live_event.data.commit.ops[0].action, "create") == 0);
        CHECK(strcmp(live_event.data.commit.ops[0].path,
                     "app.bsky.feed.post/first") == 0);
    }
    CHECK(live_event.data.commit.blocks_len > 0);
    wf_subscribe_event_free(&live_event);
    if (firehose >= 0) close(firehose);

    /* Comfortably past the head, whatever the base happens to be. */
    firehose =
        firehose_connect(metalbear_server_port(server), seq_base + 100000);
    CHECK(firehose >= 0);
    wf_subscribe_event future_event = {0};
    CHECK(firehose >= 0 && firehose_read(firehose, &future_event));
    CHECK(future_event.type == WF_SUBSCRIBE_EVENT_ERROR);
    if (future_event.type == WF_SUBSCRIBE_EVENT_ERROR)
        CHECK(strcmp(future_event.data.error.error, "FutureCursor") == 0);
    wf_subscribe_event_free(&future_event);
    if (firehose >= 0) close(firehose);

    wf_xrpc_client_set_auth(client, access_token);
    wf_xrpc_param service_auth_params[] = {
        {"aud", "did:web:labeler.example.com"},
        {"lxm", "com.atproto.moderation.createReport"},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.server.getServiceAuth",
                               service_auth_params, 2, &response) == WF_OK);
    json = json_response(&response);
    cJSON *service_token = cJSON_GetObjectItemCaseSensitive(json, "token");
    CHECK(cJSON_IsString(service_token));
    if (cJSON_IsString(service_token)) {
        const char *first_dot = strchr(service_token->valuestring, '.');
        CHECK(first_dot && strchr(first_dot + 1, '.'));
    }
    cJSON_Delete(json);
    wf_response_free(&response);
    wf_xrpc_param bad_exp_params[] = {
        {"aud", "did:web:labeler.example.com"},
        {"exp", "1"},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.server.getServiceAuth",
                               bad_exp_params, 2, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "BadExpiration") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_param status_params[] = {{"did", "did:plc:metalbeartest"}};
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus",
                               status_params, 1, &response) == WF_OK);
    json = json_response(&response);
    CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "active")));
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "rev")));
    cJSON_Delete(json);
    wf_response_free(&response);

    CHECK(wf_xrpc_query(client, "com.atproto.sync.listRepos", NULL,
                        &response) == WF_OK);
    json = json_response(&response);
    cJSON *repos = cJSON_GetObjectItemCaseSensitive(json, "repos");
    cJSON *listed_repo = cJSON_GetArrayItem(repos, 0);
    CHECK(cJSON_GetArraySize(repos) == 1);
    CHECK(
        cJSON_IsString(cJSON_GetObjectItemCaseSensitive(listed_repo, "head")));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* listBlobs: public, enumerates the uploaded blob for the account */
    wf_xrpc_client_set_auth(client, NULL);
    wf_xrpc_param list_blobs_params[] = {{"did", "did:plc:metalbeartest"}};
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.listBlobs",
                               list_blobs_params, 1, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *cids = cJSON_GetObjectItemCaseSensitive(json, "cids");
    CHECK(cJSON_IsArray(cids) && cJSON_GetArraySize(cids) >= 1);
    bool found = false;
    for (int i = 0; i < cJSON_GetArraySize(cids); i++) {
        cJSON *c = cJSON_GetArrayItem(cids, i);
        if (cJSON_IsString(c) && blob_cid &&
            strcmp(c->valuestring, blob_cid) == 0)
            found = true;
    }
    CHECK(found);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* listBlobs: unknown did is RepoNotFound */
    wf_xrpc_param wrong_did_params[] = {{"did", "did:plc:other"}};
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.listBlobs",
                               wrong_did_params, 1, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "RepoNotFound") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, NULL);
    wf_xrpc_param get_params[] = {
        {"repo", "did:plc:metalbeartest"},
        {"collection", "app.bsky.feed.post"},
        {"rkey", "first"},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord", get_params,
                               3, &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *value = cJSON_GetObjectItemCaseSensitive(json, "value");
    cJSON *text = cJSON_GetObjectItemCaseSensitive(value, "text");
    CHECK(cJSON_IsString(text) &&
          strcmp(text->valuestring, "hello from MetalBear") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_param repo_params[] = {{"did", "did:plc:metalbeartest"}};
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getRepo", repo_params,
                               1, &response) == WF_OK);
    CHECK(response.status == 200 && response.body_len > 0);
    wf_car repo_car = {0};
    CHECK(wf_car_parse((const unsigned char *)response.body, response.body_len,
                       &repo_car) == WF_OK);
    CHECK(repo_car.root_count == 1 && repo_car.block_count > 0);
    wf_car_free(&repo_car);
    wf_response_free(&response);

    wf_xrpc_param incremental_params[] = {
        {"did", "did:plc:metalbeartest"},
        {"since", commit_rev},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getRepo",
                               incremental_params, 2, &response) == WF_OK);
    memset(&repo_car, 0, sizeof(repo_car));
    CHECK(wf_car_parse((const unsigned char *)response.body, response.body_len,
                       &repo_car) == WF_OK);
    CHECK(repo_car.root_count == 1 && repo_car.block_count == 0);
    wf_car_free(&repo_car);
    wf_response_free(&response);

    wf_xrpc_param block_params[] = {
        {"did", "did:plc:metalbeartest"},
        {"cids", commit_cid},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getBlocks",
                               block_params, 2, &response) == WF_OK);
    memset(&repo_car, 0, sizeof(repo_car));
    CHECK(wf_car_parse((const unsigned char *)response.body, response.body_len,
                       &repo_car) == WF_OK);
    CHECK(repo_car.root_count == 0 && repo_car.block_count == 1);
    wf_car_free(&repo_car);
    wf_response_free(&response);

    /* === confirmEmail success path === */
    wf_xrpc_client_set_auth(client, access_token);
    CHECK(wf_xrpc_procedure(client,
                            "com.atproto.server.requestEmailConfirmation", "{}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* confirmEmail without token should fail */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.confirmEmail",
                            "{\"email\":\"new@example.com\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidToken") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* confirmEmail with wrong email should fail */
    CHECK(wf_xrpc_procedure(
              client, "com.atproto.server.confirmEmail",
              "{\"email\":\"wrong@example.com\",\"token\":\"bogus\"}",
              &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);

    /* === requestAccountDelete === */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestAccountDelete",
                            "{}", &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    cJSON *del_token = cJSON_GetObjectItemCaseSensitive(json, "token");
    CHECK(cJSON_IsString(del_token) && del_token->valuestring[0] != '\0');
    char *delete_token =
        cJSON_IsString(del_token) ? strdup(del_token->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);

    /* deleteAccount with wrong token should fail */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.deleteAccount",
                            "{\"did\":\"did:plc:metalbeartest\",\"password\":"
                            "\"correct horse battery staple\","
                            "\"token\":\"wrongtoken\"}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidToken") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* === resetPassword flow === */
    /* First store an email on the account for the reset flow */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.updateEmail",
                            "{\"email\":\"reset@example.com\"}",
                            &response) == WF_OK);
    wf_response_free(&response);

    /* Request password reset */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestPasswordReset",
                            "{\"email\":\"reset@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* resetPassword is the forgot-password endpoint: a user who has lost
     * their password has no session to present, so the reference PDS
     * registers it with no auth verifier at all — the emailed token in the
     * body is the authentication. Prove it works with NO bearer token: a
     * request that reaches token validation (InvalidToken) rather than being
     * turned away at the auth layer confirms the route is public. */
    wf_xrpc_client_set_auth(client, NULL);
    CHECK(
        wf_xrpc_procedure(client, "com.atproto.server.resetPassword",
                          "{\"token\":\"bad\",\"password\":\"newpassword123\"}",
                          &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidToken") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, access_token);

    /* resetPassword with wrong token should fail the same way when a bearer
     * token IS present, too — auth is simply irrelevant to this route. */
    CHECK(
        wf_xrpc_procedure(client, "com.atproto.server.resetPassword",
                          "{\"token\":\"bad\",\"password\":\"newpassword123\"}",
                          &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "InvalidToken") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    /* deleteToken was not consumed — still valid for later use */
    free(delete_token);

    firehose = firehose_connect(metalbear_server_port(server), commit_seq);
    CHECK(firehose >= 0);
    wf_xrpc_client_set_auth(client, access_token);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.deactivateAccount",
                            "{}", &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);
    wf_subscribe_event deactivated_event = {0};
    CHECK(firehose >= 0 &&
          firehose_read_until(firehose, WF_SUBSCRIBE_EVENT_ACCOUNT,
                              &deactivated_event));
    CHECK(deactivated_event.type == WF_SUBSCRIBE_EVENT_ACCOUNT);
    int64_t deactivated_seq = deactivated_event.seq;
    CHECK(deactivated_seq > commit_seq);
    CHECK(!deactivated_event.data.account.active);
    CHECK(deactivated_event.data.account.has_status &&
          strcmp(deactivated_event.data.account.status, "deactivated") == 0);
    wf_subscribe_event_free(&deactivated_event);
    if (firehose >= 0) close(firehose);

    CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                        &response) == WF_OK);
    json = json_response(&response);
    CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(json, "active")));
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "status")->valuestring,
                 "deactivated") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, NULL);
    CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord", get_params,
                               3, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                 "RepoDeactivated") == 0);
    cJSON_Delete(json);
    wf_response_free(&response);

    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus",
                               status_params, 1, &response) == WF_OK);
    json = json_response(&response);
    CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(json, "active")));
    CHECK(!cJSON_GetObjectItemCaseSensitive(json, "rev"));
    cJSON_Delete(json);
    wf_response_free(&response);
    CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveHandle",
                               handle_params, 1, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);

    wf_xrpc_client_free(client);
    metalbear_server_free(server);

    /* Restart on the same data directory: stored credentials survive, and the
     * account is found through the registry rather than through configuration
     * naming it. */
    server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (server) {
        snprintf(base, sizeof(base), "http://127.0.0.1:%u",
                 (unsigned)metalbear_server_port(server));
        client = wf_xrpc_client_new(base);
        CHECK(client != NULL);
        if (client) {
            CHECK(wf_xrpc_procedure(
                      client, "com.atproto.server.createSession",
                      "{\"identifier\":\"alice.example.com\","
                      "\"password\":\"correct horse battery staple\"}",
                      &response) == WF_OK);
            wf_response_free(&response);

            /* Replay from just before the commit: it must come back. */
            firehose =
                firehose_connect(metalbear_server_port(server), commit_seq - 1);
            CHECK(firehose >= 0);
            wf_subscribe_event replay_event = {0};
            CHECK(firehose >= 0 &&
                  firehose_read_until(firehose, WF_SUBSCRIBE_EVENT_COMMIT,
                                      &replay_event));
            CHECK(replay_event.type == WF_SUBSCRIBE_EVENT_COMMIT);
            CHECK(replay_event.seq == commit_seq);
            CHECK(replay_event.data.commit.ops_count == 1);
            if (replay_event.data.commit.ops_count == 1)
                CHECK(strcmp(replay_event.data.commit.ops[0].path,
                             "app.bsky.feed.post/first") == 0);
            wf_subscribe_event_free(&replay_event);
            if (firehose >= 0) close(firehose);

            wf_xrpc_client_set_auth(client, access_token);
            CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                                &response) == WF_OK);
            CHECK(response.status == 200);
            json = json_response(&response);
            CHECK(cJSON_IsFalse(
                cJSON_GetObjectItemCaseSensitive(json, "active")));
            cJSON_Delete(json);
            wf_response_free(&response);

            firehose = firehose_connect(metalbear_server_port(server),
                                        deactivated_seq);
            CHECK(firehose >= 0);
            CHECK(wf_xrpc_procedure(client,
                                    "com.atproto.server.activateAccount", "{}",
                                    &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);
            /* Activation emits identity, then account, then sync — in that
             * order and strictly after the deactivation.  Skip past any
             * reconciliation events for other accounts that startup may
             * have emitted. */
            wf_subscribe_event activation_event = {0};
            CHECK(firehose >= 0 &&
                  firehose_read_until(firehose, WF_SUBSCRIBE_EVENT_IDENTITY,
                                      &activation_event));
            CHECK(activation_event.seq > deactivated_seq);
            int64_t prev_seq = activation_event.seq;
            wf_subscribe_event_free(&activation_event);
            memset(&activation_event, 0, sizeof(activation_event));
            CHECK(firehose >= 0 &&
                  firehose_read_until(firehose, WF_SUBSCRIBE_EVENT_ACCOUNT,
                                      &activation_event));
            CHECK(activation_event.seq > prev_seq &&
                  activation_event.data.account.active);
            prev_seq = activation_event.seq;
            wf_subscribe_event_free(&activation_event);
            memset(&activation_event, 0, sizeof(activation_event));
            CHECK(firehose >= 0 &&
                  firehose_read_until(firehose, WF_SUBSCRIBE_EVENT_SYNC,
                                      &activation_event));
            CHECK(activation_event.seq > prev_seq &&
                  activation_event.data.sync.blocks_len > 0);
            /* The lexicon caps #sync.blocks at 10000 bytes: it carries the
             * commit block alone, not the repo. Exporting everything here
             * grew with the account and silently passed the limit, and a
             * validating relay drops the event that exists to repair a
             * broken stream. */
            CHECK(activation_event.data.sync.blocks_len <= 10000);
            wf_subscribe_event_free(&activation_event);
            if (firehose >= 0) close(firehose);

            /* App-password verifiers and privilege survive a full restart. */
            snprintf(login_body, sizeof(login_body),
                     "{\"identifier\":\"alice.example.com\","
                     "\"password\":\"%s\"}",
                     privileged_password ? privileged_password : "");
            wf_xrpc_client_set_auth(client, NULL);
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                                    login_body, &response) == WF_OK);
            json = json_response(&response);
            access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
            char *restarted_privileged_access =
                cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
            cJSON_Delete(json);
            wf_response_free(&response);
            wf_xrpc_client_set_auth(client, restarted_privileged_access);
            CHECK(wf_xrpc_query_params(
                      client, "com.atproto.server.getServiceAuth",
                      privileged_service_params, 2, &response) == WF_OK);
            wf_response_free(&response);
            free(restarted_privileged_access);

            wf_xrpc_client_set_auth(client, refresh_token);
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                    "{}", &response) == WF_OK);
            CHECK(response.status == 200);
            json = json_response(&response);
            refresh = cJSON_GetObjectItemCaseSensitive(json, "refreshJwt");
            char *rotated_refresh =
                cJSON_IsString(refresh) ? strdup(refresh->valuestring) : NULL;
            CHECK(rotated_refresh != NULL &&
                  strcmp(rotated_refresh, refresh_token) != 0);
            cJSON_Delete(json);
            wf_response_free(&response);

            /* The previous refresh token remains reusable during its bounded
             * grace period and resolves to the same successor token id. */
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                    "{}", &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);

            wf_xrpc_client_set_auth(client, rotated_refresh);
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.deleteSession",
                                    "{}", &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                    "{}", &response) == WF_ERR_HTTP);
            CHECK(response.status == 401);
            wf_response_free(&response);
            free(rotated_refresh);

            wf_xrpc_client_set_auth(client, NULL);
            CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                                       get_params, 3, &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);

            /* === com.atproto.moderation.createReport (auth-gated) ===
             * Requires a valid authenticated session. Returns the persisted
             * report with generated id and timestamps. */
            {
                wf_xrpc_client_set_auth(client, access_token);
                CHECK(wf_xrpc_procedure(
                          client, "com.atproto.moderation.createReport",
                          "{\"reasonType\":\"com.atproto.moderation.defs#"
                          "reasonSpam\","
                          "\"subject\":{\"did\":\"did:plc:bob\"}}",
                          &response) == WF_OK);
                CHECK(response.status == 200);
                cJSON *report = json_response(&response);
                CHECK(cJSON_IsNumber(
                    cJSON_GetObjectItemCaseSensitive(report, "id")));
                CHECK(strcmp(
                          cJSON_GetObjectItemCaseSensitive(report, "reasonType")
                              ->valuestring,
                          "com.atproto.moderation.defs#reasonSpam") == 0);
                CHECK(strcmp(
                          cJSON_GetObjectItemCaseSensitive(report, "reportedBy")
                              ->valuestring,
                          "did:plc:metalbeartest") == 0);
                CHECK(cJSON_IsString(
                    cJSON_GetObjectItemCaseSensitive(report, "createdAt")));
                cJSON *subject =
                    cJSON_GetObjectItemCaseSensitive(report, "subject");
                CHECK(cJSON_IsObject(subject));
                CHECK(cJSON_IsString(
                    cJSON_GetObjectItemCaseSensitive(subject, "did")));
                cJSON_Delete(report);
                wf_response_free(&response);

                CHECK(wf_xrpc_procedure(client,
                                        "com.atproto.moderation.createReport",
                                        "{\"reasonType\":\"com.atproto."
                                        "moderation.defs#reasonViolation\","
                                        "\"reason\":\"test report\","
                                        "\"subject\":{\"uri\":\"at://"
                                        "did:plc:bob/app.bsky.feed.post/xyz\","
                                        "\"cid\":\"bafkreid7example\"}}",
                                        &response) == WF_OK);
                CHECK(response.status == 200);
                report = json_response(&response);
                CHECK(cJSON_IsNumber(
                    cJSON_GetObjectItemCaseSensitive(report, "id")));
                subject = cJSON_GetObjectItemCaseSensitive(report, "subject");
                CHECK(cJSON_IsString(
                    cJSON_GetObjectItemCaseSensitive(subject, "uri")));
                CHECK(cJSON_IsString(
                    cJSON_GetObjectItemCaseSensitive(subject, "cid")));
                cJSON_Delete(report);
                wf_response_free(&response);

                /* No auth -> 401 */
                wf_xrpc_client_set_auth(client, NULL);
                CHECK(wf_xrpc_procedure(
                          client, "com.atproto.moderation.createReport",
                          "{\"reasonType\":\"com.atproto.moderation.defs#"
                          "reasonSpam\","
                          "\"subject\":{\"did\":\"did:plc:bob\"}}",
                          &response) == WF_ERR_HTTP);
                CHECK(response.status == 401);
                wf_response_free(&response);

                wf_xrpc_client_set_auth(client, access_token);
            }

            /* === deleteAccount: end-to-end success === */
            /* Need a fresh session after restart */
            snprintf(login_body, sizeof(login_body),
                     "{\"identifier\":\"alice.example.com\","
                     "\"password\":\"correct horse battery staple\"}");
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                                    login_body, &response) == WF_OK);
            json = json_response(&response);
            access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
            char *final_access =
                cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
            cJSON_Delete(json);
            wf_response_free(&response);

            /* Request a fresh deletion token */
            wf_xrpc_client_set_auth(client, final_access);
            CHECK(wf_xrpc_procedure(client,
                                    "com.atproto.server.requestAccountDelete",
                                    "{}", &response) == WF_OK);
            CHECK(response.status == 200);
            json = json_response(&response);
            del_token = cJSON_GetObjectItemCaseSensitive(json, "token");
            char *final_delete_token = cJSON_IsString(del_token)
                                           ? strdup(del_token->valuestring)
                                           : NULL;
            cJSON_Delete(json);
            wf_response_free(&response);

            /* Wrong token should be rejected */
            wf_xrpc_client_set_auth(client, final_access);
            CHECK(wf_xrpc_procedure(
                      client, "com.atproto.server.deleteAccount",
                      "{\"did\":\"did:plc:metalbeartest\","
                      "\"password\":\"correct horse battery staple\","
                      "\"token\":\"totallywrong\"}",
                      &response) == WF_ERR_HTTP);
            CHECK(response.status == 400);
            wf_response_free(&response);

            /* Correct token should succeed */
            char del_body[512];
            snprintf(del_body, sizeof(del_body),
                     "{\"did\":\"did:plc:metalbeartest\","
                     "\"password\":\"correct horse battery staple\","
                     "\"token\":\"%s\"}",
                     final_delete_token ? final_delete_token : "");
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.deleteAccount",
                                    del_body, &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);

            /* Account is deleted — getSession shows inactive */
            CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                                &response) == WF_OK);
            json = json_response(&response);
            CHECK(cJSON_IsFalse(
                cJSON_GetObjectItemCaseSensitive(json, "active")));
            cJSON_Delete(json);
            wf_response_free(&response);

            free(final_access);
            free(final_delete_token);
            wf_xrpc_client_set_auth(client, NULL);
        }

        /* Test app.bsky.actor.getPreferences and putPreferences */
        CHECK(wf_xrpc_query(client, "app.bsky.actor.getPreferences", NULL,
                            &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);

        /* Create a session for preference tests (alice was deleted above;
         * use bob, whose account persists). */
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                                "{\"identifier\":\"bob.example.com\","
                                "\"password\":\"bobsecret\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *pref_access =
            cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
        char *pref_token = cJSON_IsString(pref_access)
                               ? strdup(pref_access->valuestring)
                               : NULL;
        cJSON_Delete(json);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, pref_token);

        /* getPreferences returns empty array initially */
        CHECK(wf_xrpc_query(client, "app.bsky.actor.getPreferences", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *prefs = cJSON_GetObjectItemCaseSensitive(json, "preferences");
        CHECK(prefs != NULL);
        CHECK(cJSON_IsArray(prefs));
        CHECK(cJSON_GetArraySize(prefs) == 0);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* putPreferences with invalid body returns error */
        CHECK(wf_xrpc_procedure(client, "app.bsky.actor.putPreferences",
                                "not-json", &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);

        /* putPreferences with valid preferences stores them */
        CHECK(wf_xrpc_procedure(client, "app.bsky.actor.putPreferences",
                                "{\"preferences\":[{\"$type\":\"app.bsky.actor."
                                "defs#preferences\","
                                "\"feedViewPref\":{\"itemsPerPage\":25}}]}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);

        /* getPreferences returns the stored preferences */
        CHECK(wf_xrpc_query(client, "app.bsky.actor.getPreferences", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        prefs = cJSON_GetObjectItemCaseSensitive(json, "preferences");
        CHECK(prefs != NULL);
        CHECK(cJSON_IsArray(prefs));
        CHECK(cJSON_GetArraySize(prefs) == 1);
        cJSON_Delete(json);
        wf_response_free(&response);

        free(pref_token);
        wf_xrpc_client_set_auth(client, NULL);

        /* Test com.atproto.identity.resolveDid (public) */
        wf_xrpc_param did_params[] = {{"did", "did:plc:bob"}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveDid",
                                   did_params, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *did_doc = cJSON_GetObjectItemCaseSensitive(json, "didDoc");
        CHECK(did_doc != NULL);
        cJSON *doc_id = cJSON_GetObjectItemCaseSensitive(did_doc, "id");
        CHECK(cJSON_IsString(doc_id));
        CHECK(strcmp(doc_id->valuestring, "did:plc:bob") == 0);
        cJSON *doc_service =
            cJSON_GetObjectItemCaseSensitive(did_doc, "service");
        CHECK(cJSON_IsArray(doc_service));
        cJSON_Delete(json);
        wf_response_free(&response);

        /* resolveDid with a malformed DID returns DidNotFound */
        wf_xrpc_param bad_did_params[] = {{"did", "not-a-did"}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveDid",
                                   bad_did_params, 1,
                                   &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        json = json_response(&response);
        CHECK(
            strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                   "DidNotFound") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* resolveDid with an unknown DID returns DidNotFound (no plc_url
         * configured, so no network access happens). */
        wf_xrpc_param unknown_did_params[] = {
            {"did", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveDid",
                                   unknown_did_params, 1,
                                   &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);

        /* Test com.atproto.identity.resolveIdentity by handle (public):
         * local account, bi-directionally verified. */
        wf_xrpc_param id_handle_params[] = {{"identifier", "bob.example.com"}};
        CHECK(wf_xrpc_query_params(client,
                                   "com.atproto.identity.resolveIdentity",
                                   id_handle_params, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "did")->valuestring,
                     "did:plc:bob") == 0);
        CHECK(strcmp(
                  cJSON_GetObjectItemCaseSensitive(json, "handle")->valuestring,
                  "bob.example.com") == 0);
        CHECK(cJSON_GetObjectItemCaseSensitive(json, "didDoc") != NULL);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* resolveIdentity by DID: the claimed handle resolves back through
         * the local registry, so it verifies. */
        wf_xrpc_param id_did_params[] = {{"identifier", "did:plc:bob"}};
        CHECK(wf_xrpc_query_params(client,
                                   "com.atproto.identity.resolveIdentity",
                                   id_did_params, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        CHECK(strcmp(
                  cJSON_GetObjectItemCaseSensitive(json, "handle")->valuestring,
                  "bob.example.com") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* resolveIdentity with an unknown handle returns HandleNotFound
         * (.invalid is reserved and fails DNS resolution fast). */
        wf_xrpc_param id_unknown_params[] = {{"identifier", "nobody.invalid"}};
        CHECK(wf_xrpc_query_params(
                  client, "com.atproto.identity.resolveIdentity",
                  id_unknown_params, 1, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        json = json_response(&response);
        CHECK(
            strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")->valuestring,
                   "HandleNotFound") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* Test com.atproto.identity.refreshIdentity (public procedure):
         * same shape as resolveIdentity. */
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.refreshIdentity",
                                "{\"identifier\":\"bob.example.com\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "did")->valuestring,
                     "did:plc:bob") == 0);
        CHECK(cJSON_GetObjectItemCaseSensitive(json, "didDoc") != NULL);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* refreshIdentity requires an identifier */
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.refreshIdentity",
                                "{}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);

        /* Test com.atproto.repo.listMissingBlobs (authed) */
        CHECK(wf_xrpc_query(client, "com.atproto.repo.listMissingBlobs", NULL,
                            &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);

        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                                "{\"identifier\":\"bob.example.com\","
                                "\"password\":\"bobsecret\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *lmb_access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
        char *lmb_token =
            cJSON_IsString(lmb_access) ? strdup(lmb_access->valuestring) : NULL;
        cJSON_Delete(json);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, lmb_token);

        /* No records yet: empty list, no cursor */
        CHECK(wf_xrpc_query(client, "com.atproto.repo.listMissingBlobs", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *missing = cJSON_GetObjectItemCaseSensitive(json, "blobs");
        CHECK(cJSON_IsArray(missing));
        CHECK(cJSON_GetArraySize(missing) == 0);
        CHECK(cJSON_GetObjectItemCaseSensitive(json, "cursor") == NULL);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* Two posts referencing missing blobs. cid_low sorts before
         * cid_high, so ascending-CID order must return cid_low first even
         * though img_high's record was created first. */
        const char *cid_high =
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
        const char *cid_low =
            "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        char lmb_body[1024];
        snprintf(
            lmb_body, sizeof(lmb_body),
            "{\"repo\":\"did:plc:bob\",\"collection\":\"app.bsky.feed.post\","
            "\"rkey\":\"img_high\",\"record\":{\"$type\":\"app.bsky.feed."
            "post\","
            "\"text\":\"pic\",\"embed\":{\"$type\":\"app.bsky.embed.images\","
            "\"images\":[{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
            "\"ref\":{\"$link\":\"%s\"},\"mimeType\":\"image/"
            "png\",\"size\":4}}]},"
            "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
            cid_high);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                lmb_body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        snprintf(
            lmb_body, sizeof(lmb_body),
            "{\"repo\":\"did:plc:bob\",\"collection\":\"app.bsky.feed.post\","
            "\"rkey\":\"img_low\",\"record\":{\"$type\":\"app.bsky.feed.post\","
            "\"text\":\"pic\",\"embed\":{\"$type\":\"app.bsky.embed.images\","
            "\"images\":[{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
            "\"ref\":{\"$link\":\"%s\"},\"mimeType\":\"image/"
            "png\",\"size\":4}}]},"
            "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
            cid_low);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                lmb_body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);

        /* Both missing CIDs, ascending order, correct recordUris */
        CHECK(wf_xrpc_query(client, "com.atproto.repo.listMissingBlobs", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        missing = cJSON_GetObjectItemCaseSensitive(json, "blobs");
        CHECK(cJSON_IsArray(missing));
        CHECK(cJSON_GetArraySize(missing) == 2);
        cJSON *first_blob = cJSON_GetArrayItem(missing, 0);
        cJSON *second_blob = cJSON_GetArrayItem(missing, 1);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(first_blob, "cid")
                         ->valuestring,
                     cid_low) == 0);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(second_blob, "cid")
                         ->valuestring,
                     cid_high) == 0);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(first_blob, "recordUri")
                         ->valuestring,
                     "at://did:plc:bob/app.bsky.feed.post/img_low") == 0);
        CHECK(cJSON_GetObjectItemCaseSensitive(json, "cursor") == NULL);
        cJSON_Delete(json);
        wf_response_free(&response);

        /* limit=1 truncates and returns a cursor; the cursored page returns
         * the remaining CID and no further cursor. */
        wf_xrpc_param limit_one[] = {{"limit", "1"}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.repo.listMissingBlobs",
                                   limit_one, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        missing = cJSON_GetObjectItemCaseSensitive(json, "blobs");
        CHECK(cJSON_GetArraySize(missing) == 1);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(
                         cJSON_GetArrayItem(missing, 0), "cid")
                         ->valuestring,
                     cid_low) == 0);
        cJSON *lmb_cursor = cJSON_GetObjectItemCaseSensitive(json, "cursor");
        CHECK(cJSON_IsString(lmb_cursor));
        char *lmb_cursor_copy =
            cJSON_IsString(lmb_cursor) ? strdup(lmb_cursor->valuestring) : NULL;
        cJSON_Delete(json);
        wf_response_free(&response);

        wf_xrpc_param page_two[] = {{"limit", "1"},
                                    {"cursor", lmb_cursor_copy}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.repo.listMissingBlobs",
                                   page_two, 2, &response) == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        missing = cJSON_GetObjectItemCaseSensitive(json, "blobs");
        CHECK(cJSON_GetArraySize(missing) == 1);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(
                         cJSON_GetArrayItem(missing, 0), "cid")
                         ->valuestring,
                     cid_high) == 0);
        CHECK(cJSON_GetObjectItemCaseSensitive(json, "cursor") == NULL);
        cJSON_Delete(json);
        wf_response_free(&response);
        free(lmb_cursor_copy);

        /* A record referencing an uploaded (present) blob is not missing */
        wf_status lmb_upload = wf_xrpc_upload_blob(
            client, "com.atproto.repo.uploadBlob", blob_data, sizeof(blob_data),
            "image/png", &response);
        CHECK(lmb_upload == WF_OK);
        CHECK(response.status == 200);
        json = json_response(&response);
        cJSON *up_blob = cJSON_GetObjectItemCaseSensitive(json, "blob");
        cJSON *up_ref = cJSON_GetObjectItemCaseSensitive(up_blob, "ref");
        cJSON *up_link = cJSON_GetObjectItemCaseSensitive(up_ref, "$link");
        char *present_cid =
            cJSON_IsString(up_link) ? strdup(up_link->valuestring) : NULL;
        cJSON_Delete(json);
        wf_response_free(&response);
        CHECK(present_cid != NULL);
        snprintf(
            lmb_body, sizeof(lmb_body),
            "{\"repo\":\"did:plc:bob\",\"collection\":\"app.bsky.feed.post\","
            "\"rkey\":\"img_present\",\"record\":{\"$type\":\"app.bsky.feed."
            "post\","
            "\"text\":\"pic\",\"embed\":{\"$type\":\"app.bsky.embed.images\","
            "\"images\":[{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
            "\"ref\":{\"$link\":\"%s\"},\"mimeType\":\"image/"
            "png\",\"size\":4}}]},"
            "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
            present_cid);
        free(present_cid);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                lmb_body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        CHECK(wf_xrpc_query(client, "com.atproto.repo.listMissingBlobs", NULL,
                            &response) == WF_OK);
        json = json_response(&response);
        missing = cJSON_GetObjectItemCaseSensitive(json, "blobs");
        CHECK(cJSON_GetArraySize(missing) == 2);
        cJSON_Delete(json);
        wf_response_free(&response);

        free(lmb_token);
        wf_xrpc_client_set_auth(client, NULL);

        /* Registered app.bsky.* endpoints require auth; without a token the
         * auth callback returns 401 before the handler runs. */
        CHECK(wf_xrpc_query(client, "app.bsky.feed.getFeedSkeleton", NULL,
                            &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);

        wf_xrpc_client_free(client);
        metalbear_server_free(server);
    }

    char path[512];
    if (blob_cid) {
        snprintf(path, sizeof(path), "%s/blobs/%s", directory, blob_cid);
        unlink(path);
        snprintf(path, sizeof(path), "%s/blobs/%s.mime", directory, blob_cid);
        unlink(path);
    }
    free(blob_cid);
    free(access_token);
    free(refresh_token);
    free(privileged_password);
    free(commit_cid);
    free(commit_rev);
    snprintf(path, sizeof(path), "%s/repo.sqlite3", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/auth.sqlite3", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/auth.sqlite3-shm", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/auth.sqlite3-wal", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/account.sqlite3", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/account.sqlite3-shm", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/account.sqlite3-wal", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/sequencer.sqlite3", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/sequencer.sqlite3-shm", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/sequencer.sqlite3-wal", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/accounts.sqlite3", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/accounts.sqlite3-shm", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/accounts.sqlite3-wal", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/reports.sqlite3", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/reports.sqlite3-shm", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/reports.sqlite3-wal", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/blobs", directory);
    rmdir(path);
    rmtree(directory);
    if (failures) fprintf(stderr, "%d test(s) failed\n", failures);
    return failures ? 1 : 0;
}

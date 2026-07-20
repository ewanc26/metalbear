#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include "metalbear/server.h"
#include "wolfram/repo/car.h"
#include "wolfram/sync_subscribe.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    failures++; } } while (0)

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
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
    if (fd < 0 || connect(fd, (struct sockaddr *)&address,
                          sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    char request[512];
    int length = snprintf(request, sizeof(request),
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
    wf_status status = wf_subscribe_decode_frame(payload, (size_t)length,
                                                  event);
    free(payload);
    return status == WF_OK;
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
        .account_did = "did:plc:metalbeartest",
        .account_handle = "alice.example.com",
        .user_domain = ".example.com",
        .password = "correct horse battery staple",
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
    int firehose = firehose_connect(metalbear_server_port(server), 2);
    CHECK(firehose >= 0);

    CHECK(wf_xrpc_query(client, "_health", NULL, &response) == WF_OK);
    cJSON *health_json = json_response(&response);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(health_json,
                                                          "version")));
    cJSON_Delete(health_json);
    wf_response_free(&response);

    /* Test createAccount: register a second account in the registry */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
        "{\"handle\":\"bob.example.com\",\"password\":\"bobsecret\","
        "\"did\":\"did:plc:bob\"}",
        &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *create_json = json_response(&response);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(create_json, "did")));
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(create_json, "did")->valuestring,
                 "did:plc:bob") == 0);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(create_json, "handle")->valuestring,
                 "bob.example.com") == 0);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(create_json, "accessJwt")));
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(create_json, "refreshJwt")));
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* Missing handle should return InvalidHandle */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
        "{\"password\":\"test\",\"did\":\"did:plc:x\"}",
        &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    create_json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(create_json, "error")->valuestring,
                 "InvalidHandle") == 0);
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* Duplicate handle should return HandleNotAvailable */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
        "{\"handle\":\"bob.example.com\",\"password\":\"other\","
        "\"did\":\"did:plc:bob2\"}",
        &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    create_json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(create_json, "error")->valuestring,
                 "HandleNotAvailable") == 0);
    cJSON_Delete(create_json);
    wf_response_free(&response);

    /* Test requestPasswordReset: accepts email, not identifier */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestPasswordReset",
        "{\"email\":\"alice@example.com\"}",
        &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    /* Missing email should fail */
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestPasswordReset",
        "{}",
        &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    create_json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(create_json, "error")->valuestring,
                 "InvalidRequest") == 0);
    cJSON_Delete(create_json);
    wf_response_free(&response);

    CHECK(wf_http_get(client, base, &response) == WF_OK);
    CHECK(response.status == 200 && response.body_len > 0);
    wf_response_free(&response);

    char well_known_url[160];
    snprintf(well_known_url, sizeof(well_known_url),
             "%s/.well-known/atproto-did", base);
    CHECK(wf_http_get(client, well_known_url, &response) == WF_OK);
    CHECK(response.status == 200);
    CHECK(response.body_len == strlen("did:plc:metalbeartest") &&
          memcmp(response.body, "did:plc:metalbeartest", response.body_len) == 0);
    wf_response_free(&response);

    snprintf(well_known_url, sizeof(well_known_url),
             "%s/.well-known/did.json", base);
    CHECK(wf_http_get(client, well_known_url, &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *did_document = json_response(&response);
    cJSON *did_id = cJSON_GetObjectItemCaseSensitive(did_document, "id");
    cJSON *did_services = cJSON_GetObjectItemCaseSensitive(did_document,
                                                            "service");
    cJSON *did_service = cJSON_GetArrayItem(did_services, 0);
    cJSON *did_endpoint = cJSON_GetObjectItemCaseSensitive(did_service,
                                                            "serviceEndpoint");
    CHECK(cJSON_IsString(did_id) &&
          strcmp(did_id->valuestring, "did:web:pds.example.com") == 0);
    CHECK(cJSON_IsString(did_endpoint) &&
          strcmp(did_endpoint->valuestring, "https://pds.example.com") == 0);
    cJSON_Delete(did_document);
    wf_response_free(&response);

    CHECK(wf_xrpc_query(client, "com.atproto.server.describeServer", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "did")));
    CHECK(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(
        json, "availableUserDomains")));
    CHECK(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(
        json, "inviteCodeRequired")));
    CHECK(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(
        json, "phoneVerificationRequired")));
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

    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
        "{\"identifier\":\"alice.example.com\",\"password\":\"wrong\"}",
        &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);

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
            cJSON *svc_ep = cJSON_GetObjectItemCaseSensitive(svc0,
                                                             "serviceEndpoint");
            CHECK(cJSON_IsString(svc_ep));
        }
    }
    char *access_token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    char *refresh_token = cJSON_IsString(refresh) ? strdup(refresh->valuestring) : NULL;
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
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.updateEmail",
        "{}",
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
        "{}",
        &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "tokenRequired")));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* getSession now includes email and emailConfirmed per lexicon */
    CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                        &response) == WF_OK);
    CHECK(response.status == 200);
    json = json_response(&response);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "email")->valuestring,
                 "new@example.com") == 0);
    CHECK(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(json,
                                                         "emailConfirmed")));
    cJSON_Delete(json);
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
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.confirmEmail",
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
    char *desktop_password = cJSON_IsString(app_password)
        ? strdup(app_password->valuestring) : NULL;
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
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(listed_password,
                                                          "name")));
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
    char *desktop_access = cJSON_IsString(access)
        ? strdup(access->valuestring) : NULL;
    char *desktop_refresh = cJSON_IsString(refresh)
        ? strdup(refresh->valuestring) : NULL;
    CHECK(desktop_access && desktop_refresh);
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, desktop_access);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAppPassword",
        "{\"name\":\"forbidden\"}", &response) == WF_ERR_HTTP);
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
            privileged_service_params, 2, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, access_token);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAppPassword",
        "{\"name\":\"trusted\",\"privileged\":true}", &response) == WF_OK);
    json = json_response(&response);
    app_password = cJSON_GetObjectItemCaseSensitive(json, "password");
    privileged_password = cJSON_IsString(app_password)
        ? strdup(app_password->valuestring) : NULL;
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
    char *privileged_access = cJSON_IsString(access)
        ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, privileged_access);
    CHECK(wf_xrpc_query_params(client, "com.atproto.server.getServiceAuth",
            privileged_service_params, 2, &response) == WF_OK);
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
    wf_status upload_status = wf_xrpc_upload_blob(
        client, "com.atproto.repo.uploadBlob", blob_data, sizeof(blob_data),
        "image/png", &response);
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
        {"did", "did:plc:metalbeartest"}, {"cid", blob_cid ? blob_cid : ""},
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
                           ? strdup(commit_cid_json->valuestring) : NULL;
    char *commit_rev = cJSON_IsString(commit_rev_json)
                           ? strdup(commit_rev_json->valuestring) : NULL;
    CHECK(commit_cid && commit_rev);
    cJSON_Delete(json);
    wf_response_free(&response);
    wf_subscribe_event live_event = {0};
    CHECK(firehose >= 0 && firehose_read(firehose, &live_event));
    CHECK(live_event.type == WF_SUBSCRIBE_EVENT_COMMIT);
    CHECK(live_event.seq == 3);
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

    firehose = firehose_connect(metalbear_server_port(server), 999);
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
        {"aud", "did:web:labeler.example.com"}, {"exp", "1"},
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
    CHECK(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(listed_repo,
                                                          "head")));
    cJSON_Delete(json);
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, NULL);
    wf_xrpc_param get_params[] = {
        {"repo", "did:plc:metalbeartest"},
        {"collection", "app.bsky.feed.post"},
        {"rkey", "first"},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                               get_params, 3, &response) == WF_OK);
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
        {"did", "did:plc:metalbeartest"}, {"since", commit_rev},
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
        {"did", "did:plc:metalbeartest"}, {"cids", commit_cid},
    };
    CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getBlocks",
                               block_params, 2, &response) == WF_OK);
    memset(&repo_car, 0, sizeof(repo_car));
    CHECK(wf_car_parse((const unsigned char *)response.body, response.body_len,
                       &repo_car) == WF_OK);
    CHECK(repo_car.root_count == 0 && repo_car.block_count == 1);
    wf_car_free(&repo_car);
    wf_response_free(&response);

    firehose = firehose_connect(metalbear_server_port(server), 3);
    CHECK(firehose >= 0);
    wf_xrpc_client_set_auth(client, access_token);
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.deactivateAccount",
                            "{}", &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);
    wf_subscribe_event deactivated_event = {0};
    CHECK(firehose >= 0 && firehose_read(firehose, &deactivated_event));
    CHECK(deactivated_event.type == WF_SUBSCRIBE_EVENT_ACCOUNT);
    CHECK(deactivated_event.seq == 4);
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
    CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                               get_params, 3, &response) == WF_ERR_HTTP);
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

    /* The environment password is bootstrap-only; an existing store keeps its
     * salted verifier rather than silently replacing credentials on restart. */
    config.password = "replacement must not overwrite stored credentials";
    server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (server) {
        snprintf(base, sizeof(base), "http://127.0.0.1:%u",
                 (unsigned)metalbear_server_port(server));
        client = wf_xrpc_client_new(base);
        CHECK(client != NULL);
        if (client) {
            CHECK(wf_xrpc_procedure(client,
                "com.atproto.server.createSession",
                "{\"identifier\":\"alice.example.com\","
                "\"password\":\"correct horse battery staple\"}",
                &response) == WF_OK);
            wf_response_free(&response);

            firehose = firehose_connect(metalbear_server_port(server), 2);
            CHECK(firehose >= 0);
            wf_subscribe_event replay_event = {0};
            CHECK(firehose >= 0 && firehose_read(firehose, &replay_event));
            CHECK(replay_event.type == WF_SUBSCRIBE_EVENT_COMMIT);
            CHECK(replay_event.seq == 3);
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
            CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(json,
                                                                  "active")));
            cJSON_Delete(json);
            wf_response_free(&response);

            firehose = firehose_connect(metalbear_server_port(server), 4);
            CHECK(firehose >= 0);
            CHECK(wf_xrpc_procedure(client,
                    "com.atproto.server.activateAccount", "{}", &response) ==
                  WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);
            wf_subscribe_event activation_event = {0};
            CHECK(firehose >= 0 && firehose_read(firehose, &activation_event));
            CHECK(activation_event.type == WF_SUBSCRIBE_EVENT_IDENTITY &&
                  activation_event.seq == 5);
            wf_subscribe_event_free(&activation_event);
            memset(&activation_event, 0, sizeof(activation_event));
            CHECK(firehose >= 0 && firehose_read(firehose, &activation_event));
            CHECK(activation_event.type == WF_SUBSCRIBE_EVENT_ACCOUNT &&
                  activation_event.seq == 6 &&
                  activation_event.data.account.active);
            wf_subscribe_event_free(&activation_event);
            memset(&activation_event, 0, sizeof(activation_event));
            CHECK(firehose >= 0 && firehose_read(firehose, &activation_event));
            CHECK(activation_event.type == WF_SUBSCRIBE_EVENT_SYNC &&
                  activation_event.seq == 7 &&
                  activation_event.data.sync.blocks_len > 0);
            wf_subscribe_event_free(&activation_event);
            if (firehose >= 0) close(firehose);

            /* App-password verifiers and privilege survive a full restart. */
            snprintf(login_body, sizeof(login_body),
                "{\"identifier\":\"alice.example.com\","
                "\"password\":\"%s\"}",
                privileged_password ? privileged_password : "");
            wf_xrpc_client_set_auth(client, NULL);
            CHECK(wf_xrpc_procedure(client,
                    "com.atproto.server.createSession", login_body,
                    &response) == WF_OK);
            json = json_response(&response);
            access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
            char *restarted_privileged_access = cJSON_IsString(access)
                ? strdup(access->valuestring) : NULL;
            cJSON_Delete(json);
            wf_response_free(&response);
            wf_xrpc_client_set_auth(client, restarted_privileged_access);
            CHECK(wf_xrpc_query_params(client,
                    "com.atproto.server.getServiceAuth",
                    privileged_service_params, 2, &response) == WF_OK);
            wf_response_free(&response);
            free(restarted_privileged_access);

            wf_xrpc_client_set_auth(client, refresh_token);
            CHECK(wf_xrpc_procedure(client,
                    "com.atproto.server.refreshSession", "{}", &response) == WF_OK);
            CHECK(response.status == 200);
            json = json_response(&response);
            refresh = cJSON_GetObjectItemCaseSensitive(json, "refreshJwt");
            char *rotated_refresh = cJSON_IsString(refresh)
                                        ? strdup(refresh->valuestring) : NULL;
            CHECK(rotated_refresh != NULL &&
                  strcmp(rotated_refresh, refresh_token) != 0);
            cJSON_Delete(json);
            wf_response_free(&response);

            /* The previous refresh token remains reusable during its bounded
             * grace period and resolves to the same successor token id. */
            CHECK(wf_xrpc_procedure(client,
                    "com.atproto.server.refreshSession", "{}", &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);

            wf_xrpc_client_set_auth(client, rotated_refresh);
            CHECK(wf_xrpc_procedure(client,
                    "com.atproto.server.deleteSession", "{}", &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);
            CHECK(wf_xrpc_procedure(client,
                    "com.atproto.server.refreshSession", "{}", &response) ==
                  WF_ERR_HTTP);
            CHECK(response.status == 401);
            wf_response_free(&response);
            free(rotated_refresh);

            wf_xrpc_client_set_auth(client, NULL);
            CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                                       get_params, 3, &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);
            wf_xrpc_client_free(client);
        }
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
    snprintf(path, sizeof(path), "%s/blobs", directory);
    rmdir(path);
    rmdir(directory);
    if (failures) fprintf(stderr, "%d test(s) failed\n", failures);
    return failures ? 1 : 0;
}

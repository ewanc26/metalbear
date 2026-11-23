#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

/*
 * test_public_status.c — issue #267's public resource panel contract.
 *
 * The opt-in flag changes /operator.json from "no status fields at all" to a
 * process/disk/host snapshot with no account identifiers and no raw HTTP
 * paths. Both states are exercised over real HTTP because the gate lives in
 * the route, not in a helper the parser can inspect.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
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

static metalbear_server *start_server(const char *directory, bool enabled) {
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .admin_password = "secret-admin",
        .invite_required = false,
        .admission_default = "open",
        .public_status = enabled,
        .rate_limit = 10000,
    };
    return metalbear_server_start(&config);
}

static void test_flag_off(void) {
    char directory[] = "/tmp/metalbear-public-off-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_server *server = start_server(directory, false);
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
    wf_response response = {0};
    if (client) {
        char url[160];
        snprintf(url, sizeof(url), "%s/operator.json", base);
        CHECK(wf_http_get(client, url, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *root = json_response(&response);
        CHECK(root != NULL);
        if (root) {
            /* Absent, not zeroed: a client must not be able to mistake an
             * opted-out host for one that really has zero accounts. */
            CHECK(cJSON_GetObjectItemCaseSensitive(root, "publicStatus") ==
                  NULL);
            cJSON_Delete(root);
        }
        wf_response_free(&response);
        wf_xrpc_client_free(client);
    }
    metalbear_server_free(server);
    rmtree(directory);
}

static void check_number_at_least(cJSON *object, const char *name,
                                  double minimum) {
    cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
    CHECK(cJSON_IsNumber(value) && value->valuedouble >= minimum);
}

static void test_flag_on(void) {
    char directory[] = "/tmp/metalbear-public-on-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_server *server = start_server(directory, true);
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
    char account_did[160] = "";
    wf_response response = {0};
    if (client) {
        CHECK(
            wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                              "{\"handle\":\"statususer.example.com\","
                              "\"email\":\"public@example.com\","
                              "\"password\":\"correct horse battery staple\"}",
                              &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *created = json_response(&response);
        if (created) {
            cJSON *did = cJSON_GetObjectItemCaseSensitive(created, "did");
            if (cJSON_IsString(did))
                snprintf(account_did, sizeof(account_did), "%s",
                         did->valuestring);
            cJSON_Delete(created);
        }
        CHECK(account_did[0] != '\0');
        wf_response_free(&response);

        char url[160];
        snprintf(url, sizeof(url), "%s/operator.json", base);
        CHECK(wf_http_get(client, url, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *root = json_response(&response);
        CHECK(root != NULL);
        if (root) {
            cJSON *status =
                cJSON_GetObjectItemCaseSensitive(root, "publicStatus");
            CHECK(cJSON_IsObject(status));
            if (cJSON_IsObject(status)) {
                check_number_at_least(status, "uptimeSeconds", 0);
                check_number_at_least(status, "workerThreads", 1);
                check_number_at_least(status, "openFdCount", 0);
                check_number_at_least(status, "rssBytes", 0);

                cJSON *load =
                    cJSON_GetObjectItemCaseSensitive(status, "cpuLoad");
                CHECK(cJSON_IsObject(load));
                if (cJSON_IsObject(load)) {
                    check_number_at_least(load, "oneMinute", 0);
                    check_number_at_least(load, "fiveMinute", 0);
                    check_number_at_least(load, "fifteenMinute", 0);
                }

                cJSON *disk = cJSON_GetObjectItemCaseSensitive(status, "disk");
                CHECK(cJSON_IsObject(disk));
                if (cJSON_IsObject(disk)) {
                    cJSON *fs =
                        cJSON_GetObjectItemCaseSensitive(disk, "filesystem");
                    CHECK(cJSON_IsObject(fs));
                    if (cJSON_IsObject(fs)) {
                        check_number_at_least(fs, "totalBytes", 0);
                        check_number_at_least(fs, "usedBytes", 0);
                        check_number_at_least(fs, "availableBytes", 0);
                    }
                    check_number_at_least(disk, "dataDirectoryBytes", 0);
                    check_number_at_least(disk, "blobStoreBytes", 0);
                }

                cJSON *storage =
                    cJSON_GetObjectItemCaseSensitive(status, "storage");
                CHECK(cJSON_IsObject(storage));
                if (cJSON_IsObject(storage)) {
                    check_number_at_least(storage, "repoBytes", 0);
                    check_number_at_least(storage, "blobBytes", 0);
                }

                cJSON *firehose =
                    cJSON_GetObjectItemCaseSensitive(status, "firehose");
                CHECK(cJSON_IsObject(firehose));
                if (cJSON_IsObject(firehose)) {
                    check_number_at_least(firehose, "sequence", 1);
                    check_number_at_least(firehose, "lastEventAgeSeconds", 0);
                }

                cJSON *requests =
                    cJSON_GetObjectItemCaseSensitive(status, "requests");
                CHECK(cJSON_IsObject(requests));
                if (cJSON_IsObject(requests)) {
                    check_number_at_least(requests, "total", 1);
                    check_number_at_least(requests, "failed", 0);
                    cJSON *routes =
                        cJSON_GetObjectItemCaseSensitive(requests, "byRoute");
                    CHECK(cJSON_IsObject(routes));
                    if (cJSON_IsObject(routes)) {
                        for (cJSON *route = routes->child; route;
                             route = route->next) {
                            if (!route->string ||
                                strcmp(route->string, "other") == 0)
                                continue;
                            /* NSIDs are reverse-DNS labels. A raw path would
                             * carry a slash, query or fragment and could
                             * expose an identifier. */
                            CHECK(strchr(route->string, '/') == NULL);
                            CHECK(strchr(route->string, '?') == NULL);
                            CHECK(strchr(route->string, '#') == NULL);
                            CHECK(strchr(route->string, '.') != NULL);
                        }
                    }
                }
            }

            char *serialized = cJSON_PrintUnformatted(root);
            CHECK(serialized != NULL);
            if (serialized) {
                CHECK(strstr(serialized, account_did) == NULL);
                CHECK(strstr(serialized, "statususer.example.com") == NULL);
                free(serialized);
            }
            cJSON_Delete(root);
        }
        wf_response_free(&response);
        wf_xrpc_client_free(client);
    }
    metalbear_server_free(server);
    rmtree(directory);
}

int main(void) {
    printf("MetalBear public status tests\n");
    test_flag_off();
    test_flag_on();
    if (failures) fprintf(stderr, "%d test(s) failed\n", failures);
    return failures ? 1 : 0;
}

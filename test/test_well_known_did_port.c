/*
 * test_well_known_did_port.c — coverage for /.well-known/did.json when the
 * service DID carries a percent-encoded port, as a local dev instance's
 * did:web:localhost%3A2583 does (scripts/setup.sh --local).
 *
 * handle_well_known_did (server.c) used to compare the request's Host header
 * -- stripped of its port by extract_hostname -- against the service DID's
 * host, which still carries the literal "%3A<port>" text. Those can never be
 * equal, so a port-bearing service DID could never resolve its own document:
 * every request fell through to account-hostname resolution and 404'd. This
 * pins the fix: a Host header that matches the DID's host:port (after
 * decoding %3A back to ':') must serve the service's own DID document.
 */

#define _POSIX_C_SOURCE 200809L
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

int main(void) {
    printf("Port-bearing did:web self-resolution Tests\n");
    printf("============================================\n\n");

    char directory[] = "/tmp/metalbear-didport-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);

    /* The service DID's host:port is fictional -- it never has to match the
     * TCP port the test server actually binds to below, since the route
     * under test compares the DID's host against the client's Host header,
     * not against the socket the request arrived on. */
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:dev.example%3A9999",
        .public_url = "http://dev.example:9999",
        .user_domain = ".dev.example",
        .invite_required = false,
        .rate_limit = 10000,
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
    wf_response response = {0};

    char well_known_url[160];
    snprintf(well_known_url, sizeof(well_known_url), "%s/.well-known/did.json",
             base);

    /* --- Host header matches the DID's decoded host:port --- */
    {
        wf_http_header hdr = {"Host", "dev.example:9999"};
        CHECK(wf_http_get_with_headers(client, well_known_url, &hdr, 1,
                                       &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *doc = json_response(&response);
        CHECK(doc != NULL);
        if (doc) {
            cJSON *id = cJSON_GetObjectItemCaseSensitive(doc, "id");
            CHECK(cJSON_IsString(id) &&
                  strcmp(id->valuestring, "did:web:dev.example%3A9999") == 0);
            cJSON *services = cJSON_GetObjectItemCaseSensitive(doc, "service");
            CHECK(cJSON_IsArray(services) && cJSON_GetArraySize(services) == 1);
            cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(
                cJSON_GetArrayItem(services, 0), "serviceEndpoint");
            CHECK(cJSON_IsString(endpoint) &&
                  strcmp(endpoint->valuestring, "http://dev.example:9999") ==
                      0);
            cJSON_Delete(doc);
        }
        wf_response_free(&response);
        if (!failures)
            printf(
                "PASS: matching host:port serves the service DID document\n");
    }

    /* --- Host header names neither the service nor any account: still a
     * clean miss, not an accidental match on the bare hostname. --- */
    {
        int before = failures;
        wf_http_header hdr = {"Host", "dev.example"};
        CHECK(wf_http_get_with_headers(client, well_known_url, &hdr, 1,
                                       &response) == WF_ERR_HTTP);
        CHECK(response.status == 404);
        wf_response_free(&response);
        if (failures == before)
            printf("PASS: bare hostname (no port) does not match\n");
    }

    metalbear_server_free(server);
    wf_xrpc_client_free(client);
    rmtree(directory);

    printf("\n%s\n", failures ? "FAILED" : "OK");
    return failures ? 1 : 0;
}

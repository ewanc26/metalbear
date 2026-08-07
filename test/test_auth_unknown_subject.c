#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_auth_unknown_subject.c — regression coverage for a NULL-deref crash
 * in authenticate() (src/server.c).
 *
 * jwt_subject() decodes a bearer token's `sub` claim WITHOUT verifying its
 * signature -- deliberately, since the claim itself is what names which
 * account's auth store should perform real verification. authenticate()
 * used to pass that unverified `sub` straight into
 * context_for_did(server, sub)->auth without checking whether
 * context_for_did() found a real account first -- so any JWT-shaped bearer
 * token (three dot-separated segments, a base64url JSON middle segment with
 * a `sub` field; the signature segment is never reached) naming a DID this
 * server never created would dereference NULL and crash the whole
 * multi-tenant server. No valid signature was required to trigger it: the
 * crash happened before signature verification ever ran.
 *
 * This sends exactly that malformed-but-JWT-shaped token against a live
 * server and confirms it's refused with an ordinary error response, then
 * confirms the server is still alive and answering unrelated requests --
 * the strongest possible proof this doesn't crash the process, since an
 * unfixed server would simply stop responding to everything after the
 * first request.
 */

#include "metalbear/server.h"
#include "wolfram/crypto.h"
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

/* Build a JWT-shaped (but unsigned/unverifiable) bearer token naming
 * `sub` -- exactly what jwt_subject() reads before any signature check. */
static char *build_fake_jwt(const char *sub) {
    char payload_json[256];
    snprintf(payload_json, sizeof(payload_json), "{\"sub\":\"%s\"}", sub);
    char *payload_b64 = NULL;
    if (wf_crypto_base64url_encode((const unsigned char *)payload_json,
                                   strlen(payload_json), &payload_b64) != WF_OK)
        return NULL;
    char *token = malloc(strlen(payload_b64) + 16);
    if (token) sprintf(token, "x.%s.x", payload_b64);
    free(payload_b64);
    return token;
}

int main(void) {
    char directory[] = "/tmp/metalbear-auth-unknown-sub-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
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

    char *fake_token = build_fake_jwt("did:plc:nobodyhome");
    CHECK(fake_token != NULL);
    if (fake_token) {
        wf_xrpc_client_set_auth(client, fake_token);
        wf_response response = {0};
        wf_status s = wf_xrpc_query_params(
            client, "com.atproto.server.getSession", NULL, 0, &response);
        /* The exact refusal shape doesn't matter as much as "the server
         * answered at all, with an error, instead of dying" -- but confirm
         * it's a refusal, not an accidental success. */
        CHECK(s == WF_ERR_HTTP);
        CHECK(response.status == 400 || response.status == 401);
        wf_response_free(&response);
    }
    free(fake_token);
    wf_xrpc_client_set_auth(client, NULL);

    /* The server must still be alive: a plain, unrelated public query
     * succeeds normally. An unfixed server would have crashed on the
     * request above and every request from here on would fail to connect
     * at all. */
    wf_response response = {0};
    CHECK(wf_xrpc_query_params(client, "com.atproto.server.describeServer",
                               NULL, 0, &response) == WF_OK);
    CHECK(response.status == 200);
    wf_response_free(&response);

    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_auth_unknown_subject: OK\n");
    return 0;
}

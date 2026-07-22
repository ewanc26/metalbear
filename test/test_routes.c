#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include "metalbear/oauth_routes.h"
#include "metalbear/key_rotation.h"
#include "wolfram/crypto.h"
#include "wolfram/oauth/pkce.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression); \
    failures++; } } while (0)

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

int main(void) {
    /* Test key rotation store */
    char key_path[] = "/tmp/metalbear-keys-XXXXXX";
    int kd = mkstemp(key_path);
    CHECK(kd >= 0);
    if (kd < 0) return 1;
    close(kd);
    unlink(key_path);

    metalbear_key_rotation *key_store = NULL;
    CHECK(metalbear_key_rotation_open(key_path, &key_store) == WF_OK);
    CHECK(key_store != NULL);

    wf_signing_key key1 = {0};
    CHECK(metalbear_key_rotation_current_key(key_store, &key1) == WF_OK);
    CHECK(key1.type == WF_KEY_TYPE_SECP256K1);

    wf_signing_key key2 = {0};
    CHECK(metalbear_key_rotation_current_key(key_store, &key2) == WF_OK);
    CHECK(memcmp(&key1, &key2, sizeof(key1)) == 0);

    wf_signing_key rotated = {0};
    char *didkey = NULL;
    CHECK(metalbear_key_rotation_rotate(key_store, &rotated,
                                         &didkey) == WF_OK);
    CHECK(rotated.type == WF_KEY_TYPE_SECP256K1);
    CHECK(didkey != NULL && strstr(didkey, "did:key:") != NULL);
    free(didkey);

    wf_signing_key key3 = {0};
    CHECK(metalbear_key_rotation_current_key(key_store, &key3) == WF_OK);
    CHECK(memcmp(&rotated, &key3, sizeof(key3)) == 0);
    CHECK(memcmp(&key1, &key3, sizeof(key3)) != 0);

    metalbear_key_rotation_free(key_store);
    unlink(key_path);
    char sidecar[256];
    snprintf(sidecar, sizeof(sidecar), "%s-shm", key_path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", key_path);
    unlink(sidecar);

    /* Test OAuth routes */
    char oauth_path[] = "/tmp/metalbear-oauth-routes-XXXXXX";
    int od = mkstemp(oauth_path);
    CHECK(od >= 0);
    if (od < 0) return 1;
    close(od);
    unlink(oauth_path);

    metalbear_oauth_store *oauth_store = NULL;
    CHECK(metalbear_oauth_store_open(oauth_path,
                                     "https://pds.example.com",
                                     "did:plc:alice",
                                     &oauth_store) == WF_OK);
    CHECK(oauth_store != NULL);

    /* Test JWKS endpoint directly */
    char *jwks = NULL;
    CHECK(metalbear_oauth_jwks(oauth_store, &jwks) == WF_OK);
    CHECK(jwks != NULL && strstr(jwks, "\"keys\"") != NULL);
    free(jwks);

    /* Test PAR + authorize + token flow */
    wf_oauth_pkce pkce = {0};
    CHECK(wf_oauth_pkce_from_verifier(
              "test-route-verifier-with-enough-entropy-012345", &pkce) == WF_OK);

    metalbear_oauth_request request = {
        .client_id = "https://client.example/metadata.json",
        .redirect_uri = "https://client.example/callback",
        .scope = "atproto transition:generic",
        .state = "test-state",
        .code_challenge = pkce.challenge,
        .dpop_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    char *request_uri = NULL;
    int64_t expires_in = 0;
    CHECK(metalbear_oauth_create_par(oauth_store, &request,
                                      &request_uri, &expires_in) == WF_OK);
    CHECK(request_uri != NULL);

    char *code = NULL;
    char *redirect_uri = NULL;
    char *state = NULL;
    CHECK(metalbear_oauth_authorize(oauth_store, request_uri,
                                     request.client_id,
                                     &code, &redirect_uri, &state) == WF_OK);
    CHECK(code != NULL && redirect_uri != NULL && state != NULL);

    metalbear_oauth_grant grant = {0};
    CHECK(metalbear_oauth_exchange_code(oauth_store, code,
                                         request.client_id,
                                         request.redirect_uri,
                                         pkce.verifier,
                                         request.dpop_jkt,
                                         &grant) == WF_OK);
    CHECK(grant.access_token != NULL && grant.refresh_token != NULL);

    /* Test token refresh */
    metalbear_oauth_grant rotated_grant = {0};
    CHECK(metalbear_oauth_refresh(oauth_store, grant.refresh_token,
                                   request.client_id,
                                   request.dpop_jkt,
                                   &rotated_grant) == WF_OK);
    CHECK(rotated_grant.access_token != NULL);

    /* Test revocation */
    CHECK(metalbear_oauth_revoke(oauth_store,
                                  rotated_grant.refresh_token) == WF_OK);

    metalbear_oauth_grant_free(&grant);
    metalbear_oauth_grant_free(&rotated_grant);
    free(request_uri);
    free(code);
    free(redirect_uri);
    free(state);
    metalbear_oauth_store_free(oauth_store);
    unlink(oauth_path);
    snprintf(sidecar, sizeof(sidecar), "%s-shm", oauth_path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", oauth_path);
    unlink(sidecar);

    if (failures) fprintf(stderr, "%d route test(s) failed\n", failures);
    return failures ? 1 : 0;
}

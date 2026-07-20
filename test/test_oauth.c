#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression); \
    failures++; } } while (0)

int main(void) {
    char path[] = "/tmp/metalbear-oauth-XXXXXX";
    int descriptor = mkstemp(path);
    CHECK(descriptor >= 0);
    if (descriptor < 0) return 1;
    close(descriptor);
    unlink(path);

    metalbear_oauth_store *store = NULL;
    CHECK(metalbear_oauth_store_open(path, "https://pds.example.com",
                                    "did:plc:alice", &store) == WF_OK);
    CHECK(store != NULL);
    if (!store) return 1;

    char *jwk = NULL;
    char *jwks = NULL;
    CHECK(metalbear_oauth_public_jwk(store, &jwk) == WF_OK);
    CHECK(jwk && strstr(jwk, "\"kid\":\"metalbear-oauth\""));
    CHECK(metalbear_oauth_jwks(store, &jwks) == WF_OK);
    CHECK(jwks && strstr(jwks, "\"keys\""));
    free(jwk);
    free(jwks);

    wf_oauth_pkce pkce = {0};
    CHECK(wf_oauth_pkce_from_verifier(
              "v3ry-long-test-verifier-with-enough-entropy-0123456789", &pkce) == WF_OK);
    metalbear_oauth_request request = {
        .client_id = "https://client.example/metadata.json",
        .redirect_uri = "https://client.example/callback",
        .scope = "atproto transition:generic",
        .state = "state-123",
        .code_challenge = pkce.challenge,
        .dpop_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    char *request_uri = NULL;
    int64_t expires_in = 0;
    CHECK(metalbear_oauth_create_par(store, &request, &request_uri,
                                     &expires_in) == WF_OK);
    CHECK(request_uri && strstr(request_uri, "urn:ietf:params:oauth:request_uri:"));
    CHECK(expires_in == 300);

    char *code = NULL;
    char *redirect_uri = NULL;
    char *state = NULL;
    CHECK(metalbear_oauth_authorize(store, request_uri, request.client_id,
                                    &code, &redirect_uri, &state) == WF_OK);
    CHECK(code && redirect_uri && state);
    CHECK(redirect_uri && strcmp(redirect_uri, request.redirect_uri) == 0);
    CHECK(state && strcmp(state, request.state) == 0);

    metalbear_oauth_grant grant = {0};
    CHECK(metalbear_oauth_exchange_code(store, code, request.client_id,
                                        request.redirect_uri, pkce.verifier,
                                        request.dpop_jkt, &grant) == WF_OK);
    CHECK(grant.access_token && grant.refresh_token && grant.expires_in == 3600);
    metalbear_oauth_grant rejected = {0};
    CHECK(metalbear_oauth_exchange_code(store, code, request.client_id,
                                        request.redirect_uri, pkce.verifier,
                                        request.dpop_jkt, &rejected) == WF_ERR_PERMISSION);

    CHECK(metalbear_oauth_refresh(store, grant.refresh_token, request.client_id,
                                  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                                  &rejected) == WF_ERR_PERMISSION);
    metalbear_oauth_grant rotated = {0};
    CHECK(metalbear_oauth_refresh(store, grant.refresh_token, request.client_id,
                                  request.dpop_jkt, &rotated) == WF_OK);
    CHECK(rotated.access_token && rotated.refresh_token);
    CHECK(metalbear_oauth_revoke(store, rotated.refresh_token) == WF_OK);
    metalbear_oauth_grant_free(&rejected);
    CHECK(metalbear_oauth_refresh(store, rotated.refresh_token, request.client_id,
                                  request.dpop_jkt, &rejected) == WF_ERR_PERMISSION);

    metalbear_oauth_grant_free(&grant);
    metalbear_oauth_grant_free(&rotated);
    metalbear_oauth_grant_free(&rejected);
    free(request_uri);
    free(code);
    free(redirect_uri);
    free(state);
    metalbear_oauth_store_free(store);
    unlink(path);
    char sidecar[256];
    snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
    unlink(sidecar);
    if (failures) fprintf(stderr, "%d OAuth test(s) failed\n", failures);
    return failures ? 1 : 0;
}

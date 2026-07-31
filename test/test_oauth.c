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
                                    &store) == WF_OK);
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
    /* The account is named per authorization now, not baked into the store. */
    CHECK(metalbear_oauth_authorize(store, request_uri, request.client_id,
                                    "did:plc:alice",
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

    /* Device sessions: the storage layer /oauth/authorize's gate depends on. */
    {
        char *token = NULL;
        CHECK(metalbear_oauth_device_session_create(
                  store, "did:plc:alice", &token) == WF_OK);
        CHECK(token && token[0]);

        char subject[256];
        CHECK(metalbear_oauth_device_session_verify(
                  store, token, subject, sizeof(subject)) == WF_OK);
        CHECK(strcmp(subject, "did:plc:alice") == 0);

        /* A token that never existed, and a token that did but was for a
         * different subject entirely, must not be confused with each other —
         * both simply fail. */
        CHECK(metalbear_oauth_device_session_verify(
                  store, "not-a-real-token", subject,
                  sizeof(subject)) == WF_ERR_NOT_FOUND);
        CHECK(metalbear_oauth_device_session_verify(
                  store, NULL, subject, sizeof(subject)) == WF_ERR_NOT_FOUND);

        /* Revoking clears it; the same token then verifies as absent, not as
         * still valid for whoever it used to name. */
        CHECK(metalbear_oauth_device_session_revoke(store, token) == WF_OK);
        CHECK(metalbear_oauth_device_session_verify(
                  store, token, subject, sizeof(subject)) ==
              WF_ERR_NOT_FOUND);

        /* Revoking a token that is already gone is success, not an error:
         * the desired end state (signed out) already holds. */
        CHECK(metalbear_oauth_device_session_revoke(store, token) == WF_OK);
        CHECK(metalbear_oauth_device_session_revoke(store, "never-issued") ==
              WF_OK);

        /* Two accounts hold independent sessions; revoking one must not
         * touch the other's. */
        char *token_a = NULL, *token_b = NULL;
        CHECK(metalbear_oauth_device_session_create(
                  store, "did:plc:a", &token_a) == WF_OK);
        CHECK(metalbear_oauth_device_session_create(
                  store, "did:plc:b", &token_b) == WF_OK);
        CHECK(metalbear_oauth_device_session_revoke(store, token_a) == WF_OK);
        CHECK(metalbear_oauth_device_session_verify(
                  store, token_b, subject, sizeof(subject)) == WF_OK);
        CHECK(strcmp(subject, "did:plc:b") == 0);

        free(token);
        free(token_a);
        free(token_b);
    }

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

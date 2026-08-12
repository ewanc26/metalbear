#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth/oauth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expression)                                                      \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,            \
                    #expression);                                              \
            failures++;                                                        \
        }                                                                      \
    } while (0)

int main(void) {
    char path[] = "/tmp/metalbear-oauth-XXXXXX";
    int descriptor = mkstemp(path);
    CHECK(descriptor >= 0);
    if (descriptor < 0) return 1;
    close(descriptor);
    unlink(path);

    metalbear_oauth_store *store = NULL;
    CHECK(metalbear_oauth_store_open(path, "https://pds.example.com", &store) ==
          WF_OK);
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
              "v3ry-long-test-verifier-with-enough-entropy-0123456789",
              &pkce) == WF_OK);
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
    CHECK(request_uri &&
          strstr(request_uri, "urn:ietf:params:oauth:request_uri:"));
    CHECK(expires_in == 300);

    /* The consent screen peeks at a pending PAR to show what is actually
     * being requested, without consuming it -- unlike authorize below,
     * which is one-time-use. */
    char *peeked_scope = NULL, *peeked_redirect = NULL;
    CHECK(metalbear_oauth_par_peek(store, request_uri, request.client_id,
                                   &peeked_scope, &peeked_redirect) == WF_OK);
    CHECK(peeked_scope && strcmp(peeked_scope, request.scope) == 0);
    CHECK(peeked_redirect &&
          strcmp(peeked_redirect, request.redirect_uri) == 0);
    free(peeked_scope);
    free(peeked_redirect);
    /* A second peek must still succeed: peeking does not consume the PAR. */
    peeked_scope = NULL;
    peeked_redirect = NULL;
    CHECK(metalbear_oauth_par_peek(store, request_uri, request.client_id,
                                   &peeked_scope, &peeked_redirect) == WF_OK);
    free(peeked_scope);
    free(peeked_redirect);
    /* A client_id that does not match the PAR's own must be refused, same as
     * authorize's own mismatch check. */
    peeked_scope = NULL;
    peeked_redirect = NULL;
    CHECK(metalbear_oauth_par_peek(
              store, request_uri, "https://impostor.example/metadata.json",
              &peeked_scope, &peeked_redirect) == WF_ERR_PERMISSION);
    CHECK(!peeked_scope && !peeked_redirect);
    /* An unknown request_uri is WF_ERR_NOT_FOUND, not a crash or a match. */
    CHECK(metalbear_oauth_par_peek(store,
                                   "urn:ietf:params:oauth:request_uri:"
                                   "does-not-exist",
                                   request.client_id, &peeked_scope,
                                   &peeked_redirect) == WF_ERR_NOT_FOUND);

    char *code = NULL;
    char *redirect_uri = NULL;
    char *state = NULL;
    /* The account is named per authorization now, not baked into the store. */
    CHECK(metalbear_oauth_authorize(store, request_uri, request.client_id,
                                    "did:plc:alice", &code, &redirect_uri,
                                    &state) == WF_OK);

    /* authorize() consumed the PAR: peeking the same request_uri afterward
     * must fail, not return stale data. */
    peeked_scope = NULL;
    peeked_redirect = NULL;
    CHECK(metalbear_oauth_par_peek(store, request_uri, request.client_id,
                                   &peeked_scope,
                                   &peeked_redirect) == WF_ERR_NOT_FOUND);
    CHECK(code && redirect_uri && state);
    CHECK(redirect_uri && strcmp(redirect_uri, request.redirect_uri) == 0);
    CHECK(state && strcmp(state, request.state) == 0);

    metalbear_oauth_grant grant = {0};
    CHECK(metalbear_oauth_exchange_code(store, code, request.client_id,
                                        request.redirect_uri, pkce.verifier,
                                        request.dpop_jkt, &grant) == WF_OK);
    CHECK(grant.access_token && grant.refresh_token &&
          grant.expires_in == 3600);
    metalbear_oauth_grant rejected = {0};
    CHECK(metalbear_oauth_exchange_code(
              store, code, request.client_id, request.redirect_uri,
              pkce.verifier, request.dpop_jkt, &rejected) == WF_ERR_PERMISSION);

    CHECK(metalbear_oauth_refresh(store, grant.refresh_token, request.client_id,
                                  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                                  &rejected) == WF_ERR_PERMISSION);
    metalbear_oauth_grant rotated = {0};
    CHECK(metalbear_oauth_refresh(store, grant.refresh_token, request.client_id,
                                  request.dpop_jkt, &rotated) == WF_OK);
    CHECK(rotated.access_token && rotated.refresh_token);
    CHECK(metalbear_oauth_revoke(store, rotated.refresh_token) == WF_OK);
    metalbear_oauth_grant_free(&rejected);
    CHECK(metalbear_oauth_refresh(store, rotated.refresh_token,
                                  request.client_id, request.dpop_jkt,
                                  &rejected) == WF_ERR_PERMISSION);

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
        CHECK(metalbear_oauth_device_session_create(store, "did:plc:alice",
                                                    &token) == WF_OK);
        CHECK(token && token[0]);

        char subject[256];
        CHECK(metalbear_oauth_device_session_verify(store, token, subject,
                                                    sizeof(subject)) == WF_OK);
        CHECK(strcmp(subject, "did:plc:alice") == 0);

        /* A token that never existed, and a token that did but was for a
         * different subject entirely, must not be confused with each other —
         * both simply fail. */
        CHECK(metalbear_oauth_device_session_verify(store, "not-a-real-token",
                                                    subject, sizeof(subject)) ==
              WF_ERR_NOT_FOUND);
        CHECK(metalbear_oauth_device_session_verify(
                  store, NULL, subject, sizeof(subject)) == WF_ERR_NOT_FOUND);

        /* Revoking clears it; the same token then verifies as absent, not as
         * still valid for whoever it used to name. */
        CHECK(metalbear_oauth_device_session_revoke(store, token) == WF_OK);
        CHECK(metalbear_oauth_device_session_verify(
                  store, token, subject, sizeof(subject)) == WF_ERR_NOT_FOUND);

        /* Revoking a token that is already gone is success, not an error:
         * the desired end state (signed out) already holds. */
        CHECK(metalbear_oauth_device_session_revoke(store, token) == WF_OK);
        CHECK(metalbear_oauth_device_session_revoke(store, "never-issued") ==
              WF_OK);

        /* Two accounts hold independent sessions; revoking one must not
         * touch the other's. */
        char *token_a = NULL, *token_b = NULL;
        CHECK(metalbear_oauth_device_session_create(store, "did:plc:a",
                                                    &token_a) == WF_OK);
        CHECK(metalbear_oauth_device_session_create(store, "did:plc:b",
                                                    &token_b) == WF_OK);
        CHECK(metalbear_oauth_device_session_revoke(store, token_a) == WF_OK);
        CHECK(metalbear_oauth_device_session_verify(store, token_b, subject,
                                                    sizeof(subject)) == WF_OK);
        CHECK(strcmp(subject, "did:plc:b") == 0);

        free(token);
        free(token_a);
        free(token_b);
    }

    /* dpop_jkt is mandatory throughout -- atproto's OAuth profile requires
     * DPoP for every client with no exemptions (atproto.com/specs/oauth).
     * A prior version of this server treated it as optional for "loopback
     * clients"; that was never a real exemption in the spec, and let a
     * DPoP-unbound token be minted and then bound to any attacker-chosen
     * key on first resource-server use, defeating DPoP's sender constraint
     * entirely. Verify each stage now fails closed without it. */
    {
        metalbear_oauth_request no_jkt = {
            .client_id = "https://client.example/metadata2.json",
            .redirect_uri = "https://client.example/callback2",
            .scope = "atproto",
            .state = "state-no-jkt",
            .code_challenge = pkce.challenge,
            .dpop_jkt = NULL,
        };
        char *request_uri2 = NULL;
        int64_t expires2 = 0;
        CHECK(metalbear_oauth_create_par(store, &no_jkt, &request_uri2,
                                         &expires2) != WF_OK);
        CHECK(request_uri2 == NULL);

        /* Even a legitimately-issued code/refresh token (real jkt
         * established at PAR) must not be exchangeable/refreshable without
         * presenting a matching dpop_jkt -- exercise both the "omitted
         * entirely" and "wrong key" cases against the real flow set up
         * below. */
        metalbear_oauth_request real = {
            .client_id = "https://client.example/metadata3.json",
            .redirect_uri = "https://client.example/callback3",
            .scope = "atproto",
            .state = "state-real-jkt",
            .code_challenge = pkce.challenge,
            .dpop_jkt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        };
        char *request_uri3 = NULL;
        int64_t expires3 = 0;
        CHECK(metalbear_oauth_create_par(store, &real, &request_uri3,
                                         &expires3) == WF_OK);
        CHECK(request_uri3 != NULL);

        char *code3 = NULL, *redirect3 = NULL, *state3 = NULL;
        CHECK(metalbear_oauth_authorize(store, request_uri3, real.client_id,
                                        "did:plc:alice", &code3, &redirect3,
                                        &state3) == WF_OK);
        CHECK(code3 && code3[0]);

        metalbear_oauth_grant grant3 = {0};
        CHECK(metalbear_oauth_exchange_code(
                  store, code3, real.client_id, real.redirect_uri,
                  pkce.verifier, NULL, &grant3) == WF_ERR_INVALID_ARG);
        CHECK(!grant3.access_token);
        CHECK(metalbear_oauth_exchange_code(
                  store, code3, real.client_id, real.redirect_uri,
                  pkce.verifier, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                  &grant3) != WF_OK);
        CHECK(!grant3.access_token);
        CHECK(metalbear_oauth_exchange_code(store, code3, real.client_id,
                                            real.redirect_uri, pkce.verifier,
                                            real.dpop_jkt, &grant3) == WF_OK);
        CHECK(grant3.access_token && grant3.access_token[0]);
        CHECK(grant3.refresh_token && grant3.refresh_token[0]);

        metalbear_oauth_grant rotated3 = {0};
        CHECK(metalbear_oauth_refresh(store, grant3.refresh_token,
                                      real.client_id, NULL,
                                      &rotated3) == WF_ERR_INVALID_ARG);
        CHECK(!rotated3.access_token);
        CHECK(metalbear_oauth_refresh(
                  store, grant3.refresh_token, real.client_id,
                  "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                  &rotated3) != WF_OK);
        CHECK(!rotated3.access_token);
        CHECK(metalbear_oauth_refresh(store, grant3.refresh_token,
                                      real.client_id, real.dpop_jkt,
                                      &rotated3) == WF_OK);
        CHECK(rotated3.access_token && rotated3.access_token[0]);

        free(request_uri3);
        free(code3);
        free(redirect3);
        free(state3);
        metalbear_oauth_grant_free(&grant3);
        metalbear_oauth_grant_free(&rotated3);
        free(request_uri2);
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

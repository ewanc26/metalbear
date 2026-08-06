#define _POSIX_C_SOURCE 200809L

/*
 * test_oauth_token_assertion.c — offline end-to-end test for
 * private_key_jwt client authentication at the OAuth token endpoint.
 *
 * A confidential client (e.g. mu.social) authenticates at /oauth/token by
 * presenting an RFC 7523 client_assertion JWT signed with a key published in
 * its metadata document. The endpoint must fetch that document, take the
 * jwks, verify the assertion with wolfram's wf_oauth_verify_client_assertion,
 * and then treat the authenticated client_id as authoritative. This test
 * serves the client's metadata from a local MHD stub and drives the whole
 * path over the wire: happy path (metadata `jwks` and `jwks_uri`), every
 * client-auth failure the RFC names (wrong key, wrong audience, missing
 * client_id, bad assertion type), and the metadata `token_endpoint_auth_method:
 * "none"` refusal.
 *
 * Requires WOLFRAM_BUILD_SERVER and libmicrohttpd.
 */

#include "metalbear/oauth/oauth.h"
#include "metalbear/oauth/oauth_routes.h"
#include "wolfram/xrpc_server.h"

#include "test.h"

#include <cJSON.h>
#include <microhttpd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static const char ISSUER[] = "https://pds.example.com";
static const char CLIENT_JKT[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char CLIENT_KID[] = "client-key-1";

/* OpenSSL 3.0 deprecated the EC_KEY/ECDSA API in favor of EVP_PKEY. wolfram's
 * src/crypto/crypto.c and src/session/oauth/dpop.c already suppress this same
 * warning with a scoped pragma and a comment tracking full EVP migration as
 * separate future work; this file (EC_KEY threaded through every helper and
 * through run() itself) follows the identical, already-established pattern. */
_Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

    /* ------------------------------------------------------------------ */
    /* ES256 assertion signing (OpenSSL, low-S normalized)                */
    /* ------------------------------------------------------------------ */

    static char *b64url(const unsigned char *in, size_t len) {
    size_t plen = ((len + 2) / 3) * 4;
    char *p = malloc(plen + 1), *out = malloc(plen + 1);
    size_t i, n = 0;
    if (!p || !out) {
        free(p);
        free(out);
        return NULL;
    }
    EVP_EncodeBlock((unsigned char *)p, in, (int)len);
    for (i = 0; i < plen; i++) {
        char c = p[i];
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
        else if (c == '=')
            break;
        out[n++] = c;
    }
    out[n] = '\0';
    free(p);
    return out;
}

static char *es256_sign(EC_KEY *ec, const char *signing_input) {
    unsigned char digest[32], raw[64];
    SHA256((const unsigned char *)signing_input, strlen(signing_input), digest);
    ECDSA_SIG *sig = ECDSA_do_sign(digest, 32, ec);
    if (!sig) return NULL;
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(g, order, NULL);
    BIGNUM *half = BN_dup(order);
    BN_rshift1(half, half);
    BIGNUM *sn = BN_dup(s);
    if (BN_cmp(sn, half) > 0) {
        BIGNUM *norm = BN_dup(order);
        BN_sub(norm, norm, sn);
        BN_free(sn);
        sn = norm;
    }
    BN_bn2binpad(r, raw, 32);
    BN_bn2binpad(sn, raw + 32, 32);
    BN_free(order);
    BN_free(half);
    BN_free(sn);
    ECDSA_SIG_free(sig);
    return b64url(raw, 64);
}

/* RFC 7523 assertion. `alg` defaults to ES256. */
static char *make_assertion(EC_KEY *ec, const char *kid, const char *iss,
                            const char *sub, const char *aud, const char *jti,
                            int64_t iat, int64_t exp, const char *alg) {
    cJSON *h = cJSON_CreateObject();
    cJSON *p = cJSON_CreateObject();
    cJSON_AddStringToObject(h, "alg", alg ? alg : "ES256");
    cJSON_AddStringToObject(h, "kid", kid);
    cJSON_AddStringToObject(p, "iss", iss);
    cJSON_AddStringToObject(p, "sub", sub);
    cJSON_AddStringToObject(p, "aud", aud);
    cJSON_AddStringToObject(p, "jti", jti);
    cJSON_AddNumberToObject(p, "iat", (double)iat);
    cJSON_AddNumberToObject(p, "exp", (double)exp);

    char *hj = cJSON_PrintUnformatted(h);
    char *pj = cJSON_PrintUnformatted(p);
    char *hb = b64url((const unsigned char *)hj, strlen(hj));
    char *pb = b64url((const unsigned char *)pj, strlen(pj));
    size_t silen = strlen(hb) + 1 + strlen(pb);
    char *si = malloc(silen + 1);
    char *sig, *jwt;
    snprintf(si, silen + 1, "%s.%s", hb, pb);
    sig = es256_sign(ec, si);
    size_t jlen = silen + 1 + strlen(sig);
    jwt = malloc(jlen + 1);
    snprintf(jwt, jlen + 1, "%s.%s", si, sig);
    free(hj);
    free(pj);
    free(hb);
    free(pb);
    free(si);
    free(sig);
    cJSON_Delete(h);
    cJSON_Delete(p);
    return jwt;
}

static wf_status pub_coords(EC_KEY *ec, unsigned char x[32],
                            unsigned char y[32]) {
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    const EC_POINT *pt = EC_KEY_get0_public_key(ec);
    BIGNUM *bx = BN_new(), *by = BN_new();
    wf_status st;
    if (EC_POINT_get_affine_coordinates_GFp(g, pt, bx, by, NULL) != 1 ||
        BN_bn2binpad(bx, x, 32) != 32 || BN_bn2binpad(by, y, 32) != 32) {
        st = WF_ERR_PARSE;
    } else {
        st = WF_OK;
    }
    BN_free(bx);
    BN_free(by);
    return st;
}

/* Public JWK JSON (with kid) for the client metadata document. */
static char *client_jwk_json(EC_KEY *ec, const char *kid) {
    unsigned char x[32], y[32];
    char *xb, *yb, *out;
    cJSON *j;
    if (pub_coords(ec, x, y) != WF_OK) return NULL;
    xb = b64url(x, 32);
    yb = b64url(y, 32);
    j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "kty", "EC");
    cJSON_AddStringToObject(j, "crv", "P-256");
    cJSON_AddStringToObject(j, "x", xb);
    cJSON_AddStringToObject(j, "y", yb);
    cJSON_AddStringToObject(j, "kid", kid);
    out = cJSON_PrintUnformatted(j);
    free(xb);
    free(yb);
    cJSON_Delete(j);
    return out;
}

/* ------------------------------------------------------------------ */
/* Client metadata stub (local MHD server)                            */
/* ------------------------------------------------------------------ */

enum { METADATA_JWKS, METADATA_JWKS_URI, METADATA_NONE, METADATA_BROKEN };

static struct {
    int auth_method;
    char base[256]; /* http://127.0.0.1:PORT */
    char jwks[2048];
} stub;

static enum MHD_Result send_json(struct MHD_Connection *conn, int status,
                                 const char *json) {
    struct MHD_Response *res = MHD_create_response_from_buffer(
        strlen(json), (void *)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(res, "Content-Type", "application/json");
    enum MHD_Result rc = MHD_queue_response(conn, (unsigned)status, res);
    MHD_destroy_response(res);
    return rc;
}

static enum MHD_Result metadata_handler(void *cls, struct MHD_Connection *conn,
                                        const char *url, const char *method,
                                        const char *version,
                                        const char *upload_data,
                                        size_t *upload_size, void **con_cls) {
    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_size;
    (void)con_cls;
    if (strcmp(method, "GET") != 0) return MHD_NO;
    if (strcmp(url, "/jwks.json") == 0) return send_json(conn, 200, stub.jwks);
    if (strcmp(url, "/metadata.json") != 0) return MHD_NO;

    char body[4096];
    if (stub.auth_method == METADATA_JWKS_URI) {
        snprintf(body, sizeof(body),
                 "{\"client_id\":\"%s/metadata.json\","
                 "\"token_endpoint_auth_method\":\"private_key_jwt\","
                 "\"jwks_uri\":\"%s/jwks.json\","
                 "\"redirect_uris\":[\"https://client.example/callback\"]}",
                 stub.base, stub.base);
    } else if (stub.auth_method == METADATA_NONE) {
        snprintf(body, sizeof(body),
                 "{\"client_id\":\"%s/metadata.json\","
                 "\"token_endpoint_auth_method\":\"none\","
                 "\"jwks\":%s}",
                 stub.base, stub.jwks);
    } else if (stub.auth_method == METADATA_BROKEN) {
        return send_json(conn, 200, "not json at all");
    } else {
        snprintf(body, sizeof(body),
                 "{\"client_id\":\"%s/metadata.json\","
                 "\"token_endpoint_auth_method\":\"private_key_jwt\","
                 "\"jwks\":%s}",
                 stub.base, stub.jwks);
    }
    return send_json(conn, 200, body);
}

/* ------------------------------------------------------------------ */
/* Raw HTTP client                                                     */
/* ------------------------------------------------------------------ */

static int raw_post(const char *host, uint16_t port, const char *path,
                    const char *content_type, const char *body,
                    unsigned char **out_body, size_t *out_len,
                    long *out_status) {
    *out_body = NULL;
    *out_len = 0;
    *out_status = 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    char head[512];
    int hh = snprintf(head, sizeof(head),
                      "POST %s HTTP/1.1\r\nHost: %s:%u\r\n"
                      "Content-Type: %s\r\nContent-Length: %zu\r\n"
                      "Connection: close\r\n\r\n",
                      path, host, (unsigned)port, content_type, strlen(body));
    if (send(sock, head, (size_t)hh, 0) < 0 ||
        send(sock, body, strlen(body), 0) < 0) {
        close(sock);
        return -1;
    }

    size_t cap = 65536, got = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) {
        close(sock);
        return -1;
    }
    for (;;) {
        if (got == cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                close(sock);
                return -1;
            }
            buf = nb;
        }
        ssize_t n = recv(sock, buf + got, cap - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(sock);

    const char *sep = NULL;
    for (size_t i = 0; i + 3 < got; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
            buf[i + 3] == '\n') {
            sep = (const char *)&buf[i + 4];
            break;
        }
    }
    if (!sep) {
        free(buf);
        return -1;
    }
    sscanf((const char *)buf, "HTTP/%*s %ld", out_status);
    size_t blen = got - (size_t)(sep - (char *)buf);
    unsigned char *body_out = (unsigned char *)malloc(blen ? blen : 1);
    if (!body_out) {
        free(buf);
        return -1;
    }
    memcpy(body_out, sep, blen);
    *out_body = body_out;
    *out_len = blen;
    free(buf);
    return 0;
}

static char *urlencode(const char *in) {
    size_t n = strlen(in);
    char *out = malloc(n * 3 + 1);
    size_t w = 0;
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
            c == '~') {
            out[w++] = (char)c;
        } else {
            out[w++] = '%';
            out[w++] = hex[c >> 4];
            out[w++] = hex[c & 15];
        }
    }
    out[w] = '\0';
    return out;
}

static int has_bytes(const void *hay, size_t hay_len, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen) return 0;
    const unsigned char *h = (const unsigned char *)hay;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        if (memcmp(h + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

/* Seed a valid refresh token through the store. Refresh tokens rotate on use,
 * so each happy-path case needs its own; `seed` differentiates the PKCE
 * verifier. Returns a caller-owned refresh token. */
static char *seed_refresh(metalbear_oauth_store *store, const char *client_id,
                          const char *seed) {
    char verifier[128];
    snprintf(verifier, sizeof(verifier),
             "v3ry-long-test-verifier-with-enough-entropy-%s", seed);
    wf_oauth_pkce pkce = {0};
    if (wf_oauth_pkce_from_verifier(verifier, &pkce) != WF_OK) return NULL;
    metalbear_oauth_request req = {
        .client_id = client_id,
        .redirect_uri = "https://client.example/callback",
        .scope = "atproto",
        .state = "state-123",
        .code_challenge = pkce.challenge,
        .dpop_jkt = CLIENT_JKT,
    };
    char *request_uri = NULL, *code = NULL, *redirect_uri = NULL, *state = NULL;
    int64_t par_exp = 0;
    metalbear_oauth_grant grant = {0};
    if (metalbear_oauth_create_par(store, &req, &request_uri, &par_exp) !=
            WF_OK ||
        metalbear_oauth_authorize(store, request_uri, req.client_id,
                                  "did:plc:alice", &code, &redirect_uri,
                                  &state) != WF_OK ||
        metalbear_oauth_exchange_code(store, code, req.client_id,
                                      req.redirect_uri, pkce.verifier,
                                      req.dpop_jkt, &grant) != WF_OK) {
        free(request_uri);
        free(code);
        free(redirect_uri);
        free(state);
        return NULL;
    }
    free(request_uri);
    free(code);
    free(redirect_uri);
    free(state);
    return grant.refresh_token;
}

/* ------------------------------------------------------------------ */
/* Test                                                                */
/* ------------------------------------------------------------------ */

static int run(void) {
    int failures_before = wf_test_fail_count;

    /* Client key pair (the one the metadata jwks publishes). */
    EC_KEY *client_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    WF_CHECK(client_ec && EC_KEY_generate_key(client_ec) == 1);
    /* A second key that is NOT in the jwks (wrong-key test). */
    EC_KEY *other_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    WF_CHECK(other_ec && EC_KEY_generate_key(other_ec) == 1);

    char *jwk = client_jwk_json(client_ec, CLIENT_KID);
    WF_CHECK(jwk != NULL);

    /* Client metadata stub. */
    struct MHD_Daemon *stub_daemon =
        MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, 0, NULL, NULL,
                         metadata_handler, NULL, MHD_OPTION_END);
    WF_CHECK(stub_daemon != NULL);
    const union MHD_DaemonInfo *info =
        MHD_get_daemon_info(stub_daemon, MHD_DAEMON_INFO_BIND_PORT);
    WF_CHECK(info != NULL);
    snprintf(stub.base, sizeof(stub.base), "http://127.0.0.1:%u",
             (unsigned)info->port);
    char client_id[256];
    snprintf(client_id, sizeof(client_id), "%s/metadata.json", stub.base);
    snprintf(stub.jwks, sizeof(stub.jwks), "{\"keys\":[%s]}", jwk);
    stub.auth_method = METADATA_JWKS;

    /* OAuth store + server. */
    char path[] = "/tmp/metalbear-oauth-token-XXXXXX";
    int fd = mkstemp(path);
    WF_CHECK(fd >= 0);
    if (fd >= 0) close(fd);
    unlink(path);

    metalbear_oauth_store *store = NULL;
    WF_CHECK(metalbear_oauth_store_open(path, ISSUER, &store) == WF_OK);
    if (!store) {
        if (client_ec) EC_KEY_free(client_ec);
        if (other_ec) EC_KEY_free(other_ec);
        free(jwk);
        MHD_stop_daemon(stub_daemon);
        unlink(path);
        return wf_test_fail_count - failures_before;
    }

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 1);
    WF_CHECK(server != NULL);
    if (!server) {
        metalbear_oauth_store_free(store);
        if (client_ec) EC_KEY_free(client_ec);
        if (other_ec) EC_KEY_free(other_ec);
        free(jwk);
        MHD_stop_daemon(stub_daemon);
        unlink(path);
        return wf_test_fail_count - failures_before;
    }
    WF_CHECK(metalbear_oauth_routes_register(server, store, ISSUER, NULL, NULL,
                                             NULL, NULL) == WF_OK);

    uint16_t port = wf_xrpc_server_port(server);

    /* Seed a valid refresh token through the same store the server serves. */
    char *enc_cid = urlencode(client_id);
    char *refresh_token = seed_refresh(store, client_id, "assert-1");
    WF_CHECK(refresh_token != NULL);
    char *enc_rt = urlencode(refresh_token);

    int64_t now = (int64_t)time(NULL);
    unsigned char *body = NULL;
    size_t len = 0;
    long status = 0;
    char *assertion = NULL, *form = NULL;

    /* Happy path: assertion signed with the published key. */
    assertion = make_assertion(client_ec, CLIENT_KID, client_id, client_id,
                               ISSUER, "jti-ok-1", now, now + 60, NULL);
    WF_CHECK(assertion != NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_cid) + strlen(enc_rt) + strlen(enc_ass) + 200;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&client_id=%s"
                 "&dpop_jkt=%s"
                 "&client_assertion_type=urn:ietf:params:oauth:client-"
                 "assertion-type:jwt-bearer&client_assertion=%s",
                 enc_rt, enc_cid, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 200);
    WF_CHECK(body && has_bytes(body, len, "\"access_token\"") != NULL);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    /* Happy path via jwks_uri instead of inline jwks. Refresh tokens
     * rotate on use, so this case gets a freshly seeded one. */
    stub.auth_method = METADATA_JWKS_URI;
    free(refresh_token);
    free(enc_rt);
    refresh_token = seed_refresh(store, client_id, "assert-2");
    WF_CHECK(refresh_token != NULL);
    enc_rt = urlencode(refresh_token);
    assertion = make_assertion(client_ec, CLIENT_KID, client_id, client_id,
                               ISSUER, "jti-ok-2", now, now + 60, NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_cid) + strlen(enc_rt) + strlen(enc_ass) + 200;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&client_id=%s"
                 "&dpop_jkt=%s"
                 "&client_assertion_type=urn:ietf:params:oauth:client-"
                 "assertion-type:jwt-bearer&client_assertion=%s",
                 enc_rt, enc_cid, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 200);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    /* Wrong signing key: assertion signed by a key absent from the jwks. */
    stub.auth_method = METADATA_JWKS;
    assertion = make_assertion(other_ec, CLIENT_KID, client_id, client_id,
                               ISSUER, "jti-bad-1", now, now + 60, NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_cid) + strlen(enc_rt) + strlen(enc_ass) + 200;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&client_id=%s"
                 "&dpop_jkt=%s"
                 "&client_assertion_type=urn:ietf:params:oauth:client-"
                 "assertion-type:jwt-bearer&client_assertion=%s",
                 enc_rt, enc_cid, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 400);
    WF_CHECK(body && has_bytes(body, len, "invalid_client") != NULL);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    /* Wrong audience: assertion aimed at a different AS. */
    assertion = make_assertion(client_ec, CLIENT_KID, client_id, client_id,
                               "https://evil.example", "jti-bad-2", now,
                               now + 60, NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_cid) + strlen(enc_rt) + strlen(enc_ass) + 200;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&client_id=%s"
                 "&dpop_jkt=%s"
                 "&client_assertion_type=urn:ietf:params:oauth:client-"
                 "assertion-type:jwt-bearer&client_assertion=%s",
                 enc_rt, enc_cid, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 400);
    WF_CHECK(body && has_bytes(body, len, "invalid_client") != NULL);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    /* Metadata declares the client public ("none"): an assertion must
     * be refused rather than silently accepted. */
    stub.auth_method = METADATA_NONE;
    assertion = make_assertion(client_ec, CLIENT_KID, client_id, client_id,
                               ISSUER, "jti-bad-3", now, now + 60, NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_cid) + strlen(enc_rt) + strlen(enc_ass) + 200;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&client_id=%s"
                 "&dpop_jkt=%s"
                 "&client_assertion_type=urn:ietf:params:oauth:client-"
                 "assertion-type:jwt-bearer&client_assertion=%s",
                 enc_rt, enc_cid, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 400);
    WF_CHECK(body && has_bytes(body, len, "invalid_client") != NULL);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    /* Non-jwt-bearer assertion type. */
    stub.auth_method = METADATA_JWKS;
    assertion = make_assertion(client_ec, CLIENT_KID, client_id, client_id,
                               ISSUER, "jti-bad-4", now, now + 60, NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_cid) + strlen(enc_rt) + strlen(enc_ass) + 200;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&client_id=%s"
                 "&dpop_jkt=%s"
                 "&client_assertion_type=not-jwt-bearer"
                 "&client_assertion=%s",
                 enc_rt, enc_cid, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 400);
    WF_CHECK(body && has_bytes(body, len, "invalid_client") != NULL);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    /* Assertion with no client_id in the form. */
    assertion = make_assertion(client_ec, CLIENT_KID, client_id, client_id,
                               ISSUER, "jti-bad-5", now, now + 60, NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_rt) + strlen(enc_ass) + 200;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&dpop_jkt=%s"
                 "&client_assertion_type=urn:ietf:params:oauth:client-"
                 "assertion-type:jwt-bearer&client_assertion=%s",
                 enc_rt, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 400);
    WF_CHECK(body && has_bytes(body, len, "invalid_client") != NULL);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    /* A client_id that is not https and not loopback must be refused
     * before any fetch happens (SSRF). */
    assertion = make_assertion(client_ec, CLIENT_KID,
                               "http://169.254.169.254/latest/meta-data",
                               "http://169.254.169.254/latest/meta-data",
                               ISSUER, "jti-bad-6", now, now + 60, NULL);
    {
        char *enc_ass = urlencode(assertion);
        size_t fl = strlen(enc_rt) + strlen(enc_ass) + 400;
        form = malloc(fl);
        snprintf(form, fl,
                 "grant_type=refresh_token&refresh_token=%s&dpop_jkt=%s"
                 "&client_id=http://169.254.169.254/latest/meta-data"
                 "&client_assertion_type=urn:ietf:params:oauth:client-"
                 "assertion-type:jwt-bearer&client_assertion=%s",
                 enc_rt, CLIENT_JKT, enc_ass);
        free(enc_ass);
    }
    WF_CHECK(raw_post("127.0.0.1", port, "/oauth/token",
                      "application/x-www-form-urlencoded", form, &body, &len,
                      &status) == 0);
    WF_CHECK(status == 400);
    WF_CHECK(body && has_bytes(body, len, "invalid_client") != NULL);
    free(body);
    body = NULL;
    free(form);
    form = NULL;
    free(assertion);
    assertion = NULL;

    free(enc_cid);
    free(enc_rt);
    free(refresh_token);

    wf_xrpc_server_free(server);
    metalbear_oauth_store_free(store);
    MHD_stop_daemon(stub_daemon);
    EC_KEY_free(client_ec);
    EC_KEY_free(other_ec);
    free(jwk);
    unlink(path);
    char sidecar[256];
    snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
    unlink(sidecar);

    return wf_test_fail_count - failures_before;
}

int main(void) {
    run();
    WF_TEST_SUMMARY();
}

_Pragma("GCC diagnostic pop")

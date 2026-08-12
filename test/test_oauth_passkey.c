#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_oauth_passkey.c — end-to-end coverage for the /oauth/passkey routes
 * (src/oauth/oauth_routes.c) and their CBOR/crypto verification
 * (src/oauth/webauthn.c), driven the same way test_oauth_device_session.c
 * drives the plain password flow: a real metalbear_server_start instance,
 * real HTTP requests, no mocks.
 *
 * There is no real WebAuthn authenticator to hand this a browser, so this
 * file IS one: it CBOR-encodes attestationObject/authenticatorData and
 * ECDSA-signs assertions itself, the same bytes a real browser/authenticator
 * would produce, and drives the server exactly the way the frontend does
 * (see frontend/src/lib/webauthn.ts and pds.ts's passkey* functions).
 *
 * Covers:
 *   (a) registration succeeds and stores a passkey,
 *   (b) registration with the wrong challenge is refused,
 *   (c) registration without a device session for the target account is
 *       refused,
 *   (d) authentication succeeds, verifies the ES256 signature, and sets a
 *       device-session cookie,
 *   (e) authentication with a signature from the WRONG key is refused,
 *   (f) a challenge cannot be replayed,
 *   (g) list and remove work, and removal is scoped so one account cannot
 *       remove another's passkey.
 */

_Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

#include "metalbear/server.h"
#include "wolfram/oauth.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

        static int rmtree_remove_cb(const char *path, const struct stat *sb,
                                    int type, struct FTW *ftwbuf) {
    (void)sb;
    (void)type;
    (void)ftwbuf;
    return remove(path);
}
static void rmtree(const char *path) {
    nftw(path, rmtree_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* The server's public_url/OAuth issuer is derived from service_did
 * (did:web:pds.example.com -> https://pds.example.com; see
 * public_url_from_service_did in server.c), NOT the http://127.0.0.1:<port>
 * address this test actually talks to -- WebAuthn's origin check compares
 * against public_url, so every clientDataJSON this test builds must use
 * this, not `base`. */
#define TEST_ORIGIN "https://pds.example.com"

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ------------------------------------------------------------------ */
/* base64url + tiny growable buffer                                    */
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
    if (len > 0) EVP_EncodeBlock((unsigned char *)p, in, (int)len);
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

typedef struct buf {
    unsigned char *data;
    size_t len, cap;
} buf;
static void buf_push(buf *b, const unsigned char *bytes, size_t n) {
    if (b->len + n > b->cap) {
        size_t newcap = b->cap ? b->cap * 2 : 64;
        while (newcap < b->len + n) newcap *= 2;
        unsigned char *grown = realloc(b->data, newcap);
        if (!grown) return;
        b->data = grown;
        b->cap = newcap;
    }
    memcpy(b->data + b->len, bytes, n);
    b->len += n;
}
static void buf_byte(buf *b, unsigned char byte) {
    buf_push(b, &byte, 1);
}

/* ------------------------------------------------------------------ */
/* Minimal definite-length CBOR encoder -- just enough for a COSE EC2  */
/* P-256 key, authenticatorData, and a {fmt,attStmt,authData} map,     */
/* mirroring what src/oauth/webauthn.c parses.                         */
/* ------------------------------------------------------------------ */

static void cbor_uint(buf *b, uint64_t v) {
    if (v < 24)
        buf_byte(b, (unsigned char)v);
    else {
        buf_byte(b, 0x18);
        buf_byte(b, (unsigned char)v);
    }
}
static void cbor_negint_label(buf *b, int64_t v) {
    uint64_t arg = (uint64_t)(-1 - v);
    if (arg < 24)
        buf_byte(b, (unsigned char)(0x20 | arg));
    else {
        buf_byte(b, 0x38);
        buf_byte(b, (unsigned char)arg);
    }
}
static void cbor_bytes(buf *b, const unsigned char *data, size_t len) {
    if (len < 24)
        buf_byte(b, (unsigned char)(0x40 | len));
    else {
        buf_byte(b, 0x58);
        buf_byte(b, (unsigned char)len);
    }
    buf_push(b, data, len);
}
static void cbor_text(buf *b, const char *s) {
    size_t len = strlen(s);
    buf_byte(b, (unsigned char)(0x60 | len)); /* every string here is < 24 */
    buf_push(b, (const unsigned char *)s, len);
}
static void cbor_map_header(buf *b, size_t pairs) {
    buf_byte(b, (unsigned char)(0xA0 | pairs)); /* every map here is < 24 */
}

static void build_cose_p256_key(buf *out, const unsigned char x[32],
                                const unsigned char y[32]) {
    cbor_map_header(out, 5);
    cbor_uint(out, 1);
    cbor_uint(out, 2); /* kty: EC2 */
    cbor_uint(out, 3);
    cbor_negint_label(out, -7); /* alg: ES256 */
    cbor_negint_label(out, -1);
    cbor_uint(out, 1); /* crv: P-256 */
    cbor_negint_label(out, -2);
    cbor_bytes(out, x, 32); /* x */
    cbor_negint_label(out, -3);
    cbor_bytes(out, y, 32); /* y */
}

/* attested credential data appended only when x/y are non-NULL. */
static void build_auth_data(buf *out, const unsigned char rp_id_hash[32],
                            unsigned char flags, uint32_t sign_count,
                            const unsigned char *cred_id, size_t cred_id_len,
                            const unsigned char x[32],
                            const unsigned char y[32]) {
    buf_push(out, rp_id_hash, 32);
    buf_byte(out, flags);
    unsigned char sc[4] = {
        (unsigned char)(sign_count >> 24), (unsigned char)(sign_count >> 16),
        (unsigned char)(sign_count >> 8), (unsigned char)sign_count};
    buf_push(out, sc, 4);
    if (x && y) {
        unsigned char aaguid[16] = {0};
        buf_push(out, aaguid, 16);
        unsigned char idlen[2] = {(unsigned char)(cred_id_len >> 8),
                                  (unsigned char)cred_id_len};
        buf_push(out, idlen, 2);
        buf_push(out, cred_id, cred_id_len);
        build_cose_p256_key(out, x, y);
    }
}

static void build_attestation_object(buf *out, const unsigned char *auth_data,
                                     size_t auth_data_len) {
    cbor_map_header(out, 3);
    cbor_text(out, "fmt");
    cbor_text(out, "none");
    cbor_text(out, "attStmt");
    cbor_map_header(out, 0);
    cbor_text(out, "authData");
    cbor_bytes(out, auth_data, auth_data_len);
}

/* ------------------------------------------------------------------ */
/* Fake authenticator: a P-256 keypair this test signs with directly.  */
/* ------------------------------------------------------------------ */

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

/* DER-encoded ECDSA-Sig-Value, exactly what a real authenticator's
 * assertion.signature carries -- the server converts this back to raw r||s
 * itself (wf_crypto_ecdsa_der_to_raw). */
static unsigned char *der_sign(EC_KEY *ec, const unsigned char *msg,
                               size_t msg_len, size_t *out_len) {
    unsigned char digest[32];
    SHA256(msg, msg_len, digest);
    ECDSA_SIG *sig = ECDSA_do_sign(digest, sizeof(digest), ec);
    if (!sig) return NULL;
    int len = i2d_ECDSA_SIG(sig, NULL);
    unsigned char *der = len > 0 ? malloc((size_t)len) : NULL;
    unsigned char *p = der;
    if (der) len = i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    if (!der || len <= 0) {
        free(der);
        return NULL;
    }
    *out_len = (size_t)len;
    return der;
}

/* ------------------------------------------------------------------ */
/* HTTP helpers                                                        */
/* ------------------------------------------------------------------ */

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

static wf_status oauth_post(wf_xrpc_client *client, const char *base,
                            const char *path, const char *body,
                            const wf_http_header *extra, size_t extra_count,
                            wf_response *out) {
    char url[256];
    snprintf(url, sizeof(url), "%s%s", base, path);
    return wf_http_post(client, url, "application/json", body, extra,
                        extra_count, out);
}

static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *password, char *out_did,
                            size_t out_did_len) {
    char body[512];
    snprintf(
        body, sizeof(body),
        "{\"handle\":\"%s\",\"password\":\"%s\",\"email\":\"%s@example.com\"}",
        handle, password, handle);
    wf_response response = {0};
    if (wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                          &response) != WF_OK ||
        response.status != 200) {
        wf_response_free(&response);
        return NULL;
    }
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
    if (out_did && out_did_len && cJSON_IsString(did))
        snprintf(out_did, out_did_len, "%s", did->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

static char *extract_cookie_pair(const char *set_cookie) {
    if (!set_cookie) return NULL;
    const char *semi = strchr(set_cookie, ';');
    size_t len = semi ? (size_t)(semi - set_cookie) : strlen(set_cookie);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, set_cookie, len);
    out[len] = '\0';
    return out;
}

/* Sign in with a password and return the mb_device cookie pair. */
static char *device_signin(wf_xrpc_client *client, const char *base,
                           const char *handle, const char *password) {
    char body[256];
    snprintf(body, sizeof(body), "{\"identifier\":\"%s\",\"password\":\"%s\"}",
             handle, password);
    wf_response response = {0};
    if (oauth_post(client, base, "/oauth/signin", body, NULL, 0, &response) !=
            WF_OK ||
        response.status != 200 || !response.set_cookie) {
        wf_response_free(&response);
        return NULL;
    }
    char *cookie = extract_cookie_pair(response.set_cookie);
    wf_response_free(&response);
    return cookie;
}

int main(void) {
    char directory[] = "/tmp/metalbear-oauth-passkey-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .admin_password = "secret-admin",
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

    /* Declared up front, before any `goto done`, so the cleanup label below
     * never frees an uninitialized pointer on an early-exit path. */
    char *token = NULL, *other_token = NULL, *cookie = NULL,
         *other_cookie = NULL, *cred_id_b64 = NULL, *auth_device_cookie = NULL;
    EC_KEY *authenticator = NULL;

    char did[128] = "", other_did[128] = "";
    token = create_account(client, "alice.example.com", "alice-secret-pw", did,
                           sizeof(did));
    other_token = create_account(client, "bob.example.com", "bob-secret-pw",
                                 other_did, sizeof(other_did));
    CHECK(token != NULL);
    CHECK(other_token != NULL);
    if (!token || !other_token) goto done;

    cookie =
        device_signin(client, base, "alice.example.com", "alice-secret-pw");
    CHECK(cookie != NULL);
    other_cookie =
        device_signin(client, base, "bob.example.com", "bob-secret-pw");
    CHECK(other_cookie != NULL);
    if (!cookie || !other_cookie) goto done;

    authenticator = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    CHECK(authenticator && EC_KEY_generate_key(authenticator) == 1);
    unsigned char pub_x[32], pub_y[32];
    CHECK(pub_coords(authenticator, pub_x, pub_y) == WF_OK);
    unsigned char cred_id[16];
    CHECK(RAND_bytes(cred_id, sizeof(cred_id)) == 1);
    cred_id_b64 = b64url(cred_id, sizeof(cred_id));

    char rp_id[128] = "";
    char passkey_id[512] = "";
    wf_response response = {0};

    /* ---- (c) registration without a device session for the target account
     * ------------------------------------------------------------------ */
    {
        char body[128];
        snprintf(body, sizeof(body), "{\"did\":\"%s\"}", did);
        CHECK(oauth_post(client, base, "/oauth/passkey/register/options", body,
                         NULL, 0, &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);
    }

    /* ---- (a) registration succeeds ---------------------------------- */
    {
        wf_http_header hdr = {"Cookie", cookie};
        char body[128];
        snprintf(body, sizeof(body), "{\"did\":\"%s\"}", did);
        CHECK(oauth_post(client, base, "/oauth/passkey/register/options", body,
                         &hdr, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *opts = json_response(&response);
        cJSON *challenge = cJSON_GetObjectItemCaseSensitive(opts, "challenge");
        cJSON *rp = cJSON_GetObjectItemCaseSensitive(opts, "rp");
        cJSON *rp_id_j = rp ? cJSON_GetObjectItemCaseSensitive(rp, "id") : NULL;
        CHECK(cJSON_IsString(challenge));
        CHECK(cJSON_IsString(rp_id_j));
        if (cJSON_IsString(rp_id_j))
            snprintf(rp_id, sizeof(rp_id), "%s", rp_id_j->valuestring);

        char client_data_json[512];
        snprintf(client_data_json, sizeof(client_data_json),
                 "{\"type\":\"webauthn.create\",\"challenge\":\"%s\","
                 "\"origin\":\"%s\",\"crossOrigin\":false}",
                 cJSON_IsString(challenge) ? challenge->valuestring : "",
                 TEST_ORIGIN);
        char *client_data_b64 = b64url((const unsigned char *)client_data_json,
                                       strlen(client_data_json));

        unsigned char rp_id_hash[32];
        SHA256((const unsigned char *)rp_id, strlen(rp_id), rp_id_hash);
        buf auth_data = {0};
        build_auth_data(&auth_data, rp_id_hash, 0x41 /* UP|AT */, 0, cred_id,
                        sizeof(cred_id), pub_x, pub_y);
        buf attestation = {0};
        build_attestation_object(&attestation, auth_data.data, auth_data.len);
        char *attestation_b64 = b64url(attestation.data, attestation.len);

        char verify_body[2048];
        snprintf(verify_body, sizeof(verify_body),
                 "{\"did\":\"%s\",\"name\":\"Test Authenticator\","
                 "\"response\":{\"clientDataJSON\":\"%s\","
                 "\"attestationObject\":\"%s\"}}",
                 did, client_data_b64, attestation_b64);
        wf_response verify_resp = {0};
        oauth_post(client, base, "/oauth/passkey/register/verify", verify_body,
                   &hdr, 1, &verify_resp);
        if (verify_resp.status != 200)
            fprintf(stderr, "DEBUG register/verify status=%ld body=%.*s\n",
                    verify_resp.status, (int)verify_resp.body_len,
                    verify_resp.body ? verify_resp.body : "");
        CHECK(verify_resp.status == 200);

        cJSON_Delete(opts);
        free(client_data_b64);
        free(auth_data.data);
        free(attestation.data);
        free(attestation_b64);
        wf_response_free(&response);
        wf_response_free(&verify_resp);
    }

    /* ---- (b) registration with the wrong challenge is refused -------- */
    {
        wf_http_header hdr = {"Cookie", cookie};
        char client_data_json[512];
        snprintf(client_data_json, sizeof(client_data_json),
                 "{\"type\":\"webauthn.create\",\"challenge\":\"not-a-real-"
                 "challenge\",\"origin\":\"%s\",\"crossOrigin\":false}",
                 TEST_ORIGIN);
        char *client_data_b64 = b64url((const unsigned char *)client_data_json,
                                       strlen(client_data_json));

        unsigned char rp_id_hash[32];
        SHA256((const unsigned char *)rp_id, strlen(rp_id), rp_id_hash);
        unsigned char cred_id2[16];
        RAND_bytes(cred_id2, sizeof(cred_id2));
        buf auth_data = {0};
        build_auth_data(&auth_data, rp_id_hash, 0x41, 0, cred_id2,
                        sizeof(cred_id2), pub_x, pub_y);
        buf attestation = {0};
        build_attestation_object(&attestation, auth_data.data, auth_data.len);
        char *attestation_b64 = b64url(attestation.data, attestation.len);

        char verify_body[1024];
        snprintf(verify_body, sizeof(verify_body),
                 "{\"did\":\"%s\",\"response\":{\"clientDataJSON\":\"%s\","
                 "\"attestationObject\":\"%s\"}}",
                 did, client_data_b64, attestation_b64);
        wf_response verify_resp = {0};
        CHECK(oauth_post(client, base, "/oauth/passkey/register/verify",
                         verify_body, &hdr, 1, &verify_resp) == WF_ERR_HTTP);
        CHECK(verify_resp.status == 401);

        free(client_data_b64);
        free(auth_data.data);
        free(attestation.data);
        free(attestation_b64);
        wf_response_free(&verify_resp);
    }

    /* ---- (d) authentication succeeds and sets a device session ------- */
    {
        char body[128];
        snprintf(body, sizeof(body), "{\"identifier\":\"alice.example.com\"}");
        CHECK(oauth_post(client, base, "/oauth/passkey/authenticate/options",
                         body, NULL, 0, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *opts = json_response(&response);
        cJSON *available = cJSON_GetObjectItemCaseSensitive(opts, "available");
        CHECK(cJSON_IsTrue(available));
        cJSON *challenge = cJSON_GetObjectItemCaseSensitive(opts, "challenge");
        CHECK(cJSON_IsString(challenge));

        char client_data_json[512];
        snprintf(client_data_json, sizeof(client_data_json),
                 "{\"type\":\"webauthn.get\",\"challenge\":\"%s\","
                 "\"origin\":\"%s\",\"crossOrigin\":false}",
                 cJSON_IsString(challenge) ? challenge->valuestring : "",
                 TEST_ORIGIN);
        char *client_data_b64 = b64url((const unsigned char *)client_data_json,
                                       strlen(client_data_json));
        unsigned char client_data_hash[32];
        SHA256((const unsigned char *)client_data_json,
               strlen(client_data_json), client_data_hash);

        unsigned char rp_id_hash[32];
        SHA256((const unsigned char *)rp_id, strlen(rp_id), rp_id_hash);
        buf auth_data = {0};
        build_auth_data(&auth_data, rp_id_hash, 0x01 /* UP only */, 1, NULL, 0,
                        NULL, NULL);
        char *auth_data_b64 = b64url(auth_data.data, auth_data.len);

        buf signed_data = {0};
        buf_push(&signed_data, auth_data.data, auth_data.len);
        buf_push(&signed_data, client_data_hash, sizeof(client_data_hash));
        size_t sig_len = 0;
        unsigned char *sig = der_sign(authenticator, signed_data.data,
                                      signed_data.len, &sig_len);
        CHECK(sig != NULL);
        char *sig_b64 = sig ? b64url(sig, sig_len) : NULL;

        char verify_body[2048];
        snprintf(verify_body, sizeof(verify_body),
                 "{\"id\":\"%s\",\"response\":{\"clientDataJSON\":\"%s\","
                 "\"authenticatorData\":\"%s\",\"signature\":\"%s\"}}",
                 cred_id_b64, client_data_b64, auth_data_b64,
                 sig_b64 ? sig_b64 : "");
        wf_response verify_resp = {0};
        CHECK(oauth_post(client, base, "/oauth/passkey/authenticate/verify",
                         verify_body, NULL, 0, &verify_resp) == WF_OK);
        CHECK(verify_resp.status == 200);
        CHECK(verify_resp.set_cookie != NULL);
        CHECK(verify_resp.set_cookie &&
              strstr(verify_resp.set_cookie, "mb_device="));
        if (verify_resp.set_cookie)
            auth_device_cookie = extract_cookie_pair(verify_resp.set_cookie);

        /* ---- (f) the same challenge cannot be replayed ---------------- */
        wf_response replay_resp = {0};
        CHECK(oauth_post(client, base, "/oauth/passkey/authenticate/verify",
                         verify_body, NULL, 0, &replay_resp) == WF_ERR_HTTP);
        CHECK(replay_resp.status == 401);

        cJSON_Delete(opts);
        free(client_data_b64);
        free(auth_data.data);
        free(auth_data_b64);
        free(signed_data.data);
        free(sig);
        free(sig_b64);
        wf_response_free(&response);
        wf_response_free(&verify_resp);
        wf_response_free(&replay_resp);
    }
    CHECK(auth_device_cookie != NULL);

    /* ---- (e) a signature from the wrong key is refused ---------------- */
    {
        char body[128];
        snprintf(body, sizeof(body), "{\"identifier\":\"alice.example.com\"}");
        wf_response opts_resp = {0};
        CHECK(oauth_post(client, base, "/oauth/passkey/authenticate/options",
                         body, NULL, 0, &opts_resp) == WF_OK);
        cJSON *opts = json_response(&opts_resp);
        cJSON *challenge = cJSON_GetObjectItemCaseSensitive(opts, "challenge");

        char client_data_json[512];
        snprintf(client_data_json, sizeof(client_data_json),
                 "{\"type\":\"webauthn.get\",\"challenge\":\"%s\","
                 "\"origin\":\"%s\",\"crossOrigin\":false}",
                 cJSON_IsString(challenge) ? challenge->valuestring : "",
                 TEST_ORIGIN);
        char *client_data_b64 = b64url((const unsigned char *)client_data_json,
                                       strlen(client_data_json));
        unsigned char client_data_hash[32];
        SHA256((const unsigned char *)client_data_json,
               strlen(client_data_json), client_data_hash);
        unsigned char rp_id_hash[32];
        SHA256((const unsigned char *)rp_id, strlen(rp_id), rp_id_hash);
        buf auth_data = {0};
        build_auth_data(&auth_data, rp_id_hash, 0x01, 2, NULL, 0, NULL, NULL);
        char *auth_data_b64 = b64url(auth_data.data, auth_data.len);
        buf signed_data = {0};
        buf_push(&signed_data, auth_data.data, auth_data.len);
        buf_push(&signed_data, client_data_hash, sizeof(client_data_hash));

        /* Signed by an unrelated key, never registered. */
        EC_KEY *wrong_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(wrong_key);
        size_t sig_len = 0;
        unsigned char *sig =
            der_sign(wrong_key, signed_data.data, signed_data.len, &sig_len);
        char *sig_b64 = sig ? b64url(sig, sig_len) : NULL;

        char verify_body[2048];
        snprintf(verify_body, sizeof(verify_body),
                 "{\"id\":\"%s\",\"response\":{\"clientDataJSON\":\"%s\","
                 "\"authenticatorData\":\"%s\",\"signature\":\"%s\"}}",
                 cred_id_b64, client_data_b64, auth_data_b64,
                 sig_b64 ? sig_b64 : "");
        wf_response verify_resp = {0};
        CHECK(oauth_post(client, base, "/oauth/passkey/authenticate/verify",
                         verify_body, NULL, 0, &verify_resp) == WF_ERR_HTTP);
        CHECK(verify_resp.status == 401);

        EC_KEY_free(wrong_key);
        cJSON_Delete(opts);
        free(client_data_b64);
        free(auth_data.data);
        free(auth_data_b64);
        free(signed_data.data);
        free(sig);
        free(sig_b64);
        wf_response_free(&opts_resp);
        wf_response_free(&verify_resp);
    }

    /* ---- (g) list, and removal scoped to the owning account ----------- */
    {
        char url[256];
        snprintf(url, sizeof(url), "%s/oauth/passkey/list?did=%s", base, did);
        wf_http_header hdr = {"Cookie", cookie};
        wf_response list_resp = {0};
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &list_resp) ==
              WF_OK);
        CHECK(list_resp.status == 200);
        cJSON *body = json_response(&list_resp);
        cJSON *passkeys = cJSON_GetObjectItemCaseSensitive(body, "passkeys");
        CHECK(cJSON_IsArray(passkeys) && cJSON_GetArraySize(passkeys) == 1);
        cJSON *first = cJSON_GetArrayItem(passkeys, 0);
        cJSON *id =
            first ? cJSON_GetObjectItemCaseSensitive(first, "id") : NULL;
        CHECK(cJSON_IsString(id));
        if (cJSON_IsString(id))
            snprintf(passkey_id, sizeof(passkey_id), "%s", id->valuestring);
        cJSON_Delete(body);
        wf_response_free(&list_resp);

        /* bob cannot remove alice's passkey */
        char remove_body[512];
        snprintf(remove_body, sizeof(remove_body),
                 "{\"did\":\"%s\",\"id\":\"%s\"}", did, passkey_id);
        wf_http_header other_hdr = {"Cookie", other_cookie};
        wf_response bad_remove = {0};
        CHECK(oauth_post(client, base, "/oauth/passkey/remove", remove_body,
                         &other_hdr, 1, &bad_remove) == WF_ERR_HTTP);
        CHECK(bad_remove.status == 401);
        wf_response_free(&bad_remove);

        wf_response good_remove = {0};
        CHECK(oauth_post(client, base, "/oauth/passkey/remove", remove_body,
                         &hdr, 1, &good_remove) == WF_OK);
        CHECK(good_remove.status == 200);
        wf_response_free(&good_remove);

        wf_response list_after = {0};
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &list_after) ==
              WF_OK);
        cJSON *after_body = json_response(&list_after);
        cJSON *after_passkeys =
            cJSON_GetObjectItemCaseSensitive(after_body, "passkeys");
        CHECK(cJSON_IsArray(after_passkeys) &&
              cJSON_GetArraySize(after_passkeys) == 0);
        cJSON_Delete(after_body);
        wf_response_free(&list_after);
    }

done:
    free(cred_id_b64);
    if (authenticator) EC_KEY_free(authenticator);
    free(auth_device_cookie);
    free(cookie);
    free(other_cookie);
    free(token);
    free(other_token);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_oauth_passkey: OK\n");
    return 0;
}

_Pragma("GCC diagnostic pop")

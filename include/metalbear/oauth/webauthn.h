#ifndef METALBEAR_OAUTH_WEBAUTHN_H
#define METALBEAR_OAUTH_WEBAUTHN_H

/*
 * Parsing for the CBOR structures a browser's WebAuthn implementation
 * hands the server during passkey registration/authentication: the
 * attestationObject (registration) and authenticatorData (both
 * ceremonies), including the embedded COSE_Key public key.
 *
 * A purpose-built minimal parser rather than wolfram's wf_cbor_parse:
 * that decoder enforces DAG-CBOR's canonical map-key ordering, which is a
 * real invariant for repo commits this SDK itself produces, but not one
 * the WebAuthn spec places on a browser's attestationObject encoding.
 * Rejecting anything the browser encodes with fmt/attStmt/authData in a
 * different map order would fail registration unpredictably per browser.
 * These parsers are tolerant of key order for exactly that reason.
 *
 * Every function here parses bytes from an unauthenticated HTTP request
 * body (the authentication ceremony is reached pre-login) -- every read is
 * bounds-checked against the supplied length.
 */

#include <stddef.h>
#include <stdint.h>

#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* authenticatorData.flags bits (WebAuthn §6.1). */
#define METALBEAR_WEBAUTHN_FLAG_UP 0x01u /* user present */
#define METALBEAR_WEBAUTHN_FLAG_UV 0x04u /* user verified */
/* attested credential data present */
#define METALBEAR_WEBAUTHN_FLAG_AT 0x40u

typedef struct metalbear_webauthn_p256_key {
    unsigned char x[32];
    unsigned char y[32];
} metalbear_webauthn_p256_key;

/* Parsed authenticatorData, registration ceremony (attested credential data
 * present). *out's credential_id is heap-allocated; free with
 * metalbear_webauthn_attested_credential_free. */
typedef struct metalbear_webauthn_attested_credential {
    unsigned char rp_id_hash[32];
    unsigned char flags;
    uint32_t sign_count;
    unsigned char *credential_id;
    size_t credential_id_len;
    metalbear_webauthn_p256_key public_key;
} metalbear_webauthn_attested_credential;

void metalbear_webauthn_attested_credential_free(
    metalbear_webauthn_attested_credential *cred);

/*
 * Parse authenticatorData bytes that include attested credential data (the
 * AT flag set, as produced during registration) and a P-256 COSE_Key.
 * WF_ERR_PARSE on any malformed, truncated, or non-EC2/non-P-256 input.
 */
wf_status metalbear_webauthn_parse_registration_auth_data(
    const unsigned char *data, size_t len,
    metalbear_webauthn_attested_credential *out);

/*
 * Parse authenticatorData bytes without attested credential data (the
 * authentication ceremony) -- just the fixed 37-byte rpIdHash/flags/
 * signCount prefix; any attested-credential-data or extensions bytes that
 * follow are ignored. WF_ERR_PARSE if the buffer is shorter than 37 bytes.
 */
wf_status metalbear_webauthn_parse_assertion_auth_data(
    const unsigned char *data, size_t len, unsigned char rp_id_hash_out[32],
    unsigned char *flags_out, uint32_t *sign_count_out);

/*
 * Extract the raw authData byte string from a CBOR attestationObject
 * ({fmt, attStmt, authData}). attStmt's contents are structurally skipped,
 * not interpreted -- registration only ever requests "none" attestation
 * (see webauthn.c), so there is nothing in attStmt worth verifying.
 * *out_auth_data points into `data` (no copy); valid only as long as `data`
 * is. WF_ERR_PARSE on any malformed input or a missing authData key.
 */
wf_status metalbear_webauthn_parse_attestation_object(
    const unsigned char *data, size_t len, const unsigned char **out_auth_data,
    size_t *out_auth_data_len);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_OAUTH_WEBAUTHN_H */

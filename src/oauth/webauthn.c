#include "metalbear/oauth/webauthn.h"

#include <stdlib.h>
#include <string.h>

/*
 * Minimal CBOR reader, scoped to exactly what attestationObject/
 * authenticatorData/COSE_Key need: definite-length maps, arrays, byte
 * strings, text strings, and small integers. No indefinite-length items, no
 * floats, no tags -- none of those appear in these structures, and
 * rejecting them outright is simpler and safer than a general decoder for
 * bytes that come from an unauthenticated client.
 */

#define WEBAUTHN_CBOR_MAX_DEPTH 32

/* Read one CBOR item's major type (0-7) and argument (the length/count/
 * direct-value payload of its initial byte, per RFC 8949 §3). Advances
 * *pos past the head (and, for major types 0/1/7, that IS the whole item).
 * Rejects reserved additional-info values and indefinite length (28-31). */
static wf_status read_head(const unsigned char *data, size_t len, size_t *pos,
                           unsigned *major_type, uint64_t *argument) {
    if (*pos >= len) return WF_ERR_PARSE;
    unsigned char initial = data[*pos];
    unsigned mt = (unsigned)(initial >> 5);
    unsigned info = (unsigned)(initial & 0x1f);
    size_t p = *pos + 1;
    uint64_t arg;
    if (info < 24) {
        arg = info;
    } else if (info == 24) {
        if (p + 1 > len) return WF_ERR_PARSE;
        arg = data[p];
        p += 1;
    } else if (info == 25) {
        if (p + 2 > len) return WF_ERR_PARSE;
        arg = ((uint64_t)data[p] << 8) | data[p + 1];
        p += 2;
    } else if (info == 26) {
        if (p + 4 > len) return WF_ERR_PARSE;
        arg = ((uint64_t)data[p] << 24) | ((uint64_t)data[p + 1] << 16) |
              ((uint64_t)data[p + 2] << 8) | data[p + 3];
        p += 4;
    } else if (info == 27) {
        if (p + 8 > len) return WF_ERR_PARSE;
        arg = 0;
        for (int i = 0; i < 8; i++) arg = (arg << 8) | data[p + i];
        p += 8;
    } else {
        return WF_ERR_PARSE; /* 28-30 reserved, 31 indefinite: unsupported */
    }
    *major_type = mt;
    *argument = arg;
    *pos = p;
    return WF_OK;
}

/* Skip one full CBOR value of any type (used to walk past map/array
 * entries this code does not care about). Recurses for arrays/maps/tags,
 * bounded by WEBAUTHN_CBOR_MAX_DEPTH against maliciously deep nesting. */
static wf_status skip_value(const unsigned char *data, size_t len, size_t *pos,
                            int depth) {
    if (depth > WEBAUTHN_CBOR_MAX_DEPTH) return WF_ERR_PARSE;
    unsigned mt;
    uint64_t arg;
    wf_status status = read_head(data, len, pos, &mt, &arg);
    if (status != WF_OK) return status;
    switch (mt) {
        case 0: /* unsigned int */
        case 1: /* negative int */
        case 7: /* simple/float -- fully consumed by read_head */
            return WF_OK;
        case 2: /* byte string */
        case 3: /* text string */
            if (arg > (uint64_t)(len - *pos)) return WF_ERR_PARSE;
            *pos += (size_t)arg;
            return WF_OK;
        case 4: /* array: arg items */
            for (uint64_t i = 0; i < arg; i++) {
                status = skip_value(data, len, pos, depth + 1);
                if (status != WF_OK) return status;
            }
            return WF_OK;
        case 5: /* map: arg key+value pairs */
            for (uint64_t i = 0; i < arg; i++) {
                status = skip_value(data, len, pos, depth + 1);
                if (status != WF_OK) return status;
                status = skip_value(data, len, pos, depth + 1);
                if (status != WF_OK) return status;
            }
            return WF_OK;
        case 6: /* tag: one tagged item follows */
            return skip_value(data, len, pos, depth + 1);
        default:
            return WF_ERR_PARSE;
    }
}

/* Parse a COSE_Key CBOR map (RFC 9053) at *pos, requiring kty=2 (EC2) and
 * crv=1 (P-256), capturing the x/y coordinates (COSE labels -2/-3). Any
 * other key in the map (alg, key_ops, ...) is skipped, not validated --
 * kty+crv already pin the curve, and this server only ever verifies with
 * wf_crypto_p256_verify_allow_malleable regardless of a declared alg. */
static wf_status parse_cose_p256_key(const unsigned char *data, size_t len,
                                     size_t *pos,
                                     metalbear_webauthn_p256_key *out) {
    unsigned mt;
    uint64_t pair_count;
    wf_status status = read_head(data, len, pos, &mt, &pair_count);
    if (status != WF_OK || mt != 5) return WF_ERR_PARSE;

    int have_x = 0, have_y = 0, have_kty = 0, have_crv = 0;
    for (uint64_t i = 0; i < pair_count; i++) {
        unsigned key_mt;
        uint64_t key_arg;
        status = read_head(data, len, pos, &key_mt, &key_arg);
        if (status != WF_OK || (key_mt != 0 && key_mt != 1))
            return WF_ERR_PARSE;
        /* CBOR negative-int argument N encodes the value -(1+N); COSE
         * labels -1/-2/-3 are (major type 1, argument 0/1/2). */
        int64_t key = key_mt == 0 ? (int64_t)key_arg : -(int64_t)(1 + key_arg);

        if (key == -2 || key == -3) {
            unsigned val_mt;
            uint64_t val_len;
            status = read_head(data, len, pos, &val_mt, &val_len);
            if (status != WF_OK || val_mt != 2 || val_len != 32)
                return WF_ERR_PARSE;
            if (32 > len - *pos) return WF_ERR_PARSE;
            memcpy(key == -2 ? out->x : out->y, data + *pos, 32);
            *pos += 32;
            if (key == -2)
                have_x = 1;
            else
                have_y = 1;
        } else if (key == 1) { /* kty: must be EC2 (2) */
            unsigned val_mt;
            uint64_t val;
            status = read_head(data, len, pos, &val_mt, &val);
            if (status != WF_OK || val_mt != 0 || val != 2) return WF_ERR_PARSE;
            have_kty = 1;
        } else if (key == -1) { /* crv: must be P-256 (1) */
            unsigned val_mt;
            uint64_t val;
            status = read_head(data, len, pos, &val_mt, &val);
            if (status != WF_OK || val_mt != 0 || val != 1) return WF_ERR_PARSE;
            have_crv = 1;
        } else {
            status = skip_value(data, len, pos, 0);
            if (status != WF_OK) return status;
        }
    }
    if (!have_x || !have_y || !have_kty || !have_crv) return WF_ERR_PARSE;
    return WF_OK;
}

void metalbear_webauthn_attested_credential_free(
    metalbear_webauthn_attested_credential *cred) {
    if (!cred) return;
    free(cred->credential_id);
    cred->credential_id = NULL;
    cred->credential_id_len = 0;
}

wf_status metalbear_webauthn_parse_registration_auth_data(
    const unsigned char *data, size_t len,
    metalbear_webauthn_attested_credential *out) {
    if (!data || !out) return WF_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (len < 37) return WF_ERR_PARSE;

    memcpy(out->rp_id_hash, data, 32);
    out->flags = data[32];
    out->sign_count = ((uint32_t)data[33] << 24) | ((uint32_t)data[34] << 16) |
                      ((uint32_t)data[35] << 8) | data[36];
    if (!(out->flags & METALBEAR_WEBAUTHN_FLAG_AT)) return WF_ERR_PARSE;

    size_t pos = 37;
    if (pos + 16 + 2 > len) return WF_ERR_PARSE;
    pos += 16; /* aaguid: not verified -- "none" attestation trusts no AAGUID */
    uint16_t credential_id_len =
        (uint16_t)(((uint16_t)data[pos] << 8) | data[pos + 1]);
    pos += 2;
    if ((size_t)credential_id_len > len - pos) return WF_ERR_PARSE;

    out->credential_id = malloc(credential_id_len ? credential_id_len : 1);
    if (!out->credential_id) return WF_ERR_ALLOC;
    memcpy(out->credential_id, data + pos, credential_id_len);
    out->credential_id_len = credential_id_len;
    pos += credential_id_len;

    wf_status status = parse_cose_p256_key(data, len, &pos, &out->public_key);
    if (status != WF_OK) {
        metalbear_webauthn_attested_credential_free(out);
        return status;
    }
    return WF_OK;
}

wf_status metalbear_webauthn_parse_assertion_auth_data(
    const unsigned char *data, size_t len, unsigned char rp_id_hash_out[32],
    unsigned char *flags_out, uint32_t *sign_count_out) {
    if (!data || !rp_id_hash_out || !flags_out || !sign_count_out)
        return WF_ERR_INVALID_ARG;
    if (len < 37) return WF_ERR_PARSE;
    memcpy(rp_id_hash_out, data, 32);
    *flags_out = data[32];
    *sign_count_out = ((uint32_t)data[33] << 24) | ((uint32_t)data[34] << 16) |
                      ((uint32_t)data[35] << 8) | data[36];
    return WF_OK;
}

wf_status metalbear_webauthn_parse_attestation_object(
    const unsigned char *data, size_t len, const unsigned char **out_auth_data,
    size_t *out_auth_data_len) {
    if (!data || !out_auth_data || !out_auth_data_len)
        return WF_ERR_INVALID_ARG;
    *out_auth_data = NULL;
    *out_auth_data_len = 0;

    size_t pos = 0;
    unsigned mt;
    uint64_t pair_count;
    wf_status status = read_head(data, len, &pos, &mt, &pair_count);
    if (status != WF_OK || mt != 5) return WF_ERR_PARSE;

    int found = 0;
    for (uint64_t i = 0; i < pair_count; i++) {
        unsigned key_mt;
        uint64_t key_len;
        status = read_head(data, len, &pos, &key_mt, &key_len);
        if (status != WF_OK || key_mt != 3) return WF_ERR_PARSE;
        if (key_len > (uint64_t)(len - pos)) return WF_ERR_PARSE;
        const unsigned char *key_ptr = data + pos;
        pos += (size_t)key_len;

        if (key_len == 8 && memcmp(key_ptr, "authData", 8) == 0) {
            unsigned val_mt;
            uint64_t val_len;
            status = read_head(data, len, &pos, &val_mt, &val_len);
            if (status != WF_OK || val_mt != 2) return WF_ERR_PARSE;
            if (val_len > (uint64_t)(len - pos)) return WF_ERR_PARSE;
            *out_auth_data = data + pos;
            *out_auth_data_len = (size_t)val_len;
            pos += (size_t)val_len;
            found = 1;
        } else {
            status = skip_value(data, len, &pos, 0);
            if (status != WF_OK) return status;
        }
    }
    return found ? WF_OK : WF_ERR_PARSE;
}

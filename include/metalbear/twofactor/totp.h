#ifndef METALBEAR_TWOFACTOR_TOTP_H
#define METALBEAR_TWOFACTOR_TOTP_H

/* Primitives for two-factor login (docs/totp.md): TOTP codes (RFC 6238, the
 * SHA-1, 6-digit, 30-second form that authenticator apps use), base32 for
 * enrolment, the server key that protects stored secrets and backup codes,
 * and authenticated encryption of stored secrets. These do not touch the
 * database or the login path; that is built on top. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define METALBEAR_TOTP_SECRET_BYTES 20
#define METALBEAR_TOTP_STEP_SECONDS 30
#define METALBEAR_TOTP_DIGITS 6
#define METALBEAR_TWOFACTOR_KEY_BYTES 32
#define METALBEAR_BACKUP_CODE_BYTES 10
/* 10 bytes of base32 with no padding. */
#define METALBEAR_BACKUP_CODE_CHARS 16

/* RFC 4648 base32, upper case, no padding. The encoder needs
 * ((len + 4) / 5) * 8 + 1 bytes of output. The decoder accepts either case and
 * ignores spaces; it returns WF_ERR_INVALID_ARG for any other character. */
wf_status metalbear_base32_encode(const unsigned char *in, size_t in_len,
                                  char *out, size_t out_cap);
wf_status metalbear_base32_decode(const char *in, unsigned char *out,
                                  size_t out_cap, size_t *out_len);

/* A fresh TOTP secret from the system random source. */
wf_status
metalbear_totp_secret_new(unsigned char out[METALBEAR_TOTP_SECRET_BYTES]);

/* The 6-digit code for one 30-second step. */
wf_status metalbear_totp_code(const unsigned char *secret, size_t secret_len,
                              int64_t step, uint32_t *out_code);

/* Accepts a code for the step at unix_time, or for the step either side of it
 * (clock skew). A step at or before last_step is refused, so one code is
 * accepted once. On success *accepted_step is the step it matched. last_step
 * is -1 for an account that has never been used. */
bool metalbear_totp_verify(const unsigned char *secret, size_t secret_len,
                           uint32_t code, int64_t unix_time, int64_t last_step,
                           int64_t *accepted_step);

/* The server key that protects stored secrets and backup codes. Created on
 * first use with mode 0600 and 32 random bytes. Loading refuses a file that is
 * readable by group or others, or that is not exactly 32 bytes. */
wf_status metalbear_twofactor_key_load_or_create(
    const char *path, unsigned char out[METALBEAR_TWOFACTOR_KEY_BYTES]);

/* Authenticated encryption under the server key (AES-256-GCM). Output is a
 * 12-byte nonce, the ciphertext, and a 16-byte tag. *out is caller-owned. */
wf_status
metalbear_twofactor_seal(const unsigned char key[METALBEAR_TWOFACTOR_KEY_BYTES],
                         const unsigned char *plain, size_t plain_len,
                         unsigned char **out, size_t *out_len);
/* Fails with WF_ERR_INVALID_ARG when the tag does not verify, which covers a
 * wrong key and any change to the ciphertext. */
wf_status
metalbear_twofactor_open(const unsigned char key[METALBEAR_TWOFACTOR_KEY_BYTES],
                         const unsigned char *sealed, size_t sealed_len,
                         unsigned char **out, size_t *out_len);

/* A backup code: 10 random bytes, shown once as 16 base32 characters. */
wf_status metalbear_backup_code_new(char out[METALBEAR_BACKUP_CODE_CHARS + 1]);

/* The stored form of a backup code: HMAC-SHA-256 under the server key. Codes
 * are high-entropy, so a keyed hash is enough and is fast to check. */
wf_status metalbear_backup_code_hash(
    const unsigned char key[METALBEAR_TWOFACTOR_KEY_BYTES], const char *code,
    unsigned char out[32]);

#ifdef __cplusplus
}
#endif

#endif

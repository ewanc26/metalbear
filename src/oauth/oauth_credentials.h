#ifndef METALBEAR_OAUTH_CREDENTIALS_H
#define METALBEAR_OAUTH_CREDENTIALS_H

/* metalbear_oauth_subject_resolver / metalbear_oauth_credential_verifier
 * implementations (see metalbear/oauth/oauth_routes.h) handed to
 * metalbear_oauth_routes_register by server.c's metalbear_server_start. Not
 * part of the public API. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int resolve_oauth_subject(void *ctx, const char *hint, char *out,
                          size_t out_len);
int verify_oauth_credential(void *ctx, const char *identifier,
                            const char *password, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_OAUTH_CREDENTIALS_H */

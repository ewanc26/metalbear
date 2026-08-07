#ifndef METALBEAR_EMAIL_INTERNAL_H
#define METALBEAR_EMAIL_INTERNAL_H

/* Pieces of email.c exposed only so test_email_internal.c can exercise them
 * directly, without standing up a real TLS-capable SMTP server. Not part of
 * the public API (see metalbear/email.h for that). */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct email_body_reader {
    const char *cursor;
    size_t remaining;
} email_body_reader;

size_t email_read_body(char *buffer, size_t size, size_t nitems,
                       void *userdata);

void email_build_smtp_url(bool starttls, const char *host, char *out,
                          size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_EMAIL_INTERNAL_H */

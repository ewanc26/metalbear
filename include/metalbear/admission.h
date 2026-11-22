#ifndef METALBEAR_ADMISSION_H
#define METALBEAR_ADMISSION_H

/*
 * Per-domain signup admission. The policy is configuration only: no account
 * state and therefore no schema migration. Domains are comma-separated
 * suffixes including the leading dot, matching server.user_domain's
 * convention.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    METALBEAR_ADMISSION_OPEN,
    METALBEAR_ADMISSION_INVITE,
    METALBEAR_ADMISSION_CLOSED
} metalbear_admission_mode;

/* Parse "open", "invite" or "closed". */
bool metalbear_admission_parse_mode(const char *text,
                                    metalbear_admission_mode *out);

/* Validate a whole policy: known mode, dotted domains, no domain in two
 * lists. Writes a short reason into err when returning false. */
bool metalbear_admission_config_valid(const char *default_mode,
                                      const char *open_domains,
                                      const char *invite_domains,
                                      const char *closed_domains, char *err,
                                      unsigned long err_len);

/* Resolve the effective mode for a handle. The most specific matching list
 * wins; `fallback` applies when no list matches. */
metalbear_admission_mode metalbear_admission_for_handle(
    const char *handle, metalbear_admission_mode fallback,
    const char *open_domains, const char *invite_domains,
    const char *closed_domains);

#ifdef __cplusplus
}
#endif

#endif

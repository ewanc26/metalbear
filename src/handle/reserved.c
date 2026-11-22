/**
 * reserved.c -- reserved-handle labels at signup and handle update.
 *
 * See include/metalbear/handle/reserved.h for the public contract. The
 * label table is generated from the reference PDS's reserved.ts by
 * scripts/gen_reserved_handles.py.
 */

#include "metalbear/handle/reserved.h"

#include "reserved_internal.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int reserved_label_cmp(const void *key, const void *element) {
    const char *label = *(const char *const *)key;
    const char *candidate = *(const char *const *)element;
    return strcmp(label, candidate);
}

int metalbear_handle_is_reserved(const char *handle, const char *user_domain) {
    if (!handle || !handle[0] || !user_domain || !user_domain[0]) return 0;

    size_t handle_len = strlen(handle);
    size_t domain_len = strlen(user_domain);
    if (handle_len <= domain_len) return 0;

    /* The reference normalises the whole handle before comparing it with
     * the service domain, so fold both sides rather than just the label. */
    char *lower = malloc(handle_len + 1);
    char *domain = malloc(domain_len + 1);
    if (!lower || !domain) {
        free(lower);
        free(domain);
        return 0;
    }
    for (size_t i = 0; i < handle_len; i++) {
        lower[i] = (char)tolower((unsigned char)handle[i]);
    }
    lower[handle_len] = '\0';
    for (size_t i = 0; i < domain_len; i++) {
        domain[i] = (char)tolower((unsigned char)user_domain[i]);
    }
    domain[domain_len] = '\0';

    size_t label_len = handle_len - domain_len;
    int reserved = 0;
    if (strcmp(lower + label_len, domain) == 0 &&
        /* The reference compares the whole prefix left of the service
         * domain; a dotted prefix is never a reserved single label. */
        !memchr(lower, '.', label_len)) {
        /* Terminate the normalised handle at the label boundary: the table
         * holds bare labels, not full handles. */
        lower[label_len] = '\0';
        const char *key = lower;
        reserved = bsearch(&key, metalbear_reserved_labels,
                           metalbear_reserved_label_count,
                           sizeof(*metalbear_reserved_labels),
                           reserved_label_cmp) != NULL;
    }
    free(lower);
    free(domain);
    return reserved;
}

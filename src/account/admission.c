#include "metalbear/admission.h"

#include <stdio.h>
#include <string.h>

/* Iterate comma-separated suffix entries, trimming surrounding blanks. */
static const char *next_item(const char *list, size_t *out_len) {
    if (!list) {
        *out_len = 0;
        return NULL;
    }
    const char *p = list;
    while (*p == ' ' || *p == '\t' || *p == ',') p++;
    if (!*p) {
        *out_len = 0;
        return NULL;
    }
    const char *start = p;
    while (*p && *p != ',') p++;
    size_t len = (size_t)(p - start);
    while (len && (start[len - 1] == ' ' || start[len - 1] == '\t')) len--;
    /* A purely blank item is skipped. */
    if (!len) return next_item(p, out_len);
    *out_len = len;
    return start;
}

static bool list_contains(const char *list, const char *value, size_t len) {
    size_t item_len = 0;
    const char *item = list;
    while ((item = next_item(item, &item_len)) != NULL) {
        if (item_len == len && strncmp(item, value, len) == 0) return true;
        item += item_len;
    }
    return false;
}

bool metalbear_admission_parse_mode(const char *text,
                                    metalbear_admission_mode *out) {
    if (!text || !out) return false;
    if (strcmp(text, "open") == 0)
        *out = METALBEAR_ADMISSION_OPEN;
    else if (strcmp(text, "invite") == 0)
        *out = METALBEAR_ADMISSION_INVITE;
    else if (strcmp(text, "closed") == 0)
        *out = METALBEAR_ADMISSION_CLOSED;
    else
        return false;
    return true;
}

bool metalbear_admission_config_valid(const char *default_mode,
                                      const char *open_domains,
                                      const char *invite_domains,
                                      const char *closed_domains, char *err,
                                      unsigned long err_len) {
    metalbear_admission_mode mode;
    if (default_mode && default_mode[0] &&
        !metalbear_admission_parse_mode(default_mode, &mode)) {
        if (err && err_len)
            snprintf(err, (size_t)err_len,
                     "admission.default must be open, invite or closed");
        return false;
    }
    const char *lists[3] = {open_domains, invite_domains, closed_domains};
    const char *names[3] = {"admission.open_domains",
                            "admission.invite_domains",
                            "admission.closed_domains"};
    for (int i = 0; i < 3; i++) {
        size_t len = 0;
        const char *item = lists[i];
        while ((item = next_item(item, &len)) != NULL) {
            if (len < 2 || item[0] != '.') {
                if (err && err_len)
                    snprintf(err, (size_t)err_len,
                             "%s entries must be domain suffixes starting "
                             "with '.'",
                             names[i]);
                return false;
            }
            for (size_t j = 0; j < len; j++) {
                if (item[j] == ' ' || item[j] == '\t') {
                    if (err && err_len)
                        snprintf(err, (size_t)err_len,
                                 "%s entries must not contain whitespace",
                                 names[i]);
                    return false;
                }
            }
            for (int j = i + 1; j < 3; j++) {
                if (list_contains(lists[j], item, len)) {
                    if (err && err_len)
                        snprintf(err, (size_t)err_len,
                                 "%.*s appears in more than one admission "
                                 "list",
                                 (int)len, item);
                    return false;
                }
            }
            item += len;
        }
    }
    return true;
}

/* Best (longest) matching suffix in one list, or 0 when none matches. */
static size_t match_in_list(const char *handle, const char *list) {
    size_t best = 0;
    size_t handle_len = strlen(handle);
    size_t len = 0;
    const char *item = list;
    while ((item = next_item(item, &len)) != NULL) {
        if (len > 1 && handle_len > len &&
            strncmp(handle + handle_len - len, item, len) == 0 && len > best)
            best = len;
        item += len;
    }
    return best;
}

metalbear_admission_mode metalbear_admission_for_handle(
    const char *handle, metalbear_admission_mode fallback,
    const char *open_domains, const char *invite_domains,
    const char *closed_domains) {
    if (!handle) return fallback;
    size_t open = match_in_list(handle, open_domains);
    size_t invite = match_in_list(handle, invite_domains);
    size_t closed = match_in_list(handle, closed_domains);
    if (!open && !invite && !closed) return fallback;
    /* Longest suffix wins. Ties cannot occur for an identical suffix because
     * config validation rejects domains listed twice; keep a deterministic
     * deny-biased order anyway. */
    if (closed && closed >= invite && closed >= open)
        return METALBEAR_ADMISSION_CLOSED;
    if (invite && invite >= open) return METALBEAR_ADMISSION_INVITE;
    return METALBEAR_ADMISSION_OPEN;
}

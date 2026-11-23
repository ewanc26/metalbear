#include "metalbear/branding.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* A colour is either #RGB or #RRGGBB, nothing else. Keeping the grammar this
 * small means the frontend can drop the value straight into a CSS custom
 * property without escaping, and an operator cannot smuggle a declaration or
 * a url() into a stylesheet through config. */
bool metalbear_branding_color_valid(const char *value) {
    if (!value || !*value) return true; /* empty means unset */
    if (*value != '#') return false;
    size_t n = strlen(value + 1);
    if (n != 3 && n != 6) return false;
    for (size_t i = 1; i <= n; i++)
        if (!isxdigit((unsigned char)value[i])) return false;
    return true;
}

/* Same-origin paths and http(s) links are safe to put in an href/src. Anything
 * with a scheme other than http/https (javascript:, data:, ...) is refused; a
 * leading slash keeps this usable without an absolute URL. */
bool metalbear_branding_url_valid(const char *value) {
    if (!value || !*value) return true; /* empty means unset */
    if (*value == '/') {
        /* A path must not start with // either: that is a protocol-relative
         * URL, which would send users to a host the operator did not name. */
        if (value[1] == '/') return false;
    } else {
        const char *host = NULL;
        if (strncmp(value, "http://", 7) == 0)
            host = value + 7;
        else if (strncmp(value, "https://", 8) == 0)
            host = value + 8;
        else
            return false;
        if (!*host || *host == '/') return false;
    }
    /* These values end up in href/src attributes and a CSS url(); quotes,
     * parentheses, backslashes and whitespace would let a config escape either
     * context. Control characters are refused for the same reason. */
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p <= 0x20 || *p == 0x7f || *p == '"' || *p == '\'' || *p == '(' ||
            *p == ')' || *p == '\\')
            return false;
    }
    return true;
}

const char *metalbear_branding_or_default(const char *value,
                                          const char *fallback) {
    return (value && *value) ? value : fallback;
}

/* Relative luminance per WCAG 2.1. The six-digit value is parsed into three
 * 0..255 channels; short form is expanded by digit doubling. */
static bool parse_hex(const char *value, unsigned char rgb[3]) {
    if (!value || *value != '#') return false;
    size_t n = strlen(value + 1);
    if (n != 3 && n != 6) return false;
    if (n == 3) {
        for (size_t i = 0; i < 3; i++) {
            int d = -1;
            if (value[i + 1] >= '0' && value[i + 1] <= '9')
                d = value[i + 1] - '0';
            else if (tolower((unsigned char)value[i + 1]) >= 'a' &&
                     tolower((unsigned char)value[i + 1]) <= 'f')
                d = tolower((unsigned char)value[i + 1]) - 'a' + 10;
            if (d < 0) return false;
            rgb[i] = (unsigned char)(d * 17);
        }
        return true;
    }
    for (size_t i = 0; i < 3; i++) {
        char pair[3] = {value[1 + i * 2], value[2 + i * 2], 0};
        char *end = NULL;
        long v = strtol(pair, &end, 16);
        if (end != pair + 2) return false;
        rgb[i] = (unsigned char)v;
    }
    return true;
}

static double channel_luminance(unsigned char c) {
    double s = c / 255.0;
    return s <= 0.04045 ? s / 12.92 : pow((s + 0.055) / 1.055, 2.4);
}

const char *metalbear_branding_on_color(const char *background) {
    unsigned char rgb[3];
    if (!parse_hex(background, rgb)) return "#ffffff";
    double luminance = 0.2126 * channel_luminance(rgb[0]) +
                       0.7152 * channel_luminance(rgb[1]) +
                       0.0722 * channel_luminance(rgb[2]);
    return luminance > 0.4 ? "#0d1117" : "#ffffff";
}

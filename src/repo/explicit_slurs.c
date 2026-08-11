/**
 * explicit_slurs.c — explicit-slur detection for record keys.
 *
 * See include/metalbear/repo/explicit_slurs.h for the public contract.
 *
 * Compiled with PCRE2_UTF (the patterns' Unicode character classes must be
 * matched codepoint-by-codepoint, not byte-by-byte) but deliberately
 * WITHOUT PCRE2_UCP: the reference patterns are plain (non-`/u`-flagged)
 * JavaScript RegExp literals, whose `\b` word-boundary test only ever
 * treats `[A-Za-z0-9_]` as "word" characters regardless of what Unicode
 * text surrounds it. PCRE2_UCP would make `\b` Unicode-aware instead,
 * diverging from what the reference actually matches.
 */

#include "metalbear/repo/explicit_slurs.h"
#include "explicit_slurs_internal.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pcre2_code **g_compiled = NULL;
static atomic_flag g_init_lock = ATOMIC_FLAG_INIT;
static atomic_int g_init_state =
    0; /* 0 = not started, 1 = ready, -1 = failed */

static void explicit_slurs_compile_all(void) {
    size_t count = metalbear_explicit_slur_pattern_count;
    pcre2_code **compiled = calloc(count, sizeof(*compiled));
    if (!compiled) {
        atomic_store_explicit(&g_init_state, -1, memory_order_release);
        return;
    }
    for (size_t i = 0; i < count; i++) {
        int error_code = 0;
        PCRE2_SIZE error_offset = 0;
        compiled[i] = pcre2_compile(
            (PCRE2_SPTR)metalbear_explicit_slur_patterns[i],
            PCRE2_ZERO_TERMINATED, PCRE2_UTF, &error_code, &error_offset, NULL);
        if (!compiled[i]) {
            PCRE2_UCHAR error_buf[256];
            pcre2_get_error_message(error_code, error_buf, sizeof(error_buf));
            fprintf(stderr,
                    "explicit_slurs: failed to compile pattern %zu at offset "
                    "%zu: %s\n",
                    i, (size_t)error_offset, error_buf);
            for (size_t j = 0; j < i; j++) pcre2_code_free(compiled[j]);
            free(compiled);
            atomic_store_explicit(&g_init_state, -1, memory_order_release);
            return;
        }
    }
    g_compiled = compiled;
    atomic_store_explicit(&g_init_state, 1, memory_order_release);
}

static int explicit_slurs_ready(void) {
    int state = atomic_load_explicit(&g_init_state, memory_order_acquire);
    if (state != 0) return state == 1;
    while (
        atomic_flag_test_and_set_explicit(&g_init_lock, memory_order_acquire)) {
    }
    state = atomic_load_explicit(&g_init_state, memory_order_relaxed);
    if (state == 0) explicit_slurs_compile_all();
    state = atomic_load_explicit(&g_init_state, memory_order_relaxed);
    atomic_flag_clear_explicit(&g_init_lock, memory_order_release);
    return state == 1;
}

/* True if any compiled pattern matches `text` (a NUL-terminated UTF-8
 * string; malformed UTF-8 simply fails to match rather than crashing --
 * pcre2_match reports PCRE2_ERROR_UTF... and this treats every negative
 * return as "no match", matching hasExplicitSlur's own boolean test). */
static int explicit_slurs_match_any(const char *text) {
    size_t len = strlen(text);
    for (size_t i = 0; i < metalbear_explicit_slur_pattern_count; i++) {
        pcre2_match_data *match_data =
            pcre2_match_data_create_from_pattern(g_compiled[i], NULL);
        if (!match_data) continue;
        int rc = pcre2_match(g_compiled[i], (PCRE2_SPTR)text, len, 0, 0,
                             match_data, NULL);
        pcre2_match_data_free(match_data);
        if (rc >= 0) return 1;
    }
    return 0;
}

int metalbear_has_explicit_slur(const char *text) {
    if (!text) return 0;
    if (!explicit_slurs_ready()) return 0;

    if (explicit_slurs_match_any(text)) return 1;

    /* The reference also tests the string with '.', '-', '_' removed, so a
     * slur split across those separators (e.g. as they'd appear inside an
     * rkey or handle) is still caught. */
    size_t len = strlen(text);
    char *stripped = malloc(len + 1);
    if (!stripped) return 0;
    size_t out = 0;
    for (size_t i = 0; i < len; i++) {
        char c = text[i];
        if (c == '.' || c == '-' || c == '_') continue;
        stripped[out++] = c;
    }
    stripped[out] = '\0';

    int matched = (out != len) && explicit_slurs_match_any(stripped);
    free(stripped);
    return matched;
}

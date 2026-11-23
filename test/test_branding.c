#define _POSIX_C_SOURCE 200809L

/*
 * test_branding.c — the small grammar and defaults behind operator branding
 * (issue #260). These values reach a browser, so the colour and URL checks are
 * a security boundary as much as a config convenience.
 */

#include "metalbear/branding.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void test_colors(void) {
    CHECK(metalbear_branding_color_valid(NULL));
    CHECK(metalbear_branding_color_valid(""));
    CHECK(metalbear_branding_color_valid("#abc"));
    CHECK(metalbear_branding_color_valid("#ABCDEF"));
    CHECK(!metalbear_branding_color_valid("abc"));
    CHECK(!metalbear_branding_color_valid("#ab"));
    CHECK(!metalbear_branding_color_valid("#abcd"));
    CHECK(!metalbear_branding_color_valid("#gggggg"));
    CHECK(!metalbear_branding_color_valid("red"));
    /* A config value must not be able to smuggle a CSS declaration out. */
    CHECK(!metalbear_branding_color_valid("#fff;background:url(//evil)"));
}

static void test_urls(void) {
    CHECK(metalbear_branding_url_valid(NULL));
    CHECK(metalbear_branding_url_valid(""));
    CHECK(metalbear_branding_url_valid("/logo.svg"));
    CHECK(metalbear_branding_url_valid("https://example.com/logo.png"));
    CHECK(metalbear_branding_url_valid("http://example.com"));
    CHECK(!metalbear_branding_url_valid("javascript:alert(1)"));
    CHECK(!metalbear_branding_url_valid("data:image/svg+xml,x"));
    CHECK(!metalbear_branding_url_valid("example.com/logo.png"));
    CHECK(!metalbear_branding_url_valid("https://"));
    CHECK(!metalbear_branding_url_valid("/a\"onload=\"x"));
    CHECK(!metalbear_branding_url_valid("/a(b)"));
    CHECK(!metalbear_branding_url_valid("/a\\b"));
    CHECK(!metalbear_branding_url_valid("/a b"));
}

static void test_defaults_and_contrast(void) {
    CHECK(strcmp(metalbear_branding_or_default(NULL, "fallback"), "fallback") ==
          0);
    CHECK(strcmp(metalbear_branding_or_default("", "fallback"), "fallback") ==
          0);
    CHECK(strcmp(metalbear_branding_or_default("#123456", "fallback"),
                 "#123456") == 0);

    /* Near-black on a light primary, white on a dark one. Both short and
     * six-digit forms resolve the same way. */
    CHECK(strcmp(metalbear_branding_on_color("#ffffff"), "#0d1117") == 0);
    CHECK(strcmp(metalbear_branding_on_color("#fff"), "#0d1117") == 0);
    CHECK(strcmp(metalbear_branding_on_color("#000000"), "#ffffff") == 0);
    CHECK(strcmp(metalbear_branding_on_color("#000"), "#ffffff") == 0);
    CHECK(
        strcmp(metalbear_branding_on_color(METALBEAR_BRANDING_DEFAULT_PRIMARY),
               "#ffffff") == 0);
    CHECK(strcmp(metalbear_branding_on_color(NULL), "#ffffff") == 0);
}

int main(void) {
    test_colors();
    test_urls();
    test_defaults_and_contrast();
    if (failures) {
        fprintf(stderr, "%d branding check(s) failed\n", failures);
        return 1;
    }
    printf("branding checks passed\n");
    return 0;
}

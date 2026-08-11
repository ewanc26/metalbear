/*
 * test_explicit_slurs.c — unit coverage for metalbear_has_explicit_slur.
 *
 * The reference's own detection patterns (packages/pds/src/handle/
 * explicit-slurs.ts) have no bundled test vectors, so the cases here were
 * derived by testing the reference's actual regex source under Node
 * against both hand-picked ordinary handles (must not match) and
 * candidates mechanically constructed from each pattern's own character
 * classes (must match) -- not hand-authored, to keep this file itself free
 * of any slur word list beyond what scripts/gen_explicit_slurs.py already
 * extracts programmatically from the reference.
 */

#include "metalbear/repo/explicit_slurs.h"

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

int main(void) {
    /* NULL input: no crash, no match. */
    CHECK(metalbear_has_explicit_slur(NULL) == 0);

    /* Ordinary handles and record-key-shaped strings: never a false
     * positive. Includes near-miss substrings of what the patterns detect
     * ("cook", "book", "look" all share suffixes with pattern 0's target). */
    static const char *const negatives[] = {
        "alice",
        "bob.example.com",
        "cook",
        "cooking",
        "book",
        "look",
        "test-handle",
        "my_handle.example",
        "resolve.invalid",
        "a1b2c3",
        "xn--fsq",
        "user123",
        "hello.world",
        "not-a-slur-at-all",
        "cook.er",
        "co-ok",
        "c-o-o-k",
        "co.o.k",
        "cookie.baker",
        "",
    };
    for (size_t i = 0; i < sizeof(negatives) / sizeof(*negatives); i++) {
        CHECK(metalbear_has_explicit_slur(negatives[i]) == 0);
    }

    /* Candidates mechanically derived from patterns 0, 1, 2, 3, 4, 6's own
     * character classes (see scripts/gen_explicit_slurs.py's derivation,
     * cross-checked against the reference's real regex under Node) --
     * confirmed matches, not authored ones. Pattern 5 has no derived
     * candidate (the simple per-class-minimum derivation under-approximates
     * its repetition requirements); its coverage comes from the reference
     * regex compiling and running correctly for the other six, which
     * exercises the same PCRE2_UTF/no-UCP compilation path. */
    static const char *const positives[] = {
        "chink", "coon", "fagotry", "kikerys", "nigge", "tranie",
    };
    for (size_t i = 0; i < sizeof(positives) / sizeof(*positives); i++) {
        CHECK(metalbear_has_explicit_slur(positives[i]) == 1);
    }

    /* Separator-stripped variant: hasExplicitSlur also tests the input
     * with '.', '-', '_' removed, so a slur split across those characters
     * is still caught. */
    CHECK(metalbear_has_explicit_slur("ch-ink") == 1);
    CHECK(metalbear_has_explicit_slur("ch.in.k") == 1);
    CHECK(metalbear_has_explicit_slur("ch_ink") == 1);

    /* A match must be a whole-word hit (\b-bounded in the reference), not a
     * substring of a longer, unrelated word -- "coon" appears inside
     * "raccoon" but pattern 1 requires it as its own word. */
    CHECK(metalbear_has_explicit_slur("raccoon") == 0);

    if (failures == 0) {
        printf("explicit_slurs: all tests passed\n");
        return 0;
    }
    printf("explicit_slurs: %d check(s) failed\n", failures);
    return 1;
}

/*
 * test_admission.c -- per-domain signup admission (issue #163).
 *
 * The policy is pure configuration, so the helper is tested directly: legacy
 * fallback, leading-dot suffix matching, longest-suffix precedence and config
 * validation. The createAccount handler consumes the same helper.
 */

#include "metalbear/admission.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void expect_mode(const char *handle, metalbear_admission_mode fallback,
                        const char *open, const char *invite,
                        const char *closed, metalbear_admission_mode wanted) {
    metalbear_admission_mode got =
        metalbear_admission_for_handle(handle, fallback, open, invite, closed);
    if (got != wanted) {
        fprintf(stderr, "%s: mode %d, wanted %d\n", handle, (int)got,
                (int)wanted);
        exit(1);
    }
}

int main(void) {
    const char *open = ".open.example,.partner.net";
    const char *invite = ".invite.example,.sub.invite.example";
    const char *closed = ".closed.example";

    /* Public metadata uses these exact names; pin them so /operator.json
     * cannot drift into a synonym the bundled frontend does not understand. */
    if (strcmp(metalbear_admission_mode_name(METALBEAR_ADMISSION_OPEN),
               "open") != 0 ||
        strcmp(metalbear_admission_mode_name(METALBEAR_ADMISSION_INVITE),
               "invite") != 0 ||
        strcmp(metalbear_admission_mode_name(METALBEAR_ADMISSION_CLOSED),
               "closed") != 0 ||
        strcmp(metalbear_admission_mode_name((metalbear_admission_mode)99),
               "closed") != 0) {
        fprintf(stderr, "unexpected admission mode name\n");
        return 1;
    }

    /* No match uses the legacy global fallback. */
    expect_mode("alice.other.test", METALBEAR_ADMISSION_INVITE, open, invite,
                closed, METALBEAR_ADMISSION_INVITE);
    expect_mode("alice.other.test", METALBEAR_ADMISSION_OPEN, open, invite,
                closed, METALBEAR_ADMISSION_OPEN);

    /* Domains match by leading-dot suffix, never by bare substring. */
    expect_mode("alice.open.example", METALBEAR_ADMISSION_INVITE, open, invite,
                closed, METALBEAR_ADMISSION_OPEN);
    expect_mode("alice.invite.example", METALBEAR_ADMISSION_OPEN, open, invite,
                closed, METALBEAR_ADMISSION_INVITE);
    expect_mode("bob.closed.example", METALBEAR_ADMISSION_OPEN, open, invite,
                closed, METALBEAR_ADMISSION_CLOSED);
    expect_mode("notopen.example", METALBEAR_ADMISSION_INVITE, open, invite,
                closed, METALBEAR_ADMISSION_INVITE);

    /* The longest configured suffix wins, including across lists. */
    expect_mode("alice.sub.invite.example", METALBEAR_ADMISSION_OPEN, open,
                invite, closed, METALBEAR_ADMISSION_INVITE);
    expect_mode("alice.deep.sub.invite.example", METALBEAR_ADMISSION_CLOSED,
                open, invite, ",.deep.sub.invite.example",
                METALBEAR_ADMISSION_CLOSED);

    /* Blank separators and whitespace around entries are tolerated. */
    expect_mode("alice.partner.net", METALBEAR_ADMISSION_INVITE,
                " .open.example , .partner.net , ", NULL, NULL,
                METALBEAR_ADMISSION_OPEN);

    char err[256];
    if (!metalbear_admission_config_valid("open", ".a.example", ".b.example",
                                          ".c.example", err, sizeof(err))) {
        fprintf(stderr, "valid config rejected: %s\n", err);
        return 1;
    }
    if (!metalbear_admission_config_valid(NULL, NULL, NULL, NULL, err,
                                          sizeof(err))) {
        fprintf(stderr, "empty config rejected: %s\n", err);
        return 1;
    }
    if (metalbear_admission_config_valid("sometimes", NULL, NULL, NULL, err,
                                         sizeof(err))) {
        fprintf(stderr, "invalid default accepted\n");
        return 1;
    }
    if (metalbear_admission_config_valid("open", "example.com", NULL, NULL, err,
                                         sizeof(err))) {
        fprintf(stderr, "domain without leading dot accepted\n");
        return 1;
    }
    if (metalbear_admission_config_valid("open", ".a.example", ".a.example",
                                         NULL, err, sizeof(err))) {
        fprintf(stderr, "duplicate domain accepted\n");
        return 1;
    }

    printf("admission policy: ok\n");
    return 0;
}

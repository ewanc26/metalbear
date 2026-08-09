#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_account_email_tokens.c — coverage for the email-token bulk-deletion
 * helpers added for admin.updateAccountEmail/updateAccountPassword parity:
 * an admin overriding an account's email or password must invalidate any
 * outstanding token minted against the old state, matching the reference's
 * emailToken.deleteAllEmailTokens / deleteEmailToken(kind).
 */

#include "metalbear/account/account.h"
#include "wolfram/xrpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

int main(void) {
    char path[] = "/tmp/metalbear_email_tokens_test_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd >= 0) close(fd);
    unlink(path); /* metalbear_account_store_open creates its own file */

    metalbear_account_store *store = NULL;
    CHECK(metalbear_account_store_open(path, "bootstrap-pw", &store) == WF_OK);
    CHECK(store != NULL);

    char reset_token[64];
    char confirm_token[64];
    CHECK(metalbear_account_create_email_token(store, "reset", reset_token,
                                               sizeof(reset_token)) == WF_OK);
    CHECK(metalbear_account_create_email_token(store, "confirm", confirm_token,
                                               sizeof(confirm_token)) == WF_OK);

    /* Deleting by kind only touches that kind. */
    CHECK(metalbear_account_delete_email_tokens_by_kind(store, "reset") ==
          WF_OK);
    CHECK(metalbear_account_verify_email_token(store, "reset", reset_token) !=
          WF_OK);
    CHECK(metalbear_account_verify_email_token(store, "confirm",
                                               confirm_token) == WF_OK);

    /* Re-mint both, then wipe everything regardless of kind. */
    CHECK(metalbear_account_create_email_token(store, "reset", reset_token,
                                               sizeof(reset_token)) == WF_OK);
    CHECK(metalbear_account_create_email_token(store, "confirm", confirm_token,
                                               sizeof(confirm_token)) == WF_OK);
    CHECK(metalbear_account_delete_all_email_tokens(store) == WF_OK);
    CHECK(metalbear_account_verify_email_token(store, "reset", reset_token) !=
          WF_OK);
    CHECK(metalbear_account_verify_email_token(store, "confirm",
                                               confirm_token) != WF_OK);

    metalbear_account_store_free(store);
    unlink(path);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("test_account_email_tokens: OK\n");
    return 0;
}

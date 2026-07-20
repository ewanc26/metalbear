#ifndef METALBEAR_ACCOUNT_H
#define METALBEAR_ACCOUNT_H

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_account_store metalbear_account_store;

typedef enum metalbear_credential_kind {
    METALBEAR_CREDENTIAL_INVALID = 0,
    METALBEAR_CREDENTIAL_ACCOUNT,
    METALBEAR_CREDENTIAL_APP_PASSWORD,
    METALBEAR_CREDENTIAL_APP_PASSWORD_PRIVILEGED,
} metalbear_credential_kind;

typedef struct metalbear_app_password {
    char *name;
    char *created_at;
    bool privileged;
} metalbear_app_password;

wf_status metalbear_account_store_open(const char *path,
                                       const char *bootstrap_password,
                                       metalbear_account_store **out);
void metalbear_account_store_free(metalbear_account_store *store);
int metalbear_account_is_active(metalbear_account_store *store);
wf_status metalbear_account_deactivate(metalbear_account_store *store,
                                       const char *delete_after);
wf_status metalbear_account_activate(metalbear_account_store *store);
int metalbear_account_verify_password(metalbear_account_store *store,
                                      const char *password);
metalbear_credential_kind metalbear_account_verify_credential(
    metalbear_account_store *store, const char *password,
    char **out_app_password_name);
wf_status metalbear_account_create_app_password(
    metalbear_account_store *store, const char *name, bool privileged,
    char **out_password, char **out_created_at);
wf_status metalbear_account_list_app_passwords(
    metalbear_account_store *store, metalbear_app_password **out_passwords,
    size_t *out_count);
void metalbear_app_passwords_free(metalbear_app_password *passwords,
                                  size_t count);
wf_status metalbear_account_revoke_app_password(
    metalbear_account_store *store, const char *name);
wf_status metalbear_account_delete(metalbear_account_store *store);
wf_status metalbear_account_store_email(metalbear_account_store *store,
                                        const char *email);
wf_status metalbear_account_get_email(metalbear_account_store *store,
                                      char **out_email, int *out_confirmed);
wf_status metalbear_account_create_email_token(metalbear_account_store *store,
                                               const char *kind,
                                               char *out_token,
                                               size_t token_len);
wf_status metalbear_account_verify_email_token(metalbear_account_store *store,
                                                const char *kind,
                                                const char *token);
wf_status metalbear_account_reset_password(metalbear_account_store *store,
                                           const char *new_password);
/* Hash a password with scrypt for storage. Caller must free the result. */
char *metalbear_account_hash_password(const char *password);

#ifdef __cplusplus
}
#endif

#endif

#ifndef METALBEAR_EMAIL_H
#define METALBEAR_EMAIL_H

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_email metalbear_email;

typedef struct metalbear_email_config {
    const char *smtp_host;
    uint16_t smtp_port;
    const char *smtp_username;
    const char *smtp_password;
    const char *from_address;
    const char *from_name;
    bool smtp_starttls;
} metalbear_email_config;

wf_status metalbear_email_open(const metalbear_email_config *config,
                               metalbear_email **out);
void metalbear_email_free(metalbear_email *email);

wf_status metalbear_email_send_verification(metalbear_email *email,
                                            const char *to_address,
                                            const char *verification_code);
wf_status metalbear_email_send_password_reset(metalbear_email *email,
                                              const char *to_address,
                                              const char *reset_token);
wf_status metalbear_email_send_account_deletion(metalbear_email *email,
                                                const char *to_address,
                                                const char *confirmation_code);

#ifdef __cplusplus
}
#endif

#endif

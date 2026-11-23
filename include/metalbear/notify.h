#ifndef METALBEAR_NOTIFY_H
#define METALBEAR_NOTIFY_H

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef METALBEAR_MODULE_EMAIL
#include "metalbear/email.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * notify.h — one dispatch point for account notifications (issue #132).
 *
 * A channel is an optional destination: email, a webhook, or anything else a
 * future change adds. Channels are off unless their configuration is present;
 * with no channels configured, sending is a silent no-op that returns WF_OK.
 * Every configured channel receives every notification, and the first channel
 * failure is returned after all channels have been attempted. Nothing here
 * logs a destination, a token or a code.
 */

typedef enum metalbear_notification_kind {
    METALBEAR_NOTIFY_VERIFICATION,
    METALBEAR_NOTIFY_PASSWORD_RESET,
    METALBEAR_NOTIFY_ACCOUNT_DELETION,
    /* Caller supplies subject and body (PLC operation, admin message, test). */
    METALBEAR_NOTIFY_MESSAGE
} metalbear_notification_kind;

typedef struct metalbear_notification {
    metalbear_notification_kind kind;
    const char *to_address;  /* account email; may be NULL for a test message */
    const char *account_did; /* may be NULL */
    const char *code;        /* verification/reset/deletion code; may be NULL */
    const char *subject;     /* METALBEAR_NOTIFY_MESSAGE only */
    const char *body;        /* METALBEAR_NOTIFY_MESSAGE only */
} metalbear_notification;

typedef struct metalbear_notify_channel {
    const char *name;
    wf_status (*send)(void *ctx, const metalbear_notification *note);
    void (*free)(void *ctx);
    void *ctx;
} metalbear_notify_channel;

#define METALBEAR_NOTIFY_MAX_CHANNELS 4

typedef struct metalbear_notifier metalbear_notifier;

wf_status metalbear_notifier_new(metalbear_notifier **out);
void metalbear_notifier_free(metalbear_notifier *notifier);

/* Adds a channel by value; the notifier owns the context through its free
 * callback. Returns false when the fixed channel table is full. */
bool metalbear_notifier_add(metalbear_notifier *notifier,
                            const metalbear_notify_channel *channel);
size_t metalbear_notifier_channel_count(const metalbear_notifier *notifier);

wf_status metalbear_notifier_send(metalbear_notifier *notifier,
                                  const metalbear_notification *note);

/* Convenience dispatchers. They build the same subject and body the original
 * email-only call sites used, so switching to channels changes no email copy
 * and no response behaviour. */
wf_status metalbear_notify_send_verification(metalbear_notifier *notifier,
                                             const char *to_address,
                                             const char *code,
                                             const char *account_did);
wf_status metalbear_notify_send_password_reset(metalbear_notifier *notifier,
                                               const char *to_address,
                                               const char *token,
                                               const char *account_did);
wf_status metalbear_notify_send_account_deletion(metalbear_notifier *notifier,
                                                 const char *to_address,
                                                 const char *code,
                                                 const char *account_did);
wf_status metalbear_notify_send_message(metalbear_notifier *notifier,
                                        const char *to_address,
                                        const char *subject, const char *body,
                                        const char *account_did);

/* Channel constructors. The email channel borrows `email`; the server still
 * owns and frees it. The webhook channel copies url and secret. A NULL or
 * empty url/secret disables the webhook channel. */
#ifdef METALBEAR_MODULE_EMAIL
wf_status metalbear_notify_email_channel(metalbear_email *email,
                                         metalbear_notify_channel *out);
#endif
wf_status metalbear_notify_webhook_channel(const char *url, const char *secret,
                                           metalbear_notify_channel *out);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_NOTIFY_H */

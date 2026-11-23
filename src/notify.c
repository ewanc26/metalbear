#define _POSIX_C_SOURCE 200809L

#include "metalbear/notify.h"

#include <curl/curl.h>
#include <cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct metalbear_notifier {
    size_t count;
    metalbear_notify_channel channels[METALBEAR_NOTIFY_MAX_CHANNELS];
};

wf_status metalbear_notifier_new(metalbear_notifier **out) {
    if (!out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_notifier *notifier = calloc(1, sizeof(*notifier));
    if (!notifier) return WF_ERR_ALLOC;
    *out = notifier;
    return WF_OK;
}

void metalbear_notifier_free(metalbear_notifier *notifier) {
    if (!notifier) return;
    for (size_t i = 0; i < notifier->count; i++) {
        if (notifier->channels[i].free && notifier->channels[i].ctx)
            notifier->channels[i].free(notifier->channels[i].ctx);
    }
    free(notifier);
}

bool metalbear_notifier_add(metalbear_notifier *notifier,
                            const metalbear_notify_channel *channel) {
    if (!notifier || !channel || !channel->send) return false;
    if (notifier->count >= METALBEAR_NOTIFY_MAX_CHANNELS) return false;
    notifier->channels[notifier->count++] = *channel;
    return true;
}

size_t metalbear_notifier_channel_count(const metalbear_notifier *notifier) {
    return notifier ? notifier->count : 0;
}

wf_status metalbear_notifier_send(metalbear_notifier *notifier,
                                  const metalbear_notification *note) {
    if (!note || (!note->to_address && note->kind != METALBEAR_NOTIFY_MESSAGE))
        return WF_ERR_INVALID_ARG;
    if (!notifier || notifier->count == 0) return WF_OK;

    wf_status result = WF_OK;
    for (size_t i = 0; i < notifier->count; i++) {
        wf_status status =
            notifier->channels[i].send(notifier->channels[i].ctx, note);
        if (status != WF_OK && result == WF_OK) result = status;
    }
    return result;
}

/* ---- Subject and body builders ----------------------------------------
 * These are byte-for-byte the strings the original email-only call sites
 * built. Keeping them here means an email channel, a webhook channel and a
 * future channel all report the same notification. */

static void build_verification(const char *code, char *subject,
                               size_t subject_len, char *body,
                               size_t body_len) {
    snprintf(subject, subject_len, "Verify your email address");
    snprintf(body, body_len,
             "Your verification code is: %s\n\n"
             "Enter this code in the AT Protocol PDS to verify your "
             "email address.\n\n"
             "If you did not request this, please ignore this email.\n",
             code ? code : "");
}

static void build_password_reset(const char *token, char *subject,
                                 size_t subject_len, char *body,
                                 size_t body_len) {
    snprintf(subject, subject_len, "Reset your password");
    snprintf(body, body_len,
             "You have requested a password reset.\n\n"
             "Use the following token to reset your password:\n\n"
             "%s\n\n"
             "If you did not request this, please ignore this email.\n",
             token ? token : "");
}

static void build_account_deletion(const char *code, char *subject,
                                   size_t subject_len, char *body,
                                   size_t body_len) {
    snprintf(subject, subject_len, "Confirm account deletion");
    snprintf(body, body_len,
             "You have requested to delete your account.\n\n"
             "Your confirmation code is: %s\n\n"
             "Enter this code to confirm account deletion. This action "
             "cannot be undone.\n\n"
             "If you did not request this, please ignore this email.\n",
             code ? code : "");
}

wf_status metalbear_notify_send_verification(metalbear_notifier *notifier,
                                             const char *to_address,
                                             const char *code,
                                             const char *account_did) {
    if (!to_address || !code) return WF_ERR_INVALID_ARG;
    char subject[256];
    char body[1024];
    build_verification(code, subject, sizeof(subject), body, sizeof(body));
    metalbear_notification note = {.kind = METALBEAR_NOTIFY_VERIFICATION,
                                   .to_address = to_address,
                                   .account_did = account_did,
                                   .code = code,
                                   .subject = subject,
                                   .body = body};
    return metalbear_notifier_send(notifier, &note);
}

wf_status metalbear_notify_send_password_reset(metalbear_notifier *notifier,
                                               const char *to_address,
                                               const char *token,
                                               const char *account_did) {
    if (!to_address || !token) return WF_ERR_INVALID_ARG;
    char subject[256];
    char body[1024];
    build_password_reset(token, subject, sizeof(subject), body, sizeof(body));
    metalbear_notification note = {.kind = METALBEAR_NOTIFY_PASSWORD_RESET,
                                   .to_address = to_address,
                                   .account_did = account_did,
                                   .code = token,
                                   .subject = subject,
                                   .body = body};
    return metalbear_notifier_send(notifier, &note);
}

wf_status metalbear_notify_send_account_deletion(metalbear_notifier *notifier,
                                                 const char *to_address,
                                                 const char *code,
                                                 const char *account_did) {
    if (!to_address || !code) return WF_ERR_INVALID_ARG;
    char subject[256];
    char body[1024];
    build_account_deletion(code, subject, sizeof(subject), body, sizeof(body));
    metalbear_notification note = {.kind = METALBEAR_NOTIFY_ACCOUNT_DELETION,
                                   .to_address = to_address,
                                   .account_did = account_did,
                                   .code = code,
                                   .subject = subject,
                                   .body = body};
    return metalbear_notifier_send(notifier, &note);
}

wf_status metalbear_notify_send_message(metalbear_notifier *notifier,
                                        const char *to_address,
                                        const char *subject, const char *body,
                                        const char *account_did) {
    if (!subject || !body) return WF_ERR_INVALID_ARG;
    metalbear_notification note = {.kind = METALBEAR_NOTIFY_MESSAGE,
                                   .to_address = to_address,
                                   .account_did = account_did,
                                   .subject = subject,
                                   .body = body};
    return metalbear_notifier_send(notifier, &note);
}

/* ---- Email channel ----------------------------------------------------- */

#ifdef METALBEAR_MODULE_EMAIL

static wf_status email_send(void *ctx, const metalbear_notification *note) {
    metalbear_email *email = ctx;
    if (!email || !note) return WF_ERR_INVALID_ARG;
    return metalbear_email_send(email, note->to_address ? note->to_address : "",
                                note->subject ? note->subject : "",
                                note->body ? note->body : "");
}

wf_status metalbear_notify_email_channel(metalbear_email *email,
                                         metalbear_notify_channel *out) {
    if (!email || !out) return WF_ERR_INVALID_ARG;
    out->name = "email";
    out->send = email_send;
    out->free = NULL; /* borrowed: the server owns the metalbear_email */
    out->ctx = email;
    return WF_OK;
}

#endif /* METALBEAR_MODULE_EMAIL */

/* ---- Webhook channel --------------------------------------------------- */

typedef struct webhook_ctx {
    char *url;
    char *secret; /* NULL when unset; never logged */
} webhook_ctx;

static void webhook_free(void *ctx) {
    webhook_ctx *webhook = ctx;
    if (!webhook) return;
    free(webhook->url);
    free(webhook->secret);
    free(webhook);
}

static size_t webhook_discard(void *ptr, size_t size, size_t nmemb,
                              void *data) {
    (void)ptr;
    (void)data;
    return size * nmemb;
}

static const char *kind_name(metalbear_notification_kind kind) {
    switch (kind) {
        case METALBEAR_NOTIFY_VERIFICATION:
            return "verification";
        case METALBEAR_NOTIFY_PASSWORD_RESET:
            return "password_reset";
        case METALBEAR_NOTIFY_ACCOUNT_DELETION:
            return "account_deletion";
        case METALBEAR_NOTIFY_MESSAGE:
            return "message";
    }
    return "unknown";
}

static wf_status webhook_send(void *ctx, const metalbear_notification *note) {
    webhook_ctx *webhook = ctx;
    if (!webhook || !note || !webhook->url) return WF_ERR_INVALID_ARG;

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "kind", kind_name(note->kind));
    if (note->to_address) cJSON_AddStringToObject(root, "to", note->to_address);
    if (note->account_did)
        cJSON_AddStringToObject(root, "did", note->account_did);
    if (note->code) cJSON_AddStringToObject(root, "code", note->code);
    if (note->subject) cJSON_AddStringToObject(root, "subject", note->subject);
    if (note->body) cJSON_AddStringToObject(root, "body", note->body);
    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!payload) return WF_ERR_ALLOC;

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(payload);
        return WF_ERR_INTERNAL;
    }
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    char *auth_header = NULL;
    if (webhook->secret) {
        /* "Authorization: Bearer " is 22 bytes, plus the secret and NUL. */
        size_t len =
            strlen("Authorization: Bearer ") + strlen(webhook->secret) + 1;
        auth_header = malloc(len);
        if (auth_header) {
            snprintf(auth_header, len, "Authorization: Bearer %s",
                     webhook->secret);
            headers = curl_slist_append(headers, auth_header);
        }
    }

    curl_easy_setopt(curl, CURLOPT_URL, webhook->url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, webhook_discard);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    CURLcode res = curl_easy_perform(curl);
    long status = 0;
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    free(auth_header);
    curl_easy_cleanup(curl);
    free(payload);

    /* No URL, header or payload in logs: any of them can carry a secret. */
    if (res != CURLE_OK || status < 200 || status >= 300) {
        fprintf(stderr, "MetalBear notify: webhook delivery failed\n");
        return WF_ERR_INTERNAL;
    }
    return WF_OK;
}

wf_status metalbear_notify_webhook_channel(const char *url, const char *secret,
                                           metalbear_notify_channel *out) {
    if (!url || !url[0] || !out) return WF_ERR_INVALID_ARG;
    webhook_ctx *webhook = calloc(1, sizeof(*webhook));
    if (!webhook) return WF_ERR_ALLOC;
    webhook->url = strdup(url);
    if (secret && secret[0]) webhook->secret = strdup(secret);
    if (!webhook->url || (secret && secret[0] && !webhook->secret)) {
        webhook_free(webhook);
        return WF_ERR_ALLOC;
    }
    out->name = "webhook";
    out->send = webhook_send;
    out->free = webhook_free;
    out->ctx = webhook;
    return WF_OK;
}

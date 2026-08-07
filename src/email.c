#define _POSIX_C_SOURCE 200809L

#include "metalbear/email.h"
#include "email_internal.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct metalbear_email {
    char *smtp_host;
    uint16_t smtp_port;
    char *smtp_username;
    char *smtp_password;
    char *from_address;
    char *from_name;
    bool smtp_starttls;
};

static size_t discard_response(void *ptr, size_t size, size_t nmemb,
                               void *userdata) {
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

/* Feeds the message body to curl's SMTP upload a chunk at a time from an
 * in-memory buffer. NOT the same thing as passing plain libc `fread` as
 * CURLOPT_READFUNCTION with CURLOPT_READDATA pointing at the body string --
 * fread's fourth parameter must be a FILE*, and a raw char* is not one;
 * curl would call fread(buf, size, n, body) and fread would dereference
 * `body` as if it were a FILE struct, corrupting memory or crashing on
 * every send. Not static: exercised directly by test_email_internal.c
 * against curl's actual calling contract (repeated calls with varying
 * buffer sizes must drain the whole body and then report EOF), which a
 * live-network test can't easily do without also standing up a real TLS
 * SMTP server. */
size_t email_read_body(char *buffer, size_t size, size_t nitems,
                       void *userdata) {
    email_body_reader *reader = userdata;
    size_t capacity = size * nitems;
    size_t n = reader->remaining < capacity ? reader->remaining : capacity;
    if (n > 0) {
        memcpy(buffer, reader->cursor, n);
        reader->cursor += n;
        reader->remaining -= n;
    }
    return n;
}

/*
 * Which URL scheme/security mode to use, per smtp_starttls -- see
 * send_email's comment for why there is no plaintext-SMTP mode. Not
 * static, for the same reason as email_read_body: a pure function is
 * trivial to test directly and a live-network test isn't needed to prove
 * this is right.
 */
void email_build_smtp_url(bool starttls, const char *host, char *out,
                          size_t out_len) {
    snprintf(out, out_len, "%s://%s", starttls ? "smtp" : "smtps", host);
}

wf_status metalbear_email_open(const metalbear_email_config *config,
                               metalbear_email **out) {
    if (!config || !config->smtp_host || !config->from_address || !out)
        return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_email *email = calloc(1, sizeof(*email));
    if (!email) return WF_ERR_ALLOC;
    email->smtp_host = strdup(config->smtp_host);
    email->from_address = strdup(config->from_address);
    email->from_name = config->from_name ? strdup(config->from_name) : NULL;
    email->smtp_username =
        config->smtp_username ? strdup(config->smtp_username) : NULL;
    email->smtp_password =
        config->smtp_password ? strdup(config->smtp_password) : NULL;
    email->smtp_port = config->smtp_port;
    email->smtp_starttls = config->smtp_starttls;
    if (!email->smtp_host || !email->from_address) {
        metalbear_email_free(email);
        return WF_ERR_ALLOC;
    }
    *out = email;
    return WF_OK;
}

void metalbear_email_free(metalbear_email *email) {
    if (!email) return;
    free(email->smtp_host);
    free(email->from_address);
    free(email->from_name);
    free(email->smtp_username);
    free(email->smtp_password);
    free(email);
}

static wf_status send_email(metalbear_email *email, const char *to,
                            const char *subject, const char *body) {
    if (!email || !to || !subject || !body) return WF_ERR_INVALID_ARG;
    CURL *curl = curl_easy_init();
    if (!curl) return WF_ERR_INTERNAL;
    struct curl_slist *recipients = NULL;
    struct curl_slist *headers = NULL;
    char from_buf[512];
    char subject_header[512];
    wf_status status = WF_OK;
    if (email->from_name && email->from_name[0])
        snprintf(from_buf, sizeof(from_buf), "%s <%s>", email->from_name,
                 email->from_address);
    else
        snprintf(from_buf, sizeof(from_buf), "%s", email->from_address);
    snprintf(subject_header, sizeof(subject_header), "Subject: %s", subject);
    headers = curl_slist_append(headers, subject_header);
    headers = curl_slist_append(headers, "MIME-Version: 1.0");
    headers = curl_slist_append(headers, "Content-Type: text/plain; "
                                         "charset=utf-8");
    recipients = curl_slist_append(recipients, to);
    /*
     * A bare hostname (no scheme) does NOT make curl guess "smtp" -- with
     * no CURLOPT_DEFAULT_PROTOCOL set, curl treats a schemeless URL as
     * http://, so every one of CURLOPT_MAIL_FROM/MAIL_RCPT/UPLOAD below was
     * silently ignored and the connection just sent an HTTP request at
     * whatever SMTP server was listening -- confirmed against a real
     * relay (smtp.resend.com:465), which correctly accepts a TLS
     * connection but then sits waiting for a plaintext SMTP greeting that
     * never arrives, since curl sent an HTTP GET instead; every account
     * operation that sends email (deletion confirmation, password reset,
     * email verification) was silently never actually delivering.
     *
     * smtp_starttls chooses between the two real-world SMTP/TLS
     * combinations: `smtp://` + CURLOPT_USE_SSL=ALL connects in the clear
     * and then requires a successful STARTTLS upgrade (the conventional
     * pairing with port 587), while `smtps://` -- curl's separate scheme
     * for implicit TLS, always encrypted regardless of CURLOPT_USE_SSL --
     * matches the conventional pairing with port 465. There is no
     * supported unencrypted mode; nothing in this project's own docs asks
     * for one, and defaulting to plaintext SMTP over the public internet
     * is not a default worth having.
     */
    char smtp_url[600];
    email_build_smtp_url(email->smtp_starttls, email->smtp_host, smtp_url,
                         sizeof(smtp_url));
    curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
    curl_easy_setopt(curl, CURLOPT_PORT, (long)email->smtp_port);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from_buf);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    email_body_reader reader = {.cursor = body, .remaining = strlen(body)};
    curl_easy_setopt(curl, CURLOPT_READDATA, &reader);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, email_read_body);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(
        curl, CURLOPT_USE_SSL,
        (long)(email->smtp_starttls ? CURLUSESSL_ALL : CURLUSESSL_NONE));
    if (email->smtp_username && email->smtp_username[0]) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, email->smtp_username);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, email->smtp_password);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "MetalBear email: SMTP error: %s\n",
                curl_easy_strerror(res));
        status = WF_ERR_INTERNAL;
    }
    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return status;
}

wf_status metalbear_email_send_verification(metalbear_email *email,
                                            const char *to_address,
                                            const char *verification_code) {
    if (!email || !to_address || !verification_code) return WF_ERR_INVALID_ARG;
    char subject[256];
    char body[1024];
    snprintf(subject, sizeof(subject), "Verify your email address");
    snprintf(body, sizeof(body),
             "Your verification code is: %s\n\n"
             "Enter this code in the AT Protocol PDS to verify your "
             "email address.\n\n"
             "If you did not request this, please ignore this email.\n",
             verification_code);
    return send_email(email, to_address, subject, body);
}

wf_status metalbear_email_send_password_reset(metalbear_email *email,
                                              const char *to_address,
                                              const char *reset_token) {
    if (!email || !to_address || !reset_token) return WF_ERR_INVALID_ARG;
    char subject[256];
    char body[1024];
    snprintf(subject, sizeof(subject), "Reset your password");
    snprintf(body, sizeof(body),
             "You have requested a password reset.\n\n"
             "Use the following token to reset your password:\n\n"
             "%s\n\n"
             "If you did not request this, please ignore this email.\n",
             reset_token);
    return send_email(email, to_address, subject, body);
}

wf_status metalbear_email_send_account_deletion(metalbear_email *email,
                                                const char *to_address,
                                                const char *confirmation_code) {
    if (!email || !to_address || !confirmation_code) return WF_ERR_INVALID_ARG;
    char subject[256];
    char body[1024];
    snprintf(subject, sizeof(subject), "Confirm account deletion");
    snprintf(body, sizeof(body),
             "You have requested to delete your account.\n\n"
             "Your confirmation code is: %s\n\n"
             "Enter this code to confirm account deletion. This action "
             "cannot be undone.\n\n"
             "If you did not request this, please ignore this email.\n",
             confirmation_code);
    return send_email(email, to_address, subject, body);
}

wf_status metalbear_email_send(metalbear_email *email, const char *to_address,
                               const char *subject, const char *body) {
    return send_email(email, to_address, subject, body);
}

#define _POSIX_C_SOURCE 200809L

#include "metalbear/email.h"
#include "email_internal.h"

#include <curl/curl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct CurlGuard {
    CURL *ptr = nullptr;
    explicit CurlGuard(CURL *p = nullptr) : ptr(p) {}
    ~CurlGuard() {
        if (ptr) curl_easy_cleanup(ptr);
    }
    CURL *get() const {
        return ptr;
    }
    CURL *release() {
        CURL *p = ptr;
        ptr = nullptr;
        return p;
    }
    void reset(CURL *p = nullptr) {
        if (ptr) curl_easy_cleanup(ptr);
        ptr = p;
    }
};

struct SlistGuard {
    curl_slist *ptr = nullptr;
    ~SlistGuard() {
        if (ptr) curl_slist_free_all(ptr);
    }
    void append(const char *s) {
        curl_slist *n = curl_slist_append(ptr, s);
        if (n) ptr = n;
    }
    curl_slist *get() const {
        return ptr;
    }
    curl_slist *release() {
        curl_slist *p = ptr;
        ptr = nullptr;
        return p;
    }
};

} /* anonymous namespace */

struct metalbear_email {
    std::string smtp_host;
    uint16_t smtp_port;
    std::string smtp_username;
    std::string smtp_password;
    std::string from_address;
    std::string from_name;
    bool smtp_starttls;
};

size_t email_read_body(char *buffer, size_t size, size_t nitems,
                       void *userdata) {
    email_body_reader *reader = (email_body_reader *)userdata;
    size_t capacity = size * nitems;
    size_t n = reader->remaining < capacity ? reader->remaining : capacity;
    if (n > 0) {
        std::memcpy(buffer, reader->cursor, n);
        reader->cursor += n;
        reader->remaining -= n;
    }
    return n;
}

void email_build_smtp_url(bool starttls, const char *host, char *out,
                          size_t out_len) {
    std::snprintf(out, out_len, "%s://%s", starttls ? "smtp" : "smtps", host);
}

wf_status metalbear_email_open(const metalbear_email_config *config,
                               metalbear_email **out) {
    if (!config || !config->smtp_host || !config->from_address || !out)
        return WF_ERR_INVALID_ARG;
    *out = nullptr;
    auto *email = new (std::nothrow) metalbear_email;
    if (!email) return WF_ERR_ALLOC;
    email->smtp_host = config->smtp_host;
    email->from_address = config->from_address;
    email->from_name = config->from_name ? config->from_name : "";
    email->smtp_username = config->smtp_username ? config->smtp_username : "";
    email->smtp_password = config->smtp_password ? config->smtp_password : "";
    email->smtp_port = config->smtp_port;
    email->smtp_starttls = config->smtp_starttls;
    *out = email;
    return WF_OK;
}

void metalbear_email_free(metalbear_email *email) {
    delete email;
}

static wf_status send_email(metalbear_email *email, const char *to,
                            const char *subject, const char *body) {
    if (!email || !to || !subject || !body) return WF_ERR_INVALID_ARG;
    CURL *curl_raw = curl_easy_init();
    if (!curl_raw) return WF_ERR_INTERNAL;
    CurlGuard curl(curl_raw);

    SlistGuard headers;
    SlistGuard recipients;

    std::string from_buf;
    if (!email->from_name.empty())
        from_buf = email->from_name + " <" + email->from_address + ">";
    else
        from_buf = email->from_address;

    char subject_header[512];
    std::snprintf(subject_header, sizeof(subject_header), "Subject: %s",
                  subject);
    headers.append(subject_header);
    headers.append("MIME-Version: 1.0");
    headers.append("Content-Type: text/plain; charset=utf-8");
    recipients.append(to);

    std::string smtp_url = email->smtp_starttls ? "smtp://" : "smtps://";
    smtp_url += email->smtp_host;

    curl_easy_setopt(curl.get(), CURLOPT_URL, smtp_url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PORT, (long)email->smtp_port);
    curl_easy_setopt(curl.get(), CURLOPT_MAIL_FROM, from_buf.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_MAIL_RCPT, recipients.get());
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());

    email_body_reader reader = {.cursor = body, .remaining = std::strlen(body)};
    curl_easy_setopt(curl.get(), CURLOPT_READDATA, &reader);
    curl_easy_setopt(curl.get(), CURLOPT_READFUNCTION, email_read_body);
    curl_easy_setopt(curl.get(), CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(
        curl.get(), CURLOPT_USE_SSL,
        (long)(email->smtp_starttls ? CURLUSESSL_ALL : CURLUSESSL_NONE));
    if (!email->smtp_username.empty()) {
        curl_easy_setopt(curl.get(), CURLOPT_USERNAME,
                         email->smtp_username.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_PASSWORD,
                         email->smtp_password.c_str());
    }
    curl_easy_setopt(
        curl.get(), CURLOPT_WRITEFUNCTION,
        [](void *, size_t size, size_t nmemb, void *) { return size * nmemb; });
    CURLcode res = curl_easy_perform(curl.get());
    if (res != CURLE_OK) {
        std::fprintf(stderr, "MetalBear email: SMTP error: %s\n",
                     curl_easy_strerror(res));
        return WF_ERR_INTERNAL;
    }
    return WF_OK;
}

wf_status metalbear_email_send_verification(metalbear_email *email,
                                            const char *to_address,
                                            const char *verification_code) {
    if (!email || !to_address || !verification_code) return WF_ERR_INVALID_ARG;
    char subject[256];
    char body[1024];
    std::snprintf(subject, sizeof(subject), "Verify your email address");
    std::snprintf(body, sizeof(body),
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
    std::snprintf(subject, sizeof(subject), "Reset your password");
    std::snprintf(body, sizeof(body),
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
    std::snprintf(subject, sizeof(subject), "Confirm account deletion");
    std::snprintf(body, sizeof(body),
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

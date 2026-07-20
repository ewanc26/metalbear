#ifndef METALBEAR_SERVER_H
#define METALBEAR_SERVER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_server metalbear_server;

typedef struct metalbear_config {
    const char *listen_address;
    uint16_t port;
    unsigned int thread_count;
    const char *data_directory;
    const char *service_did;
    const char *public_url; /* optional; derived from did:web when omitted */
    const char *account_did;
    const char *account_handle;
    const char *user_domain;
    const char *password;
    /* Email configuration (optional) */
    const char *smtp_host;
    uint16_t smtp_port;
    const char *smtp_username;
    const char *smtp_password;
    const char *from_address;
    const char *from_name;
    bool smtp_starttls;
    /* Account email for notifications */
    const char *account_email;
    /* Firehose retention (optional, defaults: max_age=30d, min_events=1000) */
    int64_t retention_max_age_seconds;
    int64_t retention_min_events;
} metalbear_config;

/* Start a single-account AT Protocol PDS. All strings are copied. */
metalbear_server *metalbear_server_start(const metalbear_config *config);

/* The actual bound port, useful when config.port was zero. */
uint16_t metalbear_server_port(const metalbear_server *server);

/* Stop and free the server. Durable repository and blob data remain on disk. */
void metalbear_server_free(metalbear_server *server);

#ifdef __cplusplus
}
#endif

#endif

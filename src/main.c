#define _POSIX_C_SOURCE 200809L

#include "metalbear/server.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop_handler(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static const char *required_env(const char *name) {
    const char *value = getenv(name);
    if (!value || !value[0])
        fprintf(stderr, "MetalBear [ERROR] missing required %s\n", name);
    return value;
}

int main(void) {
    const char *port_text = getenv("METALBEAR_PORT");
    char *end = NULL;
    unsigned long port = port_text ? strtoul(port_text, &end, 10) : 2583;
    if ((port_text && (!end || *end)) || port > 65535) {
        fprintf(stderr,
                "MetalBear [ERROR] METALBEAR_PORT must be between 0 and "
                "65535\n");
        return 2;
    }

    const char *listen_address = getenv("METALBEAR_LISTEN");
    const char *data_directory = getenv("METALBEAR_DATA");
    metalbear_config config = {
        .listen_address = listen_address && listen_address[0]
                              ? listen_address : "127.0.0.1",
        .port = (uint16_t)port,
        .thread_count = 4,
        .data_directory = data_directory && data_directory[0]
                              ? data_directory : "data",
        .service_did = required_env("METALBEAR_SERVICE_DID"),
        .public_url = getenv("METALBEAR_PUBLIC_URL"),
        .account_did = required_env("METALBEAR_ACCOUNT_DID"),
        .account_handle = required_env("METALBEAR_HANDLE"),
        .user_domain = required_env("METALBEAR_USER_DOMAIN"),
        .password = required_env("METALBEAR_PASSWORD"),
        .smtp_host = getenv("METALBEAR_SMTP_HOST"),
        .smtp_port = 0,
        .smtp_username = getenv("METALBEAR_SMTP_USERNAME"),
        .smtp_password = getenv("METALBEAR_SMTP_PASSWORD"),
        .from_address = getenv("METALBEAR_FROM_ADDRESS"),
        .from_name = getenv("METALBEAR_FROM_NAME"),
        .smtp_starttls = true,
        .account_email = getenv("METALBEAR_ACCOUNT_EMAIL"),
    };
    const char *smtp_port_text = getenv("METALBEAR_SMTP_PORT");
    if (smtp_port_text && smtp_port_text[0]) {
        char *end = NULL;
        unsigned long p = strtoul(smtp_port_text, &end, 10);
        if (end && !*end && p <= 65535)
            config.smtp_port = (uint16_t)p;
    }
    if (!config.service_did || !config.account_did || !config.account_handle ||
        !config.user_domain || !config.password)
        return 2;

    metalbear_server *server = metalbear_server_start(&config);
    if (!server) {
        fprintf(stderr, "MetalBear [ERROR] failed to start MetalBear\n");
        return 1;
    }

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    fprintf(stderr, "MetalBear [INFO] listening on %s:%u\n",
            config.listen_address, (unsigned)metalbear_server_port(server));
    while (!stopping) pause();
    metalbear_server_free(server);
    return 0;
}

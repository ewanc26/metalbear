#define _POSIX_C_SOURCE 200809L

#include "metalbear/server.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cJSON.h>

#include "wolfram/plc.h"
#include "wolfram/syntax.h"
#include "metalbear/key_rotation.h"
#include "metalbear/repo_store.h"

static volatile sig_atomic_t stopping;

static void stop_handler(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static char *encode_did_for_dir(const char *did) {
    size_t need = 1;
    for (const char *p = did; *p; p++) need += (*p == ':') ? 1 : 1;
    char *enc = malloc(need);
    if (!enc) return NULL;
    size_t j = 0;
    for (const char *p = did; *p; p++) enc[j++] = (*p == ':') ? '_' : *p;
    enc[j] = '\0';
    return enc;
}

static bool make_directory(const char *path) {
    if (mkdir(path, 0700) == 0) return true;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Build the on-disk account directory path for `did` under the data root.
 * Heap-allocated; caller frees. */
static char *account_dir_for_did(const metalbear_config *config,
                                 const char *did) {
    char *enc_did = encode_did_for_dir(did);
    if (!enc_did) return NULL;
    size_t root_len = strlen(config->data_directory);
    size_t enc_len = strlen(enc_did);
    bool root_slash = root_len > 0 && config->data_directory[root_len - 1] == '/';
    size_t n = root_len + (root_slash ? 0 : 1) + enc_len + 1;
    char *dir = malloc(n);
    if (dir)
        snprintf(dir, n, "%s%s%s", config->data_directory,
                 root_slash ? "" : "/", enc_did);
    free(enc_did);
    return dir;
}

/* Join a filename onto a directory. Heap-allocated; caller frees. */
static char *path_join(const char *dir, const char *name) {
    size_t n = strlen(dir) + 1 + strlen(name) + 1;
    char *p = malloc(n);
    if (p) snprintf(p, n, "%s/%s", dir, name);
    return p;
}


static const char *required_env(const char *name) {
    const char *value = getenv(name);
    if (!value || !value[0])
        fprintf(stderr, "MetalBear [ERROR] missing required %s\n", name);
    return value;
}

/*
 * Validate an operator-supplied DID before it becomes an account identity.
 *
 * A DID reaching the registry is effectively permanent: the repo is created
 * under it and its commits embed it in signed CBOR, so a bad value cannot be
 * corrected later without discarding the repo. A placeholder
 * ("did:plc:bearbootstrap") once passed generic DID validation here and became
 * a live account, and every record written under it got an AT-URI resolving
 * nowhere.
 *
 * did:web and other methods stay permitted — only the generic grammar applies
 * to them — but a did:plc must satisfy the method's own 24-character base32
 * rule. Returns 0 and logs when the value is unusable.
 */
static int did_env_is_usable(const char *name, const char *value) {
    if (!value || !value[0]) return 0; /* required_env already complained */

    if (!wf_syntax_did_is_valid(value)) {
        fprintf(stderr, "MetalBear [ERROR] %s is not a valid DID: %s\n",
                name, value);
        return 0;
    }
    if (strncmp(value, "did:plc:", 8) == 0 && !wf_syntax_did_plc_is_valid(value)) {
        fprintf(stderr,
                "MetalBear [ERROR] %s is not a valid did:plc: %s\n"
                "  A did:plc identifier is exactly 24 characters from the "
                "base32 alphabet abcdefghijklmnopqrstuvwxyz234567.\n"
                "  Mint a real one with METALBEAR_MINT_BOOTSTRAP_DID=1 rather "
                "than using a placeholder.\n",
                name, value);
        return 0;
    }
    return 1;
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
        .user_domain = required_env("METALBEAR_USER_DOMAIN"),
        /* Optional: generated and persisted on first start when unset. An
         * operator who wants the same identity authority across rebuilds
         * supplies it (refpds PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX). */
        .plc_rotation_key = getenv("METALBEAR_PLC_ROTATION_KEY"),
        .smtp_host = getenv("METALBEAR_SMTP_HOST"),
        .smtp_port = 0,
        .smtp_username = getenv("METALBEAR_SMTP_USERNAME"),
        .smtp_password = getenv("METALBEAR_SMTP_PASSWORD"),
        .from_address = getenv("METALBEAR_FROM_ADDRESS"),
        .from_name = getenv("METALBEAR_FROM_NAME"),
        .smtp_starttls = true,
        .account_email = getenv("METALBEAR_ACCOUNT_EMAIL"),
        .admin_password = getenv("METALBEAR_ADMIN_PASSWORD"),
        .crawlers = getenv("METALBEAR_CRAWLERS"),
        .plc_url = getenv("METALBEAR_PLC_URL"),
        .appview_url = getenv("METALBEAR_APPVIEW_URL"),
        .appview_did = getenv("METALBEAR_APPVIEW_DID"),
        .lexicon_dir = getenv("METALBEAR_LEXICON_DIR"),
        /* The reference PDS requires invite codes unless told otherwise;
         * defaulting to open registration turns any reachable host into one
         * anybody can create accounts on. */
        .invite_required = true,
        /* Match the reference PDS's 5 MB default. Defaulting to unlimited
         * makes an unauthenticated-adjacent upload path a disk-exhaustion
         * lever on a server whose operator never thought about it; an
         * operator who wants no cap can still set 0 explicitly. */
        .blob_upload_limit = 5 * 1024 * 1024,
    };
    /* Refuse to start on a malformed service identity rather than bake it into
     * repos that cannot be corrected afterwards. */
    if (!did_env_is_usable("METALBEAR_SERVICE_DID", config.service_did))
        return 1;

    const char *invite_required_text = getenv("METALBEAR_INVITE_REQUIRED");
    if (invite_required_text && (strcmp(invite_required_text, "0") == 0 ||
                          strcmp(invite_required_text, "false") == 0))
        config.invite_required = false;
    const char *blob_limit_text = getenv("METALBEAR_BLOB_UPLOAD_LIMIT");
    if (blob_limit_text && blob_limit_text[0]) {
        char *end = NULL;
        unsigned long long lim = strtoull(blob_limit_text, &end, 10);
        if (end && !*end)
            config.blob_upload_limit = (int64_t)lim;
    }
    const char *smtp_port_text = getenv("METALBEAR_SMTP_PORT");
    if (smtp_port_text && smtp_port_text[0]) {
        char *end = NULL;
        unsigned long p = strtoul(smtp_port_text, &end, 10);
        if (end && !*end && p <= 65535)
            config.smtp_port = (uint16_t)p;
    }
    if (!config.service_did || !config.user_domain)
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

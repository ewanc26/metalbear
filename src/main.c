#define _POSIX_C_SOURCE 200809L

#include "metalbear/config_file.h"
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

    /*
     * A config file supplies values; the environment overrides them.
     *
     * That order lets an operator keep a checked-in config.toml and still
     * override one setting per deployment without editing it, which is how the
     * container here is driven.
     */
    metalbear_config_file *config_owner = NULL;
    const char *config_path = getenv("METALBEAR_CONFIG");
    if (!config_path && access("config.toml", R_OK) == 0) config_path = "config.toml";

    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 2583,
        .thread_count = 4,
        .data_directory = "data",
        .smtp_starttls = true,
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

    if (config_path) {
        char cfg_err[512] = "";
        if (metalbear_config_file_load(config_path, &config, &config_owner,
                                       cfg_err, sizeof(cfg_err)) != WF_OK) {
            /* A config file that cannot be read is fatal: starting with
             * defaults would silently ignore what the operator asked for. */
            fprintf(stderr, "MetalBear [ERROR] %s\n",
                    cfg_err[0] ? cfg_err : "could not read config file");
            return 2;
        }
        fprintf(stderr, "MetalBear [INFO] loaded config from %s\n", config_path);
    }

    /* Environment overrides the file, one setting at a time. */
    #define ENV_STR(var, field) \
        do { const char *v = getenv(var); if (v && v[0]) config.field = v; } while (0)
    #define ENV_I64(var, field) \
        do { const char *v = getenv(var); if (v && v[0]) { \
                 char *e = NULL; long long n = strtoll(v, &e, 10); \
                 if (e && !*e) config.field = (int64_t)n; } } while (0)

    ENV_STR("METALBEAR_LISTEN",            listen_address);
    ENV_STR("METALBEAR_DATA",              data_directory);
    ENV_STR("METALBEAR_SERVICE_DID",       service_did);
    ENV_STR("METALBEAR_PUBLIC_URL",        public_url);
    ENV_STR("METALBEAR_USER_DOMAIN",       user_domain);
    ENV_STR("METALBEAR_PLC_ROTATION_KEY",  plc_rotation_key);
    ENV_STR("METALBEAR_PLC_URL",           plc_url);
    ENV_STR("METALBEAR_ADMIN_PASSWORD",    admin_password);
    ENV_STR("METALBEAR_CRAWLERS",          crawlers);
    ENV_STR("METALBEAR_APPVIEW_URL",       appview_url);
    ENV_STR("METALBEAR_APPVIEW_DID",       appview_did);
    ENV_STR("METALBEAR_LEXICON_DIR",       lexicon_dir);
    ENV_STR("METALBEAR_ACCOUNT_EMAIL",     account_email);
    ENV_STR("METALBEAR_OPERATOR_NAME",     operator_name);
    ENV_STR("METALBEAR_OPERATOR_URL",      operator_url);
    ENV_STR("METALBEAR_SUPPORT_URL",       support_url);
    ENV_STR("METALBEAR_DESCRIPTION",       instance_description);
    ENV_STR("METALBEAR_PRIVACY_POLICY",    privacy_policy_url);
    ENV_STR("METALBEAR_TERMS_OF_SERVICE",  terms_of_service_url);
    ENV_STR("METALBEAR_SMTP_HOST",         smtp_host);
    ENV_STR("METALBEAR_SMTP_USERNAME",     smtp_username);
    ENV_STR("METALBEAR_SMTP_PASSWORD",     smtp_password);
    ENV_STR("METALBEAR_FROM_ADDRESS",      from_address);
    ENV_STR("METALBEAR_FROM_NAME",         from_name);
    ENV_STR("METALBEAR_DNS_PROVIDER",      dns_provider);
    ENV_STR("METALBEAR_DNS_API_TOKEN",     dns_api_token);
    ENV_STR("METALBEAR_DNS_ZONE_ID",       dns_zone_id);

    ENV_I64("METALBEAR_RATE_LIMIT",              rate_limit);
    ENV_I64("METALBEAR_RATE_LIMIT_WINDOW",       rate_limit_window);
    ENV_I64("METALBEAR_BLOB_UPLOAD_LIMIT",       blob_upload_limit);
    ENV_I64("METALBEAR_DID_CACHE_TTL",           did_cache_ttl_seconds);
    ENV_I64("METALBEAR_DID_CACHE_ENTRIES",       did_cache_entries);
    ENV_I64("METALBEAR_CRAWL_NOTIFY_SECONDS",    crawl_notify_seconds);
    ENV_I64("METALBEAR_FIREHOSE_PING_SECONDS",   firehose_ping_seconds);
    ENV_I64("METALBEAR_RETENTION_MAX_AGE",       retention_max_age_seconds);
    ENV_I64("METALBEAR_RETENTION_MIN_EVENTS",    retention_min_events);
    ENV_I64("METALBEAR_DNS_TTL",                 dns_record_ttl);
    #undef ENV_STR
    #undef ENV_I64

    /* Only an explicitly set METALBEAR_PORT overrides the file; the parsed
     * default would otherwise silently win over a configured port. */
    if (port_text && port_text[0] && port > 0) config.port = (uint16_t)port;
    {
        const char *v = getenv("METALBEAR_DEVELOPMENT");
        if (v && (strcmp(v, "1") == 0 || strcmp(v, "true") == 0))
            config.development = true;
    }
    {
        const char *v = getenv("METALBEAR_THREADS");
        if (v && v[0]) {
            char *e = NULL; long n = strtol(v, &e, 10);
            if (e && !*e && n > 0) config.thread_count = (unsigned int)n;
        }
    }
    if (!config.service_did) {
        fprintf(stderr, "MetalBear [ERROR] METALBEAR_SERVICE_DID or "
                        "server.service_did is required\n");
        return 2;
    }
    if (!config.user_domain) {
        fprintf(stderr, "MetalBear [ERROR] METALBEAR_USER_DOMAIN or "
                        "server.user_domain is required\n");
        return 2;
    }
    /* Refuse to start on a malformed service identity rather than bake it into
     * repos that cannot be corrected afterwards. */
    if (!did_env_is_usable("METALBEAR_SERVICE_DID", config.service_did))
        return 1;

    const char *invite_required_text = getenv("METALBEAR_INVITE_REQUIRED");
    if (invite_required_text && (strcmp(invite_required_text, "0") == 0 ||
                          strcmp(invite_required_text, "false") == 0))
        config.invite_required = false;
    const char *rate_text = getenv("METALBEAR_RATE_LIMIT");
    if (rate_text && rate_text[0]) {
        char *end = NULL;
        long long v = strtoll(rate_text, &end, 10);
        if (end && !*end && v > 0) config.rate_limit = (int64_t)v;
    }
    const char *rate_window_text = getenv("METALBEAR_RATE_LIMIT_WINDOW");
    if (rate_window_text && rate_window_text[0]) {
        char *end = NULL;
        long long v = strtoll(rate_window_text, &end, 10);
        if (end && !*end && v > 0) config.rate_limit_window = (int64_t)v;
    }
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

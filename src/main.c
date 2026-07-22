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
#include "metalbear/key_rotation.h"

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

static int mint_bootstrap_did(const metalbear_config *config) {
    char *enc_did = encode_did_for_dir(config->account_did);
    if (!enc_did) {
        fprintf(stderr, "MetalBear [ERROR] failed to encode DID for directory\n");
        return 1;
    }

    size_t root_len = strlen(config->data_directory);
    size_t enc_len = strlen(enc_did);
    bool root_slash = root_len > 0 && config->data_directory[root_len - 1] == '/';
    char *dir = malloc(root_len + (root_slash ? 0 : 1) + enc_len + 1);
    if (!dir) {
        fprintf(stderr, "MetalBear [ERROR] allocation failed\n");
        free(enc_did);
        return 1;
    }
    snprintf(dir, root_len + (root_slash ? 0 : 1) + enc_len + 1,
             "%s%s%s", config->data_directory,
             root_slash ? "" : "/", enc_did);
    free(enc_did);

    if (!make_directory(dir)) {
        fprintf(stderr, "MetalBear [ERROR] cannot create account directory %s\n", dir);
        free(dir);
        return 1;
    }

    char *key_path = NULL;
    int key_path_len = snprintf(NULL, 0, "%s/keys.sqlite3", dir) + 1;
    key_path = malloc((size_t)key_path_len);
    if (!key_path) {
        fprintf(stderr, "MetalBear [ERROR] allocation failed\n");
        free(dir);
        return 1;
    }
    snprintf(key_path, (size_t)key_path_len, "%s/keys.sqlite3", dir);
    free(dir);

    metalbear_key_rotation *rotation = NULL;
    if (metalbear_key_rotation_open(key_path, &rotation) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot open key rotation store at %s\n", key_path);
        free(key_path);
        return 1;
    }
    free(key_path);

    wf_signing_key rotation_key;
    memset(&rotation_key, 0, sizeof(rotation_key));
    if (metalbear_key_rotation_current_key(rotation, &rotation_key) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot get rotation key\n");
        metalbear_key_rotation_free(rotation);
        return 1;
    }
    char *rotation_didkey = NULL;
    if (wf_signing_key_public_didkey(&rotation_key, &rotation_didkey) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot derive rotation did:key\n");
        metalbear_key_rotation_free(rotation);
        return 1;
    }

    wf_signing_key acct_key;
    memset(&acct_key, 0, sizeof(acct_key));
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &acct_key) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot generate account signing key\n");
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }
    char *acct_didkey = NULL;
    if (wf_signing_key_public_didkey(&acct_key, &acct_didkey) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot derive account did:key\n");
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }

    const char *handle = config->account_handle ? config->account_handle : "";
    const char *public_url = config->public_url ? config->public_url : "";
    const char *plc_url = config->plc_url ? config->plc_url : "https://plc.directory";

    char aka_buf[256];
    char services_buf[512];
    snprintf(aka_buf, sizeof(aka_buf), "at://%s", handle);
    snprintf(services_buf, sizeof(services_buf),
             "{\"atproto_pds\":{\"type\":\"AtprotoPersonalDataServer\","
             "\"endpoint\":\"%s\"}}",
             public_url);

    const char *rotation_keys[] = { rotation_didkey };
    wf_plc_operation_update update = {
        .rotation_keys = rotation_keys,
        .rotation_keys_count = 1,
        .verification_methods_json = NULL,
        .services_json = services_buf,
        .also_known_as = (const char *const[]){ aka_buf },
        .also_known_as_count = 1,
        .prev = NULL,
    };

    char *unsigned_json = NULL;
    if (wf_plc_operation_build(&update, &unsigned_json) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] failed to build PLC operation\n");
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }

    cJSON *root = cJSON_Parse(unsigned_json);
    if (!root) {
        fprintf(stderr, "MetalBear [ERROR] failed to parse unsigned operation JSON\n");
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }
    cJSON *verification = cJSON_GetObjectItemCaseSensitive(root, "verificationMethods");
    if (!cJSON_IsObject(verification)) {
        cJSON_Delete(root);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }
    {
        cJSON *old = cJSON_DetachItemFromObjectCaseSensitive(verification, "atproto");
        if (old) cJSON_Delete(old);
    }
    if (!cJSON_AddStringToObject(verification, "atproto", acct_didkey)) {
        cJSON_Delete(root);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }
    char *unsigned_with_key = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!unsigned_with_key) {
        fprintf(stderr, "MetalBear [ERROR] failed to serialize unsigned operation\n");
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }

    char *signed_json = NULL;
    if (wf_plc_operation_sign(unsigned_with_key, &rotation_key, &signed_json) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] failed to sign PLC operation\n");
        free(unsigned_with_key);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }

    char *plc_did = NULL;
    if (wf_plc_operation_compute_did(unsigned_with_key, &plc_did) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] failed to compute PLC DID\n");
        free(signed_json);
        free(unsigned_with_key);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }

    fprintf(stderr, "MetalBear [INFO] submitting PLC operation to %s for DID %s\n",
            plc_url, plc_did);
    if (wf_plc_submit_operation_raw(plc_url, plc_did, signed_json) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] failed to submit PLC operation to directory\n");
        free(plc_did);
        free(signed_json);
        free(unsigned_with_key);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        metalbear_key_rotation_free(rotation);
        return 1;
    }

    fprintf(stderr, "MetalBear [INFO] minted bootstrap PLC DID: %s\n", plc_did);
    printf("%s\n", plc_did);

    free(plc_did);
    free(signed_json);
    free(unsigned_with_key);
    free(unsigned_json);
    free(acct_didkey);
    free(rotation_didkey);
    metalbear_key_rotation_free(rotation);
    return 0;
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
        .admin_password = getenv("METALBEAR_ADMIN_PASSWORD"),
        .crawlers = getenv("METALBEAR_CRAWLERS"),
        .plc_url = getenv("METALBEAR_PLC_URL"),
        .invite_required = false,
        .blob_upload_limit = 0,
    };
    const char *invite_required_text = getenv("METALBEAR_INVITE_REQUIRED");
    if (invite_required_text && (strcmp(invite_required_text, "1") == 0 ||
                          strcmp(invite_required_text, "true") == 0))
        config.invite_required = true;
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
    const char *mint = getenv("METALBEAR_MINT_BOOTSTRAP_DID");
    if (mint && mint[0] == '1') {
        if (!config.service_did || !config.account_did || !config.account_handle ||
            !config.user_domain || !config.password || !config.password[0] ||
            !config.data_directory) {
            fprintf(stderr, "MetalBear [ERROR] invalid config for mint mode\n");
            return 2;
        }
        return mint_bootstrap_did(&config);
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

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

/*
 * Mint a fresh did:plc for the bootstrap account and leave it immediately
 * usable.
 *
 * A DID's name is the hash of its own genesis operation, so neither key can be
 * filed under the account directory until the operation is signed and the DID
 * computed. Both keys are therefore generated in memory first, and only once
 * the directory name is known are they persisted:
 *
 *   - the rotation key into keys.sqlite3, so later PLC operations for this DID
 *     can actually be signed;
 *   - the account signing key into the repo store, so the repo signs its
 *     commits with exactly the key this operation publishes as
 *     verificationMethods.atproto.
 *
 * Persisting the signing key is what makes the identity federate. Publishing a
 * key and then letting the repo store generate its own — as this did before —
 * produces a DID document that disagrees with every commit the repo signs, so
 * relays and AppViews reject the repo outright while the PDS reports success.
 */
static int mint_bootstrap_did(const metalbear_config *config) {
    wf_signing_key rotation_key;
    memset(&rotation_key, 0, sizeof(rotation_key));
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &rotation_key) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot generate rotation key\n");
        return 1;
    }
    char *rotation_didkey = NULL;
    if (wf_signing_key_public_didkey(&rotation_key, &rotation_didkey) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot derive rotation did:key\n");
        return 1;
    }

    wf_signing_key acct_key;
    memset(&acct_key, 0, sizeof(acct_key));
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &acct_key) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot generate account signing key\n");
        free(rotation_didkey);
        return 1;
    }
    char *acct_didkey = NULL;
    if (wf_signing_key_public_didkey(&acct_key, &acct_didkey) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] cannot derive account did:key\n");
        free(rotation_didkey);
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
        return 1;
    }

    cJSON *root = cJSON_Parse(unsigned_json);
    if (!root) {
        fprintf(stderr, "MetalBear [ERROR] failed to parse unsigned operation JSON\n");
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        return 1;
    }
    cJSON *verification = cJSON_GetObjectItemCaseSensitive(root, "verificationMethods");
    if (!cJSON_IsObject(verification)) {
        cJSON_Delete(root);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
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
        return 1;
    }
    char *unsigned_with_key = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!unsigned_with_key) {
        fprintf(stderr, "MetalBear [ERROR] failed to serialize unsigned operation\n");
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        return 1;
    }

    char *signed_json = NULL;
    if (wf_plc_operation_sign(unsigned_with_key, &rotation_key, &signed_json) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] failed to sign PLC operation\n");
        free(unsigned_with_key);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
        return 1;
    }

    char *plc_did = NULL;
    if (wf_plc_operation_compute_did(signed_json, &plc_did) != WF_OK) {
        fprintf(stderr, "MetalBear [ERROR] failed to compute PLC DID\n");
        free(signed_json);
        free(unsigned_with_key);
        free(unsigned_json);
        free(acct_didkey);
        free(rotation_didkey);
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
        return 1;
    }

    /* The DID now exists in the directory, so its account directory can be
     * named and both keys filed where the server will look for them. */
    int rc = 1;
    char *dir = account_dir_for_did(config, plc_did);
    char *key_path = dir ? path_join(dir, "keys.sqlite3") : NULL;
    char *repo_path = dir ? path_join(dir, "repo.sqlite3") : NULL;
    if (!dir || !key_path || !repo_path) {
        fprintf(stderr, "MetalBear [ERROR] allocation failed\n");
        goto cleanup;
    }
    if (!make_directory(dir)) {
        fprintf(stderr, "MetalBear [ERROR] cannot create account directory %s\n",
                dir);
        goto cleanup;
    }

    metalbear_key_rotation *rotation = NULL;
    if (metalbear_key_rotation_open(key_path, &rotation) != WF_OK ||
        metalbear_key_rotation_import(rotation, &rotation_key) != WF_OK) {
        fprintf(stderr,
                "MetalBear [ERROR] cannot persist rotation key at %s; the DID "
                "was published but no further PLC operation for it could be "
                "signed\n", key_path);
        metalbear_key_rotation_free(rotation);
        goto cleanup;
    }
    metalbear_key_rotation_free(rotation);

    /* Create the repo with the signing key just published, so its commits
     * verify against the DID document. */
    metalbear_repo_store *repo = NULL;
    if (metalbear_repo_store_open_with_key(repo_path, plc_did,
                                           config->account_handle, &acct_key,
                                           &repo) != WF_OK) {
        fprintf(stderr,
                "MetalBear [ERROR] cannot create repo at %s with the published "
                "signing key\n", repo_path);
        goto cleanup;
    }
    const char *stored = metalbear_repo_store_signing_key_did(repo);
    if (!stored || strcmp(stored, acct_didkey) != 0) {
        fprintf(stderr,
                "MetalBear [ERROR] repo signing key %s does not match the "
                "published key %s\n", stored ? stored : "(none)", acct_didkey);
        metalbear_repo_store_free(repo);
        goto cleanup;
    }
    metalbear_repo_store_free(repo);

    fprintf(stderr, "MetalBear [INFO] minted bootstrap PLC DID: %s\n", plc_did);
    fprintf(stderr, "MetalBear [INFO] signing key %s published and stored in %s\n",
            acct_didkey, repo_path);
    fprintf(stderr, "MetalBear [INFO] set METALBEAR_ACCOUNT_DID=%s and restart\n",
            plc_did);
    printf("%s\n", plc_did);
    rc = 0;

cleanup:
    free(dir);
    free(key_path);
    free(repo_path);
    free(plc_did);
    free(signed_json);
    free(unsigned_with_key);
    free(unsigned_json);
    free(acct_didkey);
    free(rotation_didkey);
    return rc;
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

    /* Mint mode derives the account DID from the operation it is about to
     * publish, so METALBEAR_ACCOUNT_DID is neither needed nor meaningful yet —
     * demanding a valid one up front would make the operator supply the very
     * identifier they are asking to have minted. */
    const char *mint = getenv("METALBEAR_MINT_BOOTSTRAP_DID");
    const bool minting = mint && mint[0] == '1';

    metalbear_config config = {
        .listen_address = listen_address && listen_address[0]
                              ? listen_address : "127.0.0.1",
        .port = (uint16_t)port,
        .thread_count = 4,
        .data_directory = data_directory && data_directory[0]
                              ? data_directory : "data",
        .service_did = required_env("METALBEAR_SERVICE_DID"),
        .public_url = getenv("METALBEAR_PUBLIC_URL"),
        /* Not required when minting: the DID is the output of that run. */
        .account_did = minting ? getenv("METALBEAR_ACCOUNT_DID")
                               : required_env("METALBEAR_ACCOUNT_DID"),
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
        .appview_url = getenv("METALBEAR_APPVIEW_URL"),
        .appview_did = getenv("METALBEAR_APPVIEW_DID"),
        .invite_required = false,
        .blob_upload_limit = 0,
    };
    /* Refuse to start on a malformed identity rather than bake it into a repo
     * that cannot be corrected afterwards. */
    if ((!minting &&
         !did_env_is_usable("METALBEAR_ACCOUNT_DID", config.account_did)) ||
        !did_env_is_usable("METALBEAR_SERVICE_DID", config.service_did))
        return 1;

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
    if (minting) {
        if (!config.service_did || !config.account_handle ||
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

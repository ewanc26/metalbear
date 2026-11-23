#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "metalbear/oauth/auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int failures;
#define CHECK(expression)                                                      \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,            \
                    #expression);                                              \
            failures++;                                                        \
        }                                                                      \
    } while (0)

int main(void) {
    char path[] = "/tmp/metalbear-auth-XXXXXX";
    int descriptor = mkstemp(path);
    CHECK(descriptor >= 0);
    if (descriptor < 0) return 1;
    close(descriptor);
    unlink(path);

    metalbear_auth_store *store = NULL;
    CHECK(metalbear_auth_store_open(path, "did:web:pds.example.com",
                                    "did:plc:alice", &store) == WF_OK);
    CHECK(store != NULL);
    struct stat info;
    CHECK(stat(path, &info) == 0 && (info.st_mode & 0777) == 0600);

    metalbear_session_tokens first = {0};
    CHECK(metalbear_auth_create_session(store, &first) == WF_OK);
    CHECK(first.access_jwt && first.refresh_jwt);
    CHECK(metalbear_auth_verify_access(store, first.access_jwt) == WF_OK);

    metalbear_session_tokens app_session = {0};
    CHECK(metalbear_auth_create_scoped_session(
              store, METALBEAR_ACCESS_APP_PASSWORD, "desktop", &app_session) ==
          WF_OK);
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    CHECK(metalbear_auth_verify_access_scope(store, app_session.access_jwt,
                                             &scope) == WF_OK);
    CHECK(scope == METALBEAR_ACCESS_APP_PASSWORD);
    metalbear_session_tokens app_rotated = {0};
    metalbear_session_tokens rejected = {0};
    CHECK(metalbear_auth_rotate_refresh(store, app_session.refresh_jwt,
                                        &app_rotated) == WF_OK);
    scope = METALBEAR_ACCESS_FULL;
    CHECK(metalbear_auth_verify_access_scope(store, app_rotated.access_jwt,
                                             &scope) == WF_OK);
    CHECK(scope == METALBEAR_ACCESS_APP_PASSWORD);
    CHECK(metalbear_auth_revoke_app_password_sessions(store, "desktop") ==
          WF_OK);
    CHECK(metalbear_auth_rotate_refresh(store, app_rotated.refresh_jwt,
                                        &rejected) == WF_ERR_PERMISSION);
    CHECK(metalbear_auth_verify_access(store, first.refresh_jwt) ==
          WF_ERR_PERMISSION);

    char *tampered = strdup(first.access_jwt);
    CHECK(tampered != NULL);
    if (tampered) {
        size_t length = strlen(tampered);
        tampered[length - 1] = tampered[length - 1] == 'A' ? 'B' : 'A';
        CHECK(metalbear_auth_verify_access(store, tampered) ==
              WF_ERR_PERMISSION);
    }
    free(tampered);

    /* The signing secret and refresh registry survive process restarts. */
    metalbear_auth_store_free(store);
    store = NULL;
    CHECK(metalbear_auth_store_open(path, "did:web:pds.example.com",
                                    "did:plc:alice", &store) == WF_OK);
    CHECK(metalbear_auth_verify_access(store, first.access_jwt) == WF_OK);

    metalbear_session_tokens rotated = {0};
    CHECK(metalbear_auth_rotate_refresh(store, first.refresh_jwt, &rotated) ==
          WF_OK);
    CHECK(rotated.access_jwt && rotated.refresh_jwt &&
          strcmp(rotated.refresh_jwt, first.refresh_jwt) != 0);

    /* Reusing the predecessor inside the grace period yields its established
     * successor rather than branching the refresh-token chain. */
    metalbear_session_tokens reused = {0};
    CHECK(metalbear_auth_rotate_refresh(store, first.refresh_jwt, &reused) ==
          WF_OK);
    CHECK(reused.refresh_jwt &&
          strcmp(reused.refresh_jwt, first.refresh_jwt) != 0);

    CHECK(metalbear_auth_revoke_refresh(store, rotated.refresh_jwt) == WF_OK);
    CHECK(metalbear_auth_rotate_refresh(store, rotated.refresh_jwt,
                                        &rejected) == WF_ERR_PERMISSION);
    CHECK(metalbear_auth_rotate_refresh(store, reused.refresh_jwt, &rejected) ==
          WF_ERR_PERMISSION);
    CHECK(metalbear_auth_rotate_refresh(store, first.refresh_jwt, &rejected) ==
          WF_ERR_PERMISSION);

    /* Trusted devices (issue #131): only the keyed hash is stored, and an
     * expired row can neither validate nor appear in a listing. */
    int64_t now = (int64_t)time(NULL);
    unsigned char hash1[32], hash2[32], wrong[32];
    memset(hash1, 1, sizeof(hash1));
    memset(hash2, 2, sizeof(hash2));
    memset(wrong, 3, sizeof(wrong));
    bool valid = true;
    CHECK(metalbear_auth_trusted_device_valid(store, hash1, &valid) == WF_OK);
    CHECK(valid == false);
    CHECK(metalbear_auth_trusted_device_add(store, "device-one", hash1,
                                            now - 10, now + 3600) == WF_OK);
    CHECK(metalbear_auth_trusted_device_valid(store, hash1, &valid) == WF_OK);
    CHECK(valid == true);
    CHECK(metalbear_auth_trusted_device_valid(store, wrong, &valid) == WF_OK);
    CHECK(valid == false);
    metalbear_auth_trusted_device *devices = NULL;
    size_t count = 0;
    CHECK(metalbear_auth_trusted_device_list(store, &devices, &count) == WF_OK);
    CHECK(count == 1);
    if (count == 1) {
        CHECK(strcmp(devices[0].id, "device-one") == 0);
        CHECK(devices[0].created_at == now - 10);
        CHECK(devices[0].expires_at == now + 3600);
    }

    /* An already-expired row is pruned on the next write and never validates,
     * however it got into the database. */
    CHECK(metalbear_auth_trusted_device_add(store, "device-expired", hash2,
                                            now - 100, now - 1) == WF_OK);
    CHECK(metalbear_auth_trusted_device_valid(store, hash2, &valid) == WF_OK);
    CHECK(valid == false);
    metalbear_auth_trusted_device_list_free(devices, count);
    devices = NULL;
    count = 0;
    CHECK(metalbear_auth_trusted_device_list(store, &devices, &count) == WF_OK);
    CHECK(count == 1);

    bool removed = true;
    CHECK(metalbear_auth_trusted_device_remove(store, "missing", &removed) ==
          WF_OK);
    CHECK(removed == false);
    CHECK(metalbear_auth_trusted_device_remove(store, "device-one", &removed) ==
          WF_OK);
    CHECK(removed == true);
    CHECK(metalbear_auth_trusted_device_valid(store, hash1, &valid) == WF_OK);
    CHECK(valid == false);
    CHECK(metalbear_auth_trusted_device_remove(store, "device-one", &removed) ==
          WF_OK);
    CHECK(removed == false);
    metalbear_auth_trusted_device_list_free(devices, count);

    /* A stored device survives a process restart, so a browser can keep its
     * token across server restarts. */
    CHECK(metalbear_auth_trusted_device_add(store, "device-one", hash1,
                                            now - 10, now + 3600) == WF_OK);
    metalbear_auth_store_free(store);
    store = NULL;
    CHECK(metalbear_auth_store_open(path, "did:web:pds.example.com",
                                    "did:plc:alice", &store) == WF_OK);
    CHECK(metalbear_auth_trusted_device_valid(store, hash1, &valid) == WF_OK);
    CHECK(valid == true);
    CHECK(metalbear_auth_trusted_device_remove_all(store) == WF_OK);
    devices = NULL;
    count = 1;
    CHECK(metalbear_auth_trusted_device_list(store, &devices, &count) == WF_OK);
    CHECK(count == 0);

    /* An admin password reset and turning 2FA off both drop every device. */
    CHECK(metalbear_auth_trusted_device_add(store, "device-one", hash1,
                                            now - 10, now + 3600) == WF_OK);
    CHECK(metalbear_auth_delete_all(store) == WF_OK);
    CHECK(metalbear_auth_trusted_device_valid(store, hash1, &valid) == WF_OK);
    CHECK(valid == false);
    CHECK(metalbear_auth_trusted_device_add(store, "device-one", hash1,
                                            now - 10, now + 3600) == WF_OK);
    CHECK(metalbear_auth_totp_disable(store) == WF_OK);
    CHECK(metalbear_auth_trusted_device_valid(store, hash1, &valid) == WF_OK);
    CHECK(valid == false);
    metalbear_auth_trusted_device_list_free(devices, count);

    metalbear_session_tokens_free(&first);
    metalbear_session_tokens_free(&rotated);
    metalbear_session_tokens_free(&reused);
    metalbear_session_tokens_free(&rejected);
    metalbear_session_tokens_free(&app_session);
    metalbear_session_tokens_free(&app_rotated);
    metalbear_auth_store_free(store);
    unlink(path);
    char sidecar[256];
    snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
    unlink(sidecar);

    if (failures) fprintf(stderr, "%d auth test(s) failed\n", failures);
    return failures ? 1 : 0;
}

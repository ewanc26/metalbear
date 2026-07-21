#define _POSIX_C_SOURCE 200809L

#include "metalbear/account_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression); \
    failures++; } } while (0)

int main(void) {
    char path[] = "/tmp/metalbear-registry-XXXXXX";
    int descriptor = mkstemp(path);
    CHECK(descriptor >= 0);
    if (descriptor < 0) return 1;
    close(descriptor);
    unlink(path);

    metalbear_account_registry *registry = NULL;
    CHECK(metalbear_account_registry_open(path, &registry) == WF_OK);
    CHECK(registry != NULL);

    /* Add accounts */
    CHECK(metalbear_account_registry_add(registry,
            "did:plc:alice", "alice.example.com",
            "hash1", "/data/alice") == WF_OK);
    CHECK(metalbear_account_registry_add(registry,
            "did:plc:bob", "bob.example.com",
            "hash2", "/data/bob") == WF_OK);

    /* Duplicate handle */
    CHECK(metalbear_account_registry_add(registry,
            "did:plc:alice2", "alice.example.com",
            "hash3", "/data/alice2") == WF_ERR_CONFLICT);

    /* Find by handle */
    metalbear_account_entry *entry = NULL;
    CHECK(metalbear_account_registry_find_by_handle(registry,
            "alice.example.com", &entry) == WF_OK);
    CHECK(entry != NULL);
    CHECK(strcmp(entry->did, "did:plc:alice") == 0);
    CHECK(strcmp(entry->handle, "alice.example.com") == 0);
    CHECK(strcmp(entry->data_directory, "/data/alice") == 0);
    CHECK(entry->active == 1);
    metalbear_account_entry_free(entry);

    /* Find by DID */
    entry = NULL;
    CHECK(metalbear_account_registry_find_by_did(registry,
            "did:plc:bob", &entry) == WF_OK);
    CHECK(entry != NULL);
    CHECK(strcmp(entry->handle, "bob.example.com") == 0);
    metalbear_account_entry_free(entry);

    /* Find nonexistent */
    entry = NULL;
    CHECK(metalbear_account_registry_find_by_handle(registry,
            "nobody.example.com", &entry) == WF_ERR_NOT_FOUND);
    CHECK(entry == NULL);

    /* List all */
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    CHECK(metalbear_account_registry_list(registry, &entries, &count) == WF_OK);
    CHECK(count == 2);
    CHECK(strcmp(entries[0].handle, "alice.example.com") == 0);
    CHECK(strcmp(entries[1].handle, "bob.example.com") == 0);
    metalbear_account_entries_free(entries, count);

    /* Remove account */
    CHECK(metalbear_account_registry_remove(registry, "did:plc:bob") == WF_OK);
    CHECK(metalbear_account_registry_find_by_did(registry,
            "did:plc:bob", &entry) == WF_ERR_NOT_FOUND);

    entries = NULL;
    count = 0;
    CHECK(metalbear_account_registry_list(registry, &entries, &count) == WF_OK);
    CHECK(count == 1);
    CHECK(strcmp(entries[0].handle, "alice.example.com") == 0);
    metalbear_account_entries_free(entries, count);

    /* Persistence across restart */
    metalbear_account_registry_free(registry);
    registry = NULL;
    CHECK(metalbear_account_registry_open(path, &registry) == WF_OK);
    entries = NULL;
    count = 0;
    CHECK(metalbear_account_registry_list(registry, &entries, &count) == WF_OK);
    CHECK(count == 1);
    CHECK(strcmp(entries[0].did, "did:plc:alice") == 0);
    metalbear_account_entries_free(entries, count);

    /* account_dir_for_did: ':' is encoded as '_', joined to the root */
    char *dir = NULL;
    CHECK(metalbear_account_dir_for_did("/srv/pds", "did:plc:abc123",
                                         &dir) == WF_OK);
    CHECK(dir != NULL);
    CHECK(strcmp(dir, "/srv/pds/did_plc_abc123") == 0);
    free(dir);
    /* Trailing slash on root is preserved without doubling */
    dir = NULL;
    CHECK(metalbear_account_dir_for_did("/srv/pds/", "did:web:example.com",
                                         &dir) == WF_OK);
    CHECK(strcmp(dir, "/srv/pds/did_web_example.com") == 0);
    free(dir);

    /* --- Invite code tests --- */

    /* Create invite codes */
    const char *code1 = "TEST-CODE-AAAA";
    const char *code2 = "TEST-CODE-BBBB";
    const char *code3 = "TEST-CODE-CCCC";
    const char *codes_batch[] = { code1, code2, code3 };
    CHECK(metalbear_account_registry_create_invite_codes(
            registry, "admin", codes_batch, 3, 2) == WF_OK);

    /* Get invite codes for admin */
    metalbear_invite_code_entry *icode_entries = NULL;
    size_t icode_count = 0;
    CHECK(metalbear_account_registry_get_invite_codes(
            registry, "admin", &icode_entries, &icode_count) == WF_OK);
    CHECK(icode_count == 3);
    /* Verify codes exist (order may vary with same timestamp) */
    int found_c1 = 0, found_c2 = 0, found_c3 = 0;
    for (size_t i = 0; i < icode_count; i++) {
        if (strcmp(icode_entries[i].code, code1) == 0) found_c1 = 1;
        if (strcmp(icode_entries[i].code, code2) == 0) found_c2 = 1;
        if (strcmp(icode_entries[i].code, code3) == 0) found_c3 = 1;
        CHECK(strcmp(icode_entries[i].for_account, "admin") == 0);
    }
    CHECK(found_c1 && found_c2 && found_c3);
    metalbear_invite_code_entries_free(icode_entries, icode_count);

    /* Consume an invite code (use 1 of 2) */
    CHECK(metalbear_account_registry_consume_invite_code(
            registry, code1, "did:plc:alice") == WF_OK);

    /* Verify remaining uses */
    icode_entries = NULL;
    icode_count = 0;
    CHECK(metalbear_account_registry_get_invite_codes(
            registry, "admin", &icode_entries, &icode_count) == WF_OK);
    CHECK(icode_count == 3);
    /* Find code1 in the results */
    int found_code1 = 0;
    for (size_t i = 0; i < icode_count; i++) {
        if (strcmp(icode_entries[i].code, code1) == 0) {
            CHECK(icode_entries[i].uses_remaining == 1);
            found_code1 = 1;
        }
    }
    CHECK(found_code1);
    metalbear_invite_code_entries_free(icode_entries, icode_count);

    /* Consume again (use 2 of 2) */
    CHECK(metalbear_account_registry_consume_invite_code(
            registry, code1, "did:plc:bob") == WF_OK);

    /* Consume once more — should fail (exhausted) */
    CHECK(metalbear_account_registry_consume_invite_code(
            registry, code1, "did:plc:charlie") != WF_OK);

    /* Nonexistent code */
    CHECK(metalbear_account_registry_consume_invite_code(
            registry, "DOES-NOT-EXIST", "did:plc:alice") == WF_ERR_NOT_FOUND);

    /* Persistence across restart */
    metalbear_account_registry_free(registry);
    registry = NULL;
    CHECK(metalbear_account_registry_open(path, &registry) == WF_OK);
    icode_entries = NULL;
    icode_count = 0;
    CHECK(metalbear_account_registry_get_invite_codes(
            registry, "admin", &icode_entries, &icode_count) == WF_OK);
    CHECK(icode_count == 3);
    metalbear_invite_code_entries_free(icode_entries, icode_count);

    metalbear_account_registry_free(registry);
    unlink(path);
    char sidecar[256];
    snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
    unlink(sidecar);

    if (failures) fprintf(stderr, "%d registry test(s) failed\n", failures);
    return failures ? 1 : 0;
}

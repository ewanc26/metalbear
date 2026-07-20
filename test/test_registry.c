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

#define _POSIX_C_SOURCE 200809L

#include "metalbear/backup.h"
#include "metalbear/email.h"
#include "metalbear/sequencer.h"

#include <sqlite3.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_DIR "/tmp/test_metalbear_backup"
#define TEST_DB TEST_DIR "/test.sqlite3"
#define TEST_BACKUP TEST_DIR "/backup.dat"
#define TEST_RESTORE_DIR TEST_DIR "/restore"

static void test_backup_create_restore(void) {
    printf("test_backup_create_restore...\n");
    mkdir(TEST_DIR, 0700);
    /* Create a test database */
    sqlite3 *db = NULL;
    assert(sqlite3_open(TEST_DB, &db) == SQLITE_OK);
    assert(sqlite3_exec(db,
        "CREATE TABLE test(id INTEGER PRIMARY KEY, value TEXT);"
        "INSERT INTO test(value) VALUES('hello');"
        "INSERT INTO test(value) VALUES('world');",
        NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
    /* Create backup */
    assert(metalbear_backup_create(TEST_DIR, TEST_BACKUP) == WF_OK);
    /* Verify backup */
    assert(metalbear_backup_verify(TEST_BACKUP) == WF_OK);
    /* Restore to new location */
    mkdir(TEST_RESTORE_DIR, 0700);
    assert(metalbear_backup_restore(TEST_BACKUP, TEST_RESTORE_DIR) == WF_OK);
    /* Verify restored data */
    char restored_path[512];
    snprintf(restored_path, sizeof(restored_path), "%s/test.sqlite3",
             TEST_RESTORE_DIR);
    assert(sqlite3_open(restored_path, &db) == SQLITE_OK);
    sqlite3_stmt *stmt = NULL;
    assert(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM test;", -1, &stmt,
                              NULL) == SQLITE_OK);
    assert(sqlite3_step(stmt) == SQLITE_ROW);
    assert(sqlite3_column_int(stmt, 0) == 2);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    /* Test invalid backup */
    assert(metalbear_backup_verify("/nonexistent") == WF_ERR_NOT_FOUND);
    assert(metalbear_backup_restore("/nonexistent", TEST_RESTORE_DIR) ==
           WF_ERR_NOT_FOUND);
    printf("  PASS\n");
}

static void test_backup_verify_corrupted(void) {
    printf("test_backup_verify_corrupted...\n");
    mkdir(TEST_DIR, 0700);
    /* Create a corrupted backup */
    FILE *f = fopen(TEST_BACKUP, "wb");
    assert(f);
    const char garbage[] = "this is not a valid backup";
    fwrite(garbage, 1, sizeof(garbage) - 1, f);
    fclose(f);
    assert(metalbear_backup_verify(TEST_BACKUP) == WF_ERR_INVALID_ARG);
    printf("  PASS\n");
}

static void test_email_config(void) {
    printf("test_email_config...\n");
    metalbear_email_config config = {
        .smtp_host = "smtp.example.com",
        .smtp_port = 587,
        .smtp_username = "user@example.com",
        .smtp_password = "password",
        .from_address = "test@example.com",
        .from_name = "Test Server",
        .smtp_starttls = true,
    };
    metalbear_email *email = NULL;
    assert(metalbear_email_open(&config, &email) == WF_OK);
    assert(email != NULL);
    metalbear_email_free(email);
    /* Test invalid config */
    assert(metalbear_email_open(NULL, &email) == WF_ERR_INVALID_ARG);
    metalbear_email_config bad = {0};
    assert(metalbear_email_open(&bad, &email) == WF_ERR_INVALID_ARG);
    printf("  PASS\n");
}

static void test_sequencer_retention(void) {
    printf("test_sequencer_retention...\n");
    char path[] = "/tmp/test_retention_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    metalbear_sequencer *seq = NULL;
    assert(metalbear_sequencer_open(path, "did:plc:test", "test.example.com",
                                    &seq) == WF_OK);
    /* Add some events */
    for (int i = 0; i < 10; i++) {
        assert(metalbear_sequencer_account_status(seq, "did:plc:test", 1,
                                                  NULL) == WF_OK);
    }
    int64_t before = metalbear_sequencer_current(seq);
    assert(before >= 10);
    /* Retain with very old age should not remove anything since we have
     * fewer events than min_events */
    assert(metalbear_sequencer_retain(seq, 1, 100) == WF_OK);
    int64_t after = metalbear_sequencer_current(seq);
    assert(after == before);
    metalbear_sequencer_free(seq);
    unlink(path);
    printf("  PASS\n");
}

int main(void) {
    printf("MetalBear backup/email/retention tests\n");
    test_backup_create_restore();
    test_backup_verify_corrupted();
    test_email_config();
    test_sequencer_retention();
    printf("All tests passed.\n");
    /* Cleanup */
    unlink(TEST_DB);
    unlink(TEST_BACKUP);
    unlink(TEST_RESTORE_DIR "/test.sqlite3");
    rmdir(TEST_RESTORE_DIR);
    rmdir(TEST_DIR);
    return 0;
}

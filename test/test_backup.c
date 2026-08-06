#define _POSIX_C_SOURCE 200809L

#include "metalbear/repo/backup.h"
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

/*
 * Clear anything a previous run left behind.
 *
 * Cleanup only happened at the end of main, so an assertion failure anywhere
 * left TEST_DB in place — and the next run then failed on CREATE TABLE before
 * reaching the code under test, turning one bad run into a permanently red
 * test that says nothing about the current build.
 */
static void reset_test_dir(void) {
    unlink(TEST_RESTORE_DIR "/test.sqlite3");
    rmdir(TEST_RESTORE_DIR);
    unlink(TEST_BACKUP);
    unlink(TEST_DB);
    rmdir(TEST_DIR);
}

static void test_backup_create_restore(void) {
    printf("test_backup_create_restore...\n");
    reset_test_dir();
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
    assert(metalbear_sequencer_open(path, &seq) == WF_OK);
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

/* Read the pruning high-water mark straight from the log. */
static int64_t read_pruned_through(const char *path) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int64_t value = -1;
    if (sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
                           "SELECT value FROM meta "
                           "WHERE key='pruned_through';",
                           -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        value = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return value;
}

/*
 * Retention must record what it deleted, and record nothing when it deletes
 * nothing.
 *
 * That mark is the only honest basis for answering OutdatedCursor: once a row
 * is gone there is nothing left to infer the deletion from, the log simply
 * starts later. Note it cannot be inferred from the oldest surviving event
 * either — sequence numbers are seeded from wall-clock time, so a brand-new
 * log legitimately starts in the billions and a subscriber asking from 0 has
 * missed nothing at all.
 */
static void test_sequencer_prune_watermark(void) {
    printf("test_sequencer_prune_watermark...\n");
    char path[] = "/tmp/test_prune_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);

    metalbear_sequencer *seq = NULL;
    assert(metalbear_sequencer_open(path, &seq) == WF_OK);
    for (int i = 0; i < 10; i++) {
        assert(metalbear_sequencer_account_status(seq, "did:plc:test", 1,
                                                  NULL) == WF_OK);
    }

    /* Keeping more events than exist must delete nothing, and so must leave
     * no mark: a cursor of 0 here has missed nothing. */
    assert(metalbear_sequencer_retain(seq, 0, 100) == WF_OK);
    assert(read_pruned_through(path) == -1);

    /*
     * Now prune for real. created_at is stored at one-second granularity, so
     * rows written in the current second are not yet "older than now" — wait
     * past the boundary rather than letting the result depend on where in the
     * second the test happened to start.
     */
    int64_t current = metalbear_sequencer_current(seq);
    sleep(2);
    assert(metalbear_sequencer_retain(seq, 0, 3) == WF_OK);
    int64_t mark = read_pruned_through(path);
    assert(mark > 0);
    assert(mark <= current);

    metalbear_sequencer_free(seq);
    unlink(path);
    printf("  PASS\n");
}

/*
 * A firehose sequence must not restart at 1 on a fresh event log. Cursors are
 * per-host and consumers persist them, so a rebuilt PDS that reuses numbers it
 * already issued leaves every consumer holding a higher cursor stuck on
 * FutureCursor forever — observed as a relay reconnect-looping on cursor=390
 * against a log that had restarted.
 */
static void test_sequencer_seq_floor(void) {
    printf("test_sequencer_seq_floor...\n");
    char path[] = "/tmp/test_seqfloor_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);

    metalbear_sequencer *seq = NULL;
    assert(metalbear_sequencer_open(path, &seq) == WF_OK);
    /*
     * The floor is the AUTOINCREMENT watermark, not a row: a fresh log holds
     * no events, so what matters is the number the first event is given.
     * (This used to be observable directly because opening a log seeded the
     * configured account's events into it — nothing is seeded now.)
     */
    assert(metalbear_sequencer_current(seq) == 0);
    assert(metalbear_sequencer_account_status(seq, "did:plc:test", 1, NULL) ==
           WF_OK);
    int64_t first = metalbear_sequencer_current(seq);
    /* Seeded from wall-clock seconds, so far above any counter a previous
     * incarnation of this host is likely to have reached. */
    assert(first > 1000000000);
    metalbear_sequencer_free(seq);

    /* Reopening must continue the existing sequence, never reseed it. */
    seq = NULL;
    assert(metalbear_sequencer_open(path, &seq) == WF_OK);
    int64_t reopened = metalbear_sequencer_current(seq);
    assert(reopened == first);
    assert(metalbear_sequencer_account_status(seq, "did:plc:test", 1, NULL) ==
           WF_OK);
    assert(metalbear_sequencer_current(seq) > reopened);
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
    test_sequencer_seq_floor();
    test_sequencer_prune_watermark();
    printf("All tests passed.\n");
    /* Cleanup */
    unlink(TEST_DB);
    unlink(TEST_BACKUP);
    unlink(TEST_RESTORE_DIR "/test.sqlite3");
    rmdir(TEST_RESTORE_DIR);
    rmdir(TEST_DIR);
    return 0;
}

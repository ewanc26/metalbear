/*
 * test_schema_version.c — every MetalBear database records a schema version,
 * stamps a pre-version database as version 1, and refuses one written by a
 * newer build (metalbear/schema_version.h).
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth/auth.h"
#include "metalbear/schema_version.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static int user_version(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &st, NULL) ==
            SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void set_version(const char *path, int v) {
    sqlite3 *db = NULL;
    char sql[40];
    snprintf(sql, sizeof sql, "PRAGMA user_version=%d;", v);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
}

int main(void) {
    char path[] = "/tmp/metalbear_schema_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    close(fd);

    /* A database from before versions existed reads 0 and is stamped 1. */
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(user_version(db) == 0);
    CHECK(metalbear_schema_open(db, "test") == WF_OK);
    CHECK(user_version(db) == METALBEAR_SCHEMA_VERSION);
    /* Reopening a current database is a no-op. */
    CHECK(metalbear_schema_open(db, "test") == WF_OK);
    sqlite3_close(db);

    /* A database written by a newer build is refused, and left alone. */
    set_version(path, METALBEAR_SCHEMA_VERSION + 1);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(metalbear_schema_open(db, "test") == WF_ERR_INTERNAL);
    CHECK(user_version(db) == METALBEAR_SCHEMA_VERSION + 1);
    sqlite3_close(db);

    /* A real store refuses it too, instead of migrating it. */
    metalbear_auth_store *store = NULL;
    CHECK(metalbear_auth_store_open(path, "did:web:pds.example.com",
                                    "did:plc:alice", &store) != WF_OK);
    CHECK(store == NULL);
    set_version(path, 0);
    CHECK(metalbear_auth_store_open(path, "did:web:pds.example.com",
                                    "did:plc:alice", &store) == WF_OK);
    metalbear_auth_store_free(store);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(user_version(db) == METALBEAR_SCHEMA_VERSION);
    sqlite3_close(db);

    unlink(path);
    char wal[sizeof path + 8];
    snprintf(wal, sizeof wal, "%s-wal", path);
    unlink(wal);
    snprintf(wal, sizeof wal, "%s-shm", path);
    unlink(wal);

    if (failures) {
        fprintf(stderr, "%d schema version check(s) failed\n", failures);
        return 1;
    }
    puts("schema version tests passed");
    return 0;
}

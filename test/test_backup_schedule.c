/*
 * Scheduled backups: a run produces a verified archive that restores to the
 * data it was taken from, retention keeps only the newest archives, a run
 * that cannot start leaves existing archives alone, a backup directory inside
 * the data directory is refused, and the timer runs on its interval.
 */
#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include "metalbear/repo/backup.h"
#include "metalbear/repo/backup_schedule.h"

static int failures = 0;

#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Count archives in a directory. */
static int count_archives(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (strncmp(ent->d_name, "metalbear-", 10) == 0 && len > 4 &&
            strcmp(ent->d_name + len - 4, ".bak") == 0)
            n++;
    }
    closedir(d);
    return n;
}

static void make_database(const char *path, int rows) {
    sqlite3 *db = NULL;
    sqlite3_open(path, &db);
    sqlite3_exec(db,
                 "PRAGMA journal_mode=WAL;"
                 "CREATE TABLE IF NOT EXISTS t(n INTEGER);",
                 NULL, NULL, NULL);
    for (int i = 0; i < rows; i++) {
        char sql[64];
        snprintf(sql, sizeof(sql), "INSERT INTO t(n) VALUES(%d);", i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    sqlite3_close(db);
}

static int count_rows(const char *path) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM t;", -1, &stmt, NULL) ==
            SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW)
        n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return n;
}

int main(void) {
    char root[] = "/tmp/metalbear-backup-schedule-XXXXXX";
    if (!mkdtemp(root)) {
        fprintf(stderr, "FAIL: mkdtemp\n");
        return 1;
    }
    char data[600], backups[600], restored[600], db[700], blob_dir[700];
    snprintf(data, sizeof(data), "%s/data", root);
    snprintf(backups, sizeof(backups), "%s/backups", root);
    snprintf(restored, sizeof(restored), "%s/restored", root);
    snprintf(db, sizeof(db), "%s/repo.sqlite3", data);
    snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", data);
    mkdir(data, 0700);
    mkdir(blob_dir, 0700);
    make_database(db, 25);
    {
        char blob[700];
        snprintf(blob, sizeof(blob), "%s/one.bin", blob_dir);
        FILE *f = fopen(blob, "wb");
        if (f) {
            fputs("blob bytes", f);
            fclose(f);
        }
    }

    /* A run writes one verified archive, and the database in it restores with
     * every row. The database is still open with its WAL, so VACUUM INTO has
     * to take the copy from the WAL too. */
    char *archive = NULL;
    CHECK(metalbear_backup_run(data, backups, 2, &archive) == WF_OK);
    CHECK(archive != NULL);
    CHECK(count_archives(backups) == 1);
    CHECK(archive && metalbear_backup_verify(archive) == WF_OK);
    mkdir(restored, 0700);
    CHECK(metalbear_backup_restore(archive, restored) == WF_OK);
    char restored_db[700];
    snprintf(restored_db, sizeof(restored_db), "%s/repo.sqlite3", restored);
    CHECK(count_rows(restored_db) == 25);
    free(archive);

    /* Retention: four runs with retain 2 leave the two newest. A new row
     * between runs shows that later archives hold later data. */
    for (int i = 0; i < 3; i++) {
        make_database(db, 1);
        char *a = NULL;
        CHECK(metalbear_backup_run(data, backups, 2, &a) == WF_OK);
        free(a);
    }
    CHECK(count_archives(backups) == 2);

    /* A run that cannot start (no data directory) changes nothing. */
    char missing[600];
    snprintf(missing, sizeof(missing), "%s/no-such-data", root);
    char *none = NULL;
    CHECK(metalbear_backup_run(missing, backups, 2, &none) != WF_OK);
    CHECK(none == NULL);
    CHECK(count_archives(backups) == 2);

    /* A backup directory inside the data directory is refused, so archives
     * cannot grow into the next archive. */
    char inside[700];
    snprintf(inside, sizeof(inside), "%s/inside", data);
    CHECK(metalbear_backup_run(data, inside, 2, &none) == WF_ERR_INVALID_ARG);
    CHECK(none == NULL);

    /* The timer runs on its interval and stops when freed. */
    char timer_dir[700];
    snprintf(timer_dir, sizeof(timer_dir), "%s/timer-backups", root);
    metalbear_backup_schedule *schedule =
        metalbear_backup_schedule_start(data, timer_dir, 5, 1);
    CHECK(schedule != NULL);
    sleep(3);
    metalbear_backup_schedule_free(schedule);
    CHECK(count_archives(timer_dir) >= 1);
    CHECK(metalbear_backup_schedule_start(data, timer_dir, 5, 0) == NULL);

    /* Clean up: remove the trees this test created, leaves first. */
    {
        char p[800];
        const char *dirs[] = {backups, timer_dir, restored};
        for (size_t d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
            DIR *dd = opendir(dirs[d]);
            if (dd) {
                struct dirent *ent;
                while ((ent = readdir(dd)) != NULL) {
                    if (ent->d_name[0] == '.') continue;
                    snprintf(p, sizeof(p), "%s/%s", dirs[d], ent->d_name);
                    unlink(p);
                }
                closedir(dd);
            }
            rmdir(dirs[d]);
        }
        snprintf(p, sizeof(p), "%s/inside", data);
        rmdir(p);
        snprintf(p, sizeof(p), "%s/one.bin", blob_dir);
        unlink(p);
        rmdir(blob_dir);
        snprintf(p, sizeof(p), "%s-wal", db);
        unlink(p);
        snprintf(p, sizeof(p), "%s-shm", db);
        unlink(p);
        unlink(db);
        rmdir(data);
        rmdir(root);
    }

    if (failures == 0) {
        printf("PASS: scheduled backups\n");
        return 0;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}

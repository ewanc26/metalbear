#define _POSIX_C_SOURCE 200809L

#include "metalbear/repo/backup_schedule.h"

#include "metalbear/log.h"
#include "metalbear/repo/backup.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SCHEDULE_PREFIX "metalbear-"
#define SCHEDULE_SUFFIX ".bak"

static bool ends_with(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

/* Remove a directory tree this module created. Only used on the staging
 * directory, which holds nothing but copies made by this run. */
static void remove_tree(const char *path) {
    DIR *dir = opendir(path);
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;
            char child[PATH_MAX];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) != 0) continue;
            if (S_ISDIR(st.st_mode))
                remove_tree(child);
            else
                unlink(child);
        }
        closedir(dir);
    }
    rmdir(path);
}

/* A consistent copy of one SQLite database, taken while the server may be
 * writing to it. VACUUM INTO reads through one transaction, and it includes
 * anything still in the WAL, so the copy is a single whole file. */
static wf_status vacuum_into(const char *source, const char *dest) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(source, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return WF_ERR_INTERNAL;
    }
    sqlite3_stmt *stmt = NULL;
    wf_status st = WF_OK;
    if (sqlite3_prepare_v2(db, "VACUUM INTO ?1;", -1, &stmt, NULL) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, 1, dest, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE) {
        st = WF_ERR_INTERNAL;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return st;
}

static wf_status copy_file(const char *source, const char *dest) {
    FILE *in = fopen(source, "rb");
    if (!in) return WF_ERR_NOT_FOUND;
    FILE *out = fopen(dest, "wb");
    if (!out) {
        fclose(in);
        return WF_ERR_INTERNAL;
    }
    unsigned char buffer[64 * 1024];
    wf_status st = WF_OK;
    size_t got;
    while ((got = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (fwrite(buffer, 1, got, out) != got) {
            st = WF_ERR_INTERNAL;
            break;
        }
    }
    if (ferror(in)) st = WF_ERR_INTERNAL;
    if (fflush(out) != 0) st = WF_ERR_INTERNAL;
    if (fclose(out) != 0) st = WF_ERR_INTERNAL;
    fclose(in);
    return st;
}

/* Mirror `source` into `dest`. Databases are taken with VACUUM INTO under
 * their own name. The WAL and shared-memory files are skipped, because the
 * database copy already contains their contents. */
static wf_status stage_tree(const char *source, const char *dest) {
    DIR *dir = opendir(source);
    if (!dir) return WF_ERR_NOT_FOUND;
    struct dirent *ent;
    wf_status st = WF_OK;
    while (st == WF_OK && (ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (ends_with(ent->d_name, "-wal") || ends_with(ent->d_name, "-shm"))
            continue;
        char from[PATH_MAX], to[PATH_MAX];
        snprintf(from, sizeof(from), "%s/%s", source, ent->d_name);
        snprintf(to, sizeof(to), "%s/%s", dest, ent->d_name);
        struct stat sb;
        if (stat(from, &sb) != 0) continue;
        if (S_ISDIR(sb.st_mode)) {
            if (mkdir(to, 0700) != 0 && errno != EEXIST) {
                st = WF_ERR_INTERNAL;
                break;
            }
            st = stage_tree(from, to);
        } else if (S_ISREG(sb.st_mode)) {
            st = ends_with(ent->d_name, ".sqlite3") ? vacuum_into(from, to)
                                                    : copy_file(from, to);
        }
    }
    closedir(dir);
    return st;
}

static int compare_names(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Delete the oldest archives beyond `retain`. Names carry a UTC timestamp, so
 * sorting the names sorts by time. */
static void prune(const char *backup_dir, int retain) {
    if (retain < 1) return;
    DIR *dir = opendir(backup_dir);
    if (!dir) return;
    char **names = NULL;
    size_t count = 0, capacity = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, SCHEDULE_PREFIX, strlen(SCHEDULE_PREFIX)) !=
                0 ||
            !ends_with(ent->d_name, SCHEDULE_SUFFIX))
            continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 16;
            char **grown = realloc(names, next * sizeof(*names));
            if (!grown) break;
            names = grown;
            capacity = next;
        }
        names[count] = strdup(ent->d_name);
        if (!names[count]) break;
        count++;
    }
    closedir(dir);
    if (count > 1) qsort(names, count, sizeof(*names), compare_names);
    size_t excess = count > (size_t)retain ? count - (size_t)retain : 0;
    for (size_t i = 0; i < excess; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", backup_dir, names[i]);
        if (unlink(path) == 0)
            LOG_INFO("backup: pruned %s", names[i]);
        else
            LOG_WARN("backup: could not prune %s", names[i]);
    }
    for (size_t i = 0; i < count; i++) free(names[i]);
    free(names);
}

/* A name no existing archive has, so two runs in one millisecond do not
 * overwrite each other. */
static bool archive_name(const char *backup_dir, char *out, size_t out_len) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return false;
    long ms = ts.tv_nsec / 1000000L;
    time_t t = ts.tv_sec;
    struct tm tm;
    if (!gmtime_r(&t, &tm)) return false;
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%S", &tm);
    for (int bump = 0; bump < 1000; bump++) {
        snprintf(out, out_len, "%s/%s%s-%03ld%s", backup_dir, SCHEDULE_PREFIX,
                 stamp, (ms + bump) % 1000, SCHEDULE_SUFFIX);
        if (access(out, F_OK) != 0) return true;
    }
    return false;
}

wf_status metalbear_backup_run(const char *data_dir, const char *backup_dir,
                               int retain, char **out_archive) {
    if (!data_dir || !backup_dir || !out_archive) return WF_ERR_INVALID_ARG;
    *out_archive = NULL;

    /* An archive written inside the data directory would be copied into the
     * next one, and the set would grow without bound. */
    char real_data[PATH_MAX], real_backup[PATH_MAX];
    if (!realpath(data_dir, real_data)) return WF_ERR_NOT_FOUND;
    if (mkdir(backup_dir, 0700) != 0 && errno != EEXIST) return WF_ERR_INTERNAL;
    if (!realpath(backup_dir, real_backup)) return WF_ERR_INTERNAL;
    size_t dlen = strlen(real_data);
    if (strncmp(real_backup, real_data, dlen) == 0 &&
        (real_backup[dlen] == '/' || real_backup[dlen] == '\0')) {
        LOG_ERROR(
            "backup: backup directory must not be inside the data directory");
        return WF_ERR_INVALID_ARG;
    }

    char name[PATH_MAX];
    if (!archive_name(backup_dir, name, sizeof(name))) return WF_ERR_INTERNAL;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", name);
    char staging[PATH_MAX];
    snprintf(staging, sizeof(staging), "%s/.staging-%ld", backup_dir,
             (long)getpid());
    remove_tree(staging);

    wf_status st = WF_OK;
    if (mkdir(staging, 0700) != 0) {
        st = WF_ERR_INTERNAL;
    } else {
        st = stage_tree(real_data, staging);
    }
    if (st == WF_OK) st = metalbear_backup_create(staging, tmp);
    if (st == WF_OK) st = metalbear_backup_verify(tmp);
    remove_tree(staging);

    if (st != WF_OK) {
        unlink(tmp);
        LOG_ERROR("backup: run failed (%d); existing archives are untouched",
                  (int)st);
        return st;
    }
    if (rename(tmp, name) != 0) {
        unlink(tmp);
        return WF_ERR_INTERNAL;
    }
    *out_archive = strdup(name);
    if (!*out_archive) return WF_ERR_ALLOC;
    LOG_INFO("backup: wrote %s", name);
    prune(backup_dir, retain);
    return WF_OK;
}

struct metalbear_backup_schedule {
    char *data_dir;
    char *backup_dir;
    int retain;
    long interval_seconds;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop;
};

static void *schedule_main(void *arg) {
    metalbear_backup_schedule *s = arg;
    pthread_mutex_lock(&s->mutex);
    while (!s->stop) {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += s->interval_seconds;
        while (!s->stop) {
            int rc = pthread_cond_timedwait(&s->cond, &s->mutex, &deadline);
            if (rc == ETIMEDOUT) break;
        }
        if (s->stop) break;
        pthread_mutex_unlock(&s->mutex);
        char *archive = NULL;
        wf_status st = metalbear_backup_run(s->data_dir, s->backup_dir,
                                            s->retain, &archive);
        if (st != WF_OK) LOG_WARN("backup: scheduled run did not complete");
        free(archive);
        pthread_mutex_lock(&s->mutex);
    }
    pthread_mutex_unlock(&s->mutex);
    return NULL;
}

metalbear_backup_schedule *
metalbear_backup_schedule_start(const char *data_dir, const char *backup_dir,
                                int retain, long interval_seconds) {
    if (!data_dir || !backup_dir || interval_seconds < 1) return NULL;
    metalbear_backup_schedule *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->data_dir = strdup(data_dir);
    s->backup_dir = strdup(backup_dir);
    s->retain = retain;
    s->interval_seconds = interval_seconds;
    if (!s->data_dir || !s->backup_dir ||
        pthread_mutex_init(&s->mutex, NULL) != 0) {
        free(s->data_dir);
        free(s->backup_dir);
        free(s);
        return NULL;
    }
    if (pthread_cond_init(&s->cond, NULL) != 0) {
        pthread_mutex_destroy(&s->mutex);
        free(s->data_dir);
        free(s->backup_dir);
        free(s);
        return NULL;
    }
    if (pthread_create(&s->thread, NULL, schedule_main, s) != 0) {
        pthread_cond_destroy(&s->cond);
        pthread_mutex_destroy(&s->mutex);
        free(s->data_dir);
        free(s->backup_dir);
        free(s);
        return NULL;
    }
    return s;
}

void metalbear_backup_schedule_free(metalbear_backup_schedule *s) {
    if (!s) return;
    pthread_mutex_lock(&s->mutex);
    s->stop = true;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->mutex);
    pthread_join(s->thread, NULL);
    pthread_cond_destroy(&s->cond);
    pthread_mutex_destroy(&s->mutex);
    free(s->data_dir);
    free(s->backup_dir);
    free(s);
}

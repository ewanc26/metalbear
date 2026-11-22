#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

/*
 * deletion_sweep.c -- hard-delete deactivated accounts once a configured hold
 * has elapsed (issue #159).
 *
 * The per-account store already records deactivated_at when
 * com.atproto.server.deactivateAccount runs. This module walks the registry on
 * a timer (or on demand from a test), reads that timestamp directly from each
 * account's store, and hands expired accounts to the shared hard-delete
 * helper so the firehose events are identical to deleteAccount.
 */

#include "metalbear/account/deletion_sweep.h"

#include "../server_internal.h"

#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/log.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Parse the ISO-8601 UTC timestamps this project writes (the account store
 * uses strftime('%Y-%m-%dT%H:%M:%fZ','now'), and deactivateAccount may echo a
 * client-supplied datetime). Returns 0 when the string is absent or not a
 * timestamp we understand -- an unparsable time must never turn into a
 * deletion.
 */
/* Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm). This
 * is UTC by construction; timegm() is not declared under a strict
 * _POSIX_C_SOURCE on every platform we build on, and mktime() would interpret
 * the timestamp in the server's local zone. */
static int64_t days_from_civil(int year, unsigned month, unsigned day) {
    year -= month <= 2;
    const int64_t era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = (unsigned)(year - era * 400);
    const unsigned doy =
        (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static int64_t parse_timestamp(const char *text) {
    if (!text || !text[0]) return 0;
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    /* Fractional seconds and a trailing Z/offset are optional. */
    int matched = sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d", &year, &month, &day,
                         &hour, &minute, &second);
    if (matched != 6 || year < 1970 || month < 1 || month > 12 || day < 1 ||
        day > 31 || hour > 23 || minute > 59 || second > 60)
        return 0;
    int64_t epoch =
        days_from_civil(year, (unsigned)month, (unsigned)day) * 86400;
    epoch += hour * 3600 + minute * 60 + (second > 59 ? 59 : second);
    return epoch < 0 ? 0 : epoch;
}

/* Open just the account store for `entry`, so the sweep can read its state
 * without resolving a request context or pinning an account-cache reference. */
static wf_status open_account_store(const metalbear_server *server,
                                    const metalbear_account_entry *entry,
                                    metalbear_account_store **out) {
    *out = NULL;
    char *account_path = join_path(entry->data_directory, "account.sqlite3");
    if (!account_path) return WF_ERR_ALLOC;
    wf_status status = metalbear_account_store_open(account_path, "", out);
    free(account_path);
    (void)server;
    return status;
}

int metalbear_deletion_sweep_run(metalbear_server *server, int64_t hold_seconds,
                                 int64_t now) {
    if (!server || hold_seconds <= 0) return 0;
    if (now <= 0) now = (int64_t)time(NULL);

    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK)
        return 0;

    int deleted = 0;
    for (size_t i = 0; i < count; i++) {
        metalbear_account_entry *entry = &entries[i];
        metalbear_account_store *store = NULL;
        if (open_account_store(server, entry, &store) != WF_OK || !store)
            continue;

        int active = metalbear_account_is_active(store);
        char *deactivated_at = NULL;
        wf_status ts_status =
            active
                ? WF_ERR_INVALID_ARG
                : metalbear_account_get_deactivated_at(store, &deactivated_at);
        metalbear_account_store_free(store);
        /* `active` is 0 only for deactivated accounts, and that is the only
         * state eligible for sweeping. Skip active accounts and any whose
         * timestamp is missing or unreadable. */
        if (active || ts_status != WF_OK || !deactivated_at) {
            free(deactivated_at);
            continue;
        }

        int64_t deactivated = parse_timestamp(deactivated_at);
        free(deactivated_at);
        if (deactivated == 0) continue;
        /* Elapsed time only: a clock set backwards must not delete an account
         * whose hold has not really run. */
        if (now < deactivated || now - deactivated < hold_seconds) continue;

        LOG_INFO("deletion_sweep: hold elapsed for %s, hard-deleting",
                 entry->did);
        metalbear_hard_delete_account(server, entry->did, entry->data_directory,
                                      entry->handle);
        deleted++;
    }

    metalbear_account_entries_free(entries, count);
    return deleted;
}

/* ------------------------------------------------------------------ */
/* Background timer                                                    */
/* ------------------------------------------------------------------ */

struct metalbear_deletion_sweep {
    metalbear_server *server;
    int64_t hold_seconds;
    long interval_seconds;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop;
};

static void *sweep_main(void *arg) {
    metalbear_deletion_sweep *sweep = arg;
    pthread_mutex_lock(&sweep->mutex);
    while (!sweep->stop) {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += sweep->interval_seconds;
        while (!sweep->stop) {
            int rc =
                pthread_cond_timedwait(&sweep->cond, &sweep->mutex, &deadline);
            if (rc == ETIMEDOUT) break;
        }
        if (sweep->stop) break;
        pthread_mutex_unlock(&sweep->mutex);
        metalbear_deletion_sweep_run(sweep->server, sweep->hold_seconds, 0);
        pthread_mutex_lock(&sweep->mutex);
    }
    pthread_mutex_unlock(&sweep->mutex);
    return NULL;
}

metalbear_deletion_sweep *
metalbear_deletion_sweep_start(metalbear_server *server, int64_t hold_seconds,
                               long interval_seconds) {
    if (!server || hold_seconds <= 0 || interval_seconds < 1) return NULL;
    metalbear_deletion_sweep *sweep = calloc(1, sizeof(*sweep));
    if (!sweep) return NULL;
    sweep->server = server;
    sweep->hold_seconds = hold_seconds;
    sweep->interval_seconds = interval_seconds;
    if (pthread_mutex_init(&sweep->mutex, NULL) != 0) {
        free(sweep);
        return NULL;
    }
    if (pthread_cond_init(&sweep->cond, NULL) != 0) {
        pthread_mutex_destroy(&sweep->mutex);
        free(sweep);
        return NULL;
    }
    if (pthread_create(&sweep->thread, NULL, sweep_main, sweep) != 0) {
        pthread_cond_destroy(&sweep->cond);
        pthread_mutex_destroy(&sweep->mutex);
        free(sweep);
        return NULL;
    }
    return sweep;
}

void metalbear_deletion_sweep_free(metalbear_deletion_sweep *sweep) {
    if (!sweep) return;
    pthread_mutex_lock(&sweep->mutex);
    sweep->stop = true;
    pthread_cond_broadcast(&sweep->cond);
    pthread_mutex_unlock(&sweep->mutex);
    pthread_join(sweep->thread, NULL);
    pthread_cond_destroy(&sweep->cond);
    pthread_mutex_destroy(&sweep->mutex);
    free(sweep);
}

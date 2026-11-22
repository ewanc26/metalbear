#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

/*
 * repo_gc_schedule.c -- periodic repo garbage collection (issue #167).
 *
 * Walks the account registry on the backup_schedule.c timer pattern. For each
 * active, non-taken-down account it compacts the repo store in place: blocks
 * unreachable from the current head commit are dropped from both the SQLite
 * block table and the in-memory CAR. Deactivated and taken-down accounts are
 * skipped so this pass never rewrites a repo the deletion sweep or moderation
 * still owns.
 */

#include "metalbear/repo/repo_gc_schedule.h"

#include "../server_internal.h"

#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/log.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Open just the account store for `entry`, so the pass can read the active
 * flag without pinning a full account-cache reference for every account. */
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

size_t metalbear_repo_gc_run(metalbear_server *server) {
    if (!server) return 0;

    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK)
        return 0;

    size_t compacted = 0;
    for (size_t i = 0; i < count; i++) {
        metalbear_account_entry *entry = &entries[i];

        /* Skip taken-down accounts: moderation may need the old blocks. */
        char *takedown_ref = account_takedown_ref(server, entry->did);
        if (takedown_ref) {
            free(takedown_ref);
            continue;
        }

        /* Skip deactivated accounts; the deletion sweep owns their cleanup. */
        metalbear_account_store *account_store = NULL;
        if (open_account_store(server, entry, &account_store) != WF_OK ||
            !account_store)
            continue;
        int active = metalbear_account_is_active(account_store);
        metalbear_account_store_free(account_store);
        if (!active) continue;

        /* The cache hands out a live, reference-counted context whose repo
         * store is the same one requests use. GC must run there so the
         * in-memory CAR and the durable table stay in step; opening a second
         * handle on repo.sqlite3 would leave the live CAR stale. */
        metalbear_account_context *acct = metalbear_account_cache_get(
            server->account_cache, server->registry, entry->did);
        if (!acct || !acct->repo) {
            /* get() records every acquisition for this thread, even when the
             * context has no repo. Release through the same tracker so a later
             * iteration cannot drop an extra reference. */
            metalbear_account_cache_release_thread_local();
            continue;
        }

        size_t removed = 0;
        wf_status st = metalbear_repo_store_gc(acct->repo, &removed);
        if (st == WF_OK && removed > 0) {
            compacted++;
            LOG_INFO("repo_gc: %s: removed %zu unreachable blocks", entry->did,
                     removed);
        } else if (st != WF_OK) {
            LOG_WARN("repo_gc: %s: pass failed (status %d)", entry->did,
                     (int)st);
        }

        /* This timer thread owns no request contexts, so use the thread-local
         * release to drop the acquisition without leaving a stale record in
         * the cache's per-thread tracking buffer. */
        metalbear_account_cache_release_thread_local();
    }

    metalbear_account_entries_free(entries, count);
    return compacted;
}

struct metalbear_repo_gc_schedule {
    metalbear_server *server;
    long interval_seconds;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop;
};

static void *schedule_main(void *arg) {
    metalbear_repo_gc_schedule *s = arg;
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
        metalbear_repo_gc_run(s->server);
        pthread_mutex_lock(&s->mutex);
    }
    pthread_mutex_unlock(&s->mutex);
    return NULL;
}

metalbear_repo_gc_schedule *
metalbear_repo_gc_schedule_start(metalbear_server *server,
                                 long interval_seconds) {
    if (!server || interval_seconds < 1) return NULL;
    metalbear_repo_gc_schedule *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->server = server;
    s->interval_seconds = interval_seconds;
    if (pthread_mutex_init(&s->mutex, NULL) != 0) {
        free(s);
        return NULL;
    }
    if (pthread_cond_init(&s->cond, NULL) != 0) {
        pthread_mutex_destroy(&s->mutex);
        free(s);
        return NULL;
    }
    if (pthread_create(&s->thread, NULL, schedule_main, s) != 0) {
        pthread_cond_destroy(&s->cond);
        pthread_mutex_destroy(&s->mutex);
        free(s);
        return NULL;
    }
    return s;
}

void metalbear_repo_gc_schedule_free(metalbear_repo_gc_schedule *s) {
    if (!s) return;
    pthread_mutex_lock(&s->mutex);
    s->stop = true;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->mutex);
    pthread_join(s->thread, NULL);
    pthread_cond_destroy(&s->cond);
    pthread_mutex_destroy(&s->mutex);
    free(s);
}

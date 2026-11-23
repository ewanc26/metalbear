#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

/*
 * blob_sweep.c -- scheduled/reconciling pass for issue #253.
 *
 * Uses the same account-cache pattern as repo_gc_schedule.c so a sweep sees
 * the live stores requests use. The pass is safe to run while the server is
 * serving: all payload deletion goes through the blob store's mutex.
 */

#include "metalbear/repo/blob_sweep.h"

#include "../server_internal.h"

#include "metalbear/account/account_registry.h"
#include "metalbear/log.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct sweep_context {
    metalbear_server *server;
    int64_t now;
    int64_t temp_seconds;
    bool dry_run;
} sweep_context;

typedef struct account_callback_context {
    sweep_context *sweep;
    const char *did;
} account_callback_context;

static metalbear_account_context *acquire_context(sweep_context *ctx,
                                                  const char *did) {
    metalbear_account_context *acct = metalbear_account_cache_get(
        ctx->server->account_cache, ctx->server->registry, did);
    if (!acct) metalbear_account_cache_release_thread_local();
    return acct;
}

static void release_context(void) {
    metalbear_account_cache_release_thread_local();
}

/* Existing refs whose commit revision is gone no longer protect a blob. */
static wf_status revision_exists_cb(const char *did, const char *rev,
                                    void *opaque) {
    sweep_context *ctx = opaque;
    metalbear_account_context *acct = acquire_context(ctx, did);
    if (!acct || !acct->repo) {
        release_context();
        return WF_ERR_NOT_FOUND;
    }
    wf_status st = metalbear_repo_store_revision_exists(acct->repo, rev);
    release_context();
    return st;
}

static wf_status delete_blob_cb(const char *did, const char *cid,
                                void *opaque) {
    sweep_context *ctx = opaque;
    metalbear_account_context *acct = acquire_context(ctx, did);
    if (!acct || !acct->blobs) {
        release_context();
        return WF_ERR_NOT_FOUND;
    }
    wf_status st = metalbear_blob_store_delete(acct->blobs, cid);
    release_context();
    return st;
}

/*
 * Reconcile payloads that predate the lifecycle database. INSERT OR IGNORE
 * semantics in seed_blob preserve live temporary state; a restart can never
 * turn a pending upload into a durable one by accident.
 */
static void reconcile_account(sweep_context *ctx, const char *did,
                              metalbear_account_context *acct) {
    if (!acct || !acct->blobs || !ctx->server->blob_lifecycle) return;
    char **cids = NULL;
    size_t count = 0;
    /* list_physical is deliberate: untracked payloads have no lifecycle row
     * yet, so the public list (which filters on lifecycle state) would hide
     * exactly the blobs this reconciliation needs to discover. */
    if (metalbear_blob_store_list_physical(acct->blobs, &cids, &count) != WF_OK)
        return;
    for (size_t i = 0; i < count; i++) {
        size_t size = 0;
        if (metalbear_blob_store_get_size(acct->blobs, cids[i], &size) != WF_OK)
            continue;
        (void)metalbear_blob_lifecycle_seed_blob(ctx->server->blob_lifecycle,
                                                 did, cids[i], size, ctx->now);

        /* Rebuild the revision-aware reference table from the sidecars that
         * predate schema 7. add_ref is idempotent and promotes on first use,
         * but seed_blob above has already made legacy payloads durable. */
        char **uris = NULL;
        size_t uri_count = 0;
        if (metalbear_blob_store_get_refs(acct->blobs, cids[i], &uris,
                                          &uri_count) == WF_OK) {
            char *rev = NULL;
            if (metalbear_blob_store_get_revision(acct->blobs, cids[i], &rev) !=
                WF_OK)
                rev = NULL;
            for (size_t j = 0; j < uri_count; j++)
                (void)metalbear_blob_lifecycle_add_ref(
                    ctx->server->blob_lifecycle, did, cids[i], uris[j], rev);
            metalbear_blob_store_list_free(uris, uri_count);
            free(rev);
        }
    }
    metalbear_blob_store_list_free(cids, count);
}

wf_status metalbear_blob_sweep_run(metalbear_server *server, bool dry_run,
                                   metalbear_blob_sweep_summary *out) {
    if (!server || !server->blob_lifecycle || !out) return WF_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    sweep_context ctx = {server, (int64_t)time(NULL), server->blob_temp_seconds,
                         dry_run};
    if (ctx.temp_seconds < 0) ctx.temp_seconds = 0;

    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK)
        return WF_ERR_INTERNAL;

    for (size_t i = 0; i < count; i++) {
        const char *did = entries[i].did;
        char *takedown = account_takedown_ref(server, did);
        if (takedown) {
            free(takedown);
            continue; /* moderation owns taken-down accounts */
        }
        metalbear_account_context *acct = acquire_context(&ctx, did);
        if (!acct) continue;
        reconcile_account(&ctx, did, acct);
        release_context();
    }
    metalbear_account_entries_free(entries, count);

    /* The callbacks reacquire the account contexts they need; no context is
     * pinned across the whole pass, so cache eviction and requests can run. */
    return metalbear_blob_lifecycle_sweep(
        server->blob_lifecycle, ctx.now, ctx.temp_seconds, dry_run,
        revision_exists_cb, dry_run ? NULL : delete_blob_cb, &ctx, out);
}

wf_status metalbear_blob_sweep_stats(metalbear_server *server,
                                     metalbear_blob_sweep_summary *out) {
    if (!server || !server->blob_lifecycle || !out) return WF_ERR_INVALID_ARG;
    sweep_context ctx = {server, (int64_t)time(NULL), server->blob_temp_seconds,
                         true};
    if (ctx.temp_seconds < 0) ctx.temp_seconds = 0;
    return metalbear_blob_lifecycle_stats(server->blob_lifecycle, ctx.now,
                                          ctx.temp_seconds, revision_exists_cb,
                                          &ctx, out);
}

struct metalbear_blob_sweep_schedule {
    metalbear_server *server;
    long interval_seconds;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop;
};

static void *schedule_main(void *arg) {
    metalbear_blob_sweep_schedule *s = arg;
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
        metalbear_blob_sweep_summary summary;
        if (metalbear_blob_sweep_run(s->server, false, &summary) == WF_OK &&
            (summary.deleted || summary.refs_pruned)) {
            LOG_INFO("blob sweep: deleted %zu copies, pruned %zu refs",
                     summary.deleted, summary.refs_pruned);
        }
        pthread_mutex_lock(&s->mutex);
    }
    pthread_mutex_unlock(&s->mutex);
    return NULL;
}

metalbear_blob_sweep_schedule *
metalbear_blob_sweep_schedule_start(metalbear_server *server,
                                    long interval_seconds) {
    if (!server || interval_seconds < 1) return NULL;
    metalbear_blob_sweep_schedule *s = calloc(1, sizeof(*s));
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

void metalbear_blob_sweep_schedule_free(metalbear_blob_sweep_schedule *s) {
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

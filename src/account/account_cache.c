#define _POSIX_C_SOURCE 200809L

#include "metalbear/account/account_cache.h"

#include "metalbear/ops/metrics.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration: get() records each acquisition so the request observer
 * can release it via metalbear_account_cache_release_thread_local. */
void account_cache_push_acquired(metalbear_account_cache *cache,
                                 metalbear_account_context *ctx);

/* Conservative default resident budget. Each cached account holds a SQLite
 * repo store plus a blob store; on a 256 MB Pi 1B this should be lowered via
 * metalbear_account_cache_set_max_resident (the daemon reads
 * METALBEAR_MAX_RESIDENT_ACCOUNTS). */
#define ACCOUNT_CACHE_DEFAULT_MAX_RESIDENT 256

struct metalbear_account_cache {
    char *service_did;
    char *public_url;
    char *data_directory;
    /* Borrowed: the PDS-wide event log every cached account publishes into. */
    metalbear_sequencer *sequencer;
    pthread_mutex_t lock;
    struct cache_entry {
        char *did;
        metalbear_account_context *ctx;
        struct cache_entry *next;
        /* Number of live references (get acquisitions not yet released). */
        int refcount;
        /* Monotonic LRU timestamp; lower means evicted first when idle. */
        unsigned long seq;
    } *entries;
    /* Bumped on every touch so idle eviction can pick the oldest. */
    unsigned long seq_counter;
    size_t idle_count;
    size_t total_count;
    size_t max_resident;
    _Atomic uint64_t evictions;
    _Atomic uint64_t hits;
    _Atomic uint64_t misses;
};

metalbear_account_cache *
metalbear_account_cache_new(const char *service_did, const char *public_url,
                            const char *data_directory) {
    if (!service_did || !data_directory) return NULL;
    metalbear_account_cache *cache = calloc(1, sizeof(*cache));
    if (!cache) return NULL;
    cache->service_did = strdup(service_did);
    cache->public_url = public_url ? strdup(public_url) : NULL;
    cache->data_directory = strdup(data_directory);
    if (!cache->service_did || !cache->data_directory ||
        pthread_mutex_init(&cache->lock, NULL) != 0) {
        free(cache->service_did);
        free(cache->public_url);
        free(cache->data_directory);
        free(cache);
        return NULL;
    }
    cache->max_resident = ACCOUNT_CACHE_DEFAULT_MAX_RESIDENT;
    return cache;
}

void metalbear_account_cache_set_sequencer(metalbear_account_cache *cache,
                                           metalbear_sequencer *sequencer) {
    if (cache) cache->sequencer = sequencer;
}

void metalbear_account_cache_set_max_resident(metalbear_account_cache *cache,
                                              size_t max_resident) {
    if (!cache) return;
    pthread_mutex_lock(&cache->lock);
    cache->max_resident =
        max_resident ? max_resident : ACCOUNT_CACHE_DEFAULT_MAX_RESIDENT;
    pthread_mutex_unlock(&cache->lock);
}

void metalbear_account_cache_free(metalbear_account_cache *cache) {
    if (!cache) return;
    pthread_mutex_lock(&cache->lock);
    struct cache_entry *e = cache->entries;
    while (e) {
        struct cache_entry *next = e->next;
        free(e->did);
        metalbear_account_context_close(e->ctx);
        free(e);
        e = next;
    }
    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache->service_did);
    free(cache->public_url);
    free(cache->data_directory);
    free(cache);
}

/*
 * Close and unlink `victim` (must already be unlinked by the caller). Caller
 * holds cache->lock.
 */
static void entry_close(struct cache_entry *victim) {
    free(victim->did);
    metalbear_account_context_close(victim->ctx);
    free(victim);
}

/*
 * Evict the least-recently-used idle (refcount == 0) entry if the idle count
 * is over budget. Caller holds cache->lock.
 */
static void evict_if_over_budget_locked(metalbear_account_cache *cache) {
    while (cache->idle_count > cache->max_resident && cache->entries) {
        struct cache_entry *oldest = NULL;
        struct cache_entry *oldest_prev = NULL;
        struct cache_entry *prev = NULL;
        for (struct cache_entry *e = cache->entries; e; e = e->next) {
            if (e->refcount != 0) continue;
            if (!oldest || e->seq < oldest->seq) {
                oldest = e;
                oldest_prev = prev;
            }
            prev = e;
        }
        if (!oldest) break; /* nothing idle to evict */

        if (oldest_prev)
            oldest_prev->next = oldest->next;
        else
            cache->entries = oldest->next;

        cache->idle_count--;
        cache->total_count--;
        atomic_fetch_add_explicit(&cache->evictions, 1, memory_order_relaxed);
        entry_close(oldest);
    }
}

metalbear_account_context *
metalbear_account_cache_get(metalbear_account_cache *cache,
                            metalbear_account_registry *registry,
                            const char *did) {
    if (!cache || !registry || !did) return NULL;

    pthread_mutex_lock(&cache->lock);
    for (struct cache_entry *e = cache->entries; e; e = e->next) {
        if (strcmp(e->did, did) == 0) {
            if (e->refcount == 0) cache->idle_count--;
            e->refcount++;
            e->seq = ++cache->seq_counter;
            metalbear_account_context *ctx = e->ctx;
            pthread_mutex_unlock(&cache->lock);
            atomic_fetch_add_explicit(&cache->hits, 1, memory_order_relaxed);
            account_cache_push_acquired(cache, ctx);
            return ctx;
        }
    }
    pthread_mutex_unlock(&cache->lock);

    /* Not cached yet: resolve the registry entry and open its bundle. */
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(registry, did, &entry) !=
            WF_OK ||
        !entry) {
        metalbear_account_entry_free(entry);
        return NULL;
    }

    metalbear_account_context *ctx = NULL;
    wf_status status = metalbear_account_context_open_shared(
        cache->service_did, cache->public_url, did, entry->handle,
        entry->data_directory, NULL, NULL, cache->sequencer, &ctx);
    metalbear_account_entry_free(entry);
    if (status != WF_OK || !ctx) return NULL;

    pthread_mutex_lock(&cache->lock);
    /* Re-check after re-acquiring the lock in case another thread won. */
    for (struct cache_entry *e = cache->entries; e; e = e->next) {
        if (strcmp(e->did, did) == 0) {
            if (e->refcount == 0) cache->idle_count--;
            e->refcount++;
            e->seq = ++cache->seq_counter;
            metalbear_account_context *existing = e->ctx;
            pthread_mutex_unlock(&cache->lock);
            metalbear_account_context_close(ctx);
            atomic_fetch_add_explicit(&cache->hits, 1, memory_order_relaxed);
            account_cache_push_acquired(cache, existing);
            return existing;
        }
    }
    struct cache_entry *ne = malloc(sizeof(*ne));
    if (!ne) {
        pthread_mutex_unlock(&cache->lock);
        metalbear_account_context_close(ctx);
        return NULL;
    }
    ne->did = strdup(did);
    if (!ne->did) {
        pthread_mutex_unlock(&cache->lock);
        free(ne);
        metalbear_account_context_close(ctx);
        return NULL;
    }
    ne->ctx = ctx;
    ne->refcount = 1;
    ne->seq = ++cache->seq_counter;
    ne->next = cache->entries;
    cache->entries = ne;
    cache->total_count++;
    evict_if_over_budget_locked(cache);
    pthread_mutex_unlock(&cache->lock);
    atomic_fetch_add_explicit(&cache->misses, 1, memory_order_relaxed);
    account_cache_push_acquired(cache, ctx);
    return ctx;
}

void metalbear_account_cache_release(metalbear_account_cache *cache,
                                     metalbear_account_context *ctx) {
    if (!cache || !ctx) return;
    pthread_mutex_lock(&cache->lock);
    for (struct cache_entry *e = cache->entries; e; e = e->next) {
        if (e->ctx == ctx) {
            if (e->refcount > 0) {
                e->refcount--;
                if (e->refcount == 0) {
                    cache->idle_count++;
                    e->seq = ++cache->seq_counter;
                    evict_if_over_budget_locked(cache);
                }
            }
            pthread_mutex_unlock(&cache->lock);
            return;
        }
    }
    pthread_mutex_unlock(&cache->lock);
}

/* ------------------------------------------------------------------ */
/* Per-thread acquisition tracking                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    metalbear_account_cache *cache;
    metalbear_account_context *ctx;
} acquired_ref;

static _Thread_local acquired_ref *acq_buf = NULL;
static _Thread_local size_t acq_len = 0;
static _Thread_local size_t acq_cap = 0;

/* Called by metalbear_account_cache_get on every successful acquisition so the
 * request observer can release the reference at request end. Internal to this
 * file; declared here so get() can call it. */
void account_cache_push_acquired(metalbear_account_cache *cache,
                                 metalbear_account_context *ctx) {
    if (acq_len == acq_cap) {
        size_t new_cap = acq_cap ? acq_cap * 2 : 8;
        acquired_ref *grown = realloc(acq_buf, new_cap * sizeof(*grown));
        if (!grown)
            return; /* out of memory: skip tracking, the cache still
                     * owns the context and will free it at cache_free
                     * time. The reference simply stays pinned. */
        acq_buf = grown;
        acq_cap = new_cap;
    }
    acq_buf[acq_len].cache = cache;
    acq_buf[acq_len].ctx = ctx;
    acq_len++;
}

void metalbear_account_cache_release_thread_local(void) {
    for (size_t i = 0; i < acq_len; i++)
        metalbear_account_cache_release(acq_buf[i].cache, acq_buf[i].ctx);
    acq_len = 0;
}

void metalbear_account_cache_stats(metalbear_account_cache *cache,
                                   size_t *resident, size_t *idle,
                                   uint64_t *evictions, uint64_t *hits,
                                   uint64_t *misses) {
    if (resident) *resident = 0;
    if (idle) *idle = 0;
    if (evictions)
        *evictions =
            atomic_load_explicit(&cache->evictions, memory_order_relaxed);
    if (hits) *hits = atomic_load_explicit(&cache->hits, memory_order_relaxed);
    if (misses)
        *misses = atomic_load_explicit(&cache->misses, memory_order_relaxed);
    if (!cache || (!resident && !idle)) return;
    pthread_mutex_lock(&cache->lock);
    if (resident) *resident = cache->total_count;
    if (idle) *idle = cache->idle_count;
    pthread_mutex_unlock(&cache->lock);
}

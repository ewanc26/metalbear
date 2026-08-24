#ifndef METALBEAR_ACCOUNT_CACHE_H
#define METALBEAR_ACCOUNT_CACHE_H

#include "metalbear/account/account_context.h"
#include "metalbear/sequencer.h"
#include "metalbear/account/account_registry.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_account_cache metalbear_account_cache;

/*
 * A bounded cache of open per-account store bundles.
 *
 * Every account context this cache opens is reference-counted. A call to
 * metalbear_account_cache_get acquires one reference and returns the context;
 * the matching metalbear_account_cache_release (or, for request-bound use,
 * metalbear_account_cache_release_thread_local at request end) drops it. The
 * cache never frees a context whose reference count is still above zero, so a
 * handler that is still using a context can never observe a use-after-free.
 *
 * Idle (fully-released) contexts are evicted under a configurable resident
 * budget, least-recently-used first, so memory no longer grows without bound
 * with the number of accounts ever touched. Durable account state lives in
 * each account's own data directory and is reopened on the next get, so
 * eviction is transparent to callers.
 */
metalbear_account_cache *
metalbear_account_cache_new(const char *service_did, const char *public_url,
                            const char *data_directory);

/* Point the cache at the PDS-wide event log, so every account it opens
 * publishes its commits into the single stream subscribeRepos serves. Borrowed
 * — the caller keeps ownership and must outlive the cache. Call before the
 * first metalbear_account_cache_get; without it, cached accounts fall back to
 * their own per-account logs, which nothing serves. */
void metalbear_account_cache_set_sequencer(metalbear_account_cache *cache,
                                           metalbear_sequencer *sequencer);

/*
 * Configure the resident budget: the maximum number of idle (fully released)
 * account contexts the cache will keep open at once. When the idle count
 * exceeds `max_resident`, the least-recently-used idle contexts are closed
 * until it is back under budget. A context still referenced by a request is
 * never evicted regardless of this limit.
 *
 * `max_resident` of 0 selects a conservative default. On a 256 MB Raspberry Pi
 * 1B, each account context carries a SQLite repo store and blob store; set
 * this low (e.g. 16–32) and watch the account_cache_resident gauge.
 */
void metalbear_account_cache_set_max_resident(metalbear_account_cache *cache,
                                              size_t max_resident);

void metalbear_account_cache_free(metalbear_account_cache *cache);

/*
 * Return the open context for `did`, opening it on first use, and acquire a
 * reference on it. The caller must release the reference exactly once when the
 * context is no longer needed — either with metalbear_account_cache_release,
 * or, for contexts used only for the duration of a request, by calling
 * metalbear_account_cache_release_thread_local at request end (the MetalBear
 * server wires this to the XRPC request observer, so ordinary route handlers
 * never release by hand). Returns NULL when the account is unknown to
 * `registry` or cannot be opened.
 */
metalbear_account_context *
metalbear_account_cache_get(metalbear_account_cache *cache,
                            metalbear_account_registry *registry,
                            const char *did);

/*
 * Drop a single reference acquired by metalbear_account_cache_get. When the
 * last reference is released the context becomes evictable; if the resident
 * budget is exceeded it may be closed immediately. Safe to call once per
 * acquired reference; passing a context not owned by `cache` is a no-op.
 */
void metalbear_account_cache_release(metalbear_account_cache *cache,
                                     metalbear_account_context *ctx);

/*
 * Release every reference this thread has acquired since the last call. The
 * MetalBear server calls this from its XRPC request observer, so route
 * handlers that resolve accounts through the request path never manage
 * references by hand. Calling it from a thread that made no acquisitions is a
 * no-op. Not safe to call concurrently with a handler still using a context on
 * the same thread — only invoke it once the request has fully completed.
 */
void metalbear_account_cache_release_thread_local(void);

/*
 * Snapshot of cache health for operational metrics. `resident` is the total
 * number of open contexts (referenced or idle), `idle` the number fully
 * released and therefore evictable, `evictions`/`hits`/`misses` are monotonic
 * counters since the cache was created. Any pointer may be NULL.
 */
void metalbear_account_cache_stats(metalbear_account_cache *cache,
                                   size_t *resident, size_t *idle,
                                   uint64_t *evictions, uint64_t *hits,
                                   uint64_t *misses);

#ifdef __cplusplus
}
#endif

#endif

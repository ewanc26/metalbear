/*
 * metrics.c — the counter table behind `GET /metrics`.
 *
 * One atomic per metric, incremented from the request path. Relaxed ordering
 * is deliberate: a counter carries no happens-before relationship with
 * anything else, and a scrape reading a value one increment stale is
 * indistinguishable from a scrape that arrived a microsecond earlier.
 */

#include "metalbear/metrics.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Atomic uint64_t counters[METALBEAR_METRIC_COUNT];

/* Name and help text, in enum order. Kept beside the enum rather than built
 * at the call site so a metric cannot be exported under two spellings. */
static const struct {
    const char *name;
    const char *help;
} descriptions[METALBEAR_METRIC_COUNT] = {
    [METALBEAR_METRIC_REQUESTS] =
        { "requests_total", "Requests served." },
    [METALBEAR_METRIC_REQUESTS_FAILED] =
        { "requests_failed_total", "Requests that answered 4xx or 5xx." },
    [METALBEAR_METRIC_AUTH_REFUSED] =
        { "auth_refused_total",
          "Requests refused by the authentication callback." },
    [METALBEAR_METRIC_ACCOUNTS_CREATED] =
        { "accounts_created_total", "Accounts created on this host." },
    [METALBEAR_METRIC_ACCOUNTS_DELETED] =
        { "accounts_deleted_total", "Accounts deleted from this host." },
    [METALBEAR_METRIC_SESSIONS_CREATED] =
        { "sessions_created_total", "Sessions issued." },
    [METALBEAR_METRIC_LOGIN_FAILURES] =
        { "login_failures_total", "Logins refused." },
    [METALBEAR_METRIC_COMMITS_SEQUENCED] =
        { "commits_sequenced_total",
          "Signed repository commits published to the firehose." },
    [METALBEAR_METRIC_BLOBS_UPLOADED] =
        { "blobs_uploaded_total", "Blobs stored." },
    [METALBEAR_METRIC_TAKEDOWNS_APPLIED] =
        { "takedowns_applied_total", "Takedowns applied to a subject." },
    [METALBEAR_METRIC_FIREHOSE_SUBSCRIBES] =
        { "firehose_subscribes_total",
          "Firehose subscribers that have connected." },
    [METALBEAR_METRIC_FIREHOSE_DISCONNECTS] =
        { "firehose_disconnects_total",
          "Firehose subscribers that have disconnected." },
    [METALBEAR_METRIC_DNS_FAILURES] =
        { "dns_failures_total", "Handle DNS records that could not be written." },
    [METALBEAR_METRIC_CRAWL_FAILURES] =
        { "crawl_failures_total", "requestCrawl announcements that failed." },
};

void metalbear_metrics_inc(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return;
    atomic_fetch_add_explicit(&counters[metric], 1, memory_order_relaxed);
}

uint64_t metalbear_metrics_get(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return 0;
    return atomic_load_explicit(&counters[metric], memory_order_relaxed);
}

const char *metalbear_metric_name(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return NULL;
    return descriptions[metric].name;
}

const char *metalbear_metric_help(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return NULL;
    return descriptions[metric].help;
}


/* ------------------------------------------------------------------ */
/* Per-route accounting                                                */
/* ------------------------------------------------------------------ */

/*
 * A small open table guarded by one mutex rather than an atomic per row: a
 * route has to be found before it can be incremented, and a lookup that races
 * an insert is how the same NSID ends up occupying two rows and reporting half
 * its traffic in each.
 *
 * The lock is held for a string compare over a bounded table. That is
 * comfortably cheaper than the SQLite transaction and the secp256k1 signature
 * on the write path it sits beside.
 */
typedef struct route_row {
    char name[128];
    uint64_t requests;
    uint64_t errors;
} route_row;

/*
 * Storage is a fixed array sized at compile time. The configurable capacity
 * only ever selects a prefix of it, so however the knob is set — or however
 * many distinct NSIDs the network invents — this is all the memory per-route
 * accounting can ever occupy.
 */
static route_row routes[METALBEAR_METRICS_ROUTE_CEILING];
static size_t route_count;
static size_t route_capacity = METALBEAR_METRICS_MAX_ROUTES;
static pthread_mutex_t routes_lock = PTHREAD_MUTEX_INITIALIZER;
/* Counts that are no longer attributed to a name: requests that arrived while
 * the table was at capacity, and rows evicted to make room. Kept rather than
 * dropped, so the per-route numbers always sum to the total. */
static uint64_t overflow_requests;
static uint64_t overflow_errors;

/* Index of the row with the fewest requests. Ties go to the earlier row, which
 * makes eviction deterministic and therefore testable. Caller holds the lock;
 * only called with a non-empty table. */
static size_t coldest_row(void) {
    size_t cold = 0;
    for (size_t i = 1; i < route_count; i++)
        if (routes[i].requests < routes[cold].requests) cold = i;
    return cold;
}

/* Fold a row's counts into `other` and remove it, keeping the table dense.
 * Caller holds the lock. */
static void evict_row(size_t idx) {
    overflow_requests += routes[idx].requests;
    overflow_errors += routes[idx].errors;
    route_count--;
    if (idx != route_count) routes[idx] = routes[route_count];
}

void metalbear_metrics_set_max_routes(size_t max_routes) {
    if (max_routes == 0) max_routes = METALBEAR_METRICS_MAX_ROUTES;
    if (max_routes > METALBEAR_METRICS_ROUTE_CEILING)
        max_routes = METALBEAR_METRICS_ROUTE_CEILING;
    pthread_mutex_lock(&routes_lock);
    route_capacity = max_routes;
    while (route_count > route_capacity) evict_row(coldest_row());
    pthread_mutex_unlock(&routes_lock);
}

size_t metalbear_metrics_max_routes(void) {
    pthread_mutex_lock(&routes_lock);
    size_t n = route_capacity;
    pthread_mutex_unlock(&routes_lock);
    return n;
}

void metalbear_metrics_record_request(const char *nsid, const char *path,
                                      unsigned int status) {
    const char *name = (nsid && nsid[0]) ? nsid : path;
    if (!name || !name[0]) name = "unknown";
    bool is_error = status >= 400;

    pthread_mutex_lock(&routes_lock);
    for (size_t i = 0; i < route_count; i++) {
        if (strcmp(routes[i].name, name) == 0) {
            routes[i].requests++;
            if (is_error) routes[i].errors++;
            pthread_mutex_unlock(&routes_lock);
            return;
        }
    }
    /*
     * A new name and no room. Give the row to the least-used route instead of
     * refusing every name after the first `capacity` of them: the table then
     * keeps tracking whatever is actually busy, and an attacker cannot displace
     * a hot route with junk, because the coldest row is by definition one of
     * the junk names already there. The displaced counts move to `other`, so
     * nothing is lost from the totals — only from attribution.
     */
    if (route_count >= route_capacity && route_count > 0)
        evict_row(coldest_row());
    if (route_count < route_capacity) {
        route_row *row = &routes[route_count++];
        snprintf(row->name, sizeof(row->name), "%s", name);
        row->requests = 1;
        row->errors = is_error ? 1 : 0;
    } else {
        /* capacity 0 is impossible (clamped to >= 1), but keep the totals
         * honest rather than assume it. */
        overflow_requests++;
        if (is_error) overflow_errors++;
    }
    pthread_mutex_unlock(&routes_lock);
}

void metalbear_metrics_visit_routes(metalbear_metrics_route_visitor visit,
                                    void *ctx) {
    if (!visit) return;
    /*
     * Copied out under the lock and visited outside it. The visitor formats
     * into a growing buffer, and holding a lock the request path needs across
     * an allocation is how a scrape starts blocking writes.
     *
     * The copy is on the heap: the table can be configured up to the ceiling,
     * and a snapshot of that size is more than a worker thread's stack should
     * be asked to hold. If the allocation fails the scrape visits under the
     * lock instead — a slower scrape beats a silent one.
     */
    size_t count;
    uint64_t spilled_requests, spilled_errors;
    pthread_mutex_lock(&routes_lock);
    count = route_count;
    route_row *snapshot = count ? malloc(count * sizeof(route_row)) : NULL;
    if (count && !snapshot) {
        for (size_t i = 0; i < count; i++)
            visit(ctx, routes[i].name, routes[i].requests, routes[i].errors);
        spilled_requests = overflow_requests;
        spilled_errors = overflow_errors;
        pthread_mutex_unlock(&routes_lock);
        if (spilled_requests)
            visit(ctx, "other", spilled_requests, spilled_errors);
        return;
    }
    if (count) memcpy(snapshot, routes, count * sizeof(route_row));
    spilled_requests = overflow_requests;
    spilled_errors = overflow_errors;
    pthread_mutex_unlock(&routes_lock);

    for (size_t i = 0; i < count; i++)
        visit(ctx, snapshot[i].name, snapshot[i].requests, snapshot[i].errors);
    free(snapshot);
    if (spilled_requests) visit(ctx, "other", spilled_requests, spilled_errors);
}

void metalbear_metrics_reset(void) {
    for (int i = 0; i < METALBEAR_METRIC_COUNT; i++)
        atomic_store_explicit(&counters[i], 0, memory_order_relaxed);
    pthread_mutex_lock(&routes_lock);
    route_count = 0;
    overflow_requests = 0;
    overflow_errors = 0;
    pthread_mutex_unlock(&routes_lock);
}

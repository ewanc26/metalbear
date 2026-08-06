/*
 * metrics.c — the counter table behind `GET /metrics`.
 *
 * One atomic per metric, incremented from the request path. Relaxed ordering
 * is deliberate: a counter carries no happens-before relationship with
 * anything else, and a scrape reading a value one increment stale is
 * indistinguishable from a scrape that arrived a microsecond earlier.
 */

#include "metalbear/ops/metrics.h"

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
    [METALBEAR_METRIC_REQUESTS] = {"requests_total", "Requests served."},
    [METALBEAR_METRIC_REQUESTS_FAILED] = {"requests_failed_total",
                                          "Requests that answered 4xx or 5xx."},
    [METALBEAR_METRIC_AUTH_REFUSED] =
        {"auth_refused_total",
         "Requests refused by the authentication callback."},
    [METALBEAR_METRIC_ACCOUNTS_CREATED] = {"accounts_created_total",
                                           "Accounts created on this host."},
    [METALBEAR_METRIC_ACCOUNTS_DELETED] = {"accounts_deleted_total",
                                           "Accounts deleted from this host."},
    [METALBEAR_METRIC_SESSIONS_CREATED] = {"sessions_created_total",
                                           "Sessions issued."},
    [METALBEAR_METRIC_LOGIN_FAILURES] = {"login_failures_total",
                                         "Logins refused."},
    [METALBEAR_METRIC_COMMITS_SEQUENCED] =
        {"commits_sequenced_total",
         "Signed repository commits published to the firehose."},
    [METALBEAR_METRIC_BLOBS_UPLOADED] = {"blobs_uploaded_total",
                                         "Blobs stored."},
    [METALBEAR_METRIC_TAKEDOWNS_APPLIED] = {"takedowns_applied_total",
                                            "Takedowns applied to a subject."},
    [METALBEAR_METRIC_FIREHOSE_SUBSCRIBES] =
        {"firehose_subscribes_total",
         "Firehose subscribers that have connected."},
    [METALBEAR_METRIC_FIREHOSE_DISCONNECTS] =
        {"firehose_disconnects_total",
         "Firehose subscribers that have disconnected."},
    [METALBEAR_METRIC_DNS_FAILURES] =
        {"dns_failures_total", "Handle DNS records that could not be written."},
    [METALBEAR_METRIC_CRAWL_FAILURES] =
        {"crawl_failures_total", "requestCrawl announcements that failed."},
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

/* Grows on demand to METALBEAR_METRICS_MAX_ROUTES so an idle host allocates
 * only what it uses; the cap is what keeps a label-cardinality attack from
 * exhausting memory. Guarded by routes_lock. */
static route_row *routes;
static size_t route_count;
static size_t route_capacity;
static pthread_mutex_t routes_lock = PTHREAD_MUTEX_INITIALIZER;
/* Requests that arrived after the table filled up. Counted rather than
 * dropped, so the per-route numbers always sum to the total. */
static uint64_t overflow_requests;
static uint64_t overflow_errors;

/* Grow the table geometrically under routes_lock. False when the cap is
 * already reached or the allocation failed. */
static bool grow_routes_locked(void) {
    size_t new_cap = route_capacity ? route_capacity * 2 : 16;
    route_row *grown;
    if (new_cap > METALBEAR_METRICS_MAX_ROUTES)
        new_cap = METALBEAR_METRICS_MAX_ROUTES;
    if (new_cap <= route_capacity) return false;
    grown = realloc(routes, new_cap * sizeof(route_row));
    if (!grown) return false;
    routes = grown;
    route_capacity = new_cap;
    return true;
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
    if (route_count == METALBEAR_METRICS_MAX_ROUTES ||
        (route_count == route_capacity && !grow_routes_locked())) {
        overflow_requests++;
        if (is_error) overflow_errors++;
        pthread_mutex_unlock(&routes_lock);
        return;
    }
    route_row *row = &routes[route_count++];
    snprintf(row->name, sizeof(row->name), "%s", name);
    row->requests = 1;
    row->errors = is_error ? 1 : 0;
    pthread_mutex_unlock(&routes_lock);
}

void metalbear_metrics_visit_routes(metalbear_metrics_route_visitor visit,
                                    void *ctx) {
    if (!visit) return;
    /*
     * Copied out under the lock and visited outside it. The visitor formats
     * into a growing buffer, and holding a lock the request path needs across
     * an allocation is how a scrape starts blocking writes.
     */
    route_row *snapshot = NULL;
    size_t count;
    uint64_t spilled_requests, spilled_errors;
    pthread_mutex_lock(&routes_lock);
    count = route_count;
    spilled_requests = overflow_requests;
    spilled_errors = overflow_errors;
    if (count) {
        snapshot = malloc(count * sizeof(route_row));
        if (snapshot) memcpy(snapshot, routes, count * sizeof(route_row));
    }
    if (snapshot) {
        pthread_mutex_unlock(&routes_lock);
        for (size_t i = 0; i < count; i++)
            visit(ctx, snapshot[i].name, snapshot[i].requests,
                  snapshot[i].errors);
        free(snapshot);
    } else {
        /* Rare allocation failure: visit under the lock rather than drop
         * accounting data. */
        for (size_t i = 0; i < count; i++)
            visit(ctx, routes[i].name, routes[i].requests, routes[i].errors);
        pthread_mutex_unlock(&routes_lock);
    }
    if (spilled_requests) visit(ctx, "other", spilled_requests, spilled_errors);
}

void metalbear_metrics_reset(void) {
    for (int i = 0; i < METALBEAR_METRIC_COUNT; i++)
        atomic_store_explicit(&counters[i], 0, memory_order_relaxed);
    pthread_mutex_lock(&routes_lock);
    free(routes);
    routes = NULL;
    route_count = 0;
    route_capacity = 0;
    overflow_requests = 0;
    overflow_errors = 0;
    pthread_mutex_unlock(&routes_lock);
}

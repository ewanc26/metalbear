#ifndef METALBEAR_METRICS_H
#define METALBEAR_METRICS_H

/*
 * metrics.h — process-wide counters, exposed at `GET /metrics` in the
 * Prometheus text format.
 *
 * Only counters live here: values that start at zero and never go down, so a
 * scrape that is missed loses resolution rather than information. Everything
 * that describes the host's current state — how many accounts it holds, where
 * the firehose has got to — is read from the real thing at scrape time instead
 * of being mirrored here, because a mirrored gauge is a second copy of the
 * truth and drifts from the first.
 *
 * Counters are atomic and lock-free. They are written on the request path, and
 * a metric that could contend with a commit being signed would be worth less
 * than it costs.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum metalbear_metric {
    /* Every request the server finished, XRPC and plain HTTP alike, and
     * those of them that answered 4xx or 5xx. */
    METALBEAR_METRIC_REQUESTS = 0,
    METALBEAR_METRIC_REQUESTS_FAILED,
    /* Requests the auth callback refused: no token, a bad one, the wrong
     * scope, or an account that may not act. Distinct from the 4xx count
     * because the status alone does not say which of those it was, and a
     * rate of these is the first sign of a misconfigured client or a
     * credential-stuffing run. */
    METALBEAR_METRIC_AUTH_REFUSED,
    METALBEAR_METRIC_ACCOUNTS_CREATED,
    METALBEAR_METRIC_ACCOUNTS_DELETED,
    METALBEAR_METRIC_SESSIONS_CREATED,
    METALBEAR_METRIC_LOGIN_FAILURES,
    METALBEAR_METRIC_COMMITS_SEQUENCED,
    METALBEAR_METRIC_BLOBS_UPLOADED,
    METALBEAR_METRIC_TAKEDOWNS_APPLIED,
    /* A firehose subscriber that connected, and one that went away. The
     * difference is the number attached now; both are counters so a
     * connection storm is still visible after it ends. */
    METALBEAR_METRIC_FIREHOSE_SUBSCRIBES,
    METALBEAR_METRIC_FIREHOSE_DISCONNECTS,
    /* A DNS record that could not be written. Silent failure here is what
     * leaves every handle showing as handle.invalid. */
    METALBEAR_METRIC_DNS_FAILURES,
    /* A relay that could not be told there was new data. */
    METALBEAR_METRIC_CRAWL_FAILURES,
    METALBEAR_METRIC_COUNT
} metalbear_metric;

void metalbear_metrics_inc(metalbear_metric metric);
uint64_t metalbear_metrics_get(metalbear_metric metric);

/*
 * Per-route request accounting.
 *
 * A single total says a host is busy; it does not say which method is being
 * hammered or which one started failing, and those are the two questions an
 * operator actually has. Routes are recorded as they are seen rather than
 * enumerated up front, because the set is not fixed — the AppView proxy
 * forwards NSIDs this server has never heard of.
 *
 * The table is bounded, and the bound is not negotiable: an unbounded label
 * set is how a metrics endpoint becomes the thing that exhausts a host's
 * memory, and an NSID arrives from the network. The storage is a fixed array
 * of METALBEAR_METRICS_ROUTE_CEILING rows, sized at compile time, so no
 * configuration and no traffic pattern can make the table grow.
 *
 * Within that ceiling the capacity is what an operator chooses, defaulting to
 * METALBEAR_METRICS_MAX_ROUTES, and a full table evicts its *least-used* route
 * rather than freezing. Freezing was the real defect: the first 128 names seen
 * kept their rows forever, so a route that became hot after startup — which is
 * to say, the one an operator went looking for — was invisible for the life of
 * the process, while a burst of junk NSIDs seen during boot held rows on
 * nothing. Evicting the coldest row is also self-defending: a flood of
 * one-request names evicts the previous one-request name, never the busy route
 * beside it.
 *
 * Evicted counts, and requests that arrive while the table is at capacity,
 * are folded into the name `other`, so per-route totals still sum to the
 * overall request count.
 */
#define METALBEAR_METRICS_MAX_ROUTES 128
#define METALBEAR_METRICS_ROUTE_CEILING 1024

/*
 * Set the number of routes tracked by name. Clamped to
 * [1, METALBEAR_METRICS_ROUTE_CEILING]; zero restores the default. Lowering it
 * below the number of rows in use folds the coldest of them into `other`
 * rather than losing their counts. Called once at startup.
 */
void metalbear_metrics_set_max_routes(size_t max_routes);
size_t metalbear_metrics_max_routes(void);

/* Record one finished request. `nsid` may be NULL for a plain HTTP route, in
 * which case `path` names it. */
void metalbear_metrics_record_request(const char *nsid, const char *path,
                                      unsigned int status);

/*
 * Visit each recorded route in turn. `requests` is the total seen, and
 * `errors` those that answered 4xx or 5xx — the ratio being the thing worth
 * alerting on, and cheaper to carry than a bucket per status code.
 */
typedef void (*metalbear_metrics_route_visitor)(void *ctx, const char *route,
                                                uint64_t requests,
                                                uint64_t errors);
void metalbear_metrics_visit_routes(metalbear_metrics_route_visitor visit,
                                    void *ctx);

/* The metric's Prometheus name, without the `metalbear_` prefix, and its HELP
 * text. Both are static strings; NULL for an out-of-range metric. */
const char *metalbear_metric_name(metalbear_metric metric);
const char *metalbear_metric_help(metalbear_metric metric);

/* Reset every counter. For tests; a running server never calls it, since a
 * counter that can go down breaks every rate() over it. */
void metalbear_metrics_reset(void);

#ifdef __cplusplus
}
#endif

#endif

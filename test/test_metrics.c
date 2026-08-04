/*
 * test_metrics.c — offline unit tests for the process-wide counters and the
 * per-route request table (metalbear/metrics.h).
 *
 * The route table grows on demand up to METALBEAR_METRICS_MAX_ROUTES and
 * spills the excess under `other`, so these tests pin the accounting (counts,
 * error split, unknown fallback, spill totals, reset) rather than the
 * Prometheus formatting.
 */

#include "metalbear/metrics.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Visitor accumulator                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t requests_total;
    uint64_t errors_total;
    size_t rows_seen;
    const char *want_route; /* exact route to look for, or NULL */
    int found_route;
    uint64_t want_requests;
    uint64_t want_errors;
    int found_other;
    uint64_t other_requests;
    uint64_t other_errors;
} visit_ctx;

static void collect(void *ctx, const char *route, uint64_t requests,
                    uint64_t errors) {
    visit_ctx *v = (visit_ctx *)ctx;
    v->rows_seen++;
    v->requests_total += requests;
    v->errors_total += errors;
    if (strcmp(route, "other") == 0) {
        v->found_other = 1;
        v->other_requests = requests;
        v->other_errors = errors;
    }
    if (v->want_route && strcmp(route, v->want_route) == 0) {
        v->found_route = 1;
        v->want_requests = requests;
        v->want_errors = errors;
    }
}

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            fail++;                                                        \
        }                                                                  \
    } while (0)

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static int test_counters(void) {
    int fail = 0;
    metalbear_metrics_reset();
    for (int i = 0; i < 7; i++)
        metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS);
    CHECK(metalbear_metrics_get(METALBEAR_METRIC_REQUESTS) == 7);
    CHECK(metalbear_metrics_get(METALBEAR_METRIC_REQUESTS_FAILED) == 0);
    /* Out-of-range access is ignored, not a crash. */
    metalbear_metrics_inc((metalbear_metric)-1);
    metalbear_metrics_inc((metalbear_metric)METALBEAR_METRIC_COUNT);
    CHECK(metalbear_metric_name(METALBEAR_METRIC_REQUESTS) != NULL);
    CHECK(metalbear_metric_name((metalbear_metric)9999) == NULL);
    if (!fail) printf("PASS: counters\n");
    return fail;
}

static int test_route_accounting(void) {
    int fail = 0;
    metalbear_metrics_reset();

    metalbear_metrics_record_request("com.atproto.repo.getRecord", NULL, 200);
    metalbear_metrics_record_request("com.atproto.repo.getRecord", NULL, 200);
    metalbear_metrics_record_request("com.atproto.repo.getRecord", NULL, 500);
    metalbear_metrics_record_request("app.bsky.feed.getFeed", NULL, 404);
    metalbear_metrics_record_request("app.bsky.feed.getFeed", NULL, 200);

    visit_ctx v = {0};
    v.want_route = "com.atproto.repo.getRecord";
    metalbear_metrics_visit_routes(collect, &v);
    CHECK(v.rows_seen == 2);
    CHECK(v.found_route && v.want_requests == 3 && v.want_errors == 1);
    CHECK(v.found_other == 0);
    CHECK(v.requests_total == 5 && v.errors_total == 2);
    if (!fail) printf("PASS: route accounting\n");
    return fail;
}

static int test_unknown_fallback(void) {
    int fail = 0;
    metalbear_metrics_reset();

    metalbear_metrics_record_request(NULL, NULL, 200);
    metalbear_metrics_record_request("", NULL, 200);
    metalbear_metrics_record_request(NULL, "plain/status", 503);
    metalbear_metrics_record_request("", "plain/status", 200);

    visit_ctx v = {0};
    v.want_route = "unknown";
    metalbear_metrics_visit_routes(collect, &v);
    CHECK(v.found_route && v.want_requests == 2);
    v.rows_seen = 0;
    v.requests_total = 0;
    v.errors_total = 0;
    v.found_route = 0;
    v.want_route = "plain/status";
    metalbear_metrics_visit_routes(collect, &v);
    CHECK(v.found_route && v.want_requests == 2 && v.want_errors == 1);
    CHECK(v.rows_seen == 2);
    if (!fail) printf("PASS: unknown fallback\n");
    return fail;
}

static int test_overflow_spill(void) {
    int fail = 0;
    metalbear_metrics_reset();

    /* Fill the table to its cap with distinct NSIDs. */
    for (size_t i = 1; i <= METALBEAR_METRICS_MAX_ROUTES; i++) {
        char name[64];
        snprintf(name, sizeof(name), "over.%zu", i);
        metalbear_metrics_record_request(name, NULL, 200);
    }
    /* A second request to an existing route still finds it (no dup row). */
    metalbear_metrics_record_request("over.1", NULL, 500);

    /* These arrive past the cap and must spill to `other`. */
    size_t spills = 5;
    for (size_t i = 1; i <= spills; i++) {
        char name[64];
        snprintf(name, sizeof(name), "spill.%zu", i);
        metalbear_metrics_record_request(name, NULL, 200);
    }
    metalbear_metrics_record_request("spill.1", NULL, 503);

    visit_ctx v = {0};
    v.want_route = "over.1";
    metalbear_metrics_visit_routes(collect, &v);
    CHECK(v.rows_seen == METALBEAR_METRICS_MAX_ROUTES + 1); /* + "other" */
    CHECK(v.found_route && v.want_requests == 2 && v.want_errors == 1);
    CHECK(v.found_other);
    CHECK(v.other_requests == spills + 1 && v.other_errors == 1);
    CHECK(v.requests_total == METALBEAR_METRICS_MAX_ROUTES + spills + 2);
    CHECK(v.errors_total == 2);

    /* The spilled routes are not individually named. */
    v = (visit_ctx){0};
    v.want_route = "spill.1";
    metalbear_metrics_visit_routes(collect, &v);
    CHECK(v.found_route == 0);
    if (!fail) printf("PASS: overflow spill\n");
    return fail;
}

static int test_reset(void) {
    int fail = 0;
    metalbear_metrics_reset();

    metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS);
    metalbear_metrics_record_request("com.atproto.repo.getRecord", NULL, 200);

    metalbear_metrics_reset();
    CHECK(metalbear_metrics_get(METALBEAR_METRIC_REQUESTS) == 0);
    visit_ctx v = {0};
    metalbear_metrics_visit_routes(collect, &v);
    CHECK(v.rows_seen == 0);

    /* The table still works after a reset released its storage. */
    metalbear_metrics_record_request("com.atproto.repo.getRecord", NULL, 200);
    v = (visit_ctx){0};
    v.want_route = "com.atproto.repo.getRecord";
    metalbear_metrics_visit_routes(collect, &v);
    CHECK(v.found_route && v.want_requests == 1);
    if (!fail) printf("PASS: reset\n");
    return fail;
}

int main(void) {
    int failures = 0;
    failures += test_counters();
    failures += test_route_accounting();
    failures += test_unknown_fallback();
    failures += test_overflow_spill();
    failures += test_reset();
    if (failures == 0) printf("ALL PASS: metrics\n");
    return failures;
}

/*
 * test_metrics.c — the per-route metrics table, and what it does when full.
 *
 * The bound is a security property: route names arrive from the network (the
 * AppView proxy forwards NSIDs this server has never heard of), so an
 * unbounded label set is a memory-exhaustion lever. These tests pin both
 * halves of the design — the bound holds under a flood of distinct names, and
 * the table still tracks the busiest routes rather than freezing on whatever
 * it happened to see first.
 */

#include "metalbear/metrics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                    \
    } while (0)

/* ------------------------------------------------------------------ */
/* Collecting the visitor's output                                     */
/* ------------------------------------------------------------------ */

typedef struct seen_row {
    char name[128];
    uint64_t requests;
    uint64_t errors;
} seen_row;

typedef struct collected {
    seen_row rows[METALBEAR_METRICS_ROUTE_CEILING + 8];
    size_t count;
    int overflowed;
} collected;

static void collect(void *ctx, const char *route, uint64_t requests,
                    uint64_t errors) {
    collected *c = ctx;
    if (c->count >= sizeof(c->rows) / sizeof(c->rows[0])) {
        c->overflowed = 1;
        return;
    }
    seen_row *row = &c->rows[c->count++];
    snprintf(row->name, sizeof(row->name), "%s", route);
    row->requests = requests;
    row->errors = errors;
}

static void snapshot(collected *out) {
    memset(out, 0, sizeof(*out));
    metalbear_metrics_visit_routes(collect, out);
}

static const seen_row *find(const collected *c, const char *name) {
    for (size_t i = 0; i < c->count; i++)
        if (strcmp(c->rows[i].name, name) == 0) return &c->rows[i];
    return NULL;
}

static uint64_t total_requests(const collected *c) {
    uint64_t n = 0;
    for (size_t i = 0; i < c->count; i++) n += c->rows[i].requests;
    return n;
}

static uint64_t total_errors(const collected *c) {
    uint64_t n = 0;
    for (size_t i = 0; i < c->count; i++) n += c->rows[i].errors;
    return n;
}

static void hit(const char *nsid, unsigned int status, unsigned int times) {
    for (unsigned int i = 0; i < times; i++)
        metalbear_metrics_record_request(nsid, NULL, status);
}

/* ------------------------------------------------------------------ */

/* Ordinary accounting: a route is reported by name, with its error count. */
static void test_basic(void) {
    metalbear_metrics_reset();
    metalbear_metrics_set_max_routes(8);
    CHECK(metalbear_metrics_max_routes() == 8);

    hit("com.atproto.repo.createRecord", 200, 3);
    hit("com.atproto.repo.createRecord", 400, 2);
    metalbear_metrics_record_request(NULL, "/metrics", 200);
    /* Neither an NSID nor a path: still counted, never dropped. */
    metalbear_metrics_record_request(NULL, NULL, 200);

    collected c;
    snapshot(&c);
    const seen_row *create = find(&c, "com.atproto.repo.createRecord");
    CHECK(create && create->requests == 5 && create->errors == 2);
    const seen_row *metrics = find(&c, "/metrics");
    CHECK(metrics && metrics->requests == 1 && metrics->errors == 0);
    CHECK(find(&c, "unknown") != NULL);
    CHECK(find(&c, "other") == NULL);
    CHECK(total_requests(&c) == 7);
}

/*
 * The bound holds. A flood of distinct names — which is what an attacker
 * pointing junk NSIDs at the AppView proxy produces — never grows the table
 * past its capacity, and every request is still counted somewhere.
 */
static void test_bound_holds_under_flood(void) {
    metalbear_metrics_reset();
    metalbear_metrics_set_max_routes(16);

    for (int i = 0; i < 5000; i++) {
        char name[64];
        snprintf(name, sizeof(name), "junk.example.route%d", i);
        metalbear_metrics_record_request(name, NULL, i % 7 == 0 ? 500 : 200);
    }

    collected c;
    snapshot(&c);
    CHECK(!c.overflowed);
    /* At most the capacity, plus the single `other` row. */
    CHECK(c.count <= 17);
    /* Not one request lost: named rows plus `other` equal what was recorded. */
    CHECK(total_requests(&c) == 5000);
    CHECK(total_errors(&c) == 715); /* every 7th of 0..4999 */
}

/*
 * A busy route is not displaced by junk. This is the eviction policy's whole
 * point: the coldest row is one of the one-request junk names, so a flood
 * churns through a single slot and leaves the routes an operator cares about
 * reported by name.
 */
static void test_hot_route_survives_flood(void) {
    metalbear_metrics_reset();
    metalbear_metrics_set_max_routes(4);

    hit("app.bsky.feed.getTimeline", 200, 500);
    hit("com.atproto.sync.getRepo", 200, 100);
    for (int i = 0; i < 1000; i++) {
        char name[64];
        snprintf(name, sizeof(name), "junk.example.route%d", i);
        metalbear_metrics_record_request(name, NULL, 200);
    }

    collected c;
    snapshot(&c);
    const seen_row *hot = find(&c, "app.bsky.feed.getTimeline");
    CHECK(hot && hot->requests == 500);
    const seen_row *warm = find(&c, "com.atproto.sync.getRepo");
    CHECK(warm && warm->requests == 100);
    const seen_row *other = find(&c, "other");
    CHECK(other != NULL);
    CHECK(total_requests(&c) == 1600);
}

/*
 * The defect this replaces: a full table used to freeze, so a route that only
 * became busy after startup was reported as `other` for the life of the
 * process. It now takes the least-used row and is named.
 */
static void test_late_route_is_admitted(void) {
    metalbear_metrics_reset();
    metalbear_metrics_set_max_routes(3);

    hit("early.one", 200, 10);
    hit("early.two", 200, 10);
    hit("early.three", 200, 1);

    /* The table is full, and `early.three` is the coldest row. */
    hit("late.hot", 200, 50);

    collected c;
    snapshot(&c);
    const seen_row *late = find(&c, "late.hot");
    CHECK(late && late->requests == 50);
    CHECK(find(&c, "early.three") == NULL);
    CHECK(find(&c, "early.one") != NULL);
    CHECK(find(&c, "early.two") != NULL);
    /* The evicted row's single request moved to `other`, not to nowhere. */
    const seen_row *other = find(&c, "other");
    CHECK(other && other->requests == 1);
    CHECK(total_requests(&c) == 71);
}

/*
 * The configured capacity is clamped to the compile-time ceiling. This is the
 * memory-safety property in one line: the storage is a fixed array, so a
 * mistyped config cannot make the table larger than the array.
 */
static void test_capacity_is_clamped(void) {
    metalbear_metrics_reset();

    metalbear_metrics_set_max_routes(1000000);
    CHECK(metalbear_metrics_max_routes() == METALBEAR_METRICS_ROUTE_CEILING);

    /* Zero means "the default", not "track nothing". */
    metalbear_metrics_set_max_routes(0);
    CHECK(metalbear_metrics_max_routes() == METALBEAR_METRICS_MAX_ROUTES);

    /* One is honoured, and a second name displaces the first. */
    metalbear_metrics_set_max_routes(1);
    CHECK(metalbear_metrics_max_routes() == 1);
    hit("only.one", 200, 3);
    hit("only.two", 200, 1);
    collected c;
    snapshot(&c);
    CHECK(c.count == 2); /* one route plus `other` */
    CHECK(find(&c, "only.two") != NULL);
    CHECK(total_requests(&c) == 4);
}

/* Lowering the capacity below what is already tracked folds the coldest rows
 * into `other` rather than dropping their counts on the floor. */
static void test_shrinking_capacity_keeps_totals(void) {
    metalbear_metrics_reset();
    metalbear_metrics_set_max_routes(8);

    hit("a.route", 200, 40);
    hit("b.route", 400, 30);
    hit("c.route", 200, 20);
    hit("d.route", 200, 10);

    metalbear_metrics_set_max_routes(2);

    collected c;
    snapshot(&c);
    CHECK(c.count == 3); /* two routes plus `other` */
    CHECK(find(&c, "a.route") != NULL);
    CHECK(find(&c, "b.route") != NULL);
    const seen_row *other = find(&c, "other");
    CHECK(other && other->requests == 30); /* c + d */
    CHECK(total_requests(&c) == 100);
    CHECK(total_errors(&c) == 30);
}

/* reset() clears the rows and the overflow together; a leftover `other` would
 * make the next test's totals wrong in a way that looks like a real bug. */
static void test_reset_clears_overflow(void) {
    metalbear_metrics_reset();
    metalbear_metrics_set_max_routes(1);
    hit("first.route", 200, 5);
    hit("second.route", 200, 5);

    metalbear_metrics_reset();
    collected c;
    snapshot(&c);
    CHECK(c.count == 0);
}

int main(void) {
    test_basic();
    test_bound_holds_under_flood();
    test_hot_route_survives_flood();
    test_late_route_is_admitted();
    test_capacity_is_clamped();
    test_shrinking_capacity_keeps_totals();
    test_reset_clears_overflow();

    /* Leave the process-wide table as a fresh server would find it. */
    metalbear_metrics_set_max_routes(0);
    metalbear_metrics_reset();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_metrics: OK\n");
    return 0;
}

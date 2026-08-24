#define _POSIX_C_SOURCE 200809L

#include "metalbear/account/account_cache.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/account/account_context.h"
#include "metalbear/sequencer.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NACCOUNTS 8

static const char *DIDS[NACCOUNTS] = {
    "did:plc:cachetest0001", "did:plc:cachetest0002", "did:plc:cachetest0003",
    "did:plc:cachetest0004", "did:plc:cachetest0005", "did:plc:cachetest0006",
    "did:plc:cachetest0007", "did:plc:cachetest0008",
};
static const char *HANDLES[NACCOUNTS] = {
    "acc1.test", "acc2.test", "acc3.test", "acc4.test",
    "acc5.test", "acc6.test", "acc7.test", "acc8.test",
};

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Touch every account once; with a tight resident budget the cache must evict
 * idle contexts and never exceed the budget. */
static void test_eviction(void) {
    char tmpl[] = "/tmp/mb_cache_XXXXXX";
    char *root = mkdtemp(tmpl);
    CHECK(root != NULL);

    metalbear_account_registry *registry = NULL;
    char reg_path[256];
    snprintf(reg_path, sizeof(reg_path), "%s/registry.sqlite3", root);
    CHECK(metalbear_account_registry_open(reg_path, &registry) == WF_OK);

    for (int i = 0; i < NACCOUNTS; i++) {
        char dir[256];
        snprintf(dir, sizeof(dir), "%s/acct%d", root, i);
        mkdir(dir, 0700);
        CHECK(metalbear_account_registry_add(registry, DIDS[i], HANDLES[i], "x",
                                             dir) == WF_OK);
    }

    metalbear_account_cache *cache = metalbear_account_cache_new(
        "did:plc:service", "https://example.com", root);
    CHECK(cache != NULL);
    metalbear_account_cache_set_max_resident(cache, 2);

    for (int i = 0; i < NACCOUNTS; i++) {
        metalbear_account_context *ctx =
            metalbear_account_cache_get(cache, registry, DIDS[i]);
        CHECK(ctx != NULL);
        /* A second get of the same DID must return the cached (same) context
         * and count a hit, not reopen. */
        metalbear_account_context *again =
            metalbear_account_cache_get(cache, registry, DIDS[i]);
        CHECK(again == ctx);
        metalbear_account_cache_release(cache, again);
        metalbear_account_cache_release(cache, ctx);
    }

    size_t resident = 0, idle = 0;
    uint64_t hits = 0, misses = 0, evictions = 0;
    metalbear_account_cache_stats(cache, &resident, &idle, &evictions, &hits,
                                  &misses);
    /* Budget is 2 idle; after releasing everything, resident must be <= 2. */
    CHECK(resident <= 2);
    /* Eight distinct accounts, each fetched twice: 8 misses, 8 hits. */
    CHECK(misses == NACCOUNTS);
    CHECK(hits == NACCOUNTS);
    /* At least some evictions must have occurred to stay under budget. */
    CHECK(evictions > 0);
    CHECK(idle == resident);

    metalbear_account_cache_free(cache);
    metalbear_account_registry_free(registry);
}

#define NTHREADS 4
#define ITERS 200

static metalbear_account_cache *g_cache;
static metalbear_account_registry *g_registry;

static void *hammer(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        int idx = rand() % NACCOUNTS;
        metalbear_account_context *ctx =
            metalbear_account_cache_get(g_cache, g_registry, DIDS[idx]);
        if (ctx) metalbear_account_cache_release(g_cache, ctx);
    }
    return NULL;
}

static void test_concurrent(void) {
    char tmpl[] = "/tmp/mb_cache_c_XXXXXX";
    char *root = mkdtemp(tmpl);
    CHECK(root != NULL);

    char reg_path[256];
    snprintf(reg_path, sizeof(reg_path), "%s/registry.sqlite3", root);
    CHECK(metalbear_account_registry_open(reg_path, &g_registry) == WF_OK);
    for (int i = 0; i < NACCOUNTS; i++) {
        char dir[256];
        snprintf(dir, sizeof(dir), "%s/acct%d", root, i);
        mkdir(dir, 0700);
        CHECK(metalbear_account_registry_add(g_registry, DIDS[i], HANDLES[i],
                                             "x", dir) == WF_OK);
    }

    g_cache = metalbear_account_cache_new("did:plc:service",
                                          "https://example.com", root);
    CHECK(g_cache != NULL);
    metalbear_account_cache_set_max_resident(g_cache, 4);

    pthread_t threads[NTHREADS];
    for (int i = 0; i < NTHREADS; i++)
        pthread_create(&threads[i], NULL, hammer, NULL);
    for (int i = 0; i < NTHREADS; i++) pthread_join(threads[i], NULL);

    size_t resident = 0, idle = 0;
    metalbear_account_cache_stats(g_cache, &resident, &idle, NULL, NULL, NULL);
    /* Concurrency must not let resident exceed the budget plus the in-flight
     * threads (each holds at most one referenced context). */
    CHECK(resident <= 4 + NTHREADS);

    metalbear_account_cache_free(g_cache);
    metalbear_account_registry_free(g_registry);
    g_cache = NULL;
    g_registry = NULL;
}

int main(void) {
    test_eviction();
    test_concurrent();
    if (failures) {
        fprintf(stderr, "%d account-cache check(s) failed\n", failures);
        return 1;
    }
    printf("all account-cache checks passed\n");
    return 0;
}

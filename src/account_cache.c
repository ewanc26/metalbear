#define _POSIX_C_SOURCE 200809L

#include "metalbear/account_cache.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct metalbear_account_cache {
    char *service_did;
    char *public_url;
    char *data_directory;
    pthread_mutex_t lock;
    struct cache_entry {
        char *did;
        metalbear_account_context *ctx;
        struct cache_entry *next;
    } *entries;
};

metalbear_account_cache *metalbear_account_cache_new(const char *service_did,
                                                     const char *public_url,
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
    return cache;
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

metalbear_account_context *metalbear_account_cache_get(
    metalbear_account_cache *cache, metalbear_account_registry *registry,
    const char *did) {
    if (!cache || !registry || !did) return NULL;

    pthread_mutex_lock(&cache->lock);
    for (struct cache_entry *e = cache->entries; e; e = e->next) {
        if (strcmp(e->did, did) == 0) {
            metalbear_account_context *ctx = e->ctx;
            pthread_mutex_unlock(&cache->lock);
            return ctx;
        }
    }
    pthread_mutex_unlock(&cache->lock);

    /* Not cached yet: resolve the registry entry and open its bundle. */
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(registry, did, &entry) != WF_OK ||
        !entry) {
        metalbear_account_entry_free(entry);
        return NULL;
    }

    metalbear_account_context *ctx = NULL;
    wf_status status = metalbear_account_context_open(
        cache->service_did, cache->public_url, did, entry->handle,
        entry->data_directory, NULL, &ctx);
    metalbear_account_entry_free(entry);
    if (status != WF_OK || !ctx) return NULL;

    pthread_mutex_lock(&cache->lock);
    /* Re-check after re-acquiring the lock in case another thread won. */
    for (struct cache_entry *e = cache->entries; e; e = e->next) {
        if (strcmp(e->did, did) == 0) {
            metalbear_account_context *existing = e->ctx;
            pthread_mutex_unlock(&cache->lock);
            metalbear_account_context_close(ctx);
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
    ne->ctx = ctx;
    ne->next = cache->entries;
    cache->entries = ne;
    pthread_mutex_unlock(&cache->lock);
    return ctx;
}

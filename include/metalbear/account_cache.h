#ifndef METALBEAR_ACCOUNT_CACHE_H
#define METALBEAR_ACCOUNT_CACHE_H

#include "metalbear/account_context.h"
#include "metalbear/account_registry.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_account_cache metalbear_account_cache;

/* Create a cache of open per-account store bundles. The cache owns the
 * contexts it opens and keeps them alive for the server lifetime, so the
 * pointers it returns are stable for the duration of any request that uses
 * them (this is what the wolfram per-request repo/blob resolver needs). */
metalbear_account_cache *metalbear_account_cache_new(const char *service_did,
                                                     const char *public_url,
                                                     const char *data_directory);
void metalbear_account_cache_free(metalbear_account_cache *cache);

/* Return the open context for `did`, opening it on first use. The returned
 * context is owned by the cache and must NOT be freed by the caller. Returns
 * NULL when the account is unknown to `registry` or cannot be opened. */
metalbear_account_context *metalbear_account_cache_get(
    metalbear_account_cache *cache, metalbear_account_registry *registry,
    const char *did);

#ifdef __cplusplus
}
#endif

#endif

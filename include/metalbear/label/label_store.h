#ifndef METALBEAR_LABEL_STORE_H
#define METALBEAR_LABEL_STORE_H

/* A labeler's own label records, kept in labels.sqlite3 beside the other
 * per-server databases. The labeler is MetalBear itself: each label is one
 * record that the server created about one of its accounts, such as a
 * "!takedown". Labels are stored unsigned (see docs/labeler.md).
 *
 * Only the server's own labels live here. Labels from other labelers are not
 * stored; subscribing to them is not implemented. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_label_store metalbear_label_store;

/* A query over the store. Empty sets match nothing, so callers that want
 * "any source" must pass none and leave `sources_present` false. The lexicon
 * requires at least one URI pattern; the store does not enforce it, and the
 * handler checks it before calling. */
typedef struct metalbear_label_query {
    /* Each pattern is an exact URI, or a prefix ending in '*'. */
    const char *const *uri_patterns;
    size_t uri_pattern_count;
    /* Labeler DIDs to keep. Ignored unless `sources_present` is set. */
    const char *const *sources;
    size_t source_count;
    bool sources_present;
    /* Return labels with an id greater than this. 0 starts at the beginning. */
    int64_t after_id;
    /* Maximum labels per page, clamped to 1..250 by the store. */
    int limit;
} metalbear_label_query;

wf_status metalbear_label_store_open(const char *path,
                                     metalbear_label_store **out);
void metalbear_label_store_free(metalbear_label_store *store);

/* Record one label. `cts` is an RFC 3339 timestamp; NULL uses the current
 * time. */
wf_status metalbear_label_store_insert(metalbear_label_store *store,
                                       const char *src, const char *uri,
                                       const char *val, bool neg,
                                       const char *cts);

/* Writes the com.atproto.label.queryLabels response body to `*out_json`:
 * {"labels":[...]} and, when more labels follow, "cursor" (the id to pass as
 * the next after_id). Each label carries ver, src, uri, val, cts, and neg
 * when set. `*out_json` is caller-owned. */
wf_status metalbear_label_store_query(metalbear_label_store *store,
                                      const metalbear_label_query *query,
                                      char **out_json);

#ifdef __cplusplus
}
#endif

#endif

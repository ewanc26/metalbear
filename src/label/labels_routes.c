#define _POSIX_C_SOURCE 200809L

#include "metalbear/label/labels_routes.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define LABEL_QUERY_MAX_LIMIT 250

/* Percent-decode one query component, with '+' as a space. The caller frees
 * *out. */
static wf_status decode_component(const char *in, size_t len, char **out) {
    char *buf = malloc(len + 1);
    if (!buf) return WF_ERR_ALLOC;
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        if (in[i] == '%' && i + 2 < len && isxdigit((unsigned char)in[i + 1]) &&
            isxdigit((unsigned char)in[i + 2])) {
            char hex[3] = {in[i + 1], in[i + 2], 0};
            buf[o++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (in[i] == '+') {
            buf[o++] = ' ';
        } else {
            buf[o++] = in[i];
        }
    }
    buf[o] = '\0';
    *out = buf;
    return WF_OK;
}

typedef struct query_args {
    char **uri_patterns;
    size_t uri_pattern_count;
    char **sources;
    size_t source_count;
    bool sources_present;
    int64_t after_id;
    int limit;
    bool limit_given;
} query_args;

static void free_query_args(query_args *args) {
    for (size_t i = 0; i < args->uri_pattern_count; i++)
        free(args->uri_patterns[i]);
    for (size_t i = 0; i < args->source_count; i++) free(args->sources[i]);
    free(args->uri_patterns);
    free(args->sources);
}

/* Parse the raw query string. A repeated key collects every value, which the
 * XRPC parameter map cannot do: it keeps only the first. Returns
 * WF_ERR_INVALID_ARG for a malformed value, with *message set to what the
 * client should hear. */
static wf_status parse_query(const char *raw, query_args *args,
                             const char **message) {
    memset(args, 0, sizeof(*args));
    args->limit = 0;
    if (!raw) return WF_OK;
    size_t n = strlen(raw);
    /* Upper bound on the number of values: one per '&' plus one. */
    size_t slots = 1;
    for (size_t i = 0; i < n; i++)
        if (raw[i] == '&') slots++;
    args->uri_patterns = calloc(slots, sizeof(char *));
    args->sources = calloc(slots, sizeof(char *));
    if (!args->uri_patterns || !args->sources) {
        free_query_args(args);
        return WF_ERR_ALLOC;
    }

    size_t start = 0;
    while (start <= n) {
        size_t end = start;
        while (end < n && raw[end] != '&') end++;
        const char *pair = raw + start;
        size_t pair_len = end - start;
        const char *eq = memchr(pair, '=', pair_len);
        size_t key_len = eq ? (size_t)(eq - pair) : pair_len;
        const char *val = eq ? eq + 1 : pair + pair_len;
        size_t val_len = eq ? pair_len - key_len - 1 : 0;

        char *key = NULL, *value = NULL;
        wf_status st = decode_component(pair, key_len, &key);
        if (st == WF_OK) st = decode_component(val, val_len, &value);
        if (st != WF_OK) {
            free(key);
            free(value);
            free_query_args(args);
            return st;
        }

        if (strcmp(key, "uriPatterns") == 0) {
            args->uri_patterns[args->uri_pattern_count++] = value;
        } else if (strcmp(key, "sources") == 0) {
            args->sources_present = true;
            args->sources[args->source_count++] = value;
        } else if (strcmp(key, "limit") == 0) {
            char *e = NULL;
            long v = strtol(value, &e, 10);
            if (!*value || *e || v < 1 || v > LABEL_QUERY_MAX_LIMIT) {
                *message = "limit must be an integer from 1 to 250";
                free(key);
                free(value);
                free_query_args(args);
                return WF_ERR_INVALID_ARG;
            }
            args->limit = (int)v;
            args->limit_given = true;
            free(value);
        } else if (strcmp(key, "cursor") == 0) {
            char *e = NULL;
            errno = 0;
            long long v = strtoll(value, &e, 10);
            if (!*value || *e || errno != 0 || v < 0) {
                *message = "cursor is not a valid cursor";
                free(key);
                free(value);
                free_query_args(args);
                return WF_ERR_INVALID_ARG;
            }
            args->after_id = (int64_t)v;
            free(value);
        } else {
            free(value);
        }
        free(key);
        start = end + 1;
    }
    return WF_OK;
}

static wf_status h_query_labels(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    metalbear_label_store *store = ctx;
    query_args args;
    const char *message = "invalid query";
    wf_status st = parse_query(req->raw_query, &args, &message);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest", message);
        return WF_OK;
    }
    if (args.uri_pattern_count == 0) {
        free_query_args(&args);
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "uriPatterns is required");
        return WF_OK;
    }
    for (size_t i = 0; i < args.uri_pattern_count; i++) {
        if (!args.uri_patterns[i][0]) {
            free_query_args(&args);
            wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                       "uriPatterns must not be empty");
            return WF_OK;
        }
    }

    metalbear_label_query query = {
        .uri_patterns = (const char *const *)args.uri_patterns,
        .uri_pattern_count = args.uri_pattern_count,
        .sources = (const char *const *)args.sources,
        .source_count = args.source_count,
        .sources_present = args.sources_present,
        .after_id = args.after_id,
        .limit = args.limit_given ? args.limit : 0,
    };
    char *js = NULL;
    st = metalbear_label_store_query(store, &query, &js);
    free_query_args(&args);
    if (st != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "InternalServerError",
                                   "label query failed");
        return WF_OK;
    }
    wf_xrpc_response_set_body(resp, js, strlen(js));
    free(js);
    return WF_OK;
}

wf_status metalbear_labels_register(wf_xrpc_server *server,
                                    metalbear_label_store *store) {
    if (!server || !store) return WF_ERR_INVALID_ARG;
    return wf_xrpc_server_register_query(
        server, "com.atproto.label.queryLabels", h_query_labels, store);
}

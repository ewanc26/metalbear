#ifndef METALBEAR_REPORT_H
#define METALBEAR_REPORT_H

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_report_store metalbear_report_store;

typedef struct metalbear_report {
    int64_t id;
    char *did;
    char *reason_type;
    char *reason;
    char *subject_type;
    char *subject_uri;
    char *subject_cid;
    char *mod_tool_name;
    char *mod_tool_meta;
    char *reported_by;
    char *created_at;
} metalbear_report;

wf_status metalbear_report_store_open(const char *path,
                                      metalbear_report_store **out);
void metalbear_report_store_free(metalbear_report_store *store);
wf_status metalbear_report_store_create(metalbear_report_store *store,
                                        const char *reporter_did,
                                        const char *reason_type,
                                        const char *reason,
                                        const char *subject_type,
                                        const char *subject_uri,
                                        const char *subject_cid,
                                        const char *mod_tool_name,
                                        const char *mod_tool_meta,
                                        int64_t *out_id);
wf_status metalbear_report_store_get(metalbear_report_store *store,
                                     int64_t id, metalbear_report **out);
void metalbear_report_free(metalbear_report *report);
void metalbear_report_list_free(metalbear_report *reports, size_t count);

#ifdef __cplusplus
}
#endif

#endif

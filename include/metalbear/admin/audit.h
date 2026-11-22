#ifndef METALBEAR_ADMIN_AUDIT_H
#define METALBEAR_ADMIN_AUDIT_H

/* Operator-visible audit trail for administrative actions (issue #160).
 *
 * Every com.atproto.admin.* call appends one row, whether it succeeded or was
 * refused: time, admin identity, action (the NSID), target DID and outcome.
 * Rows are read back through the admin-gated GET /_ops/audit route with an
 * id-based keyset cursor. No credential material is ever stored.
 */

#include "wolfram/xrpc_server.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_admin_audit metalbear_admin_audit;

typedef struct metalbear_admin_audit_entry {
    int64_t id;
    char *time;
    char *admin;
    char *action;
    char *target_did; /* NULL when the call had no single target DID */
    char *outcome;
} metalbear_admin_audit_entry;

wf_status metalbear_admin_audit_open(const char *path,
                                     metalbear_admin_audit **out);
void metalbear_admin_audit_free(metalbear_admin_audit *audit);

/* Append one row. `time == NULL` means "now", formatted as an ISO-8601 UTC
 * datetime. `target_did` and `outcome` may be NULL/empty where not applicable.
 * When `out_id` is non-NULL it receives the new row's id (also the cursor). */
wf_status metalbear_admin_audit_append(metalbear_admin_audit *audit,
                                       const char *time, const char *admin,
                                       const char *action,
                                       const char *target_did,
                                       const char *outcome, int64_t *out_id);

/* Newest-first page of at most `limit` rows with id < `before_id`; 0 starts at
 * the newest. `out` is a caller-owned array freed with
 * metalbear_admin_audit_entries_free. */
wf_status metalbear_admin_audit_list(metalbear_admin_audit *audit,
                                     int64_t before_id, size_t limit,
                                     metalbear_admin_audit_entry **out,
                                     size_t *out_count);
void metalbear_admin_audit_entries_free(metalbear_admin_audit_entry *entries,
                                        size_t count);

/* Total row count, for diagnostics and tests. Returns 0 on failure. */
size_t metalbear_admin_audit_count(metalbear_admin_audit *audit);

/* Best-effort extraction of the target DID from an XRPC request's parameters:
 * did, subject (string or object), recipientDid, or the first of dids. Returns
 * false and leaves `out` untouched when no DID-shaped value is present. The
 * result is copied into the caller's buffer. */
bool metalbear_admin_audit_target_did(const wf_xrpc_request *req, char *out,
                                      size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_ADMIN_AUDIT_H */

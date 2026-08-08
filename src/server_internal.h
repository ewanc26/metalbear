#ifndef METALBEAR_SERVER_INTERNAL_H
#define METALBEAR_SERVER_INTERNAL_H

/* The full metalbear_server layout and the handful of cross-cutting helpers
 * route-handler modules need (account/context resolution, response
 * serialization, DNS publish/retract), shared between server.c and the
 * per-domain route files it delegates to (src/admin/, and more as server.c's
 * remaining handlers get split out the same way). Not part of the public
 * API -- include/metalbear/server.h keeps the opaque metalbear_server
 * typedef for external consumers; this header is the real definition,
 * visible only within this module. */

#include "metalbear/account/account.h"
#include "metalbear/account/account_cache.h"
#include "metalbear/account/account_context.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/dns/handle_dns.h"
#include "metalbear/email.h"
#include "metalbear/moderation/report.h"
#include "metalbear/ops/update_watcher.h"
#include "metalbear/oauth/oauth.h"
#include "metalbear/repo/key_rotation.h"
#include "metalbear/repo/repo_store.h"
#include "metalbear/sequencer.h"
#include "metalbear/server.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct metalbear_server {
    wf_xrpc_server *xrpc;
    /* When this process began serving, for the uptime gauge at /metrics. */
    time_t started_at;
    /*
     * The server's own PLC rotation key and OAuth store.
     *
     * Both used to be reached through a configured "bootstrap" account, which
     * made that one account structurally privileged: the host could not exist
     * before its first user, and anything server-wide that reached through it
     * acted on the wrong account for everybody else. They belong to the host.
     */
    metalbear_key_rotation *plc_rotation;
    metalbear_oauth_store *oauth;
    metalbear_account_registry *registry;
    wf_rate_limiter *rate_limiter;
    /* The general per-client budget that `rate_limiter` was created with,
     * kept so /_debug/health can report what it is rather than just that it
     * exists. */
    int64_t rate_limit_budget;
    int64_t rate_limit_window;
    /*
     * The reference PDS rate-limits a handful of account-security-sensitive
     * endpoints more tightly than the general per-IP budget above, some with
     * two simultaneous tiers (both always charged; either can reject) and
     * some keyed by identifier or DID rather than IP. See createSession.ts,
     * requestPasswordReset.ts, requestAccountDelete.ts,
     * requestEmailConfirmation.ts and requestEmailUpdate.ts upstream for the
     * exact points/durationMs this mirrors.
     */
    wf_rate_limiter *rl_create_session_day;
    wf_rate_limiter *rl_create_session_5min;
    wf_rate_limiter *rl_request_password_reset_day;
    wf_rate_limiter *rl_request_password_reset_hour;
    wf_rate_limiter *rl_request_account_delete_day;
    wf_rate_limiter *rl_request_account_delete_hour;
    wf_rate_limiter *rl_request_email_confirmation_day;
    wf_rate_limiter *rl_request_email_confirmation_hour;
    wf_rate_limiter *rl_request_email_update_day;
    wf_rate_limiter *rl_request_email_update_hour;
    /* Shared across createRecord/putRecord/deleteRecord/applyWrites, keyed
     * by DID, weighted by write cost (create=3, update=2, delete=1) --
     * mirrors rate-limits.ts's "repo-write-hour"/"repo-write-day" shared
     * buckets exactly, including the weighting comment ("creates=3,
     * puts=2, deletes=1"). Shared because a client alternating write kinds
     * should not get a bigger effective budget than one that only creates. */
    wf_rate_limiter *rl_repo_write_hour;
    wf_rate_limiter *rl_repo_write_day;
    /* updateHandle.ts: 10/5min + 50/day, keyed by DID. */
    wf_rate_limiter *rl_update_handle_5min;
    wf_rate_limiter *rl_update_handle_day;
    /* sync/getRepo.ts: 6000/5min, keyed by IP, and (per rate-limits.ts's
     * "global" bucket calcKey) deliberately excluded from the global-ip
     * bucket -- a high-volume relay sync path with its own budget, not
     * sharing the general per-IP allowance every other route draws from.
     * The general allowance is `rate_limiter` above (default 3000/5min,
     * matching rate-limits.ts's "global-ip" bucket); getRepo's own
     * route-specific limiter here replaces it rather than stacking, since
     * a route-specific limiter always takes precedence (see
     * wf_server_find_route_rate_limiter in xrpc_server.c). */
    wf_rate_limiter *rl_get_repo_5min;
    metalbear_email *email;
    char *service_did;
    char *public_url;
    char *user_domain;
    char *data_directory;
    char *account_email;
    /* Override for the operator email shown on the landing page
     * and in operator.json. When set, this takes precedence over
     * account_email for the operator contact address. */
    char *operator_email;
    /* Who runs this instance; surfaced on describeServer where the protocol
     * defines a field, and on /operator.json where it does not. */
    char *operator_name;
    char *operator_url;
    char *support_url;
    char *instance_description;
    char *privacy_policy_url;
    char *terms_of_service_url;
    bool development;
    int64_t retention_max_age;
    int64_t retention_min_events;
    /* refpds-mirrored config (METALBEAR_*) */
    char *admin_password; /* may be NULL => admin endpoints 401 */
    char *crawlers;       /* comma-separated relay hosts, may be NULL */
    bool invite_required;
    int64_t blob_upload_limit; /* 0 => unlimited */
    bool accepting_imports;    /* gates com.atproto.repo.importRepo */
    int64_t max_import_size;   /* 0 => unlimited; caps importRepo's CAR body */
    char *plc_url;             /* PLC directory URL or NULL */
    char *appview_url;         /* Upstream AppView URL or NULL */
    char *appview_did; /* Upstream AppView DID for service-auth or NULL */
    metalbear_account_cache *account_cache;
    metalbear_report_store *reports;
    /* The PDS-wide firehose log. subscribeRepos is one stream for the whole
     * host, so every account publishes into this rather than its own. */
    metalbear_sequencer *sequencer;
    /* Lexicon corpus used to validate records on write. NULL when no corpus
     * was found, in which case every write reports validationStatus
     * "unknown" rather than pretending records were checked. */
    wf_lexicon_registry *lexicons;
    /* Publishes the `_atproto` TXT records that make minted handles resolve.
     * NULL when no DNS provider is configured, which leaves those records to
     * the operator. */
    metalbear_handle_dns *handle_dns;
    metalbear_update_watcher *update_watcher;
};

/* Point/retract `_atproto.<handle>` at `did`, if a DNS provider is
 * configured. Never fatal to the operation that triggered it -- see the
 * definitions in server.c for why. */
void publish_handle_dns(metalbear_server *server, const char *handle,
                        const char *did);
void retract_handle_dns(metalbear_server *server, const char *handle);

/* Join a directory and a name into a heap-allocated path, adding exactly one
 * '/' regardless of whether `directory` already ends with one. */
char *join_path(const char *directory, const char *name);

/* Clamped integer query parameter, defaulting to `fallback` when absent, not
 * a number, or out of [min, max]. */
int query_param_int(const cJSON *params, const char *name, int fallback,
                    int min, int max);

/* Boolean query parameter, defaulting to fallback when absent or not a boolean / string bool. */
bool query_param_bool(const cJSON *params, const char *name, bool fallback);

/* Split `at://<authority>/<collection>/<rkey>` into its three parts, each
 * copied into the caller's buffer. False unless all three are present and
 * fit. */
bool split_at_uri(const char *uri, char *authority, size_t authority_sz,
                  char *collection, size_t collection_sz, char *rkey,
                  size_t rkey_sz);

/* Return the cached context for `did`, owned by the cache (never freed by
 * the caller). NULL when the DID is unknown / cannot be opened. */
metalbear_account_context *context_for_did(metalbear_server *server,
                                           const char *did);

/* Resolve `identifier` (DID or handle) to its account context via the
 * registry, then context_for_did. Owned by the cache, never freed by the
 * caller. */
metalbear_account_context *context_for_identifier(metalbear_server *server,
                                                  const char *identifier);

/* The takedown ref recorded against an account, or NULL. Caller frees. */
char *account_takedown_ref(metalbear_server *server, const char *did);

/* The account status the lexicons report (mirrors the reference PDS's
 * formatAccountStatus): a takedown outranks a deactivation, and an active
 * account carries no `status` at all (returns NULL). Writes the
 * accompanying `active` boolean through `out_active`. */
const char *account_status_string(metalbear_server *server,
                                  metalbear_account_context *acct,
                                  bool *out_active);

/* Serialize `root` (consumed) into `response` as the XRPC JSON body. */
wf_status set_json(wf_xrpc_response *response, cJSON *root);

/* Resolve an XRPC request's bearer token to its account context. Owned by
 * the cache, never freed by the caller. NULL when unauthenticated or the
 * token names an unknown account. */
metalbear_account_context *resolve_request_context(metalbear_server *server,
                                                   const wf_xrpc_request *req);

/* Whether the account is taken down, which no bearer token may act
 * through. */
bool account_is_taken_down(metalbear_server *server, const char *did);

/* Build this server's DID document for a local account. Caller must
 * cJSON_Delete the result. */
cJSON *build_did_doc(metalbear_server *server, metalbear_account_context *acct);

/* Whether `acct`'s current DID document (built locally for a self-hosted
 * did:web, fetched over the network otherwise) still names this service and
 * this repo's signing key. */
bool did_doc_matches_service(metalbear_server *server,
                             metalbear_account_context *acct);

/* Consume from up to two rate-limiter tiers under the same key, matching the
 * reference PDS's MethodRateLimit[] semantics for multi-tier endpoints.
 * `tier_b` may be NULL for a single-tier check. `cost` is the number of
 * points this request consumes (1 for a normal request; repo writes are
 * weighted per rate-limits.ts's calcPoints -- create=3, update=2, delete=1).
 * Always sets the RateLimit and Retry-After response headers; returns false
 * (with the {"error":"RateLimitExceeded",...} body filled in) when any tier
 * is empty. */
bool check_endpoint_rate_limit(wf_rate_limiter *tier_a, wf_rate_limiter *tier_b,
                               const char *key, unsigned int cost,
                               wf_xrpc_response *response);

/* The token after "Bearer " in an Authorization header, or NULL when the
 * header is absent or uses a different scheme. */
const char *bearer_token(const char *header);

/* Decode the `sub` claim from a JWT *without* verifying its signature. Used
 * only to route a request to the account whose auth store can then perform
 * real signature/expiry/scope verification. Returns a caller-owned string
 * (free() it), or NULL on any parse failure. */
char *jwt_subject(const char *token);

/* The reference PDS's assertRepoAvailability, which every sync read runs
 * before touching the repository. A taken-down repository reports a
 * different error from a deactivated one. Returns false with the response
 * already filled in. */
bool assert_repo_available(metalbear_server *server,
                           metalbear_account_context *acct,
                           const wf_xrpc_request *request,
                           wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_SERVER_INTERNAL_H */

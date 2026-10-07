#include "appview_routes.h"
#include "appview_proxy_http.h"
#include "appview_raw.h"
#include "appview_resolve.h"
#include "../server_internal.h"

#include "metalbear/account/account.h"
#include "metalbear/account/account_context.h"
#include "metalbear/log.h"
#include "metalbear/oauth/auth.h"

#include "wolfram/server.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Proxy an app.bsky.* request to the AppView, minting service-auth from the
 * requester's own account (iss=requester DID, aud=AppView DID). Returns 502
 * on network failure, otherwise mirrors the upstream status/body. */
static wf_status proxy_appview(metalbear_server *server,
                               const char *requester_did,
                               const wf_xrpc_request *req,
                               wf_xrpc_response *resp, bool send_auth) {
    if (!server->appview_url || !server->appview_url[0] ||
        !server->appview_did || !server->appview_did[0]) {
        wf_xrpc_response_set_error(resp, 501, "MethodNotImplemented",
                                   "No AppView configured");
        return WF_OK;
    }

    const char *audience = NULL;
    char audience_buf[256];
    char *upstream =
        appview_resolve_upstream(server, req, resp, &audience, audience_buf);
    if (!upstream) return WF_OK;

    char target[8192];
    if (!appview_target_url(target, sizeof(target), upstream, req, resp))
        return WF_OK;

    char *service_token = NULL;
    if (send_auth && requester_did && requester_did[0]) {
        metalbear_account_context *acct =
            context_for_did(server, requester_did);
        if (acct && acct->repo) {
            metalbear_repo_store_create_service_auth(acct->repo, audience,
                                                     (int64_t)time(NULL) + 300,
                                                     req->nsid, &service_token);
        }
    }

    appview_proxy_reply reply;
    bool sent = appview_proxy_exchange(req, target, service_token, resp, &reply);
    free(service_token);
    if (!sent) return WF_OK;

    /* Read-after-write: splice in the requester's own records that the
     * upstream has not indexed yet, so a just-written post is visible to its
     * author immediately rather than only once the AppView catches up. */
    char *munged = NULL;
    if (reply.status == 200 && reply.body.data && reply.body.len > 0 &&
        reply.headers.repo_rev && reply.headers.repo_rev[0] && requester_did &&
        (!reply.headers.content_type ||
         strstr(reply.headers.content_type, "application/json") != NULL)) {
        munged = read_after_write_munge(
            server, requester_did, req->nsid ? req->nsid : "",
            reply.headers.repo_rev, reply.body.data, reply.body.len, resp);
    }
    appview_proxy_reply_send(resp, &reply, munged);
    free(munged);
    appview_proxy_reply_free(&reply);
    return WF_OK;
}

/* Generic fallback for unmatched NSIDs. Runs before MetalBear's own auth
 * callback (the framework invokes it in place of route dispatch, not
 * alongside it -- see xrpc_server.c's dispatch), so a Bearer token offered
 * here has never been checked by anything: verify it the same way
 * authenticate_request does for a registered route (decode the unverified
 * `sub` claim to find which account's store should check the signature,
 * then verify against that store), then mint the same kind of
 * self-signed service-auth JWT proxy_appview mints for explicitly
 * registered routes. Without this, every unregistered app.bsky./chat.bsky.
 * route reached the AppView with no credential at all and any endpoint
 * needing the caller's identity failed -- this function's own doc comment
 * already promised "signed by the account the request resolves to" before
 * this fix, it just never actually happened. */
wf_status proxy_fallback(void *ctx, const wf_xrpc_request *req,
                         wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (!server->appview_url || !server->appview_url[0]) {
        wf_xrpc_response_set_error(resp, 501, "MethodNotImplemented",
                                   "No AppView configured");
        return WF_OK;
    }

    const char *audience = NULL;
    char audience_buf[256];
    char *upstream =
        appview_resolve_upstream(server, req, resp, &audience, audience_buf);
    if (!upstream) return WF_OK;

    char target[8192];
    if (!appview_target_url(target, sizeof(target), upstream, req, resp))
        return WF_OK;

    /* A token was offered but has never been checked by anything at this
     * point -- verify it now, or refuse outright. Silently falling back to
     * an anonymous proxy on a bad token would let a client downgrade its
     * own auth requirement just by sending garbage, which registered
     * routes never allow. */
    char *service_token = NULL;
    const char *provided = bearer_token(req->auth_header);
    if (provided) {
        char *sub = jwt_subject(provided);
        metalbear_account_context *acct =
            sub ? context_for_did(server, sub) : NULL;
        metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
        if (!acct || metalbear_auth_verify_access_scope(acct->auth, provided,
                                                        &scope) != WF_OK) {
            free(sub);
            wf_xrpc_response_set_error(resp, 401, "InvalidToken",
                                       "Token could not be verified");
            return WF_OK;
        }
        if (acct->repo)
            metalbear_repo_store_create_service_auth(acct->repo, audience,
                                                     (int64_t)time(NULL) + 300,
                                                     req->nsid, &service_token);
        free(sub);
    }

    appview_proxy_reply reply;
    bool sent = appview_proxy_exchange(req, target, service_token, resp, &reply);
    free(service_token);
    if (!sent) return WF_OK;
    appview_proxy_reply_send(resp, &reply, NULL);
    appview_proxy_reply_free(&reply);
    return WF_OK;
}

/* ---- app.bsky.* AppView proxy handlers ----------------------------------
 *
 * Other PDS implementations (rsky-pds, ref-pds) implement these endpoints
 * as first-class handlers and proxy them to an AppView with service-auth
 * minted from the requester's account. The auth callback runs first, so
 * req->authed_subject contains the requester DID.
 */

static wf_status appview_proxy(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp, bool send_auth) {
    metalbear_server *server = ctx;
    const char *requester_did = req->authed_subject;
    return proxy_appview(server, requester_did, req, resp, send_auth);
}

/* Public read endpoints — proxy without service-auth so the public
 * AppView (api.bsky.app) serves public content. A local AppView that
 * trusts the PDS can be configured later by re-enabling auth. */
static wf_status appview_public(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    return appview_proxy(ctx, req, resp, false);
}

/* User-specific endpoints — send service-auth JWT so a trusted AppView
 * can return per-user data. The public AppView will reject these. */
static wf_status appview_private(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    return appview_proxy(ctx, req, resp, true);
}

/* Feed endpoints — public reads */
wf_status appview_get_feed(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_feed_skeleton(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_author_feed(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_actor_feeds(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_feed_generators(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_feed_generator(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_posts(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Actor endpoints — public reads */
wf_status appview_get_profile(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    metalbear_server *server = ctx;

    // Check for local profile parameter (did=...
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *did_param = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        if (cJSON_IsString(did_param) && did_param->valuestring[0]) {
            const char *provided_did = did_param->valuestring;
            metalbear_account_context *acct =
                context_for_did(server, provided_did);
            if (acct && metalbear_account_is_active(acct->account)) {
                LOG_DEBUG("Handling local profile for did:%s", provided_did);

                cJSON *root = cJSON_CreateObject();
                if (!root) {
                    wf_xrpc_response_set_error(
                        resp, 500, "InternalError",
                        "Failed to create local profile");
                    return WF_OK;
                }

                cJSON_AddStringToObject(root, "did", provided_did);
                cJSON_AddStringToObject(
                    root, "handle", acct->handle ? acct->handle : "unknown");
                // Enrich from the account's app.bsky.actor.profile record
                // (literal key "self" per profile.json). An account with no
                // profile record still gets a valid bare {did, handle} view.
                char *record_json = NULL, *record_cid = NULL;
                if (acct->repo &&
                    metalbear_repo_store_get_record(
                        acct->repo, "app.bsky.actor.profile", "self",
                        &record_json, &record_cid) == WF_OK &&
                    record_json) {
                    cJSON *record = cJSON_Parse(record_json);
                    if (record) {
                        append_profile_record_fields(root, record);
                        cJSON_Delete(record);
                    }
                    free(record_json);
                }
                free(record_cid);

                return set_json(resp, root);
            }
        }
    }

    // Fallback to public proxy for external profiles
    return appview_public(ctx, req, resp);
}
wf_status appview_get_profiles(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
/* An actor's likes are gated on the viewer, so this needs the requester's
 * identity rather than an anonymous read. */
wf_status appview_get_actor_likes(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* The requester's own following feed — meaningless without their identity. */
wf_status appview_get_timeline(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Thread content is public; viewer state is a bonus the public AppView omits.
 */
wf_status appview_get_post_thread(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Push registration is per-account state on the AppView. */
wf_status appview_register_push(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

wf_status appview_unregister_push(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_actor_statistics(void *ctx, const wf_xrpc_request *req,
                                       wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_actor_rankings(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Graph endpoints — public reads */
wf_status appview_get_follows(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_followers(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_blocks(void *ctx, const wf_xrpc_request *req,
                             wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_list(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_lists(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_list_items(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_starter_pack(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_starter_packs(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Notification endpoints — user-specific */
wf_status appview_get_unread_notifications(void *ctx,
                                           const wf_xrpc_request *req,
                                           wf_xrpc_response *resp) {
    /* Notification state lives entirely on the AppView (it's computed from
     * the firehose, not stored as a PDS record), so this has to proxy like
     * listNotifications does -- there is no local answer to "return". A
     * hardcoded {"count":0} used to sit here: a real client polling this for
     * an unread badge would see a permanent, silent "0" regardless of actual
     * state, which is exactly the fabricated-success AGENTS.md forbids for a
     * stub, just without the honesty of an error. */
    return appview_private(ctx, req, resp);
}
wf_status appview_get_notifications(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Chat/Convo endpoints — user-specific */
wf_status appview_get_convo(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_convos(void *ctx, const wf_xrpc_request *req,
                             wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_messages(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Labeler endpoints — public reads */
wf_status appview_get_labeler_info(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Unsafe/unspecced endpoints — public reads */
wf_status appview_unspecced_get_age_assurance_state(void *ctx,
                                                    const wf_xrpc_request *req,
                                                    wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_unspecced_get_age_assurance_config(void *ctx,
                                                     const wf_xrpc_request *req,
                                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_unspecced_get_age_assurance(void *ctx,
                                              const wf_xrpc_request *req,
                                              wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

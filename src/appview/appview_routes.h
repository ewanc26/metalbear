#ifndef METALBEAR_APPVIEW_ROUTES_H
#define METALBEAR_APPVIEW_ROUTES_H

/* app.bsky.* / chat.bsky.* AppView reverse-proxy plumbing and the thin
 * lexicon-specific wrappers over it, plus the generic proxy_fallback for
 * unmatched NSIDs, registered by server.c's metalbear_server_start against
 * these definitions in appview_routes.c. Not part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status proxy_fallback(void *ctx, const wf_xrpc_request *req,
                         wf_xrpc_response *resp);

wf_status appview_get_feed(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp);
wf_status appview_get_feed_skeleton(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp);
wf_status appview_get_author_feed(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp);
wf_status appview_get_actor_feeds(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp);
wf_status appview_get_feed_generators(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp);
wf_status appview_get_feed_generator(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp);
wf_status appview_get_posts(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp);
wf_status appview_get_profile(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp);
wf_status appview_get_profiles(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp);
wf_status appview_get_actor_likes(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp);
wf_status appview_get_timeline(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp);
wf_status appview_get_post_thread(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp);
wf_status appview_register_push(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp);
wf_status appview_unregister_push(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp);
wf_status appview_get_actor_statistics(void *ctx, const wf_xrpc_request *req,
                                       wf_xrpc_response *resp);
wf_status appview_get_actor_rankings(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp);
wf_status appview_get_follows(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp);
wf_status appview_get_followers(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp);
wf_status appview_get_blocks(void *ctx, const wf_xrpc_request *req,
                             wf_xrpc_response *resp);
wf_status appview_get_list(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp);
wf_status appview_get_lists(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp);
wf_status appview_get_list_items(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp);
wf_status appview_get_starter_pack(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp);
wf_status appview_get_starter_packs(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp);
wf_status appview_get_unread_notifications(void *ctx,
                                           const wf_xrpc_request *req,
                                           wf_xrpc_response *resp);
wf_status appview_get_notifications(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp);
wf_status appview_get_convo(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp);
wf_status appview_get_convos(void *ctx, const wf_xrpc_request *req,
                             wf_xrpc_response *resp);
wf_status appview_get_messages(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp);
wf_status appview_get_labeler_info(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp);
wf_status appview_unspecced_get_age_assurance_state(void *ctx,
                                                    const wf_xrpc_request *req,
                                                    wf_xrpc_response *resp);
wf_status appview_unspecced_get_age_assurance_config(void *ctx,
                                                     const wf_xrpc_request *req,
                                                     wf_xrpc_response *resp);
wf_status appview_unspecced_get_age_assurance(void *ctx,
                                              const wf_xrpc_request *req,
                                              wf_xrpc_response *resp);
wf_status get_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response);
wf_status put_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_APPVIEW_ROUTES_H */

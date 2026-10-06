#ifndef METALBEAR_PREFERENCES_ROUTES_H
#define METALBEAR_PREFERENCES_ROUTES_H

/* app.bsky.actor.getPreferences / putPreferences, registered by server.c.
 * Core routes: built in every profile. Not part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status get_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response);
wf_status put_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response);

/* Verify an inbound mod-service JWT (the reference's modService verifier, as
 * used by app.bsky.actor.getPreferences's authorizationOrModService auth).
 * `mod_service_did` is the trusted service DID (may carry the
 * `#atproto_labeler` service fragment), `local_service_did` the audience the
 * token must name. On WF_OK, *out_iss is the token's caller-owned `iss` claim
 * (the mod service DID, fragment included, matching the reference's
 * credentials.did). Any failure leaves *out_iss NULL and returns
 * WF_ERR_PERMISSION: the token is not a mod-service token for THIS server
 * (or no mod service is trusted), and ordinary user-token auth should handle
 * the request instead. Dids that resolve offline (did:key) are verified
 * without touching the network; did:plc/did:web issuers have their #atproto
 * / #atproto_label verification key resolved from the published DID document,
 * mirroring the reference's getVerificationMaterial + verifyJwt. */
wf_status metalbear_verify_mod_service_auth(const char *mod_service_did,
                                            const char *local_service_did,
                                            const char *token, char **out_iss);

#ifdef __cplusplus
}
#endif

#endif

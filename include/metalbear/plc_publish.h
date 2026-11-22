#ifndef METALBEAR_PLC_PUBLISH_H
#define METALBEAR_PLC_PUBLISH_H

/*
 * Publish an account's effective AT Protocol signing key to did:plc without
 * needing a running server. The offline maintenance helper uses this against
 * a stopped instance's rotation key and PLC directory URL; the admin route
 * uses the same code path through metalbear_plc_update_signing_key().
 */

#include "metalbear/repo/key_rotation.h"
#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Replace verificationMethods.atproto in `did`'s last PLC operation with
 * `signing_key_didkey`, copying every other field forward. did:web needs no
 * PLC operation and returns WF_OK without network access.
 */
wf_status metalbear_plc_publish_signing_key(metalbear_key_rotation *rotation,
                                            const char *plc_url,
                                            const char *did,
                                            const char *signing_key_didkey);

#ifdef __cplusplus
}
#endif

#endif

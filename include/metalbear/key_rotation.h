#ifndef METALBEAR_KEY_ROTATION_H
#define METALBEAR_KEY_ROTATION_H

#include "wolfram/crypto.h"
#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_key_rotation metalbear_key_rotation;

/* Open the key rotation store, creating it when absent.
 * Persists the current signing key and rotation state. */
wf_status metalbear_key_rotation_open(const char *path,
                                      metalbear_key_rotation **out);
void metalbear_key_rotation_free(metalbear_key_rotation *store);

/* Get the current signing key (generates on first call). */
wf_status metalbear_key_rotation_current_key(
    metalbear_key_rotation *store, wf_signing_key *out);

/* Rotate to a new signing key. Returns the new key's did:key. */
wf_status metalbear_key_rotation_rotate(metalbear_key_rotation *store,
                                         wf_signing_key *out_new_key,
                                         char **out_didkey);

/* Generate a fresh signing key and return its did:key WITHOUT persisting it
 * as the active key. Used by com.atproto.server.reserveSigningKey so a DID
 * PLC operation can be staged during account migration without disrupting
 * the live repository signing key. The caller owns *out_didkey. */
wf_status metalbear_key_rotation_reserve(metalbear_key_rotation *store,
                                          char **out_didkey);

#ifdef __cplusplus
}
#endif

#endif

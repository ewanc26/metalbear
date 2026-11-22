#ifndef METALBEAR_ACCOUNT_EXPORT_BUNDLE_H
#define METALBEAR_ACCOUNT_EXPORT_BUNDLE_H

/*
 * export_bundle.h -- a portable, single-file account migration bundle.
 *
 * The bundle is a plain ustar archive (readable by `tar -xf` everywhere)
 * containing three kinds of entry:
 *
 *   manifest.json   did, handle, signing key, indexed time and the blob list
 *   repo.car        the same CAR com.atproto.sync.getRepo returns
 *   blobs/<cid>     every blob, with its MIME type recorded in the manifest
 *
 * That is exactly what an importer needs: feed repo.car to
 * com.atproto.repo.importRepo, then re-upload each blobs/<cid> with the MIME
 * type from the manifest. Nothing here is MetalBear-specific on the wire.
 */

#include "metalbear/account/account_context.h"
#include "wolfram/xrpc.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Build a bundle for the already-open account `acct`.
 *
 * `signing_key_did` is the effective #atproto key from the account's DID
 * document (caller-owned, may be NULL); `indexed_at` is the account creation
 * time (caller-owned, may be NULL). On WF_OK, *out_data receives a malloc'd
 * buffer and *out_len its length; the caller owns both.
 */
wf_status metalbear_export_bundle_build(metalbear_account_context *acct,
                                        const char *signing_key_did,
                                        const char *indexed_at,
                                        unsigned char **out_data,
                                        size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_ACCOUNT_EXPORT_BUNDLE_H */

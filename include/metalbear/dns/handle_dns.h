#ifndef METALBEAR_HANDLE_DNS_H
#define METALBEAR_HANDLE_DNS_H

/*
 * handle_dns.h — publish the `_atproto` TXT records that make handles resolve.
 *
 * A handle is verified one of two ways: an HTTPS request to
 * `https://<handle>/.well-known/atproto-did`, or a DNS TXT record at
 * `_atproto.<handle>` containing `did=<did>`. The HTTPS route needs a
 * certificate covering the handle, and a wildcard certificate only covers one
 * label — so a host minting `alice.pds.example.com` under `*.example.com` has
 * no certificate for it and the HTTPS route cannot work at all.
 *
 * The DNS route has no such limit, but until now it meant the operator hand-
 * writing a record for every account. When a provider credential is
 * configured, MetalBear writes those records itself.
 *
 * Nothing here is required: with no provider configured every call is a
 * no-op and handle resolution stays the operator's business.
 */

#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_handle_dns metalbear_handle_dns;

/*
 * Open a publisher. `provider` is "cloudflare", "digitalocean", "desec" or
 * "rfc2136", or NULL/empty for none.
 *
 * `zone_id` is whatever the provider uses to name the zone: Cloudflare's
 * opaque zone id, or the domain name itself for the other two.
 *
 * Returns WF_OK with *out == NULL when no provider is configured — an absent
 * publisher is the normal case, not a failure. A provider named but missing
 * its credentials is an error, because it means an operator asked for
 * something that will silently not happen.
 *
 * `ttl` of 0 uses the default. Short values are better here: a handle changes
 * when a person renames, and a stale record shows the old one. A value below
 * the provider's own floor is raised to it rather than refused — failing every
 * write over a number the provider dislikes would take the whole host's handle
 * resolution down.
 */
wf_status metalbear_handle_dns_open(const char *provider, const char *api_token,
                                    const char *zone_id, int ttl,
                                    metalbear_handle_dns **out);

/*
 * As above, with the nameserver the `rfc2136` provider updates — `host` or
 * `host:port`. The HTTP providers ignore it; rfc2136 refuses to open without
 * it, since it has nowhere else to learn where to send an update.
 *
 * For rfc2136 `api_token` is the TSIG key as `<name>:<base64 secret>`, the
 * form nsupdate, certbot and a BIND key stanza all write.
 */
wf_status metalbear_handle_dns_open_ex(const char *provider,
                                       const char *api_token,
                                       const char *zone_id, const char *server,
                                       int ttl, metalbear_handle_dns **out);

void metalbear_handle_dns_free(metalbear_handle_dns *dns);

/*
 * Point `_atproto.<handle>` at `did`, creating the record or updating whatever
 * is already there. Idempotent: a record that already says the right thing is
 * left alone.
 *
 * A NULL publisher returns WF_OK, so callers need no branch.
 */
wf_status metalbear_handle_dns_publish(metalbear_handle_dns *dns,
                                       const char *handle, const char *did);

/* Remove `_atproto.<handle>`. Absent records are WF_OK: the desired state is
 * "no record", and it already holds. */
wf_status metalbear_handle_dns_retract(metalbear_handle_dns *dns,
                                       const char *handle);

/* The last provider error, for logging. Never NULL; empty when none. */
const char *metalbear_handle_dns_last_error(const metalbear_handle_dns *dns);

#ifdef __cplusplus
}
#endif

#endif

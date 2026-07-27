#ifndef METALBEAR_HANDLE_DNS_RFC2136_H
#define METALBEAR_HANDLE_DNS_RFC2136_H

/*
 * handle_dns_rfc2136.h — TSIG-signed dynamic DNS update.
 *
 * The other providers speak one vendor's HTTP API each. This one speaks the
 * protocol the DNS servers themselves implement (RFC 2136, signed per RFC
 * 8945), so it covers BIND, Knot, PowerDNS, NSD and anything else
 * standards-compliant — which is the difference between "your provider is
 * supported" and "your provider is supported if we wrote code for it".
 *
 * Kept separate from handle_dns.c because none of it is HTTP: message
 * construction, HMAC signing and a TCP exchange have nothing in common with
 * the REST providers beyond the interface they are reached through.
 */

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_rfc2136_config {
    const char *server;     /* address of the authoritative server */
    const char *port;       /* "53" unless the operator says otherwise */
    const char *zone;       /* the zone being updated */
    const char *key_name;   /* TSIG key name, as the server knows it */
    const unsigned char *secret;
    size_t secret_len;      /* the decoded key, not its base64 */
} metalbear_rfc2136_config;

/*
 * Read the current TXT at `name`.
 *
 * A missing record is WF_OK with *out_found false, not an error: it is what
 * every first account on a zone looks like, and treating it as a failure
 * would stop the record ever being written.
 */
wf_status metalbear_rfc2136_query_txt(const metalbear_rfc2136_config *config,
                                      const char *name, char *out,
                                      size_t out_len, bool *out_found,
                                      char *error, size_t error_len);

/*
 * Replace the TXT RRset at `name` with `value`, or remove it when `value` is
 * NULL.
 *
 * One message carries both the delete and the add, so the name never appears
 * without a record to a reader watching in between.
 */
wf_status metalbear_rfc2136_update_txt(const metalbear_rfc2136_config *config,
                                       const char *name, const char *value,
                                       int ttl, char *error,
                                       size_t error_len);

#ifdef __cplusplus
}
#endif

#endif

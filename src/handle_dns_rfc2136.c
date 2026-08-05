#define _POSIX_C_SOURCE 200809L

/*
 * handle_dns_rfc2136.c — `_atproto` records over RFC 2136 dynamic update.
 *
 * The HTTP providers each speak their own API; this one speaks the protocol
 * the DNS servers themselves implement, so it covers BIND, Knot, PowerDNS,
 * NSD and anything else standards-compliant rather than one vendor. It is
 * what `nsupdate` sends, minus the parts a PDS never needs.
 *
 * Two message kinds are built here:
 *
 *   a QUERY for the current TXT at `_atproto.<handle>`, so a record that
 *   already says the right thing is left alone, and
 *
 *   an UPDATE (opcode 5) that deletes the existing RRset and adds the new
 *   one. Delete-then-add in a single message is what makes the write atomic
 *   and idempotent: adding alone would leave two TXT records at one name, and
 *   a handle with two conflicting DIDs resolves to neither.
 *
 * Both are signed with TSIG (RFC 8945) and sent over TCP. TCP because an
 * update is a write and must not be answered from a truncated UDP reply, and
 * signed because an unauthenticated update is one anybody on the path can
 * forge.
 */

#include "metalbear/handle_dns_rfc2136.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DNS_TYPE_TXT 16
#define DNS_TYPE_SOA 6
#define DNS_TYPE_TSIG 250
#define DNS_CLASS_IN 1
#define DNS_CLASS_ANY 255
#define DNS_OPCODE_UPDATE 5
#define TSIG_FUDGE 300
#define DNS_TIMEOUT_SECONDS 10

/* A message under construction. Fixed size: an update naming one TXT record
 * is a few hundred bytes, and a handle long enough to overflow this could not
 * be a DNS name in the first place. */
typedef struct msg {
    unsigned char data[4096];
    size_t len;
    bool overflow;
} msg;

static void put_bytes(msg *m, const void *bytes, size_t n) {
    if (m->overflow || m->len + n > sizeof(m->data)) {
        m->overflow = true;
        return;
    }
    memcpy(m->data + m->len, bytes, n);
    m->len += n;
}

static void put_u8(msg *m, unsigned value) {
    unsigned char b = (unsigned char)value;
    put_bytes(m, &b, 1);
}

static void put_u16(msg *m, unsigned value) {
    unsigned char b[2] = {(unsigned char)(value >> 8), (unsigned char)value};
    put_bytes(m, b, 2);
}

static void put_u32(msg *m, unsigned long value) {
    unsigned char b[4] = {(unsigned char)(value >> 24),
                          (unsigned char)(value >> 16),
                          (unsigned char)(value >> 8), (unsigned char)value};
    put_bytes(m, b, 4);
}

/*
 * A domain name in wire format: each label length-prefixed, terminated by a
 * zero length. Never compressed — a pointer into the message would be
 * meaningless in the TSIG digest, which covers some names outside the message
 * body entirely.
 */
static void put_name(msg *m, const char *name) {
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label = dot ? (size_t)(dot - p) : strlen(p);
        if (label == 0) break; /* trailing dot */
        if (label > 63) {
            m->overflow = true;
            return;
        }
        put_u8(m, (unsigned)label);
        put_bytes(m, p, label);
        if (!dot) break;
        p = dot + 1;
    }
    put_u8(m, 0);
}

/* As put_name, but lower-cased: TSIG digests names in canonical form, and a
 * key name the operator wrote in mixed case must still verify. */
static void put_name_canonical(msg *m, const char *name) {
    char lowered[256];
    size_t i = 0;
    for (; name[i] && i + 1 < sizeof(lowered); i++) {
        char c = name[i];
        lowered[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    lowered[i] = '\0';
    put_name(m, lowered);
}

/* ------------------------------------------------------------------ */
/* TSIG                                                                */
/* ------------------------------------------------------------------ */

/*
 * Sign `m` in place: compute the MAC over the message so far plus the TSIG
 * variables, append the TSIG RR, and bump ARCOUNT.
 *
 * The digest covers the message with ARCOUNT still excluding the TSIG record
 * being added, which is why the count is incremented afterwards rather than
 * before. Getting that backwards produces a signature the server rejects
 * while everything here looks correct.
 */
static bool tsig_sign(msg *m, const char *key_name, const unsigned char *secret,
                      size_t secret_len, unsigned original_id) {
    const char *algorithm = "hmac-sha256";

    msg vars = {0};
    put_name_canonical(&vars, key_name);
    put_u16(&vars, DNS_CLASS_ANY);
    put_u32(&vars, 0); /* TTL */
    put_name_canonical(&vars, algorithm);
    time_t now = time(NULL);
    put_u16(&vars, (unsigned)((uint64_t)now >> 32)); /* time signed, 48 bits */
    put_u32(&vars, (unsigned long)((uint64_t)now & 0xffffffffUL));
    put_u16(&vars, TSIG_FUDGE);
    put_u16(&vars, 0); /* error */
    put_u16(&vars, 0); /* other len */
    if (vars.overflow || m->overflow) return false;

    /*
     * The digest input is the message followed by the variables, joined here
     * rather than fed in through the incremental API: the one-shot HMAC is
     * what the rest of this codebase uses, and the two buffers together are
     * bounded by the message size.
     */
    unsigned char digest_input[sizeof(m->data) + sizeof(vars.data)];
    memcpy(digest_input, m->data, m->len);
    memcpy(digest_input + m->len, vars.data, vars.len);

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha256(), secret, (int)secret_len, digest_input,
              m->len + vars.len, mac, &mac_len))
        return false;

    put_name(m, key_name);
    put_u16(m, DNS_TYPE_TSIG);
    put_u16(m, DNS_CLASS_ANY);
    put_u32(m, 0);
    /* RDLENGTH, filled in once the record body is written. */
    size_t rdlength_at = m->len;
    put_u16(m, 0);
    size_t rdata_at = m->len;
    put_name_canonical(m, algorithm);
    put_u16(m, (unsigned)((uint64_t)now >> 32));
    put_u32(m, (unsigned long)((uint64_t)now & 0xffffffffUL));
    put_u16(m, TSIG_FUDGE);
    put_u16(m, mac_len);
    put_bytes(m, mac, mac_len);
    put_u16(m, original_id);
    put_u16(m, 0); /* error */
    put_u16(m, 0); /* other len */
    if (m->overflow) return false;
    size_t rdlength = m->len - rdata_at;
    m->data[rdlength_at] = (unsigned char)(rdlength >> 8);
    m->data[rdlength_at + 1] = (unsigned char)rdlength;

    /* ARCOUNT, now that the record is in. */
    unsigned arcount = (unsigned)((m->data[10] << 8) | m->data[11]) + 1;
    m->data[10] = (unsigned char)(arcount >> 8);
    m->data[11] = (unsigned char)arcount;
    return true;
}

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

/*
 * Send `request` and read one reply, over TCP with the two-byte length prefix
 * the protocol requires there. UDP is not offered: an update is a write, and
 * a write answered from a truncated datagram is a write whose outcome is
 * unknown.
 */
static bool exchange(const char *server, const char *port, const msg *request,
                     unsigned char *reply, size_t reply_cap, size_t *reply_len,
                     char *error, size_t error_len) {
    struct addrinfo hints = {0}, *addrs = NULL;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    int rc = getaddrinfo(server, port, &hints, &addrs);
    if (rc != 0 || !addrs) {
        snprintf(error, error_len, "cannot resolve %s: %s", server,
                 gai_strerror(rc));
        return false;
    }

    int fd = -1;
    for (struct addrinfo *a = addrs; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = {DNS_TIMEOUT_SECONDS, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addrs);
    if (fd < 0) {
        snprintf(error, error_len, "cannot connect to %s:%s", server, port);
        return false;
    }

    unsigned char prefix[2] = {(unsigned char)(request->len >> 8),
                               (unsigned char)request->len};
    bool ok = true;
    if (send(fd, prefix, 2, 0) != 2 ||
        send(fd, request->data, request->len, 0) != (ssize_t)request->len) {
        snprintf(error, error_len, "cannot send to %s:%s", server, port);
        ok = false;
    }

    size_t got = 0;
    if (ok) {
        unsigned char len_buf[2];
        while (got < 2) {
            ssize_t n = recv(fd, len_buf + got, 2 - got, 0);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (got != 2) {
            snprintf(error, error_len, "no reply from %s:%s", server, port);
            ok = false;
        } else {
            size_t want = (size_t)((len_buf[0] << 8) | len_buf[1]);
            if (want > reply_cap) {
                snprintf(error, error_len, "reply from %s too large", server);
                ok = false;
            } else {
                got = 0;
                while (got < want) {
                    ssize_t n = recv(fd, reply + got, want - got, 0);
                    if (n <= 0) break;
                    got += (size_t)n;
                }
                if (got != want) {
                    snprintf(error, error_len, "short reply from %s", server);
                    ok = false;
                } else {
                    *reply_len = got;
                }
            }
        }
    }
    close(fd);
    return ok;
}

/* The RCODE names a server reports, so a refusal says which one it was. A
 * NOTAUTH here almost always means the key is right and the server does not
 * allow that key to update that zone. */
static const char *rcode_name(unsigned rcode) {
    switch (rcode) {
        case 0:
            return "NOERROR";
        case 1:
            return "FORMERR";
        case 2:
            return "SERVFAIL";
        case 3:
            return "NXDOMAIN";
        case 4:
            return "NOTIMP";
        case 5:
            return "REFUSED";
        case 6:
            return "YXDOMAIN";
        case 7:
            return "YXRRSET";
        case 8:
            return "NXRRSET";
        case 9:
            return "NOTAUTH";
        case 10:
            return "NOTZONE";
        case 16:
            return "BADSIG or BADVERS";
        case 17:
            return "BADKEY";
        case 18:
            return "BADTIME";
        default:
            return "unknown";
    }
}

/* ------------------------------------------------------------------ */
/* Public operations                                                   */
/* ------------------------------------------------------------------ */

static unsigned random_id(void) {
    unsigned char bytes[2];
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom && fread(bytes, 1, 2, urandom) == 2) {
        fclose(urandom);
        return (unsigned)((bytes[0] << 8) | bytes[1]);
    }
    if (urandom) fclose(urandom);
    return (unsigned)(time(NULL) & 0xffff);
}

wf_status metalbear_rfc2136_query_txt(const metalbear_rfc2136_config *config,
                                      const char *name, char *out,
                                      size_t out_len, bool *out_found,
                                      char *error, size_t error_len) {
    *out_found = false;
    if (out_len) out[0] = '\0';

    msg m = {0};
    unsigned id = random_id();
    put_u16(&m, id);
    put_u16(&m, 0x0100); /* standard query, recursion desired off
                          * for an authoritative server; RD is
                          * harmless and widely expected */
    put_u16(&m, 1);      /* QDCOUNT */
    put_u16(&m, 0);
    put_u16(&m, 0);
    put_u16(&m, 0); /* ARCOUNT, raised by tsig_sign */
    put_name(&m, name);
    put_u16(&m, DNS_TYPE_TXT);
    put_u16(&m, DNS_CLASS_IN);
    if (m.overflow) {
        snprintf(error, error_len, "name too long: %s", name);
        return WF_ERR_INVALID_ARG;
    }
    if (!tsig_sign(&m, config->key_name, config->secret, config->secret_len,
                   id)) {
        snprintf(error, error_len, "could not sign the query");
        return WF_ERR_INTERNAL;
    }

    unsigned char reply[4096];
    size_t reply_len = 0;
    if (!exchange(config->server, config->port, &m, reply, sizeof(reply),
                  &reply_len, error, error_len))
        return WF_ERR_NETWORK;
    if (reply_len < 12) {
        snprintf(error, error_len, "truncated reply");
        return WF_ERR_NETWORK;
    }
    unsigned rcode = reply[3] & 0x0f;
    /* NXDOMAIN and an empty answer are both "no record", which is a normal
     * state and not an error: it is what every first account on a zone
     * looks like. */
    if (rcode == 3) return WF_OK;
    if (rcode != 0) {
        snprintf(error, error_len, "query refused: %s", rcode_name(rcode));
        return WF_ERR_NETWORK;
    }
    unsigned ancount = (unsigned)((reply[6] << 8) | reply[7]);
    if (ancount == 0) return WF_OK;

    /* Skip the question section, then walk answers to the first TXT. */
    size_t at = 12;
    unsigned qdcount = (unsigned)((reply[4] << 8) | reply[5]);
    for (unsigned i = 0; i < qdcount && at < reply_len; i++) {
        while (at < reply_len && reply[at] != 0) {
            if ((reply[at] & 0xc0) == 0xc0) {
                at += 2;
                goto question_done;
            }
            at += reply[at] + 1;
        }
        at++;
    question_done:
        at += 4; /* QTYPE + QCLASS */
    }
    for (unsigned i = 0; i < ancount && at + 10 <= reply_len; i++) {
        /* Owner name, which may be a compression pointer. */
        while (at < reply_len && reply[at] != 0) {
            if ((reply[at] & 0xc0) == 0xc0) {
                at += 2;
                goto name_done;
            }
            at += reply[at] + 1;
        }
        at++;
    name_done:
        if (at + 10 > reply_len) break;
        unsigned type = (unsigned)((reply[at] << 8) | reply[at + 1]);
        unsigned rdlength = (unsigned)((reply[at + 8] << 8) | reply[at + 9]);
        at += 10;
        if (at + rdlength > reply_len) break;
        if (type == DNS_TYPE_TXT && rdlength >= 1) {
            /* TXT rdata is one or more length-prefixed strings. A `did=` value
             * fits in one, and only the first is read: a handle record with a
             * continuation is not one this server wrote. */
            unsigned segment = reply[at];
            if (segment + 1u <= rdlength && segment < out_len) {
                memcpy(out, reply + at + 1, segment);
                out[segment] = '\0';
                *out_found = true;
                return WF_OK;
            }
        }
        at += rdlength;
    }
    return WF_OK;
}

wf_status metalbear_rfc2136_update_txt(const metalbear_rfc2136_config *config,
                                       const char *name, const char *value,
                                       int ttl, char *error, size_t error_len) {
    msg m = {0};
    unsigned id = random_id();
    put_u16(&m, id);
    /* Opcode 5 (UPDATE) in bits 11-14 of the flags word. */
    put_u16(&m, DNS_OPCODE_UPDATE << 11);
    put_u16(&m, 1);             /* ZOCOUNT: the zone */
    put_u16(&m, 0);             /* PRCOUNT: no prerequisites */
    put_u16(&m, value ? 2 : 1); /* UPCOUNT */
    put_u16(&m, 0);             /* ADCOUNT, raised by tsig_sign */

    /* Zone section: the zone, as an SOA question. */
    put_name(&m, config->zone);
    put_u16(&m, DNS_TYPE_SOA);
    put_u16(&m, DNS_CLASS_IN);

    /*
     * Delete the whole TXT RRset first, then add ours. Deleting is class ANY
     * with a zero TTL and no rdata; the pair in one message is what makes the
     * write atomic, so a reader never sees the name with no record at all.
     */
    put_name(&m, name);
    put_u16(&m, DNS_TYPE_TXT);
    put_u16(&m, DNS_CLASS_ANY);
    put_u32(&m, 0);
    put_u16(&m, 0); /* RDLENGTH */

    if (value) {
        size_t value_len = strlen(value);
        if (value_len > 255) {
            snprintf(error, error_len, "record value too long");
            return WF_ERR_INVALID_ARG;
        }
        put_name(&m, name);
        put_u16(&m, DNS_TYPE_TXT);
        put_u16(&m, DNS_CLASS_IN);
        put_u32(&m, (unsigned long)(ttl > 0 ? ttl : 300));
        put_u16(&m, (unsigned)value_len + 1);
        put_u8(&m, (unsigned)value_len);
        put_bytes(&m, value, value_len);
    }

    if (m.overflow) {
        snprintf(error, error_len, "update message too large");
        return WF_ERR_INVALID_ARG;
    }
    if (!tsig_sign(&m, config->key_name, config->secret, config->secret_len,
                   id)) {
        snprintf(error, error_len, "could not sign the update");
        return WF_ERR_INTERNAL;
    }

    unsigned char reply[4096];
    size_t reply_len = 0;
    if (!exchange(config->server, config->port, &m, reply, sizeof(reply),
                  &reply_len, error, error_len))
        return WF_ERR_NETWORK;
    if (reply_len < 12) {
        snprintf(error, error_len, "truncated reply to the update");
        return WF_ERR_NETWORK;
    }
    unsigned rcode = reply[3] & 0x0f;
    if (rcode != 0) {
        snprintf(error, error_len, "update refused: %s", rcode_name(rcode));
        return WF_ERR_NETWORK;
    }
    return WF_OK;
}

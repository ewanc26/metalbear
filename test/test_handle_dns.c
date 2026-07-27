#define _POSIX_C_SOURCE 200809L

/*
 * test_handle_dns.c — `_atproto` TXT record publishing.
 *
 * The publisher writes to a live DNS zone, so what matters is that it sends
 * exactly the right requests and never sends a wrong one. These tests run it
 * against a stand-in for the Cloudflare API that records everything it
 * receives, which is the only way to assert on requests that would otherwise
 * only be visible in someone's production zone.
 */

#include "metalbear/handle_dns.h"

#include <cJSON.h>
#include <microhttpd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    failures++; } } while (0)

/* ------------------------------------------------------------------ */
/* A stand-in Cloudflare API                                           */
/* ------------------------------------------------------------------ */

#define MAX_CALLS 16

typedef struct {
    char method[16];
    char url[512];
    char body[1024];
    char auth[512];
} call;

static struct {
    pthread_mutex_t lock;
    call calls[MAX_CALLS];
    int count;
    /* The record the zone currently holds, if any. */
    int has_record;
    char record_content[256];
    /* Force `success: false`, the shape Cloudflare uses for a rejected but
     * well-formed request. */
    int reject;
} zone;

typedef struct {
    char *body;
    size_t len;
} upload;

static void record_call(const char *method, const char *url, const char *body,
                        const char *auth) {
    pthread_mutex_lock(&zone.lock);
    if (zone.count < MAX_CALLS) {
        call *c = &zone.calls[zone.count++];
        snprintf(c->method, sizeof(c->method), "%s", method ? method : "");
        snprintf(c->url, sizeof(c->url), "%s", url ? url : "");
        snprintf(c->body, sizeof(c->body), "%s", body ? body : "");
        snprintf(c->auth, sizeof(c->auth), "%s", auth ? auth : "");
    }
    pthread_mutex_unlock(&zone.lock);
}

static enum MHD_Result send_json(struct MHD_Connection *conn, int status,
                                 const char *json) {
    struct MHD_Response *res = MHD_create_response_from_buffer(
        strlen(json), (void *)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(res, "Content-Type", "application/json");
    enum MHD_Result rc = MHD_queue_response(conn, (unsigned)status, res);
    MHD_destroy_response(res);
    return rc;
}

static enum MHD_Result handler(void *cls, struct MHD_Connection *conn,
                               const char *url, const char *method,
                               const char *version, const char *upload_data,
                               size_t *upload_size, void **con_cls) {
    (void)cls; (void)version;

    /* libmicrohttpd delivers a body across several calls; accumulate first. */
    upload *up = *con_cls;
    if (!up) {
        up = calloc(1, sizeof(*up));
        *con_cls = up;
        return MHD_YES;
    }
    if (*upload_size > 0) {
        char *grown = realloc(up->body, up->len + *upload_size + 1);
        if (!grown) return MHD_NO;
        up->body = grown;
        memcpy(up->body + up->len, upload_data, *upload_size);
        up->len += *upload_size;
        up->body[up->len] = '\0';
        *upload_size = 0;
        return MHD_YES;
    }

    const char *query = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND,
                                                    "name");
    char full[512];
    if (query) snprintf(full, sizeof(full), "%s?name=%s", url, query);
    else snprintf(full, sizeof(full), "%s", url);

    const char *auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
                                                   "Authorization");
    record_call(method, full, up->body, auth);

    if (zone.reject)
        return send_json(conn, 403,
                         "{\"success\":false,\"errors\":"
                         "[{\"code\":10000,\"message\":\"Authentication error\"}]}");

    if (strcmp(method, "GET") == 0) {
        if (zone.has_record) {
            char body[512];
            snprintf(body, sizeof(body),
                     "{\"success\":true,\"result\":[{\"id\":\"rec123\","
                     "\"content\":\"%s\"}]}", zone.record_content);
            return send_json(conn, 200, body);
        }
        return send_json(conn, 200, "{\"success\":true,\"result\":[]}");
    }

    if (strcmp(method, "POST") == 0 || strcmp(method, "PATCH") == 0) {
        cJSON *doc = cJSON_Parse(up->body ? up->body : "");
        cJSON *content = doc ? cJSON_GetObjectItemCaseSensitive(doc, "content")
                             : NULL;
        if (cJSON_IsString(content)) {
            zone.has_record = 1;
            snprintf(zone.record_content, sizeof(zone.record_content), "%s",
                     content->valuestring);
        }
        cJSON_Delete(doc);
        return send_json(conn, 200,
                         "{\"success\":true,\"result\":{\"id\":\"rec123\"}}");
    }

    if (strcmp(method, "DELETE") == 0) {
        zone.has_record = 0;
        return send_json(conn, 200,
                         "{\"success\":true,\"result\":{\"id\":\"rec123\"}}");
    }

    return send_json(conn, 405, "{\"success\":false,\"errors\":[]}");
}

static void free_upload(void *cls, struct MHD_Connection *conn, void **con_cls,
                        enum MHD_RequestTerminationCode code) {
    (void)cls; (void)conn; (void)code;
    upload *up = *con_cls;
    if (up) { free(up->body); free(up); }
    *con_cls = NULL;
}

static void zone_reset(void) {
    pthread_mutex_lock(&zone.lock);
    zone.count = 0;
    zone.has_record = 0;
    zone.reject = 0;
    zone.record_content[0] = '\0';
    pthread_mutex_unlock(&zone.lock);
}

static int call_count(void) {
    pthread_mutex_lock(&zone.lock);
    int n = zone.count;
    pthread_mutex_unlock(&zone.lock);
    return n;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* An absent provider must be a silent no-op, not an error: it is what every
 * deployment that does not manage DNS looks like. */
static void test_no_provider_is_not_an_error(void) {
    metalbear_handle_dns *dns = (void *)0x1;
    CHECK(metalbear_handle_dns_open(NULL, NULL, NULL, 0, &dns) == WF_OK);
    CHECK(dns == NULL);

    dns = (void *)0x1;
    CHECK(metalbear_handle_dns_open("", "t", "z", 0, &dns) == WF_OK);
    CHECK(dns == NULL);

    /* And the calls on a NULL publisher must succeed, so callers need no
     * branch of their own. */
    CHECK(metalbear_handle_dns_publish(NULL, "a.example.com", "did:plc:x") == WF_OK);
    CHECK(metalbear_handle_dns_retract(NULL, "a.example.com") == WF_OK);
}

/*
 * A provider named without usable credentials must fail loudly. Accepting it
 * would give an operator a server that starts, mints accounts, and writes no
 * records — discovered only when every handle shows as handle.invalid.
 */
static void test_incomplete_credentials_are_rejected(void) {
    metalbear_handle_dns *dns = NULL;
    CHECK(metalbear_handle_dns_open("cloudflare", NULL, "zone", 0, &dns) != WF_OK);
    CHECK(dns == NULL);
    CHECK(metalbear_handle_dns_open("cloudflare", "token", NULL, 0, &dns) != WF_OK);
    CHECK(dns == NULL);
    CHECK(metalbear_handle_dns_open("cloudflare", "", "", 0, &dns) != WF_OK);
    CHECK(dns == NULL);
    /* An unimplemented provider is an error rather than a silent fallback. */
    CHECK(metalbear_handle_dns_open("route53", "token", "zone", 0, &dns) != WF_OK);
    CHECK(dns == NULL);
}

static metalbear_handle_dns *open_against_stub(void) {
    metalbear_handle_dns *dns = NULL;
    CHECK(metalbear_handle_dns_open("cloudflare", "test-token", "zone1", 120,
                                    &dns) == WF_OK);
    return dns;
}

static void test_publish_creates_the_record(void) {
    zone_reset();
    metalbear_handle_dns *dns = open_against_stub();
    if (!dns) return;

    CHECK(metalbear_handle_dns_publish(dns, "alice.pds.example.com",
                                       "did:plc:alice") == WF_OK);

    /* Look before writing: creating blindly would leave two TXT records at the
     * same name on a second call, and a handle with two DIDs resolves to
     * neither. */
    CHECK(call_count() == 2);
    CHECK(strcmp(zone.calls[0].method, "GET") == 0);
    CHECK(strstr(zone.calls[0].url, "_atproto.alice.pds.example.com") != NULL);
    CHECK(strcmp(zone.calls[1].method, "POST") == 0);

    /* The record must carry the `did=` prefix; without it the value is not a
     * handle declaration and no resolver will accept it. */
    CHECK(strstr(zone.calls[1].body, "\"content\":\"did=did:plc:alice\"") != NULL);
    CHECK(strstr(zone.calls[1].body, "\"type\":\"TXT\"") != NULL);
    CHECK(strstr(zone.calls[1].body, "\"name\":\"_atproto.alice.pds.example.com\"")
          != NULL);
    CHECK(strstr(zone.calls[1].body, "\"ttl\":120") != NULL);
    /* Bearer auth, not the legacy key headers. */
    CHECK(strcmp(zone.calls[1].auth, "Bearer test-token") == 0);

    metalbear_handle_dns_free(dns);
}

/* Publishing what is already there must not rewrite it: restart-time work
 * would otherwise churn the zone's history for no change. */
static void test_publish_is_idempotent(void) {
    zone_reset();
    metalbear_handle_dns *dns = open_against_stub();
    if (!dns) return;

    CHECK(metalbear_handle_dns_publish(dns, "bob.pds.example.com",
                                       "did:plc:bob") == WF_OK);
    int after_first = call_count();
    CHECK(metalbear_handle_dns_publish(dns, "bob.pds.example.com",
                                       "did:plc:bob") == WF_OK);
    /* The second attempt reads and stops. */
    CHECK(call_count() == after_first + 1);
    CHECK(strcmp(zone.calls[after_first].method, "GET") == 0);

    metalbear_handle_dns_free(dns);
}

/* A record pointing at the wrong DID must be corrected in place rather than
 * duplicated. */
static void test_publish_updates_a_stale_record(void) {
    zone_reset();
    metalbear_handle_dns *dns = open_against_stub();
    if (!dns) return;

    zone.has_record = 1;
    snprintf(zone.record_content, sizeof(zone.record_content), "did=did:plc:old");

    CHECK(metalbear_handle_dns_publish(dns, "carol.pds.example.com",
                                       "did:plc:new") == WF_OK);
    CHECK(call_count() == 2);
    CHECK(strcmp(zone.calls[1].method, "PATCH") == 0);
    CHECK(strstr(zone.calls[1].url, "rec123") != NULL);
    CHECK(strstr(zone.calls[1].body, "did=did:plc:new") != NULL);

    metalbear_handle_dns_free(dns);
}

static void test_retract_removes_the_record(void) {
    zone_reset();
    metalbear_handle_dns *dns = open_against_stub();
    if (!dns) return;

    zone.has_record = 1;
    snprintf(zone.record_content, sizeof(zone.record_content), "did=did:plc:dave");

    CHECK(metalbear_handle_dns_retract(dns, "dave.pds.example.com") == WF_OK);
    CHECK(call_count() == 2);
    CHECK(strcmp(zone.calls[1].method, "DELETE") == 0);
    CHECK(strstr(zone.calls[1].url, "rec123") != NULL);

    metalbear_handle_dns_free(dns);
}

/* Removing what is not there is success: the desired state already holds, and
 * failing would make account deletion look broken. */
static void test_retract_of_an_absent_record_succeeds(void) {
    zone_reset();
    metalbear_handle_dns *dns = open_against_stub();
    if (!dns) return;

    CHECK(metalbear_handle_dns_retract(dns, "erin.pds.example.com") == WF_OK);
    CHECK(call_count() == 1);
    CHECK(strcmp(zone.calls[0].method, "GET") == 0);

    metalbear_handle_dns_free(dns);
}

/*
 * Cloudflare answers some failures with a 200 and `success: false`, so the
 * HTTP status alone cannot tell us whether the record was written. Treating
 * one of those as success would report a handle as resolvable when it is not.
 */
static void test_a_rejected_request_is_a_failure(void) {
    zone_reset();
    metalbear_handle_dns *dns = open_against_stub();
    if (!dns) return;

    zone.reject = 1;
    CHECK(metalbear_handle_dns_publish(dns, "frank.pds.example.com",
                                       "did:plc:frank") != WF_OK);
    /* And the provider's own message must survive, because "DNS failed" and
     * "the token cannot edit this zone" need different actions. */
    CHECK(strstr(metalbear_handle_dns_last_error(dns), "Authentication error")
          != NULL);

    metalbear_handle_dns_free(dns);
}

static void test_bad_arguments(void) {
    zone_reset();
    metalbear_handle_dns *dns = open_against_stub();
    if (!dns) return;

    CHECK(metalbear_handle_dns_publish(dns, "a.example.com", "") != WF_OK);
    CHECK(metalbear_handle_dns_publish(dns, NULL, "did:plc:x") != WF_OK);
    CHECK(metalbear_handle_dns_publish(dns, "", "did:plc:x") != WF_OK);
    /* None of those may have reached the network. */
    CHECK(call_count() == 0);

    metalbear_handle_dns_free(dns);
}

int main(void) {
    printf("MetalBear handle DNS tests\n");
    pthread_mutex_init(&zone.lock, NULL);

    struct MHD_Daemon *stub = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD, 0, NULL, NULL, &handler, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, &free_upload, NULL, MHD_OPTION_END);
    if (!stub) {
        fprintf(stderr, "could not start the stand-in API\n");
        return 1;
    }
    const union MHD_DaemonInfo *info =
        MHD_get_daemon_info(stub, MHD_DAEMON_INFO_BIND_PORT);
    char base[128];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u", (unsigned)info->port);
    setenv("METALBEAR_DNS_API_BASE", base, 1);

    test_no_provider_is_not_an_error();
    test_incomplete_credentials_are_rejected();
    test_publish_creates_the_record();
    test_publish_is_idempotent();
    test_publish_updates_a_stale_record();
    test_retract_removes_the_record();
    test_retract_of_an_absent_record_succeeds();
    test_a_rejected_request_is_a_failure();
    test_bad_arguments();

    MHD_stop_daemon(stub);
    pthread_mutex_destroy(&zone.lock);

    if (failures == 0) { printf("All tests passed.\n"); return 0; }
    fprintf(stderr, "%d checks failed\n", failures);
    return 1;
}

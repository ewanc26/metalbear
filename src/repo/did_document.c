#include "metalbear/repo/repo_store.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Build the W3C DID document for an atproto account, in the same shape the
 * PLC directory serves: `verificationMethod` is an ARRAY of Multikey entries
 * keyed `<did>#atproto`, not the `verificationMethods` object map that
 * appears in unsigned PLC *operations*. Clients (@atproto/api,
 * @atproto/identity) read the array form to recover the repo signing key, so
 * emitting the operation shape here makes the document unusable to them.
 */
cJSON *metalbear_did_document_build(const char *did, const char *handle,
                                    const char *signing_key_didkey,
                                    const char *pds_endpoint) {
    cJSON *document = cJSON_CreateObject();
    if (!document) return NULL;
    cJSON *context = cJSON_AddArrayToObject(document, "@context");
    if (!context) goto fail;
    if (!cJSON_AddItemToArray(
            context, cJSON_CreateString("https://www.w3.org/ns/did/v1")) ||
        !cJSON_AddItemToArray(
            context,
            cJSON_CreateString("https://w3id.org/security/multikey/v1")) ||
        !cJSON_AddItemToArray(
            context, cJSON_CreateString(
                         "https://w3id.org/security/suites/secp256k1-2019/v1")))
        goto fail;
    if (!cJSON_AddStringToObject(document, "id", did ? did : "")) goto fail;

    cJSON *also_known_as = cJSON_AddArrayToObject(document, "alsoKnownAs");
    if (!also_known_as) goto fail;
    if (handle && handle[0]) {
        char aka[512];
        snprintf(aka, sizeof(aka), "at://%s", handle);
        if (!cJSON_AddItemToArray(also_known_as, cJSON_CreateString(aka)))
            goto fail;
    }

    /* did:key:z... — the multibase portion is everything after the prefix. */
    if (signing_key_didkey && strncmp(signing_key_didkey, "did:key:", 8) == 0 &&
        signing_key_didkey[8]) {
        cJSON *methods = cJSON_AddArrayToObject(document, "verificationMethod");
        cJSON *method = cJSON_CreateObject();
        if (!methods || !method) {
            cJSON_Delete(method);
            goto fail;
        }
        if (!cJSON_AddItemToArray(methods, method)) {
            cJSON_Delete(method);
            goto fail;
        }
        char method_id[512];
        snprintf(method_id, sizeof(method_id), "%s#atproto", did ? did : "");
        if (!cJSON_AddStringToObject(method, "id", method_id) ||
            !cJSON_AddStringToObject(method, "type", "Multikey") ||
            !cJSON_AddStringToObject(method, "controller", did ? did : "") ||
            !cJSON_AddStringToObject(method, "publicKeyMultibase",
                                     signing_key_didkey + 8))
            goto fail;
    }

    if (pds_endpoint && pds_endpoint[0]) {
        cJSON *services = cJSON_AddArrayToObject(document, "service");
        cJSON *service = cJSON_CreateObject();
        if (!services || !service) {
            cJSON_Delete(service);
            goto fail;
        }
        if (!cJSON_AddItemToArray(services, service)) {
            cJSON_Delete(service);
            goto fail;
        }
        if (!cJSON_AddStringToObject(service, "id", "#atproto_pds") ||
            !cJSON_AddStringToObject(service, "type",
                                     "AtprotoPersonalDataServer") ||
            !cJSON_AddStringToObject(service, "serviceEndpoint", pds_endpoint))
            goto fail;
    }
    return document;

fail:
    cJSON_Delete(document);
    return NULL;
}

/* First at:// handle claimed by a DID document's alsoKnownAs, or NULL. */
const char *metalbear_did_document_handle(const cJSON *document) {
    const cJSON *aka =
        cJSON_GetObjectItemCaseSensitive(document, "alsoKnownAs");
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, aka) {
        if (cJSON_IsString(entry) && entry->valuestring &&
            strncmp(entry->valuestring, "at://", 5) == 0)
            return entry->valuestring + 5;
    }
    return NULL;
}

/* DID document ids may be written as a bare fragment ("#atproto") or fully
 * qualified ("did:plc:xyz#atproto"); match either. */
static bool id_has_fragment(const char *id, const char *fragment) {
    size_t len = strlen(id), flen = strlen(fragment);
    return len >= flen && strcmp(id + len - flen, fragment) == 0;
}

/* did:key of the repo signing key advertised by a DID document's #atproto
 * verification method. Heap-allocated; caller frees. NULL when absent. */
char *metalbear_did_document_signing_key(const cJSON *document) {
    const cJSON *methods =
        cJSON_GetObjectItemCaseSensitive(document, "verificationMethod");
    const cJSON *method = NULL;
    cJSON_ArrayForEach(method, methods) {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(method, "id");
        const cJSON *key =
            cJSON_GetObjectItemCaseSensitive(method, "publicKeyMultibase");
        if (!cJSON_IsString(id) || !id->valuestring || !cJSON_IsString(key) ||
            !key->valuestring)
            continue;
        if (!id_has_fragment(id->valuestring, "#atproto")) continue;
        size_t n = strlen("did:key:") + strlen(key->valuestring) + 1;
        char *didkey = malloc(n);
        if (!didkey) return NULL;
        snprintf(didkey, n, "did:key:%s", key->valuestring);
        return didkey;
    }
    return NULL;
}

/* serviceEndpoint of the document's #atproto_pds service entry, or NULL.
 * Borrowed from `document`. */
const char *metalbear_did_document_pds_endpoint(const cJSON *document) {
    const cJSON *services =
        cJSON_GetObjectItemCaseSensitive(document, "service");
    const cJSON *service = NULL;
    cJSON_ArrayForEach(service, services) {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(service, "id");
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(service, "type");
        const cJSON *endpoint =
            cJSON_GetObjectItemCaseSensitive(service, "serviceEndpoint");
        if (!cJSON_IsString(endpoint) || !endpoint->valuestring) continue;
        bool is_pds =
            (cJSON_IsString(type) && type->valuestring &&
             strcmp(type->valuestring, "AtprotoPersonalDataServer") == 0) ||
            (cJSON_IsString(id) && id->valuestring &&
             id_has_fragment(id->valuestring, "#atproto_pds"));
        if (is_pds) return endpoint->valuestring;
    }
    return NULL;
}

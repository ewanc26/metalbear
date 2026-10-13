/* src/route_params.h — checks shared by the XRPC route handlers. */
#ifndef METALBEAR_ROUTE_PARAMS_H
#define METALBEAR_ROUTE_PARAMS_H

#include <stdbool.h>
#include <stdio.h>

#include <cJSON.h>

#include "wolfram/xrpc.h"

/* True when item is a non-empty string. Otherwise sets a 400 InvalidRequest
 * "<name> is required" on the response, which is what every required string
 * parameter reports. Use as `if (!require_string(...)) return WF_OK;`. */
static inline bool require_string(wf_xrpc_response *response, const cJSON *item,
                                  const char *name) {
    if (cJSON_IsString(item) && item->valuestring[0]) return true;
    char msg[128];
    snprintf(msg, sizeof(msg), "%s is required", name);
    wf_xrpc_response_set_error(response, 400, "InvalidRequest", msg);
    return false;
}

#endif

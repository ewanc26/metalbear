/* The include list shared by the server modules that register routes. The
 * route-registration files in src/ are kept in one list here so that adding a
 * module means editing one header, not each file. Included after the feature
 * macros (_GNU_SOURCE, _DARWIN_C_SOURCE) and server_internal.h. */

#ifndef METALBEAR_SERVER_INCLUDES_H
#define METALBEAR_SERVER_INCLUDES_H

#include "admin/admin_routes.h"
#include "identity/identity_routes.h"
#include "oauth/oauth_credentials.h"
#include "session/session_routes.h"
#include "account/account_routes.h"
#include "account/preferences_routes.h"
#include "sync/sync_routes.h"
#ifdef METALBEAR_MODULE_APPVIEW
#include "appview/appview_routes.h"
#endif
#include "moderation/moderation_routes.h"
#ifdef METALBEAR_MODULE_VIDEO
#include "video/video_routes.h"
#endif
#include "ops/status.h"
#include "ops/ops_routes.h"
#include "repo/blob_store_server.h"

#include "metalbear/server.h"
#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/account/account_context.h"
#include "metalbear/account/account_cache.h"
#include "metalbear/oauth/auth.h"
#include "metalbear/repo/backup.h"
#ifdef METALBEAR_MODULE_EMAIL
#include "metalbear/email.h"
#endif
#ifdef METALBEAR_MODULE_DNS
#include "metalbear/dns/handle_dns.h"
#endif
#include "metalbear/repo/key_rotation.h"
#include "metalbear/oauth/oauth.h"
#include "metalbear/oauth/oauth_account_routes.h"
#include "metalbear/oauth/oauth_scope.h"
#include "metalbear/moderation/report.h"
#include "metalbear/oauth/oauth_routes.h"
#include "metalbear/sequencer.h"

#include "metalbear/repo/blob_store.h"
#ifdef METALBEAR_MODULE_UPDATE_WATCHER
#include "metalbear/ops/update_watcher.h"
#endif
#include "wolfram/crypto.h"
#include "wolfram/plc.h"
#include "metalbear/repo/repo_store.h"
#include "wolfram/repo/cid.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ftw.h>
#include <curl/curl.h>

#endif

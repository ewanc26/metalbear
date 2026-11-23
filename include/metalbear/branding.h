#ifndef METALBEAR_BRANDING_H
#define METALBEAR_BRANDING_H

/*
 * branding.h — validation and defaults for operator branding (issue #260).
 *
 * The config surface is deliberately tiny: a service name, a logo URL, five
 * colours, two auth-screen background URLs and a home URL. Every field is
 * optional; the defaults below are the colours the bundled frontend already
 * ships with, so an operator who sets nothing sees the same server as before.
 *
 * Colours are restricted to #RGB / #RRGGBB and URLs to same-origin paths or
 * http(s) links. That is both a small enough grammar for the frontend and a
 * way to stop a config file from injecting CSS or a javascript: URL into a
 * page the operator's users will see.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define METALBEAR_BRANDING_DEFAULT_SERVICE_NAME "MetalBear"
#define METALBEAR_BRANDING_DEFAULT_PRIMARY "#059669"
#define METALBEAR_BRANDING_DEFAULT_PRIMARY_HOVER "#10b981"
#define METALBEAR_BRANDING_DEFAULT_ERROR "#ef4444"
#define METALBEAR_BRANDING_DEFAULT_WARNING "#f59e0b"
#define METALBEAR_BRANDING_DEFAULT_INFO "#3b82f6"
#define METALBEAR_BRANDING_DEFAULT_SUCCESS "#10b981"
#define METALBEAR_BRANDING_DEFAULT_HOME_URL "/"

/* Empty is a valid "unset" value for every branding field. */
bool metalbear_branding_color_valid(const char *value);
bool metalbear_branding_url_valid(const char *value);

/* Resolves an optional configured colour to its default when unset/empty. */
const char *metalbear_branding_or_default(const char *value,
                                          const char *fallback);

/* Accessible text colour for a #RGB/#RRGGBB background: near-black on a light
 * background, white on a dark one, by WCAG relative luminance. Always returns
 * a static string; NULL input falls back to white. */
const char *metalbear_branding_on_color(const char *background);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_BRANDING_H */

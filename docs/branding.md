# Operator branding

MetalBear can present an instance under the operator's own identity. The
frontend is prerendered static files, so branding is published by the server at
runtime through `/operator.json` rather than baked into a build. Every field is
optional; with none set, the appearance and notification bodies are exactly as
they were before.

## Configuration

Both dialects expose the same flat keys. The environment form wins over the
file, as with every other setting.

| TOML key | Environment variable | Effect |
|---|---|---|
| `branding.service_name` | `METALBEAR_BRANDING_SERVICE_NAME` | Name on the landing page, navigation, auth screens and document titles; signs transactional mail. Default `MetalBear`. |
| `branding.logo_url` | `METALBEAR_BRANDING_LOGO_URL` | Logo beside the name and on auth screens; also signed into mail. Empty by default. |
| `branding.primary_color` | `METALBEAR_BRANDING_PRIMARY_COLOR` | Primary accent (`--mb-primary`). Default `#059669`. |
| `branding.primary_hover_color` | `METALBEAR_BRANDING_PRIMARY_HOVER_COLOR` | Accent hover (`--mb-primary-hover`). Default `#10b981`. |
| `branding.error_color` | `METALBEAR_BRANDING_ERROR_COLOR` | Error state. Default `#ef4444`. |
| `branding.warning_color` | `METALBEAR_BRANDING_WARNING_COLOR` | Warning state. Default `#f59e0b`. |
| `branding.info_color` | `METALBEAR_BRANDING_INFO_COLOR` | Informational state. Default `#3b82f6`. |
| `branding.success_color` | `METALBEAR_BRANDING_SUCCESS_COLOR` | Success state. Default `#10b981`. |
| `branding.background_light_url` | `METALBEAR_BRANDING_BACKGROUND_LIGHT_URL` | Auth-screen background under a light OS preference. |
| `branding.background_dark_url` | `METALBEAR_BRANDING_BACKGROUND_DARK_URL` | Auth-screen background under a dark OS preference. |
| `branding.home_url` | `METALBEAR_BRANDING_HOME_URL` | Footer/navigation home link. Default `/`. |

Example:

```toml
[branding]
service_name = "Bear Hosting"
logo_url = "/logo.svg"
primary_color = "#4f46e5"
primary_hover_color = "#6366f1"
background_light_url = "/auth-light.webp"
background_dark_url = "/auth-dark.webp"
home_url = "/"
```

The footer also reuses the existing `[operator] support_url`,
`privacy_policy` and `terms_of_service`. Those policy URLs remain in
`com.atproto.server.describeServer`'s lexicon-defined `links` field, unchanged;
the non-lexicon links live in the branding object.

## Validation

The server refuses to start on an invalid branding value, with a plain error
on stderr and no value echoed. Colours must be `#RGB` or `#RRGGBB`. URLs must
be same-origin `/...` paths or `http(s)://...` links, with no whitespace,
quotes, parentheses or backslashes: those characters could break out of the
`href`/`src` attributes and `url()` declarations the browser uses. The logo
and background files themselves are ordinary static files served from the
frontend directory; MetalBear does not proxy or sanitise their contents.

`onPrimary` is derived server-side from `primary_color` using WCAG relative
luminance, so every client picks the same accessible text colour (near-black on
light accents, white on dark ones) instead of guessing.

## Runtime behaviour

The layout fetches `/operator.json` once on mount and sets CSS custom
properties on the document root. Tailwind v4's theme tokens are overridden
from those properties, so the accent also reaches account and admin pages that
never import a branding component. Auth screens use the light or dark
background URL according to `prefers-color-scheme`; both default to no image.

Transactional email (verification, password reset and deletion confirmation)
carries the configured name and logo URL as a short plain-text signature. With
neither configured, the original bodies are unchanged byte for byte. Webhook
notifications still receive the same machine-readable fields and are not given
a branding signature.

## Tests

`test_metalbear_branding` covers the colour/URL grammars, default resolution
and contrast choice; `test_config_file` covers the flat keys;
`test_notify_channels` covers the email signature and the no-branding case;
and `test_server` checks the resolved object served from `/operator.json`.

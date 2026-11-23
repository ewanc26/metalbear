# `atproto-proxy` forwarding

Current Bluesky clients route authenticated, non-PDS XRPC calls through the
account's PDS. The client sends an `atproto-proxy` header of the form
`<did>#<service_id>`; the PDS verifies the session, resolves the named service
through its DID document, mints a short-lived service-auth token scoped to that
destination, forwards the call and returns the response.

MetalBear does this for the AppView (`app.bsky.*`), chat (`chat.bsky.convo.*`)
and labeler/Ozone (`tools.ozone.*`) routes. `chat.bsky.convo.listConvos` is a
registered query, so it goes through the normal auth callback and per-route
rate limiting; other NSIDs are handled by the generic proxy fallback, which
verifies any offered Bearer token itself before minting service-auth.

## Destination allowlist

Forwarding is not an open relay. When an `atproto-proxy` header is present, the
bare DID and service id are checked before any network resolution:

- the configured `appview.did`, with a known service id;
- the well-known chat DID `did:web:api.bsky.chat#bsky_chat` (also accepting the
  legacy `atproto_bsky_chat` id);
- the well-known Bluesky labeler DID `did:plc:ar7c4by46qjdydhdevvrndac`
  with `atproto_labeler`;
- the configured `server.mod_service_did` with `atproto_labeler`; and
- any entry in `appview.proxy_destinations` (`METALBEAR_PROXY_DESTINATIONS`),
  a comma-separated list of `<did>` or `<did>#<service_id>`. A bare DID allows
  any known service id; a `#service_id` entry narrows it to that service.

Known service ids are `bsky_chat`, `atproto_labeler` and the two AppView ids
`bsky_appview` / `atproto_bsky_app`. A client asking for any other destination
or service id gets `403 Forbidden` with an `atproto-proxy destination is not
allowed` error; the refusal increments `metalbear_proxy_refusals_total`. The
request still passed through authentication and rate limiting, so per-user
limits continue to apply.

The `atproto-accept-labelers` header rides through with every proxied request,
so label hydration works on proxied reads. `x-bsky-topics` and other
`x-atproto-*` headers are forwarded as well.

## Response streaming

The pinned Wolfram client exposes buffered response bodies only; it has no
client-side response-streaming primitive. MetalBear therefore uses its
buffered adapter: the upstream response is read in full, then sent back with
the original status, headers and body. Chunked transfer encoding and SSE
streams arrive intact as bytes but cannot begin reaching the browser before
the upstream closes the response. True incremental relay needs an upstream
Wolfram streaming-response API and a coordinated dependency bump; until then
MetalBear does not hand-roll a local streaming transport.

## Configuration example

```toml
[appview]
url = "https://api.bsky.app"
did = "did:web:api.bsky.app"
proxy_destinations = "did:web:labeler.example.com#atproto_labeler"
```

The same key is available as `appview.proxy_destinations` in YAML and as
`METALBEAR_PROXY_DESTINATIONS` in the environment.

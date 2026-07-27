# Security Policy

MetalBear hosts real identities. A defect here can expose account credentials,
forge repository commits, or lose the key that every DID on a host was minted
under — so please report problems privately and give operators time to upgrade.

## Reporting a vulnerability

Use GitHub's private reporting form:

**→ [Report a vulnerability](https://github.com/ewanc26/metalbear/security/advisories/new)**

That keeps the report private until a fix ships and gives us somewhere to
discuss it. It needs a GitHub account; without one, email **git@ewancroft.uk**
instead. Either way, include a description, the affected version, and a
reproduction if you have one.

Do not open a public issue for a security defect.

You should get an acknowledgement within a few days. MetalBear is maintained by
one person as a spare-time project, so please treat the timelines below as
intent rather than a contractual SLA. Fixes go out in a tagged release, with the
reporter credited unless they ask otherwise.

## Supported versions

Only the latest release gets fixes. There are no maintenance branches — upgrade
to the newest tag before reporting, and check whether the issue still reproduces.

## Scope

In scope, and treated seriously:

- authentication bypass, or session/refresh tokens accepted when they should not be
- one account reading, writing, or deleting another account's repository or blobs
- admin-gated `com.atproto.admin.*` procedures reachable without the admin password
- forged repository commits, or signatures that verify against the wrong key
- disclosure of the PLC rotation key, the session-signing secret, DNS API tokens,
  or SMTP credentials
- OAuth flaws: PKCE or DPoP bypass, code or token substitution, redirect handling
- injection into SQLite, the DNS provider API, or outbound email

Out of scope, and already documented:

- **TLS.** MetalBear does not terminate TLS by design. Binding it to a public
  interface without a reverse proxy is a deployment mistake, not a defect — see
  the security boundary section of the [README](README.md).
- Rate limiting being too permissive at the default of 100 requests per 60
  seconds, which operators are expected to tune per host.
- Anything listed under **Status** in the README as missing or unproven —
  notably the absent takedown model and the offset-paginated `listRepos`.
- Vulnerabilities in Wolfram's transport, identity, repo, or crypto primitives.
  Report those against [ewanc26/wolfram](https://github.com/ewanc26/wolfram),
  which owns that code.
- Findings from automated scanners with no demonstrated impact.

## Operator guidance

If you run a MetalBear instance:

- keep it on loopback behind a reverse proxy that terminates TLS and forwards
  WebSocket upgrades
- back up `METALBEAR_PLC_ROTATION_KEY`. Every DID the host has minted is
  unrecoverable without it
- keep `config.toml` and `metalbear.env` out of version control; both hold
  secrets and both are gitignored for that reason
- raise the rate limit deliberately rather than disabling it

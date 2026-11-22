# Handle constraints

MetalBear accepts handles under the configured `user_domain` with a single
3–18 character label, for example `alice.bear1.example.com` when the domain is
`.bear1.example.com`. The label must also pass Wolfram's handle syntax rules.

Some labels are reserved, matching the reference PDS's
`packages/pds/src/handle/reserved.ts`: atproto terms (`at`, `atp`, `plc`,
`pds`, `did`, `repo`, `tid`, `nsid`, `xrpc`, `lex`, `lexicon`, `bsky`,
`bluesky`, `handle`), common service prefixes (`admin`, `api`, `www`, `mail`
and similar), and a set of well-known account names. A reserved label is
rejected with a 400 `HandleNotAvailable` response at:

- `com.atproto.server.createAccount`
- `com.atproto.identity.updateHandle`
- `com.atproto.admin.updateAccountHandle`

The admin route uses the same check: an operator override cannot assign a
handle an account holder could never set. This is a constraint on new
assignments; it does not rename existing accounts or change any stored data.

Two temporary XRPC helpers support signup forms:

- `com.atproto.temp.checkHandleAvailability` is public. It takes `handle` and
  optional `email` and `birthDate`, and returns the handle with a tagged
  `result`: `com.atproto.temp.checkHandleAvailability#resultAvailable`, or
  `#resultUnavailable` with suggestions. An invalid `email` gets a 400
  `InvalidEmail` response.
- `com.atproto.temp.addReservedHandle` is admin-only, behind the same HTTP
  Basic `admin:<METALBEAR_ADMIN_PASSWORD>` credential as the other operator
  routes. Its `{"handle":"..."}` input stores a reservation for 24 hours. The
  handle must pass the same syntax and domain rules as signup.

Dynamic reservations are checked alongside the static reserved-label table at
`com.atproto.server.createAccount`, `com.atproto.identity.updateHandle` and
`com.atproto.admin.updateAccountHandle`. Reservations are stored per account
in `account.sqlite3` and expire lazily when availability is next checked; no
background timer is involved. The account database uses schema version 3.

The table in `src/handle/reserved_data.c` is generated. To update it from a
new reference revision, run:

```sh
python3 scripts/gen_reserved_handles.py path/to/atproto/packages/pds/src/handle/reserved.ts
```

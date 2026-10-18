# Two-factor login with TOTP and backup codes

Status: design, for [#130](https://github.com/ewanc26/metalbear/issues/130). No code yet.

## Where it fits

Login goes through `create_session` in `src/session/session_routes.c`. It checks
the password, then issues a session from the auth store (`src/oauth/auth.c`).
A second factor belongs between those two steps: the password is right, but no
session is issued until the second factor is too.

The lexicon in `wolfram/lexicons/com/atproto/server/createSession.json` defines
an optional `authFactorToken` input and an `AuthFactorTokenRequired` error. Its
output carries `emailAuthFactor`, which says the account's second factor is an
emailed code. The lexicon does not describe TOTP at all.

So the protocol's own second factor is email, and the field and error are the
shape MetalBear should follow. Reusing `authFactorToken` for a TOTP code is an
extension. A client that only knows the email factor gets
`AuthFactorTokenRequired`, has nothing to enter it into, and cannot complete a
TOTP login. That is acceptable for a dev PDS, but it should be a decision,
recorded here, and not a side effect. The reference's own behaviour beyond the
lexicon is not checked here.

## Enrolment

1. An authenticated account asks for a new secret. The server generates 160
   random bits and returns them once, base32-encoded, with an `otpauth://` URI
   for an authenticator app. The secret is stored encrypted, but not yet active.
2. The account submits one current code. A correct code activates the secret and
   issues ten backup codes. The backup codes are shown once.
3. Until step 2 succeeds, nothing changes for the account.

## Login

1. The password is checked as today. A failed password is refused as today, and
   the second factor is never reached.
2. If two-factor login is on and `authFactorToken` is missing or wrong, the
   server answers `AuthFactorTokenRequired`.
3. A six-digit TOTP code is accepted for the current 30-second step and the step
   either side of it. Each step is accepted once per account: the last accepted
   step is stored, and an earlier or equal step is refused. That blocks replay of
   a code seen over the wire.
4. A backup code is accepted once. Each code is stored as a keyed hash and is
   deleted when used.
5. Failed second-factor attempts count against the same rate limit as failed
   passwords, keyed on identifier and client address, so the second factor cannot
   be guessed faster than the password could be.

## Storage

- `totp_secret(did, secret_ciphertext, active, last_step)`. The secret is
  encrypted with libsodium's secret box (already used by the blob store), under a
  server key.
- `totp_backup(did, code_hash, used)`. Codes are 80 random bits, shown once,
  and stored as HMAC-SHA-256 under the same server key.

The server key is a 32-byte file in the data directory, created with mode 0600
on first use. It is never logged or returned. Losing it means every enrolled
account must enrol again, which is an operator action, so the procedure goes
in the docs with the feature.

These are new tables in the auth database. An older binary ignores them, so
this does not need a `METALBEAR_SCHEMA_VERSION` bump. Any later change to these
columns does.

## Turning it off

Turning two-factor login off needs the password and a current code, or a backup
code. A session token alone is not enough, so a stolen session cannot remove the
second factor.

## Recovery

An operator can clear two-factor login for one account through the admin
endpoints, behind the admin password, and the action is logged. This is the only
way back for an account that has lost its device and its backup codes.

## App passwords

Open question. The reference PDS lets an app password skip the second factor,
because an app password is a separately scoped secret. That is convenient, but
it means a leaked app password gets around the second factor. Options:

- **A.** App passwords skip the second factor, as in the reference.
- **B.** App passwords still require it. This is stricter, and clients that
  only support app passwords would stop working.

I recommend A to match the reference, and treating an app password as its own
credential that can be revoked. Your call.

## Threat model for the server key

The key protects the enrolled secrets and the backup codes. It is kept in the
data directory by default, which is the same directory the scheduled backups
(#129) archive. So this is what each arrangement protects against:

- **Key beside the data.** Protects against a leak of the database files alone.
  It does not protect against a leak of the whole data directory, and a backup
  archive is a copy of the whole directory, key included.
- **Key outside the data directory.** A leaked backup or database copy cannot
  decrypt the secrets. The key is then a second thing to lose: losing it means
  every enrolled account enrols again.

Recommendation: make the key path configurable (`totp.key_file`), default it
outside the data directory, and have backups exclude it, so a backup restored
without the key fails closed.

Rotation: write a new key, re-encrypt each stored secret, then retire the old
key. A failed rotation must leave every secret readable under one of the two
keys until it completes. Rotation is an operator action, documented with the
feature.

## Not in this change

- Passkeys stay as they are. They are already a second factor where the client
  uses them.
- SMS codes. Not planned.
- Trusted devices. [#131](https://github.com/ewanc26/metalbear/issues/131) builds on this.

## Tests this design needs

- Enrolment: a wrong code does not activate; the right one does, and issues ten
  backup codes.
- Login: a password without a code is refused with `AuthFactorTokenRequired`; a
  right code succeeds; the same code twice is refused.
- Backup codes: each works once.
- Rate limit: repeated wrong codes are refused like repeated wrong passwords.
- Disable: refused without a valid second factor.
- Recovery: the admin action clears the factor and is logged.

## Questions before code

1. **App passwords** (above): decided, option A. An app password is its own
   revocable credential and skips the second factor.
2. **Server key**: decided, a key file, configurable, outside the data directory
   by default (see the threat model). Not derived from the admin password, since
   changing that password would lock everyone out.
3. **Second factor on the wire**: TOTP reuses `authFactorToken` (see above).
   Confirm that a client without TOTP support is acceptable for this instance.

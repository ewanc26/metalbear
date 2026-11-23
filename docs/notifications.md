# Notification channels

MetalBear sends account notifications (email verification, password reset,
account-deletion confirmation and PLC operation signature requests) through a
small channel interface. Every configured channel receives every notification;
a channel is off unless its settings are present, and with no channels
configured sending is a silent no-op.

The channels are:

| Channel | Settings | On when |
|---|---|---|
| Email | `[smtp]` in `config.toml` / `smtp:` in `config.yaml`, or `METALBEAR_SMTP_*` environment variables | `smtp.host` and `smtp.from_address` are set and the server was built with the email module (the default; omit it with `-DMETALBEAR_MODULE_EMAIL=OFF`) |
| Webhook | `notify.webhook_url` and `notify.webhook_secret` / `METALBEAR_NOTIFY_WEBHOOK_URL` and `METALBEAR_NOTIFY_WEBHOOK_SECRET` | `notify.webhook_url` is non-empty |

SMTP retains its existing settings and behaviour; the channel interface only
changes how the call sites reach it.

## Webhook payload

The webhook channel makes a `POST` with `Content-Type: application/json` to the
configured URL. When `notify.webhook_secret` is set it is sent as
`Authorization: Bearer <secret>`. The body is a single JSON object:

```json
{
  "kind": "verification",
  "to": "alice@example.com",
  "did": "did:plc:alice",
  "code": "123456",
  "subject": "Verify your email address",
  "body": "Your verification code is: 123456\n\n..."
}
```

`kind` is one of `verification`, `password_reset`, `account_deletion` or
`message`. Fields that do not apply to a kind are omitted: an administrator
`sendEmail` uses `kind: "message"` and has no `code`.

A failure from any channel is returned to the caller after all channels have
been attempted, so a broken webhook does not suppress email (or vice versa).
`admin.sendEmail` reports `{"sent": false}` when no channel is configured or
delivery fails.

## Secrets

The webhook secret and the notification payload can contain credentials and
one-time codes. Neither is written to MetalBear's logs: a failed delivery
logs only that a webhook delivery failed. Keep the configuration file and
environment file readable only by the operator account, and use an `https://`
webhook URL for any non-loopback destination.

The request uses a 5-second connect timeout and a 10-second total timeout. It
does not retry; a channel implementation that queues or retries belongs in the
receiver or a dedicated future channel.

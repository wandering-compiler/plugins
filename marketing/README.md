# marketing plugin

The gateway's request stream into a marketing tool. Every signed-in request
of a surface that records marketing (`request_events: { marketing: true }`)
becomes an event on the user's contact in the tool, and the contacts follow
the auth plugin's accounts: created at sign-up, updated with the address,
given the user's marketing consent, deleted with the account. The tool's own
segments and automations do the rest: who uses what, where the gaps are,
whom to write to. **Brevo first** (feature `brevo`).

## Activating it

Next to an `auth` activation in the same domain (the accounts, consent and
erasure are auth's events), on a surface that records marketing:

```proto
plugins: [
  { name: "auth" registered_as: "auth" features: { names: ["...", "user_admin", "marketing_consent"] } },
  { name: "marketing" registered_as: "marketing" features: { names: ["brevo"] } }
]
```

`user_admin` brings auth's `UserUpdated` and `UserDeleted` (contact updates
and deletion), `marketing_consent` its `MarketingConsentChanged`. Without
them the plugin still sends events and creates contacts.

| env (`<DOMAIN>_MARKETING_…`) | |
|---|---|
| `BREVO_API_KEY` | the account's API key (secret) |
| `SEND` | `mutations` (default), `queries`, `all`, `off` |
| `INCLUDE` / `EXCLUDE` | comma-separated methods (`/<package>.<Service>/<Method>`) added to / removed from `SEND`; `EXCLUDE` wins; a name the stream does not record is refused at boot |
| `BREVO_CONSENT_ATTRIBUTE` | the contact attribute the consent goes to (default `W17_MARKETING_CONSENT`) |
| `BREVO_RPS` | requests per second to Brevo (default 8 of the account's 10) |
| `PLUGINS_DURABLE_PREFIX` (`<DOMAIN>_`) | the bundle's prefix for the plugins' delivery progress; set it when two deployments share a broker |

## What reaches Brevo

- **Events** (`POST /v3/events/batch`): the method as the event name
  (`TasksBusiness_CreateTask`), on the contact keyed by the user's id
  (`ext_id`), at the request's time, with the record's own properties:
  `w17_status` (or `w17_grpc_code`), `w17_duration_ms`, `w17_api`,
  `w17_route`, `utm_<key>`, `referrer`, `w17_truncated`. The contact gets
  `W17_ORG_ID` and the consent attribute (when the record knows it).
- **Not**: the request's own fields (yet), the IP address, the user agent,
  anything marked `sensitive`.
- **Contacts** (`POST /v3/contacts`, upsert by `ext_id`): created on
  `UserCreated` with the email, updated on `UserUpdated`, the consent
  attribute set on `MarketingConsentChanged`.
- **Erasure** (`DELETE /v3/contacts/{id}?identifierType=ext_id`) on
  `UserDeleted`: the contact and its history.

Consent does not change what is recorded or sent: it is the tool's to read
before it writes to anyone.

## In development: the stub

`sandboxes/brevostub` is a dev-only stand-in for the Brevo API (the plugin's
`brevostub` sandbox): it answers the plugin's three calls and keeps what they
said, readable at `GET /_stub/contacts/{ext_id}` and `GET /_stub/events`, so a
project's suite can assert on what would have reached Brevo. Point the
activation at it with `<DOMAIN>_MARKETING_BREVO_BASE_URL=http://brevostub:8080/v3`
and `_BREVO_API_KEY=stub-key`.

## Delivery

The stream delivers at least once and Brevo's events API has no idempotency
key, so a record is remembered as sent (`SentEvent`, three days) once Brevo
accepted it, and a redelivered one is skipped. A transient failure (network,
429, 5xx) is redelivered; an event Brevo refuses for its content is logged
and not retried. A 429 is waited out as Brevo's `x-sib-ratelimit-reset`
says. The behaviour is specified in [SPEC.md](SPEC.md).

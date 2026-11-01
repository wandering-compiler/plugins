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
| `BREVO_WEBHOOK_TOKEN` | the token Brevo's webhook carries (`brevo_webhook`, secret) |
| `PLUGINS_DURABLE_PREFIX` (`<DOMAIN>_`) | the bundle's prefix for the plugins' delivery progress; set it when two deployments share a broker |

**The calls leave from the storage bundle**, where the plugin runs. A Brevo
account with *Authorised IPs* on (Security → Authorised IPs) refuses every call
from an address it does not list (401 "unrecognised IP address"): list the
storage servers' addresses, IPv4 and IPv6 each. Until then nothing is lost — the
calls fail, and the records and contact changes end in the stream's dead
letters, to be replayed once the account allows them.

## What reaches Brevo

- **Events** (`POST /v3/events/batch`): the method as the event name
  (`TasksBusiness_CreateTask`), on the contact keyed by the user's id
  (`ext_id`), at the request's time, with the record's own properties:
  `w17_status` (or `w17_grpc_code`), `w17_duration_ms`, `w17_api`,
  `w17_route`, `utm_<key>`, `referrer`, `w17_truncated`, and the request's
  context: `w17_org_id` (the organization it acted in) and `w17_account_type`
  (the caller's kind of membership there, auth's `membership_kinds`), each
  only when the project has it. The contact gets the consent attribute (when
  the record knows it). The organization is never written to the contact: a
  person may work in two organizations at once, and only the request knows
  which one it was.
- **Not**: the request's own fields (yet), the IP address, the user agent,
  anything marked `sensitive`.
- **Contacts** (`POST /v3/contacts`, upsert by `ext_id`): created on
  `UserCreated` with the email, updated on `UserUpdated`, the consent
  attribute set on `MarketingConsentChanged`. Whether campaigns may reach the
  contact (`emailBlacklisted`, Brevo's "Email campaigns: Subscribed"): a new
  account is blacklisted, a no blacklists, and only the user's newest yes
  subscribes — after reading the contact from Brevo, so a person who
  unsubscribed there stays unsubscribed (recorded, not undone). A consent the
  plugin was never told is no consent. The plugin keeps each user's last
  consent, address and what it last wrote (`Contact`), and an address change
  never subscribes anyone.
- **Erasure** (`DELETE /v3/contacts/{id}?identifierType=ext_id`) on
  `UserDeleted`: the contact and its history.

**Contacts from before `emailBlacklisted`.** Once per deployment, in the
background, the plugin blacklists every contact of its own (an `EXT_ID` that
is a user id) that is subscribed and whose user has not consented. It never
subscribes anyone, and leaves contacts it did not create alone. A
`Reconciliation` row records that it ran, so a restart or a second replica
does not run it again.

The plugin creates the contact attribute it writes (`W17_MARKETING_CONSENT`,
or `BREVO_CONSENT_ATTRIBUTE`) when it starts: Brevo drops an attribute the
account does not have, silently. Segment by organization or account type on
the events' properties.

Consent does not change what is recorded or sent: it is the tool's to read
before it writes to anyone.

## An unsubscribe in Brevo (`brevo_webhook`)

A person who unsubscribes from a campaign in Brevo has withdrawn their
consent. With the `brevo_webhook` feature, Brevo's marketing webhook tells
the plugin, the plugin keeps it on the contact, and the project records it in
auth as the user's withdrawal. auth then announces it as
`MarketingConsentWithdrawn` (the user's own decisions are
`MarketingConsentChanged`); this plugin, which reported it, does not
subscribe to it.

Plugins do not call each other, so the project connects the two with a
business method of the domain, bound to the plugin's `consent_withdrawn` hook
(auth's `marketing_consent` feature on):

```proto
plugins: [{ name: "marketing" registered_as: "marketing" features: { names: ["brevo", "brevo_webhook"] }
            hooks: [ { slot: "consent_withdrawn", methods: [ "consent.ConsentHooks.Withdrawn" ] } ] }]
```

```go
func (s *ConsentHooks) Withdrawn(ctx context.Context, req *marketingpb.ConsentWithdrawnReq) (*marketingpb.ConsentWithdrawnResp, error) {
	_, err := s.auth.WithdrawMarketingConsent(ctx, &authpb.WithdrawMarketingConsentReq{UserId: req.GetUserId(), WithdrawnAt: req.GetWithdrawnAt()})
	return &marketingpb.ConsentWithdrawnResp{}, err
}
```

Set `<DOMAIN>_MARKETING_BREVO_WEBHOOK_TOKEN` to a long random string and
create the webhook with it (the endpoint refuses every call without it, and
every call while it is unset):

```sh
curl -X POST https://api.brevo.com/v3/webhooks -H "api-key: $BREVO_API_KEY" -H 'content-type: application/json' -d '{
  "type": "marketing", "events": ["unsubscribed"],
  "url": "https://api.example.com/marketing/webhooks/brevo",
  "headers": [{"key": "X-Brevo-Webhook-Token", "value": "<the token>"}]}'
```

A delivery whose write-back fails is answered 503, and Brevo sends it again.

## In development: the stub

`sandboxes/brevostub` is a dev-only stand-in for the Brevo API (the plugin's
`brevostub` sandbox): it answers the plugin's calls and keeps what they
said — `emailBlacklisted` included — readable at `GET /_stub/contacts/{ext_id}` and `GET /_stub/events`, so a
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

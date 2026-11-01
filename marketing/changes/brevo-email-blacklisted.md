### Contacts without marketing consent are no longer subscribed to campaigns

Every contact the plugin writes to Brevo now says whether campaigns may reach it (`emailBlacklisted`, Brevo's "Email campaigns: Subscribed"). Until now it never did, so every contact was subscribed and an all-contacts campaign reached people who had not consented.

- **A new account is blacklisted** until the user consents; `MarketingConsentChanged` sets `emailBlacklisted = !consent` together with the consent attribute. A consent the plugin was never told is no consent.
- **An address change never subscribes anyone.** The plugin keeps each user's last known consent, address and Brevo-side unsubscribe in a new `Contact` table, and writes the blacklist status from it on `UserUpdated`. A consent event older than the one kept does not overwrite it. On `UserDeleted` the row loses the address.
- **Contacts created before this release** are blacklisted once per deployment, in the background, when their user has not consented (a `Reconciliation` row records that the pass ran, so restarts and other replicas skip it). The pass never subscribes anyone and touches only the plugin's own contacts (an `EXT_ID` that is a user id). **Upgrading:** the migration adds the `Contact` and `Reconciliation` tables.
- **The `brevostub` sandbox** keeps and answers `emailBlacklisted`, and answers `GET /v3/contacts`.

### An unsubscribe in Brevo comes back as the user's withdrawal (`brevo_webhook`)

The new `brevo_webhook` feature (requires `brevo`) serves Brevo's marketing webhook at `POST /marketing/webhooks/brevo`. An `unsubscribed` event is kept on the user's contact and handed to the required `consent_withdrawn` hook, bound to a business method of the domain that calls auth's `AuthService.WithdrawMarketingConsent` (plugins do not call each other; README has the method). The webhook carries no bearer: create it in Brevo with the header `X-Brevo-Webhook-Token` set to `<DOMAIN>_MARKETING_BREVO_WEBHOOK_TOKEN`; every call without it, and every call while it is unset, is refused. A delivery whose write-back fails is answered 503, and Brevo sends it again. Needs auth with this release's `WithdrawMarketingConsent`.

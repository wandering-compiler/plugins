### Requests reach Brevo as events, as contact attributes, or both

How the gateway's marketing records reach Brevo is now the activation's choice, in its features: `brevo_events` (each request an event on the contact, what `brevo` alone did until now), `brevo_attributes` (each request moves a date attribute on the contact, the shape Brevo's automations and segments start from), or both. Both require `brevo`, which keeps the contacts, consent and erasure.

- **`brevo_attributes`**: `W17_<SERVICE>_<METHOD>` holds the day the user last made that request (`W17_TASKSBUSINESS_CREATETASK = 2026-11-09`) and `W17_LAST_ACTIVITY_AT` the exact time of their last one (text, ISO 8601: Brevo's date attributes hold no time). The attributes are created in the account at boot for every method `send` / `include` / `exclude` let through. A new `Activity` table keeps each user's last date per attribute, so a redelivered or concurrent record never moves one back; it is deleted with the account. An attribute holds only the last time: the request's organization, status and UTM tags stay the event's.
- **Dated contacts**, with either: `W17_SIGNED_UP_AT` (the day the account was created, from `UserCreated.created_at`) and `W17_MARKETING_CONSENT_AT` (the day the consent kept was decided, written with the consent attribute).
- **The `brevostub` sandbox** keeps each attribute's type and refuses a date that is not `YYYY-MM-DD`, so a suite sees a malformed date the plugin would send.

**Upgrading:** an activation that names only `brevo` now refuses to boot, saying so — add `brevo_events` to keep sending events, `brevo_attributes`, or both. With `brevo_attributes` the migration adds the `Activity` table.

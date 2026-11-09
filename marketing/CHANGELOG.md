# marketing — changelog

## 0.1.0-rc.6

### Requests reach Brevo as events, as contact attributes, or both

How the gateway's marketing records reach Brevo is now the activation's choice, in its features: `brevo_events` (each request an event on the contact, what `brevo` alone does), `brevo_attributes` (each request moves a date attribute on the contact, the shape Brevo's automations and segments start from), or both. Both require `brevo`, which keeps the contacts, consent and erasure; naming neither sends events.

- **`brevo_attributes`**: `W17_<SERVICE>_<METHOD>` holds the day the user last made that request (`W17_TASKSBUSINESS_CREATETASK = 2026-11-09`) and `W17_LAST_ACTIVITY_AT` the exact time of their last one (text, ISO 8601: Brevo's date attributes hold no time). The attributes are created in the account at boot for every method `send` / `include` / `exclude` let through. A new `Activity` table keeps each user's last date per attribute, so a redelivered or concurrent record never moves one back; it is deleted with the account. An attribute holds only the last time: the request's organization, status and UTM tags stay the event's.
- **Dated contacts**, with either: `W17_SIGNED_UP_AT` (the day the account was created, from `UserCreated.created_at`) and `W17_MARKETING_CONSENT_AT` (the day the consent kept was decided, written with the consent attribute).
- **The `brevostub` sandbox** keeps each attribute's type and refuses a date that is not `YYYY-MM-DD`, so a suite sees a malformed date the plugin would send.

**Upgrading:** nothing changes for an activation that names only `brevo`: naming neither `brevo_events` nor `brevo_attributes` sends events, as before. Name `brevo_attributes` alone to send attributes instead of events, or both. With `brevo_attributes` the migration adds the `Activity` table.

### An activation without brevo compiles

`MarketingQuery` and `MarketingMutation` are tagged `plugin_feature_svc = "brevo"`, like every rpc in them and every table they read or write. Without the feature, the feature filter dropped `types/models.proto` but kept the two service files, each now holding an empty service and an import of the dropped file, so no activation without `brevo` compiled (`open …/types/models.proto: no such file`). Both files now drop with the models.

### A contact without an address says so

`ContactRow.email` is declared `(w17.field).null`: an erased contact keeps no address, and a generated query that can fill a field with SQL NULL must now say so. The lookup by address is unchanged — its `WHERE c.email = :email` already guarantees one. No wire or handler change.

## 0.1.0-rc.5

### Contacts without marketing consent are no longer subscribed to campaigns

Every contact the plugin writes to Brevo now says whether campaigns may reach it (`emailBlacklisted`, Brevo's "Email campaigns: Subscribed"). Until now it never did, so every contact was subscribed and an all-contacts campaign reached people who had not consented.

- **A new account is blacklisted** until the user consents; a no is written blacklisted together with the consent attribute. Only the user's newest yes subscribes, and only after the plugin reads the contact from Brevo: a person who unsubscribed in Brevo (blacklisted there while the plugin had left them subscribed) stays unsubscribed. A consent the plugin was never told is no consent.
- **An address change never subscribes anyone** (it leaves `emailBlacklisted` alone for a consented user). The plugin keeps each user's last known consent, address, Brevo-side unsubscribe and last written value in a new `Contact` table, by writes conditional on being newer, so concurrent deliveries cannot let an older decision win. On `UserDeleted` the row loses the address.
- **Contacts created before this release** are blacklisted once per deployment, in the background, when their user has not consented, repeating until a pass finds nothing left (a `Reconciliation` row records that the pass ran, so restarts and other replicas skip it). The pass never subscribes anyone and touches only the plugin's own contacts (an `EXT_ID` that is a user id). **Upgrading:** the migration adds the `Contact` and `Reconciliation` tables.
- **The `brevostub` sandbox** keeps and answers `emailBlacklisted`, answers `GET /v3/contacts` and `GET /v3/contacts/{id}`, and `POST /_stub/contacts/{ext_id}/unsubscribe` unsubscribes a person as Brevo would.

### An unsubscribe in Brevo comes back as the user's withdrawal (`brevo_webhook`)

The new `brevo_webhook` feature (requires `brevo`) serves Brevo's marketing webhook at `POST /marketing/webhooks/brevo`. An `unsubscribed` event is kept on the user's contact and handed to the required `consent_withdrawn` hook, bound to a business method of the domain that calls auth's `AuthService.WithdrawMarketingConsent` (plugins do not call each other; README has the method). The webhook carries no bearer: create it in Brevo with the header `X-Brevo-Webhook-Token` set to `<DOMAIN>_MARKETING_BREVO_WEBHOOK_TOKEN`; every call without it, and every call while it is unset, is refused. An unsubscribe older than the user's latest consent (late, redelivered) is not written back. A delivery whose write-back fails is answered 503, and Brevo sends it again. Needs auth with this release's `WithdrawMarketingConsent`.

## 0.1.0-rc.4

### The brevostub sandbox builds in the project

The `brevostub` sandbox (the `brevo` feature's fake Brevo API) now declares `build: { context: sandboxes/brevostub }`, and the release ships its source. A project's `compose.w17.yaml` builds the image from the vendored plugin (`<proto_dir>/plugins/marketing/sandboxes/brevostub`) on `w17ctl stack build`, `stack up --build`, or the first `stack up` that finds no image, instead of trying to pull a tag no registry publishes. Needs w17 platform 1.17 (`requires_w17: ">=1.17"`).

## 0.1.0-rc.3

### The organization and the account type go on the event, not the contact

- Every event carries `w17_org_id` (the organization the request acted in) and `w17_account_type` (the caller's kind of membership there, from auth's `membership_kinds`), each only when the record has it: a project without organizations or kinds sends neither.
- The contact no longer gets `W17_ORG_ID`. A contact is the person, and a person may work in two organizations at once; the attribute held whichever organization the last recorded request named. The plugin no longer creates the attribute either. **Upgrading:** an account that has it keeps it with its last values; delete the attribute in Brevo (Contacts → Settings → Contact attributes) and segment on the events' `w17_org_id` / `w17_account_type` instead.

### A bad Brevo setting names the setting

- A Brevo client the settings cannot build refuses the boot naming the settings (`brevo_api_key / brevo_base_url / brevo_rps`), and the generated wiring adds the real variable names. It used to print a literal `<DOMAIN>_MARKETING_…`, which no operator could look up.

## 0.1.0-rc.2

### Fixed

- **A project that activates the plugin generates again.** The subscription mirrors were in `proto/subscriptions/`, which is not a layer, so a project's codegen read it as a module inside the plugin's and refused it ("is a module … and also a group above module"). They are in `proto/types/auth_mirrors.proto` now; the messages are the same.

## 0.1.0-rc.1

### A new plugin: marketing, Brevo first

- **The gateway's marketing records as Brevo events** on the user's contact (feature `brevo`): the method as the event name, the record's own properties (status, duration, surface, route, UTM, referrer), the org and the consent on the contact. Choose with `send` (mutations, queries, all, off), `include` and `exclude`.
- **Contacts follow the auth plugin's accounts:** created on `UserCreated`, updated on `UserUpdated`, the consent attribute from `MarketingConsentChanged`, deleted with their history on `UserDeleted`.
- **Measured against a Brevo account:** contacts are written by their id (an address change included), the plugin's attributes are created at start (Brevo drops unknown ones), and an account that refuses the server's address keeps the calls for a replay.
- **Sent once:** a record is remembered as sent after Brevo accepted it (`SentEvent`), so a redelivered batch is not a second event. Requests are paced to `brevo_rps`, and a 429 is waited out.
- **A Brevo stub for development** (sandbox `brevostub`): the three calls answered and kept, readable at `/_stub/`, for a project's suite.
- Needs w17 platform 1.13 and an `auth` activation in the same domain.

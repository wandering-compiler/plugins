# marketing — changelog

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

# marketing — changelog

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

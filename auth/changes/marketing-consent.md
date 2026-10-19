### The user's consent to marketing messages (`marketing_consent`, new, off by default)

- **New feature `marketing_consent`** (requires `authenticate_turnkey`). The user reads and sets their own consent on the REST preset: `GET /auth/marketing-consent` and `PUT /auth/marketing-consent` with `{"consent": true|false}` (`GetMarketingConsent`, `SetMarketingConsent`). Both act on the caller only.
- **Stored on the user:** `User.marketing_consent` (FALSE until given) and `User.marketing_consent_at`, the time of the latest decision (NULL = never asked, which a UI reads to know whether to ask). A withdrawal is recorded like a consent.
- **`AuthResp.marketing_consent` (7):** the gateway copies it into every request record, so the tool that sends the messages has it. Nothing in w17 acts on it; what is recorded does not depend on it.
- **New event `MarketingConsentChanged`** (`auth.user.marketing_consent_changed`: `user_id`, `consent`, `decided_at`, `device_id` of the device the user decided from), for a subscriber that keeps a copy (a marketing tool's contact).
- **Migration** (only with the feature): two new columns on `User`, nothing changed or removed.

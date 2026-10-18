### A bearer token is written by IssueApiToken; IssueBotBearerToken is gone

In rc.26, `ApiTokenCreated` had two emit sites: `IssueApiToken`, and `IssueBotBearerToken` for a machine account's bearer token. A consumer that enabled `service_account` could not generate code, because an event has exactly one emit site.

- **`AuthMutation.IssueBotBearerToken` is removed.** The bearer token is written by `AuthMutation.IssueApiToken`, using a new `IssueApiTokenReq.bearer` (11, field-gated `service_account`, set only by the machine-account path).
- **`IssueApiTokenReq.device_id` may be empty**, but only for a bearer token. The handler still refuses any other API token without a device.
- Nothing changes on the wire or in the schema compared with rc.26: the same column and the same `ApiTokenCreated` event, with an empty `key_thumbprint` for a bearer token.

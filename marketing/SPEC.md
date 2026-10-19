# marketing — behaviour specification

What the `marketing` plugin does and what it must never do. It covers plugin
version 0.1.0-rc.1. Ids are `<feature>/<name>`; a property without a proof is a
gap, not a promise. The handler tests run against a fake Brevo and an
in-memory `SentEvent` ledger; the client tests (`lib/brevo`) against an HTTP
stub of the Brevo API.

## Features

| feature | default | requires | conflicts with |
|---|---|---|---|
| `brevo` | off | — (plugin requires `auth`) | — |

## Per feature

### brevo

- **Purpose.** The gateway's marketing records as Brevo events on the user's
  contact; the contacts following auth's accounts, consent and erasure.
- **Adds.** Table `SentEvent`; `MarketingQuery.ListSentEvents`;
  `MarketingMutation.RecordSentEvent`, `ForgetSentEventsBefore`; the
  request consumer `brevo` (marketing); subscriptions to auth's
  `UserCreated`, `UserUpdated`, `UserDeleted`, `MarketingConsentChanged` (the
  last three optional).

| id | invariant | category | proof |
|---|---|---|---|
| `brevo/sent-once` | A record Brevo accepted MUST NOT be sent again when the stream redelivers its batch. A record MUST be recorded as sent only after Brevo answered for it. | Consistency & concurrency | `TestConsumeMarketing_SkipsWhatWasSentAndRecordsWhatIs`, `TestConsumeMarketing_ATransientFailureRecordsNothing`, `TestRecordSent_AnotherReplicaFirstIsTheSameOutcome`. **Unit (mock) only:** a live test would kill the bundle between Brevo's answer and the record and show at most one duplicate. |
| `brevo/transient-is-redelivered` | A network failure, 429 past its waits, 5xx, or a key or server address the account does not accept (401, 403) MUST fail the call so the stream redelivers it and, past the retries, dead-letters it for a replay; only a call Brevo refuses for its content (400, 422) MUST be dropped. | Failure & configuration | `TestConsumeMarketing_ATransientFailureRecordsNothing`, `TestConsumeMarketing_ARefusedEventIsNotRetried`, `TestContacts_RetryOnlyWhatMaySucceed`, `TestRetryable`, `TestRefused_OnlyWhatTheContentCauses`, `TestDo_GivesUpOnARateLimitThatDoesNotLift` |
| `brevo/selection` | `send` MUST choose by kind (a method reads when served as GET or a Query service's), `include` add, `exclude` remove and win. A configured method the stream does not record MUST fail the boot. | Failure & configuration | `TestConsumeMarketing_SendsWhatTheSelectionSays`, `TestNewSelection_RefusesWhatTheStreamDoesNotRecord` |
| `brevo/no-personal-extras` | An event MUST NOT carry the IP address, the user agent or the request's fields; an unknown consent MUST NOT be written as false. | Security | `TestEventFor` |
| `brevo/erasure` | `UserDeleted` MUST delete the contact and its history; a transient failure MUST be retried, a missing contact counts as deleted. | Security | `TestContacts_FollowTheAccounts`, `TestContacts_RetryOnlyWhatMaySucceed`, `TestDeleteContact_AMissingContactIsDeleted` |
| `brevo/rate` | Requests MUST leave at most `brevo_rps` per second; a 429 MUST be waited out as `x-sib-ratelimit-reset` says. | Performance | `TestPace_SpacesTheRequests`, `TestDo_WaitsOutARateLimit` |
| `brevo/batch-limits` | A batch MUST hold at most 200 events and 512 KB. | Failure & configuration | `TestConsumeMarketing_SplitsAtTheBatchLimit`, `TestSendEvents_RefusesWhatBrevoWould` |

**Gaps / suspected defects**

1. **The request's fields are not sent.** The consumer runs in the storage
   bundle, which does not link the project's business services, so their
   requests arrive undecoded; linking them there is platform work.
2. **Not yet checked against a Brevo account:** whether an event for an
   unknown `ext_id` creates the contact, and how an upsert with both `ext_id`
   and a changed `email` resolves.

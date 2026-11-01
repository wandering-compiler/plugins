# marketing — behaviour specification

What the `marketing` plugin does and what it must never do. It covers plugin
version 0.1.0-rc.1. Ids are `<feature>/<name>`; a property without a proof is a
gap, not a promise. The handler tests run against a fake Brevo and in-memory
`SentEvent`, `Contact` and `Reconciliation` tables; the client tests
(`lib/brevo`) against an HTTP stub of the Brevo API.

## Features

| feature | default | requires | conflicts with |
|---|---|---|---|
| `brevo` | off | — (plugin requires `auth`) | — |
| `brevo_webhook` | off | `brevo` | — |

## Per feature

### brevo

- **Purpose.** The gateway's marketing records as Brevo events on the user's
  contact; the contacts following auth's accounts, consent and erasure.
- **Adds.** Tables `SentEvent`, `Contact` (each user's last known consent,
  address and Brevo-side unsubscribe) and `Reconciliation` (one-time passes);
  `MarketingQuery.ListSentEvents`, `ListContacts`, `ListContactsByEmail`,
  `GetReconciliation`; `MarketingMutation.RecordSentEvent`,
  `ForgetSentEventsBefore`, `SetContactEmail`, `SetContactConsent`,
  `SetContactUnsubscribed`, `EraseContact`, `ClaimReconciliation`,
  `TakeOverReconciliation`, `RenewReconciliation`, `FinishReconciliation`,
  `EnsureContact`, `SetContactSentBlacklisted`;
  the request consumer `brevo` (marketing); subscriptions to auth's
  `UserCreated`, `UserUpdated`, `UserDeleted`, `MarketingConsentChanged` (the
  last three optional).

| id | invariant | category | proof |
|---|---|---|---|
| `brevo/sent-once` | A record Brevo accepted MUST NOT be sent again when the stream redelivers its batch. A record MUST be recorded as sent only after Brevo answered for it. | Consistency & concurrency | `TestConsumeMarketing_SkipsWhatWasSentAndRecordsWhatIs`, `TestConsumeMarketing_ATransientFailureRecordsNothing`, `TestRecordSent_AnotherReplicaFirstIsTheSameOutcome`. **Unit (mock) only:** a live test would kill the bundle between Brevo's answer and the record and show at most one duplicate. |
| `brevo/transient-is-redelivered` | A network failure, 429 past its waits, 5xx, or a key or server address the account does not accept (401, 403) MUST fail the call so the stream redelivers it and, past the retries, dead-letters it for a replay; only a call Brevo refuses for its content (400, 422) MUST be dropped. | Failure & configuration | `TestConsumeMarketing_ATransientFailureRecordsNothing`, `TestConsumeMarketing_ARefusedEventIsNotRetried`, `TestContacts_RetryOnlyWhatMaySucceed`, `TestRetryable`, `TestRefused_OnlyWhatTheContentCauses`, `TestDo_GivesUpOnARateLimitThatDoesNotLift` |
| `brevo/selection` | `send` MUST choose by kind (a method reads when served as GET or a Query service's), `include` add, `exclude` remove and win. A configured method the stream does not record MUST fail the boot. | Failure & configuration | `TestConsumeMarketing_SendsWhatTheSelectionSays`, `TestNewSelection_RefusesWhatTheStreamDoesNotRecord` |
| `brevo/no-personal-extras` | An event MUST NOT carry the IP address, the user agent or the request's fields; an unknown consent MUST NOT be written as false. | Security | `TestEventFor` |
| `brevo/erasure` | `UserDeleted` MUST delete the contact and its history; a transient failure MUST be retried, a missing contact counts as deleted. The plugin's `Contact` row MUST lose the address, and a later event of the erased user MUST write nothing to Brevo. | Security | `TestContacts_FollowTheAccounts`, `TestContacts_RetryOnlyWhatMaySucceed`, `TestDeleteContact_AMissingContactIsDeleted`, `TestContacts_AnErasedUserIsNotWrittenAgain` |
| `brevo/blacklisted-without-consent` | Every contact write MUST send `emailBlacklisted: true` or leave it out, except one: `false` MUST be sent only while acting on a consent=true decision that is the newest the plugin keeps (`brevo/brevo-side-unsubscribe-stands`). `UserCreated` MUST create the contact blacklisted; a no MUST be written `true` in the same write as the consent attribute. An unknown consent MUST blacklist and MUST NOT be written as a false attribute. | Security | `TestContacts_ANewAccountIsBlacklisted`, `TestConsent_SetsEmailBlacklistedWithTheAttribute`, `TestContacts_FollowTheAccounts`, `TestContacts_ConsentBeforeTheContactCreatesIt`, `TestContactWrites_CarryEmailBlacklisted` |
| `brevo/address-change-keeps-subscription` | The last known consent, its time, a Brevo-side unsubscribe and the last `emailBlacklisted` written MUST be kept in `Contact`, before Brevo is written. The consent and unsubscribe writes MUST be conditional on being newer than what is kept, and the Brevo value MUST be derived from the row as stored after the write, never from a read before it: two deliveries at once, or two replicas, MUST NOT let an older decision decide. `UserCreated` / `UserUpdated` MUST derive the value from the row as stored: blacklisted without a consent, the field left out with one; a contact Brevo lacks MUST be created only (never overwritten if a yes created it meanwhile), and a yes landing while they blacklist MUST end subscribed. A no that lands while a yes is being written MUST win. A failure of the table MUST be retried, with nothing written to Brevo. | Consistency & concurrency | `TestContacts_AnAddressChangeNeverSubscribes`, `TestConsent_AnOlderDecisionDoesNotOverwriteANewerOne`, `TestConsent_AnOlderYesRacingANewerNoNeverSubscribes`, `TestConsent_ANoLandingDuringTheSubscribeWins`, `TestContacts_UserCreatedAroundTheYesKeepsItSubscribed`, `TestCreateContact_OnlyWhenThereIsNone`, `TestStub_ACreateOnlyLeavesAnExistingContact`, `TestContacts_AStateFailureIsRetried` |
| `brevo/brevo-side-unsubscribe-stands` | Every write of `true` MUST be recorded (`sent_blacklisted`) before Brevo is written. Before sending `false` the plugin MUST read the contact from Brevo, and re-read its row after that read; one Brevo blacklists while the plugin last left it subscribed is a person's unsubscribe in Brevo: it MUST be recorded (`unsubscribed_at`) and MUST NOT be undone — by an address change or a replayed consent — without the webhook. Only a consent decided after it subscribes again. | Security | `TestContacts_ABrevoSideUnsubscribeStandsWithoutTheWebhook`, `TestConsent_ASignUpLandingDuringTheSubscribeIsNotAnUnsubscribe`, `TestGetContact_ByTheUsersID` |
| `brevo/reconcile-once` | The contacts created before the plugin wrote `emailBlacklisted` MUST be blacklisted once per deployment when their user has not consented (the `Contact` row when the plugin knows the user, else the consent attribute). The pass MUST only blacklist, never subscribe; MUST touch only the plugin's contacts (an `EXT_ID` that is a user id); MUST repeat until a pass blacklists nothing while the account's count did not shrink (oldest-first offset paging skips a contact only when one is deleted mid-pass; sign-ups only add); MUST run in the background without holding up the boot, retried until done; MUST be recorded so neither a restart nor a second replica runs it again; and a claim not renewed within its lease MUST be taken over. | Consistency & concurrency | `TestReconcile_BlacklistsThePluginsContactsWithoutConsent`, `TestReconcile_ADeletionMidPassSkipsNobody`, `TestReconcile_SignUpsDuringThePassDoNotStopIt`, `TestReconcile_RunsOncePerDeployment`, `TestReconcile_SafeUnderSeveralReplicas`, `TestReconcile_InTheBackgroundUntilDone`, `TestListContacts_OldestFirstWithTheirExtID`. **Unit (mock) only:** the listing's `EXT_ID` attribute is what Brevo's reference documents as the ext_id identifier, not measured against an account. |
| `brevo/stub-keeps-blacklisted` | The `brevostub` sandbox MUST keep and answer `emailBlacklisted` as Brevo does: subscribed on a create that does not name it, blacklisted for a contact an event creates, set by a write that names it, read by `GET /v3/contacts/{id}`, listed by `GET /v3/contacts`; `POST /_stub/contacts/{ext_id}/unsubscribe` unsubscribes the person as Brevo would. | Failure & configuration | `TestStub_KeepsEmailBlacklisted`, `TestStub_AnswersOneContactAndAnUnsubscribe` |
| `brevo/rate` | Requests MUST leave at most `brevo_rps` per second; a 429 MUST be waited out as `x-sib-ratelimit-reset` says. | Performance | `TestPace_SpacesTheRequests`, `TestDo_WaitsOutARateLimit` |
| `brevo/contact-write` | A contact MUST be written by its `ext_id` (PUT), and created only when Brevo has none; an address change MUST reach Brevo. | Consistency & concurrency | `TestContacts_FollowTheAccounts`, `TestContacts_ConsentBeforeTheContactCreatesIt`, `TestUpdateContact_ByTheUsersID` |
| `brevo/attributes` | The consent attribute MUST exist in the account before it is written, created without holding up the bundle's boot. | Failure & configuration | `TestEnsureAttributes`, `TestEnsureAttribute_AnExistingOneIsFine` |
| `brevo/request-context-on-the-event` | The organization a request acted in and the caller's account type there MUST go on that request's event (`w17_org_id`, `w17_account_type`), each only when the record carries it, and MUST NOT be written to the contact, which is the person and not the request. | Consistency & concurrency | `TestEventFor` |
| `brevo/batch-limits` | A batch MUST hold at most 200 events and 512 KB. | Failure & configuration | `TestConsumeMarketing_SplitsAtTheBatchLimit`, `TestSendEvents_RefusesWhatBrevoWould` |

### brevo_webhook

- **Purpose.** An unsubscribe in Brevo carried back into the project as the
  user's withdrawal of their marketing consent.
- **Adds.** `MarketingService.IngestBrevo` on the REST surface (`POST
  /marketing/webhooks/brevo`, no bearer, `X-Brevo-Webhook-Token` forwarded);
  env `brevo_webhook_token`; the required hook `consent_withdrawn`, bound to a
  business method of the domain that calls auth's
  `AuthService.WithdrawMarketingConsent` (plugins do not call each other).

| id | invariant | category | proof |
|---|---|---|---|
| `brevo_webhook/authenticated` | A call MUST be refused (`Unauthenticated`) without the configured token, with another one, and every call while none is configured; nothing MUST be recorded then. The token MUST be compared in constant time. | Security | `TestIngestBrevo_RefusesWithoutTheToken` |
| `brevo_webhook/unsubscribe-writes-back` | An `unsubscribe` event MUST record `unsubscribed_at` (Brevo's time) on the `Contact` of every user with that address and call the `consent_withdrawn` hook for each; other events, unknown addresses and erased users MUST be acknowledged without effect. A failed hook MUST fail the delivery (`Unavailable`) with the unsubscribe kept, so Brevo's redelivery writes it back; a batched delivery MUST be read whole. An unsubscribe older than the consent kept (late, redelivered) MUST NOT be written back. | Consistency & concurrency | `TestIngestBrevo_AnUnsubscribeIsWrittenBack`, `TestIngestBrevo_ABatchAndWhatItIgnores`, `TestIngestBrevo_AFailedWriteBackIsRedelivered`, `TestIngestBrevo_ALateUnsubscribeDoesNotCancelANewerConsent`; auth's side: `marketing_consent/withdraw-only` |

**Gaps / suspected defects**

1. **The request's fields are not sent.** The consumer runs in the storage
   bundle, which does not link the project's business services, so their
   requests arrive undecoded; linking them there is platform work.
2. **The write-back needs the project's method.** Plugins talk through events
   and hooks only, so the `consent_withdrawn` hook is bound to a business
   method the project writes (a few lines calling auth's
   `WithdrawMarketingConsent`); no live test covers that hop yet.
3. **An unsubscribe for an address the plugin never kept** (a user whose last
   auth event predates the `Contact` table) is acknowledged and not written
   back: Brevo's webhook names only the address. Brevo still blacklists the
   contact itself, and the reconciliation blacklists it too without a consent.
4. **Without the webhook, an unsubscribe in Brevo is noticed late**: at the
   next consent=true the plugin acts on, which then records it instead of
   subscribing (at the time it noticed it). A consent decided after that
   subscribes again.
5. **A yes and a no landing within one Brevo round trip** can leave Brevo
   subscribed for that round trip: the yes re-reads its row after writing and
   blacklists again when a no overtook it.

## Measured against a Brevo account

The client (`lib/brevo`) was run against a real account, with throwaway data
deleted afterwards. What it showed, and what the plugin does about it:

- **An event for an `ext_id` Brevo does not know creates the contact** (no
  email, `emailBlacklisted: true`): an event may arrive before the contact.
- **An address cannot change by upsert.** `POST /contacts` with a known `ext_id`
  and another email is refused, `400 duplicate_parameter` ("ext_id is already
  associated with another Contact"). The plugin writes a contact by
  `PUT /contacts/{ext_id}?identifierType=ext_id` (`EMAIL` among the attributes)
  and creates it by `POST` only when that answers 404 (`brevo/contact-write`).
- **An attribute the account has not created is dropped silently** — on an
  upsert and in an event's `contact_properties`. The plugin creates its one
  (`brevo_consent_attribute`, boolean) in the background, retrying until Brevo
  has it (`brevo/attributes`). Event properties need no declaration.
- **Authorised IPs**: an account that lists addresses answers `401
  "unrecognised IP address"` to any other, IPv4 and IPv6 separately. The call
  fails and is kept for a replay (`brevo/transient-is-redelivered`).
- **Rate limits as documented**: `/events` 10 per second, `/contacts` 20 on that
  account, both reported in `x-sib-ratelimit-*`.
- A batch with an invalid event name answers `207 partiallyQueued` with its index.

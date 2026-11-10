# marketing — behaviour specification

What the `marketing` plugin does and what it must never do. It covers plugin
version 0.1.0-rc.6 and the unreleased changes in `changes/`. Ids are `<feature>/<name>`; a property without a proof is a
gap, not a promise. The handler tests run against a fake Brevo and in-memory
`SentEvent`, `Contact`, `Reconciliation` and `Activity` tables; the client tests
(`lib/brevo`) against an HTTP stub of the Brevo API.

## Features

| feature | default | requires | conflicts with |
|---|---|---|---|
| `brevo` | off | — (plugin requires `auth`) | — |
| `brevo_events` | off | `brevo` | — |
| `brevo_attributes` | off | `brevo` | — |
| `brevo_webhook` | off | `brevo` | — |

## Per feature

### brevo

- **Purpose.** The contacts following auth's accounts, consent and erasure;
  the gateway's marketing records reaching them through `brevo_events`,
  `brevo_attributes` or both.
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
| `brevo/sent-once` | A record Brevo accepted MUST NOT be sent again when the stream redelivers its batch. A record MUST be recorded as sent only after Brevo answered for it, and every record of a chunk Brevo answered MUST be recorded whatever happens to another's record (each tried 3 times): only a record whose own recording failed is sent again, never the rest of its chunk. A sent record is remembered for 72 h (`sentRetention`, far past the stream's redeliveries); a dead-letter replay later than that sends its records again. | Consistency & concurrency | `TestConsumeMarketing_SkipsWhatWasSentAndRecordsWhatIs`, `TestConsumeMarketing_ATransientFailureRecordsNothing`, `TestRecordSent_AnotherReplicaFirstIsTheSameOutcome`, `TestConsumeMarketing_AFailedRecordResendsOnlyItself`. **Unit (mock) only:** a live test would kill the bundle between Brevo's answer and the record and show the duplicates bounded by the records not yet recorded. |
| `brevo/transient-is-redelivered` | A network failure, 429 past its waits, 5xx, or a key or server address the account does not accept (401, 403) MUST fail the call so the stream redelivers it and, past the retries, dead-letters it for a replay; only a call Brevo refuses for its content (400, 422) MUST be dropped, and a dropped contact write MUST be reported through the bundle's error reporter (observx: Sentry and the trace when configured), not only logged — the contact then lacks what it carried (gap 7). | Failure & configuration | `TestConsumeMarketing_ATransientFailureRecordsNothing`, `TestConsumeMarketing_ARefusedEventIsNotRetried`, `TestContacts_RetryOnlyWhatMaySucceed`, `TestContacts_ARefusedContactWriteIsReported`, `TestRetryable`, `TestRefused_OnlyWhatTheContentCauses`, `TestDo_GivesUpOnARateLimitThatDoesNotLift` |
| `brevo/selection` | `send` MUST choose by kind (a method reads when served as GET or a Query service's), `include` add, `exclude` remove and win. A configured method the stream does not record MUST fail the boot. | Failure & configuration | `TestConsumeMarketing_SendsWhatTheSelectionSays`, `TestNewSelection_RefusesWhatTheStreamDoesNotRecord` |
| `brevo/no-personal-extras` | An event MUST NOT carry the IP address, the user agent or the request's fields; an unknown consent MUST NOT be written as false. | Security | `TestEventFor` |
| `brevo/consent-from-the-row` | An event MUST NOT write to the contact (no `contact_properties`): the consent attribute MUST be written only from the `Contact` row as stored, with the day it was decided. A record's consent is its request's snapshot (taken at its authentication, which the gateway caches for minutes); a record delivered after the user's decision — a backlog, a redelivery, a dead-letter replay — MUST NOT move the attribute back. | Consistency & concurrency | `TestEventFor`, `TestEventFor_WritesNothingToTheContact` |
| `brevo/erasure` | `UserDeleted` MUST delete the contact and its history; a transient failure MUST be retried, a missing contact counts as deleted. The plugin's `Contact` row MUST lose the address, and a later event of the erased user — an auth event, or a marketing record late in the stream, redelivered or replayed — MUST write nothing to Brevo: every path that writes to Brevo (events, attributes, contacts) MUST check the row first, since an event alone creates the contact again and an update of a deleted contact falls back to creating it. An erasure that lands while such a write is in flight MUST NOT be undone by it: the row is read again after the write, and a contact written for a user erased meanwhile MUST be deleted again (`UserDeleted` records the erasure before it deletes, so one of the two deletes comes last). | Security | `TestContacts_FollowTheAccounts`, `TestContacts_RetryOnlyWhatMaySucceed`, `TestDeleteContact_AMissingContactIsDeleted`, `TestContacts_AnErasedUserIsNotWrittenAgain`, `TestConsumeMarketing_AnErasedUsersRecordSendsNoEvent`, `TestConsumeMarketing_AnErasureDuringTheSendIsNotUndone`, `TestContacts_AnErasureDuringTheWriteIsNotUndone` |
| `brevo/blacklisted-without-consent` | Every contact write MUST send `emailBlacklisted: true` or leave it out, except one: `false` MUST be sent only while acting on a consent=true decision that is the newest the plugin keeps (`brevo/brevo-side-unsubscribe-stands`). `UserCreated` MUST create the contact blacklisted; a no MUST be written `true` in the same write as the consent attribute. An unknown consent MUST blacklist and MUST NOT be written as a false attribute. | Security | `TestContacts_ANewAccountIsBlacklisted`, `TestConsent_SetsEmailBlacklistedWithTheAttribute`, `TestContacts_FollowTheAccounts`, `TestContacts_ConsentBeforeTheContactCreatesIt`, `TestContactWrites_CarryEmailBlacklisted` |
| `brevo/address-change-keeps-subscription` | The last known consent, its time, a Brevo-side unsubscribe and the last `emailBlacklisted` written MUST be kept in `Contact`, before Brevo is written. The consent and unsubscribe writes MUST be conditional on being newer than what is kept, and the Brevo value MUST be derived from the row as stored after the write, never from a read before it: two deliveries at once, or two replicas, MUST NOT let an older decision decide. `UserCreated` / `UserUpdated` MUST derive the value from the row as stored: blacklisted without a consent, the field left out with one; a contact Brevo lacks MUST be created only (never overwritten if a yes created it meanwhile), and a yes landing while they blacklist MUST end subscribed. A no that lands while a yes is being written MUST win. A failure of the table MUST be retried, with nothing written to Brevo. | Consistency & concurrency | `TestContacts_AnAddressChangeNeverSubscribes`, `TestConsent_AnOlderDecisionDoesNotOverwriteANewerOne`, `TestConsent_AnOlderYesRacingANewerNoNeverSubscribes`, `TestConsent_ANoLandingDuringTheSubscribeWins`, `TestContacts_UserCreatedAroundTheYesKeepsItSubscribed`, `TestCreateContact_OnlyWhenThereIsNone`, `TestStub_ACreateOnlyLeavesAnExistingContact`, `TestContacts_AStateFailureIsRetried` |
| `brevo/brevo-side-unsubscribe-stands` | Every write of `true` MUST be recorded (`sent_blacklisted`) before Brevo is written, and a `Contact` row the plugin creates MUST start `sent_blacklisted` (a contact the plugin has not subscribed is blacklisted — by its own writes, or by Brevo, which creates an event's contact blacklisted), so `sent_blacklisted = false` means the plugin subscribed the contact. Before sending `false` the plugin MUST read the contact from Brevo, and re-read its row after that read; one Brevo blacklists while the plugin last left it subscribed is a person's unsubscribe in Brevo: it MUST be recorded (`unsubscribed_at`) and MUST NOT be undone — by an address change or a replayed consent — without the webhook. Only a consent decided after it subscribes again. A blacklist on a contact the plugin never subscribed (one an event created for an account older than the activation, or whose `UserCreated` came late) MUST NOT be taken for an unsubscribe: the user's yes subscribes it. | Security | `TestContacts_ABrevoSideUnsubscribeStandsWithoutTheWebhook`, `TestConsent_ASignUpLandingDuringTheSubscribeIsNotAnUnsubscribe`, `TestConsent_AContactAnEventCreatedIsNotAPersonsUnsubscribe`, `TestContactStatements_ANewRowStartsBlacklisted`, `TestGetContact_ByTheUsersID` |
| `brevo/reconcile-once` | The contacts created before the plugin wrote `emailBlacklisted` MUST be blacklisted once per deployment when their user has not consented (the `Contact` row when the plugin knows the user, else the consent attribute). The pass MUST only blacklist, never subscribe on its own reading — but a yes handled between its read of the rows and its write MUST stand: the pass records its blacklisting before writing it, reads the row again after, and a row holding the newest yes subscribes the contact on that yes (`brevo/address-change-keeps-subscription`); MUST touch only the plugin's contacts (an `EXT_ID` that is a user id); MUST repeat until a pass blacklists nothing while the account's count did not shrink (oldest-first offset paging skips a contact only when one is deleted mid-pass; sign-ups only add); MUST run in the background without holding up the boot, retried until done; MUST be recorded so neither a restart nor a second replica runs it again; and a claim not renewed within its lease MUST be taken over. | Consistency & concurrency | `TestReconcile_BlacklistsThePluginsContactsWithoutConsent`, `TestReconcile_ADeletionMidPassSkipsNobody`, `TestReconcile_SignUpsDuringThePassDoNotStopIt`, `TestReconcile_RunsOncePerDeployment`, `TestReconcile_SafeUnderSeveralReplicas`, `TestReconcile_InTheBackgroundUntilDone`, `TestReconcile_AConsentLandingDuringThePassStandsSubscribed`, `TestListContacts_OldestFirstWithTheirExtID`. **Unit (mock) only:** the listing's `EXT_ID` attribute is what Brevo's reference documents as the ext_id identifier, not measured against an account. |
| `brevo/stub-keeps-blacklisted` | The `brevostub` sandbox MUST keep and answer `emailBlacklisted` as Brevo does: subscribed on a create that does not name it, blacklisted for a contact an event creates, set by a write that names it, read by `GET /v3/contacts/{id}`, listed by `GET /v3/contacts`; `POST /_stub/contacts/{ext_id}/unsubscribe` unsubscribes the person as Brevo would. | Failure & configuration | `TestStub_KeepsEmailBlacklisted`, `TestStub_AnswersOneContactAndAnUnsubscribe` |
| `brevo/rate` | Requests MUST leave at most `brevo_rps` per second; a 429 MUST be waited out as `x-sib-ratelimit-reset` says. | Performance | `TestPace_SpacesTheRequests`, `TestDo_WaitsOutARateLimit` |
| `brevo/contact-write` | A contact MUST be written by its `ext_id` (PUT), and created only when Brevo has none; an address change MUST reach Brevo. | Consistency & concurrency | `TestContacts_FollowTheAccounts`, `TestContacts_ConsentBeforeTheContactCreatesIt`, `TestUpdateContact_ByTheUsersID` |
| `brevo/attributes` | Every attribute the plugin writes MUST be created in the account — the consent, the two dates, and with `brevo_attributes` one per method the selection sends and the last activity's time — each retried until Brevo has it and not asked for again once it does. The three the auth events write (the consent, `W17_MARKETING_CONSENT_AT`, `W17_SIGNED_UP_AT`) MUST be created before the plugin subscribes to anything, waiting at most 5 s for Brevo (an attribute Brevo lacks is dropped silently, and the sign-up date is written once); the rest, and any of the three Brevo did not create in time, MUST be created in the background without holding up the boot. | Failure & configuration | `TestEnsureAttributes`, `TestEnsureAttributes_RetriesOnlyWhatFailed`, `TestEnsureAttribute_AnExistingOneIsFine`, `TestPrepareAttributes_TheFixedOnesBeforeItReturns`, `TestPrepareAttributes_AnUnansweringBrevoHoldsTheBootForTheBoundOnly` |
| `brevo/dated-contact` | A contact MUST carry the day its account was created (`W17_SIGNED_UP_AT`, from `UserCreated.created_at`) and, with every write of the consent attribute, the day that consent was decided (`W17_MARKETING_CONSENT_AT`); dates MUST be Brevo dates (`YYYY-MM-DD`). | Consistency & concurrency | `TestContacts_CarryTheSignUpDate`, `TestConsent_SetsEmailBlacklistedWithTheAttribute`, `TestContacts_FollowTheAccounts`, `TestStub_RefusesAMalformedDate` |
| `brevo/events-by-default` | Records MUST be sent as events with `brevo_events`, and with neither `brevo_events` nor `brevo_attributes` (what `brevo` did before the choice existed); with `brevo_attributes` alone no event MUST be sent. | Failure & configuration | `TestSendsEvents`, `TestActivity_AttributesOnlyMoveTheDatesAndSendNoEvent` |
| `brevo/request-context-on-the-event` | The organization a request acted in and the caller's account type there MUST go on that request's event (`w17_org_id`, `w17_account_type`), each only when the record carries it, and MUST NOT be written to the contact, which is the person and not the request. | Consistency & concurrency | `TestEventFor` |
| `brevo/batch-limits` | A batch MUST hold at most 200 events and 512 KB. | Failure & configuration | `TestConsumeMarketing_SplitsAtTheBatchLimit`, `TestSendEvents_RefusesWhatBrevoWould` |

### brevo_events

- **Purpose.** Each marketing record as a Brevo event on the user's contact:
  what `brevo` alone did before 0.1.0-rc.6.
- **Adds.** Nothing of its own: the request consumer sends events when it is
  on; `SentEvent` and its rpcs are `brevo`'s. The `brevo/sent-once`,
  `brevo/no-personal-extras`, `brevo/request-context-on-the-event` and
  `brevo/batch-limits` invariants are its behaviour.

### brevo_attributes

- **Purpose.** Each marketing record moving a date attribute on the user's
  contact, the shape Brevo's automations and segments start from.
- **Adds.** Table `Activity` (each user's last date per attribute);
  `MarketingQuery.ListActivity`; `MarketingMutation.RecordActivity`,
  `BumpActivity`, `EraseActivity`.

| id | invariant | category | proof |
|---|---|---|---|
| `brevo_attributes/date-per-method` | A record the selection sends MUST move `W17_<SERVICE>_<METHOD>` to the day the user made it and `W17_LAST_ACTIVITY_AT` to the exact time of their latest recorded request (ISO 8601 text); without `brevo_events` no event MUST be sent. A contact Brevo lacks MUST be created blacklisted. | Consistency & concurrency | `TestActivity_AttributesOnlyMoveTheDatesAndSendNoEvent`, `TestActivity_BothWriteTheAttributesAndSendTheEvents`, `TestActivity_FollowsTheSelection`, `TestActivityAttr` |
| `brevo_attributes/never-back` | A date MUST only move forward: the row is moved by a write conditional on being later, and Brevo is written from the rows as stored; a row moved while the contact is written MUST be written again, so the last write is the newest. | Consistency & concurrency | `TestActivity_AnOlderRecordDoesNotMoveADateBack`, `TestActivity_ARowMovedDuringTheWriteIsWrittenAgain` |
| `brevo_attributes/transient-is-redelivered` | A failure of the table or of Brevo MUST fail the batch before any event of it is sent; the attributes are written first because writing them again changes nothing. | Failure & configuration | `TestActivity_AFailureSendsNoEventAndIsRedelivered`, `TestActivity_ATableFailureWritesNothing` |
| `brevo_attributes/erasure` | `UserDeleted` MUST delete the user's `Activity` rows, and a late record of an erased user MUST write nothing; rows a record wrote while the erasure landed MUST be deleted again with the contact (`brevo/erasure`). | Security | `TestActivity_AnErasedUserIsNotWrittenAndForgotten`, `TestConsumeMarketing_AnErasureDuringTheSendIsNotUndone` |

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
| `brevo_webhook/unsubscribe-writes-back` | An `unsubscribe` event MUST record `unsubscribed_at` (Brevo's time, never later than now: a future `ts_event` is dated now) on the `Contact` of every user with that address and call the `consent_withdrawn` hook for each; other events, unknown addresses and erased users MUST be acknowledged without effect. A failed hook MUST fail the delivery (`Unavailable`) with the unsubscribe kept, so Brevo's redelivery writes it back; a batched delivery MUST be read whole. An unsubscribe older than the consent kept (late, redelivered) MUST NOT be written back. | Consistency & concurrency | `TestIngestBrevo_AnUnsubscribeIsWrittenBack`, `TestIngestBrevo_ABatchAndWhatItIgnores`, `TestIngestBrevo_AFailedWriteBackIsRedelivered`, `TestIngestBrevo_ALateUnsubscribeDoesNotCancelANewerConsent`, `TestIngestBrevo_AFutureUnsubscribeIsDatedNow`; auth's side: `marketing_consent/withdraw-only` |

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
6. **`brevo_attributes` is not measured against an account yet.** The date
   format (`YYYY-MM-DD`), the `text` type of `W17_LAST_ACTIVITY_AT` and the
   attribute names (`W17_<SERVICE>_<METHOD>`, up to 255 characters) follow
   Brevo's reference; the stub refuses a malformed date, which is what Brevo
   is expected to do and not measured. Brevo's limits on an attribute name's length and on how many
   attributes an account may hold are not documented there: a name it refuses
   is logged at boot and retried, and that method's dates are dropped by Brevo
   until it exists.
7. **The sign-up date is written once.** `W17_SIGNED_UP_AT` (and, until the
   next `UserUpdated`, the address) is written only by `UserCreated`'s
   contact write. When Brevo refuses that write for its content (400/422:
   an address another contact in the account already holds, an address its
   own syntax check refuses) the write is dropped and reported
   (`brevo/transient-is-redelivered`), and no later write carries the date:
   the `Contact` row does not keep the account's creation time, and keeping
   it would need a new column. The address follows the next `UserUpdated`.


**Fixed**

1. **A late record of an erased user re-created their contact.** The records
   path (`ConsumeMarketing`) checked erasure only for the attributes, never
   before sending events, and an event for an unknown `ext_id` creates the
   contact (measured): a record in a backlog, redelivered, or replayed from the
   dead-letter stream after `UserDeleted` brought the erased user back into
   Brevo, keyed by their user id. Now every Brevo write path checks the row
   before it writes and again after (`brevo/erasure`).
2. **A contact an event created was taken for a person's unsubscribe.** A
   blacklisted contact whose row said `sent_blacklisted = false` was read as
   "the person unsubscribed in Brevo", but a row the consent handler had just
   created said false too, and an event creates the contact blacklisted: the
   first yes of a user whose contact only events had created (an account
   older than the activation, a late `UserCreated`) was recorded as an
   unsubscribe and never honoured. A new row now starts `sent_blacklisted`
   (`brevo/brevo-side-unsubscribe-stands`).
3. **Events wrote the consent attribute from the request's snapshot.** Each
   event carried `contact_properties: {<consent attribute>: <consent at the
   request>}`, undated and bypassing the `Contact` row, so a record delivered
   after a withdrawal set the attribute back to true. Events now write nothing
   to the contact (`brevo/consent-from-the-row`).

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

### An erased user's late record no longer brings their contact back

A marketing record of a user the plugin holds erased is dropped before anything reaches Brevo, with `brevo_events`, `brevo_attributes` or both; before, a record late in the stream, redelivered or replayed from the dead-letter stream sent an event, and the event re-created the deleted contact (Brevo creates the contact of an unknown `ext_id`). Every path that writes to Brevo — records and auth events alike — also reads the row again after its write and deletes the contact again (and the activity rows) when an erasure landed meanwhile.

### A contact only events created is subscribed by the user's yes

A `Contact` row the plugin creates (`EnsureContact`, `SetContactEmail`) now starts `sent_blacklisted`. Before, a user whose contact existed in Brevo only because events had created it (blacklisted) — an account older than the activation, or one whose `UserCreated` came late — had their first consent `true` recorded as an unsubscribe made in Brevo and was never subscribed. A row created by an earlier version for such a user keeps that recorded unsubscribe; a consent decided after it subscribes as before.

### Events no longer write the consent attribute

An event carries no `contact_properties`. It used to carry the consent attribute as the request saw it (its authentication, cached for minutes), undated and bypassing the `Contact` row, so a record delivered after the user's decision moved the attribute back. The attribute is written only by the consent handler, from the row, with `W17_MARKETING_CONSENT_AT`.

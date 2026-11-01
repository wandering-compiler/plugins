### `DeleteRelay` ends a relay instead of deleting it; `Worker.relay_id` is a foreign key

`RelayMutation.DeleteRelay` keeps its name and its request (callers, and the Relays page's delete, need no change), but it no longer deletes the row: it **ends** the relay — `Relay.removed_at` is stamped and the new `Relay.ended_key` takes the row's own id. The row stays, with its name, address, pin and observed state, as the record of what was registered. Ending an ended or unknown relay changes nothing and is not an error, as deleting a missing row was not.

An ended relay is invisible to every read: `ListRelays` (both forms) and `GetRelay` read live relays only, so placement, the worker sweep, reservations (a handle naming an ended relay polls as `expired`), registration codes, drain, the ban delivery and the admin pages never see it. `UpdateRelay`, `RecordRelayReached` and `RecordRelayFailed` write live relays only.

`RecordWorker` files a worker only under a live relay: a relay ended between the sweep's relay list and the write is refused (`InvalidArgument`, `RELAY_ENDED`, on `relay_id`), and the sweep reports that relay as failed rather than each of its workers as refused.

**Registering a relay again** under the name of an ended one creates a new row with a new id; the ended row is never revived. `Relay.name` is now unique together with `ended_key` (`''` on every live row) instead of on its own, so two live relays still cannot share a name. Workers recorded under the old id keep pointing at the ended row until the next "Check for workers" files them under the new one.

**`Worker.relay_id` is a foreign key** to the activation's `Relay` (`fk: "@module.Relay"`), `ON DELETE RESTRICT` (`deletion_rule: BLOCK`). A worker recorded for a relay id that does not exist is refused instead of stored.

The deploy block follows: `register` upserts on `(name, ended_key)` and `unregister_sql` ends the row `local` instead of deleting it. **A seed or script of your own that upserts relays with `ON CONFLICT (name)` must now name `(name, ended_key)`** — the single-column unique index is gone, and Postgres refuses a conflict target no unique index matches.

**Before you deploy it.** The foreign key is added over existing rows, and a database whose relays were deleted before this release holds `Worker` rows naming relays that no longer exist. Adding the key over them needs the w17 platform release that adds a foreign key over existing rows `NOT VALID` and reports the orphans (`migrate apply --checks`) instead of failing the migration (platform pull request #617); do not apply this version with an older one. Repaired, the key can be validated (`ALTER TABLE … VALIDATE CONSTRAINT`). To repair the orphans without deleting anything, give each missing relay a row that is already ended (table names are `<registered_as>_<model>`; `codegen` here):

```sql
INSERT INTO codegen_relay (id, name, url, cert_fingerprint, enabled, removed_at, ended_key, last_error)
SELECT DISTINCT w.relay_id, 'missing-' || w.relay_id, 'missing:1', repeat('0', 64), false, NOW(), w.relay_id::text, ''
FROM codegen_worker w
WHERE NOT EXISTS (SELECT 1 FROM codegen_relay r WHERE r.id = w.relay_id);
```

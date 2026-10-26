### Seeding an approved envelope by fixture is documented

- `SPEC.md` gains "Seeding an approved envelope". It gives the fixture shape of an approved envelope: `status: "approved"`, `approved_slot: "approved"`, `decided_at`. It also says how to replace a seeded envelope: the previous one becomes `superseded` with `approved_slot` null, written before the new one. A fixture is re-applied on every deploy, so once the backoffice approves a newer envelope for a seeded organization, change the seeded row to `superseded` too, or the next apply is refused. These values are now a public contract: what a fixture writes.
- The handlers name them `StatusProposed`, `StatusApproved`, `StatusRejected`, `StatusSuperseded` and `ApprovedSlot`. A test holds the plugin's own statements to them.

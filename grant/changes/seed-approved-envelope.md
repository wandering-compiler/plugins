### Seeding an approved envelope by fixture is documented

- `SPEC.md` gains "Seeding an approved envelope". It gives the fixture shape of an approved envelope: `status: "approved"`, `approved_slot: "approved"`, `decided_at`. It also says how to replace a seeded envelope: the previous one becomes `superseded` with no `approved_slot`. These values are now a public contract.
- The handlers export them as `StatusProposed`, `StatusApproved`, `StatusRejected`, `StatusSuperseded` and `ApprovedSlot`. A test holds the plugin's own statements to them.

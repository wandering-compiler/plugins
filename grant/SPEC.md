# grant plugin — specification

What an organization shows before a person trusts it, approved by the
platform: its **envelope** — name, logos, verified host, links, colour,
language, operator — on the OAuth consent page, an invitation and sign-in on a
co-brand host. The organization proposes, the backoffice approves or rejects,
and only an approved envelope is ever read — a self-declared one would lend
another organization's name and logo to whoever typed them.

The hosts an organization is presented on are the auth plugin's `org_hosts`
feature: a host decides the organization a request acts in, which
Authenticate enforces, so the binding lives where it is enforced. A page on a
co-brand host asks the auth plugin which organization the host serves
(`GET /auth/hosts/{host}`) and then reads its envelope here.

The packages an organization is given (what its members can hold) are the
auth plugin's `org_packages` feature, which enforces them on every request.

## Surface

| method | who | REST |
|---|---|---|
| `ProposeEnvelope`, `GetMyEnvelopes` | a member, acting in the organization | `POST` / `GET /grant/orgs/{org}/envelopes` |
| `ListEnvelopeProposals`, `ApproveEnvelope`, `RejectEnvelope` | the backoffice, realm-wide | `GET /grant/admin/envelopes`, `POST …/{id}/approve`, `POST …/{id}/reject` |
| `GetOrgEnvelope` | anyone (unauthenticated, limited per address) | `GET /grant/envelopes/orgs/{org_id}` |

Which members and which operators may call a method is the project's endpoint
ACL.

| id | invariant | category | proof |
|---|---|---|---|
| grant/approved-only | Only an APPROVED envelope MUST be readable publicly; a proposal or a rejected one never is. | Security | `TestEnvelopeLifecycle` |
| grant/realm-decides | Approving and rejecting MUST be refused to a request acting inside an organization, unless its credential holds the method realm-wide (the auth plugin's `realm_permissions` scope: `*`, or the method's permission id): the backoffice may also be a member of an organization. | Security | `TestEnvelopeLifecycle`, `TestEnvelopeDecisions_TheBackofficeFromInsideAnOrganization`; live: `examples/grant-proof` |
| grant/one-approved | Approving a version MUST supersede the organization's previous approved one in the same transaction, and a unique index on `(org_id, approved_slot)` MUST keep two racing approvals from both committing (the loser is `Aborted`), on every dialect; nothing is deleted. | Data | `TestEnvelopeLifecycle`, `TestApproveEnvelopeRace`, the `Envelope` index |
| grant/acl-required | The backoffice's methods MUST be refused unless they are in the deployed ACL lock. | Security | `TestRealmOnlyNeedsTheACL` |
| grant/seed-contract | A fixture that writes `status = 'approved'` and `approved_slot = 'approved'` MUST be the organization's approved envelope, read publicly and held to one per organization, exactly as an approval leaves it. | Data | `TestEnvelopeStatementsUseTheContractValues` (the values only: it holds the statements and the index to them; that a seeded row is read and that the index refuses a second one is **unit (mock) only** — a live test seeds an approved envelope, reads it with `GetOrgEnvelope`, and asserts a second seeded approved row for the organization is refused) |
| grant/safe-fields | Links MUST be absolute https (http only for localhost) without credentials; a colour #rrggbb; a host a lower-case DNS name. A proposal breaking a rule MUST be refused, and the public read MUST serve no field of an approved envelope that breaks one (a row seeded by fixture is checked nowhere else): the field is left out, the envelope stays. | Security | `TestCheckFields`, `TestGetOrgEnvelope_LeavesOutAFieldThatBreaksTheRules` |

## Seeding an approved envelope

The backoffice decides an envelope by approving a proposal. A project that
decides it at deploy time instead, with a fixture (an organization the
deployment itself creates), writes the row exactly as `ApproveEnvelope`
leaves it. A fixture file (`fixtures/<domain>/<name>.json`, in the domain the
plugin is activated in) is a JSON array of rows:

```json
[
  {
    "model": "grant.Envelope",
    "pk": ["<uuid>"],
    "fields": {
      "org_id": "<the organization>",
      "status": "approved",
      "approved_slot": "approved",
      "display_name": "Acme",
      "decided_at": "2026-10-26T00:00:00Z"
    }
  }
]
```

(`grant` is the activation's name; use yours.)

- `status: "approved"` is what the public read (`GetOrgEnvelope`) shows, and
  `approved_slot: "approved"` is what the unique `(org_id, approved_slot)`
  index holds to one per organization. Both are required: a row approved
  without the slot is shown, but escapes the one-approved rule.
- `decided_by` is left out (NULL: no operator decided it); an empty string
  is not a UUID and the row is refused. `decided_at` is set.
- One per organization. To replace a seeded envelope, write the previous one
  with `status: "superseded"` and `"approved_slot": null` — what an approval
  does to its predecessor — and the new one as above, both in the SAME
  fixture file. Rows of one model are written in file order and the index is
  checked per statement, so the superseded row comes FIRST: the other way
  round, the new row meets the old one still holding the slot and the apply
  is refused. Across files the order is the files' names, not the rows'
  meaning.
- A fixture is re-applied on every deploy (an upsert by `pk`), so it keeps
  writing what it says. Once the backoffice approves a newer proposal for a
  seeded organization (which supersedes the seeded row), the next apply would
  make the seeded row approved again and is refused by the index — and the
  whole group with it. Decide a seeded organization's envelope in one place:
  either the fixture alone, or, after the first approval by the backoffice,
  change the seeded row in the fixture to `superseded` with
  `"approved_slot": null`.
- The other fields are not checked when the fixture is applied: a proposal
  is held to `grant/safe-fields` (links absolute https, a colour `#rrggbb`, a
  host a lower-case DNS name) when it is written. The public read holds a
  seeded row to the same rules and leaves out any field that breaks one, so a
  bad link is simply missing from the page — keep to the rules.

The VALUES are the public contract — what a fixture writes. The handlers
name them (`StatusApproved`, `ApprovedSlot`, `StatusSuperseded` in
`src/handlers`; a project cannot import them, the handlers are staged into
it), and `TestEnvelopeStatementsUseTheContractValues` holds the plugin's own
statements to them.

## Gaps

1. The verified host is the organization's claim until the backoffice approves the version; nothing checks DNS.
2. The envelope of a host is two reads — the auth plugin's host binding, then the organization's envelope here.

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
| grant/realm-decides | Approving and rejecting MUST be refused to a request acting inside an organization. | Security | `TestEnvelopeLifecycle` |
| grant/one-approved | Approving a version MUST supersede the organization's previous approved one in the same transaction, and a unique index on `(org_id, approved_slot)` MUST keep two racing approvals from both committing (the loser is `Aborted`), on every dialect; nothing is deleted. | Data | `TestEnvelopeLifecycle`, `TestApproveEnvelopeRace`, the `Envelope` index |
| grant/acl-required | The backoffice's methods MUST be refused unless they are in the deployed ACL lock. | Security | `TestRealmOnlyNeedsTheACL` |
| grant/safe-fields | Links MUST be absolute https (http only for localhost) without credentials; a colour #rrggbb; a host a lower-case DNS name. | Security | `TestCheckFields` |

## Gaps

1. The verified host is the organization's claim until the backoffice approves the version; nothing checks DNS.
2. The envelope of a host is two reads — the auth plugin's host binding, then the organization's envelope here.

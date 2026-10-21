# grant plugin — specification

What an organization shows before a person trusts it, approved by the
platform: its **envelope** — name, logos, verified host, links, colour,
language, operator — on the OAuth consent page, an invitation and sign-in on a
co-brand host; and the **co-brand hosts** bound to the organization they
present. The organization proposes, the backoffice approves or rejects, and
only an approved envelope is ever read — a self-declared one would lend
another organization's name and logo to whoever typed them.

The packages an organization is given (what its members can hold) are the
auth plugin's `org_packages` feature, which enforces them on every request.

## Surface

| method | who | REST |
|---|---|---|
| `ProposeEnvelope`, `GetMyEnvelopes` | a member, acting in the organization | `POST` / `GET /grant/orgs/{org}/envelopes` |
| `ListEnvelopeProposals`, `ApproveEnvelope`, `RejectEnvelope` | the backoffice, realm-wide | `GET /grant/admin/envelopes`, `POST …/{id}/approve`, `POST …/{id}/reject` |
| `ListHosts`, `BindHost`, `UnbindHost` | the backoffice, realm-wide | `GET /grant/admin/hosts`, `PUT` / `DELETE …/{host}` |
| `GetOrgEnvelope`, `GetHostEnvelope` | anyone (unauthenticated, limited per address) | `GET /grant/envelopes/orgs/{org_id}`, `GET /grant/envelopes/hosts/{host}` |

Which members and which operators may call a method is the project's endpoint
ACL.

| id | invariant | category | proof |
|---|---|---|---|
| grant/approved-only | Only an APPROVED envelope MUST be readable publicly; a proposal or a rejected one never is. | Security | `TestEnvelopeLifecycle` |
| grant/realm-decides | Approving, rejecting and binding hosts MUST be refused to a request acting inside an organization. | Security | `TestEnvelopeLifecycle` |
| grant/one-approved | Approving a version MUST supersede the organization's previous approved one in the same transaction; nothing is deleted. | Data | `TestEnvelopeLifecycle`, `ApproveEnvelopeRow` |
| grant/host-binds-once | A host bound to one organization MUST NOT be re-bound to another without unbinding. | Security | `TestEnvelopeLifecycle` |
| grant/safe-fields | Links MUST be absolute https (http only for localhost) without credentials; a colour #rrggbb; a host a lower-case DNS name. | Security | `TestCheckFields` |

## Gaps

1. The verified host is the organization's claim until the backoffice approves the version; nothing checks DNS.
2. A co-brand host does not yet pick the tenant of an MCP consent (`TENANT_SOURCE_HOST` is refused in the audience vocabulary).

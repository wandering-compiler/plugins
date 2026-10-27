# grant — changelog

## 0.1.0-rc.4

### The organization envelope offered to other domains' services

- **`presets.rpc` (requires w17 ≥ 1.15).** The plugin offers `GrantService.GetOrgEnvelope` — an organization's approved name, logos and verified host — to other domains' services through the domain's private surface, for a product's sign-in on a co-brand host to show whose it is. Served only when the domain's `(w17.private_api)` confirms it.

## 0.1.0-rc.3

### The backoffice decides envelopes from inside an organization

- `ListEnvelopeProposals`, `ApproveEnvelope` and `RejectEnvelope` were refused to every request acting inside an organization, so a backoffice operator who is also a member of one (and is inferred into it when naming none) could not decide envelopes. They now act realm-wide for a credential holding the method realm-wide, wherever the request acts: the auth plugin's `realm_permissions` scope (auth 0.1.0-rc.38 or newer). An organization's own admins are refused as before.

### Seeding an approved envelope by fixture is documented

- `SPEC.md` gains "Seeding an approved envelope". It gives the fixture shape of an approved envelope: `status: "approved"`, `approved_slot: "approved"`, `decided_at`. It also says how to replace a seeded envelope: the previous one becomes `superseded` with `approved_slot` null, written before the new one. A fixture is re-applied on every deploy, so once the backoffice approves a newer envelope for a seeded organization, change the seeded row to `superseded` too, or the next apply is refused. These values are now a public contract: what a fixture writes.
- The public read (`GetOrgEnvelope`) now holds every approved envelope to the proposal's field rules (`grant/safe-fields`) and leaves out a field that breaks one; the envelope stays. A seeded row is checked nowhere else, so a `javascript:` link or a colour that is not `#rrggbb` no longer reaches the consent, invitation and sign-in pages — it is simply missing there.

## 0.1.0-rc.2

### Co-brand hosts moved to the auth plugin (read first)

`BindHost`, `UnbindHost`, `ListHosts` and `GetHostEnvelope` (`/grant/admin/hosts…`, `/grant/envelopes/hosts/{host}`) are gone, with the `HostBinding` table. A host decides which organization a request acts in, which `Authenticate` enforces, so the binding now lives there: the auth plugin's `org_hosts` (`PUT` / `DELETE /auth/admin/hosts/{host}`, `GET /auth/hosts/{host}` for the organization a host serves). A page on a co-brand host asks the auth plugin for the host's organization and reads its envelope with `GET /grant/envelopes/orgs/{org_id}`. Rebind any host through `org_hosts`; nothing copies the old rows.

## 0.1.0-rc.1

### Added

- **The grant plugin**: an organization's envelope (name, logos, verified host, links, colour, language, operator) proposed by the organization and approved or rejected by the backoffice — only an approved one is ever read, publicly, by organization or by co-brand host — and the co-brand hosts the backoffice binds to the organization they present. A newer approval supersedes the previous one; nothing is deleted.

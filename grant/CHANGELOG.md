# grant — changelog

## 0.1.0-rc.2

### Co-brand hosts moved to the auth plugin (read first)

`BindHost`, `UnbindHost`, `ListHosts` and `GetHostEnvelope` (`/grant/admin/hosts…`, `/grant/envelopes/hosts/{host}`) are gone, with the `HostBinding` table. A host decides which organization a request acts in, which `Authenticate` enforces, so the binding now lives there: the auth plugin's `org_hosts` (`PUT` / `DELETE /auth/admin/hosts/{host}`, `GET /auth/hosts/{host}` for the organization a host serves). A page on a co-brand host asks the auth plugin for the host's organization and reads its envelope with `GET /grant/envelopes/orgs/{org_id}`. Rebind any host through `org_hosts`; nothing copies the old rows.

## 0.1.0-rc.1

### Added

- **The grant plugin**: an organization's envelope (name, logos, verified host, links, colour, language, operator) proposed by the organization and approved or rejected by the backoffice — only an approved one is ever read, publicly, by organization or by co-brand host — and the co-brand hosts the backoffice binds to the organization they present. A newer approval supersedes the previous one; nothing is deleted.

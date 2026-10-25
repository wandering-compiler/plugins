# grant

An organization's **envelope** — how it presents itself on the consent,
invitation and sign-in pages — approved by the platform. See
[SPEC.md](SPEC.md).

Activate it beside the auth plugin, in the same domain, and include its REST
preset on the surfaces that serve organizations, the backoffice and the
public pages. A page that shows an organization fetches its approved envelope
(`GET /grant/envelopes/orgs/{org_id}`) and renders neutrally when `found` is
false. On a white-label or co-brand host, the page first asks the auth
plugin which organization the host serves (`GET /auth/hosts/{host}`,
org_hosts).

# grant

An organization's **envelope** — how it presents itself on the consent,
invitation and sign-in pages — and its **co-brand hosts**, both approved by
the platform. See [SPEC.md](SPEC.md).

Activate it beside the auth plugin, in the same domain, and include its REST
preset on the surfaces that serve organizations, the backoffice and the
public pages. A page that shows an organization fetches its approved envelope
(`GET /grant/envelopes/orgs/{org_id}` or `/grant/envelopes/hosts/{host}`) and
renders neutrally when `found` is false.

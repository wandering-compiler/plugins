### A registration on the identity's own host names the host it comes from (`org_signup`)

- `SignUpReq.signup_host` and `OAuthExchangeReq.signup_host` (new, present with `org_signup`). When a person comes from an organization's host to register on the identity's own host, the registration page there sends that host. The identity's host serves several organizations' sign-ups and is bound to none of them.
- With no gateway host, the named host decides exactly as a registration arriving on it would: the organization bound to it (`org_hosts`) and that organization's policies (kind, role, open or closed), and `invite_only` when no policy speaks. An unbound host joins nothing. An invitation still decides its own organization.
- A gateway that takes the tenant from the host still decides by the host the request arrived on. A body host naming another host is refused with `SIGNUP_HOST_CONFLICT`; one that is not a host name is refused with `HOST_INVALID` on `signup_host`.
- The page shows the organization the same way as on its own host: `GET /auth/hosts/{host}` (with `open_kinds`), then the grant plugin's approved envelope (`GET /grant/envelopes/orgs/{org_id}`).
- Nothing extra is verified. An open policy already admits anyone who reaches that host, so naming the host gains nothing more.

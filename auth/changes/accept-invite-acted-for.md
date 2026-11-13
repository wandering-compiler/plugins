### Accepting an invitation for the person another domain serves

Fixed: since rc.59, `AcceptOrgInvite` and `AcceptMyOrgInvite` refused a call
from the identity domain's own code acting for the person (`ResolveUser` +
`principal.ActAs`), with `PermissionDenied` / `SESSION_REQUIRED`. A product that
accepts an invitation through the identity's private surface has no other way
to name the person, so every such acceptance failed. Both now admit the person
the domain acts for (`AuthResp.acted_for`) as well as their session. An API
token is still refused, and what mints a credential still takes a session.

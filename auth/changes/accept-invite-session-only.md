### Accepting an invitation takes a session (read first)

Behaviour change. `AcceptOrgInvite` and `AcceptMyOrgInvite` now refuse an API-token
caller (`PermissionDenied` / `SESSION_REQUIRED`) before anything is read: joining an
organization changes what the person holds, which only their session may do. A
client that accepted invitations with an API token must call from a signed-in session.

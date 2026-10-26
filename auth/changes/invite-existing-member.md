### An invitation for someone who is already a member is refused

- `InviteToOrg` (`POST /auth/orgs/{org}/invites`) refuses an address whose account is already a live member of the organization: `AlreadyExists` with the detail `INVITE_ALREADY_MEMBER` on `email` ("This person is already a member of the organization."), and nothing is written. Until now the invitation was written and listed as pending, and only acceptance refused it, on the membership's unique index, so it could never be accepted.
- A removed member can still be invited back, and an address with no account or with a membership of another organization is invited as before. Open invitations (no address) are not affected.

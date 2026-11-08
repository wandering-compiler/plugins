### An organization's email proof, on every way in

- **New feature `org_email_proof_policy`** (requires `email_verification` and `org_membership`):
  an organization's own address-proof floor (`none` | `derived` | `full`) over the activation's
  `email_proof_required`. Table `OrgEmailProofPolicy`; the backoffice's `SetOrgEmailProof`,
  `ClearOrgEmailProof`, `GetOrgEmailProof` (`/auth/admin/orgs/{org_id}/email-proof`, realm-wide)
  and the organization's `SetMyOrgEmailProof`, `ClearMyOrgEmailProof`, `GetMyOrgEmailProof`
  (`/auth/orgs/{org}/email-proof`), all refused unless the endpoint ACL gates them. A migration
  adds the table.
- **Behaviour change (read before upgrading): the floor now holds on a registration through an
  organization's host (`org_signup`), not only on an invitation.** Under a floor above `none` —
  the activation's or the organization's — a registration an open policy takes joins only when
  it proves the address itself (a `sign_up_confirmation` code, an OAuth provider's
  `email_verified`); otherwise it is refused before anything is written, with
  `SIGNUP_EMAIL_PROOF_REQUIRED` (412). An activation with `email_proof_required` above `none`
  and open sign-up policies without `sign_up_confirmation` now refuses those registrations:
  turn `sign_up_confirmation` on, or lower the organization's floor.

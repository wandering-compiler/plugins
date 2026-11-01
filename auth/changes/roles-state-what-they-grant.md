### A role states what it grants (README)

The README now says what the compiler requires of the roles this plugin seeds
and hands out. A `(w17.acl_roles)` role with no `include`, no
`all_permissions` and no `no_permissions` is refused. It used to be read as
every permission in the catalogue, so a customer invited onto it held all of
them. Declare an invitation's customer role `no_permissions: true`, and a
role meant to grant everything `include: ["*"]`. A sign-up role (`first_user` / `default`) whose
resolved grants are everything or include a sensitive permission needs
`all_permissions_at_signup: true`. The plugin itself does not change, but the
fields need a w17 platform whose compiler has them.

### Redefining an organization's product role is held to the role as it is

`DefineOrgProductRole` on a live key checked the ceiling against the new
permissions only, so a caller could narrow a role and take from every holder a
permission the caller does not hold. The live role must now be covered too (as
`RetireOrgProductRole` requires); otherwise `PRODUCT_ROLE_ABOVE_CALLER`.

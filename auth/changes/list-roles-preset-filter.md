### ListRoles takes an optional `preset_key` filter

`ListRolesReq.preset_key` (optional) narrows the role catalogue to the role a declared preset seeded. Absent, the call lists the whole catalogue as before, so the admin role page is unchanged. A caller after one preset role (`org-admin`) names it here instead of scanning the paged list, which would quietly miss the preset once the catalogue grows past the first page.

`ListRoles` and `GetRole` already return `org_scoped` (and `token_type`, `org_id`) when their feature is on; the query's comment that said otherwise is corrected.

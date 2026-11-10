### SPEC: the sign-up policy's missing role snapshot is a documented limit

No behaviour change. org_signup gap 4 now states as a deliberate limit that an open
registration policy keeps the role's name, not a snapshot, so a role widened after
the policy was set (by `UpdateOrgRole` or a preset re-seed) is granted as widened;
re-set the policy after widening its role. The fix (a `role_snapshot` column) needs
a migration and is deferred.

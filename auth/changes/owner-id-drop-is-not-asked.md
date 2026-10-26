### Correction: the `owner_id` drop is not asked for (`org_membership`)

- The rc.36 notes said the migration that drops `Organization.owner_id` "is lossy and the migrator asks you to confirm it". It does not. Removing a field from the proto is the decision, so `migrate generate` writes the drop and asks nothing. `migrate check` reports nothing to decide, and the plan's risk report lists the step as `drop_column`, MEDIUM. Only a local `stack build` stops on it, as on any lossy sync, until `--lossy` says what to do.
- If a deployment set `owner_id` by hand and wants the values, export them before generating the migration. Grant those people a role and a membership first, as the rc.36 notes say.

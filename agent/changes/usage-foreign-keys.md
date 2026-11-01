### The usage tables reference each other through foreign keys

`Usage.scope_id` and `model_id`, `ModelPrice.model_id`, `ScopeLimit.scope_id`, `UsageLabel.usage_id` and `label_id` (feature `usage_persistence`) now carry a foreign key to the interned row they name (`fk: "@module.<Model>"`, expanded to the activation's own table), `ON DELETE RESTRICT` (`deletion_rule: BLOCK`). A price or a limit recorded for an id that was never interned is refused (`InvalidArgument`, "referenced record does not exist") instead of stored.

Before you deploy it, apply with `migrate apply --checks` (or `W17_MIGRATE_CHECKS=1`): a database holding a row the keys refuse then refuses the migration by the check's name before any of it runs. Each check is `SELECT count(*) FROM <child> WHERE <col> NOT IN (SELECT id FROM <parent>)`.

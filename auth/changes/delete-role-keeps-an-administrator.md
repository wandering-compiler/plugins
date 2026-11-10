### Retiring a wildcard role no longer strands its holders (read first)

Behaviour change. `AuthMutation.DeleteRole` — the admin Roles page's delete — now
refuses to retire a live wildcard role (`all_permissions`) while one of its live
holders holds no live grant of another live wildcard role (`LAST_ADMIN_ROLE`,
FailedPrecondition; nothing is revoked). Before, retiring the wildcard preset
revoked every superadmin's grant in one click and nothing in the product could
give one back. To retire a wildcard its holders rely on, grant them the
replacement first. Every other role, and a wildcard nobody relies on alone,
retires as before. The statement gains two operations (a lock on the live
wildcard rows and the guard), so a project picks the change up by regenerating
its storage from this release.

### Pending invitations to a role of all permissions survive the lock growing

- **Fixed: every pending invitation to a role of `all_permissions` became unacceptable when the project added a method** ("this invitation's role has changed since it was sent"). The invitation stored the lock the role expanded to; it now stores `<role>:*`, accepted while the role still grants all permissions. Invitations sent before this release keep their list and are held to it: one sent while the lock was smaller is refused — send it again.

### The first_user bootstrap goes to the first person, not a seeded machine account

Fixed: with `service_account` on, a machine account created before anybody
signed up (by a fixture, say) counted as the first registered user, so the
first person who signed up on a fresh database got no `first_user` role and
nobody held the bootstrap superadmin. `CountUsers` now also counts the
machine accounts apart, and the bootstrap goes to the first person. Without
`service_account` nothing changes.

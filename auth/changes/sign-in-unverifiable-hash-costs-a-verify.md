### A sign-in to an account without a usable password costs a verify

`SignIn` for an account whose stored hash no algorithm verifies (a machine
account's or an erased account's `!` sentinel) now runs the same throwaway
password verification an unknown address does, so the response time no longer
tells a machine account's address apart. The answer is unchanged. New:
`passwordhash.Verifiable`.

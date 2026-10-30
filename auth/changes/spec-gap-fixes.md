### Sign-in upgrades weak hashes, resets end sessions with the password, and more fail closed

- `SignIn` stores a password whose hash is weaker than the current settings (another algorithm, a lower cost) rehashed, through `AuthMutation.RehashUserPassword`. The write is a compare-and-swap on the verified hash and touches nothing else. A failed write never fails the sign-in.
- `ResetPassword` revokes every token inside its transaction. A sweep that fails rolls the reset back, so a thief's session no longer outlives a reset.
- `RequestPasswordReset` answers registered and unregistered addresses alike, in time and in errors. A registered address's link is minted after the answer.
- Under `tenant_scope`, an account that resolves to no tenant is refused by `Authenticate` (Unauthenticated) instead of being authenticated unscoped.
- New event `BotCreated` when an operator creates a machine account. Its tokens were already `ApiTokenCreated`.

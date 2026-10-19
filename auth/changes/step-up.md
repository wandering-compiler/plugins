### A session's password confirmation (`step_up`, new, off by default)

- **New feature `step_up`.** `ConfirmPassword` (`POST /auth/password/confirm` with `{"password": "…"}`) verifies the caller's password and stamps their session: `UserToken.stepped_up_at`. A consumer that guards a sensitive action reads the caller's own token row and asks for a recent confirmation. A stolen token and its device key do not carry the password, so they cannot pass.
- **A session only.** An API token is refused (`SESSION_REQUIRED`).
- **Guess budget.** Every guess is counted on the session in one statement. After five wrong passwords in a row the step-up is locked for fifteen minutes (`PASSWORD_STEP_UP_LOCKED`), and a confirmation resets the count. A wrong password is `PASSWORD_NOT_CONFIRMED`.
- **Migration** (only with the feature): three new columns on `UserToken`, nothing changed or removed.

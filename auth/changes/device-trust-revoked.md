### A password change or a disable ends device trust

With `devices`, a trusted device used to stay trusted after the account's password was changed or the account was disabled, so under `two_factor_scope=new_devices` it kept skipping the second factor, also for whoever had signed in from it with the old password.

- **`ChangePassword` (`password_change`) and `DisableUsers` (`user_admin`) now end the trust of every device of the account**, in the same statement that writes the new password or `disabled_at`. The session a change came from keeps working, but its device passes the second factor again on the next sign-in; so does every device of a re-enabled account. `ListDevices` shows these devices as untrusted. A sign-in already in flight when the change commits cannot trust the device after it.
- **A password reset still keeps device trust**, unchanged.
- **New column `User.device_trust_revoked_at`** (nullable, `devices` only) and query `AuthQuery.GetDeviceTrustRevokedAt`. A project with `devices` enabled must generate and apply a migration for the column.
- **OAuth sign-in does not ask for the plugin's second factor**, also for an account that has one confirmed. This is now a recorded decision, not an open question: the provider already verified the identity. An OAuth sign-in still never makes the device trusted.

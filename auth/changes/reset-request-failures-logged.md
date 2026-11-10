### A password reset that sends no link is logged

`RequestPasswordReset` still answers the same success for every address, but a
link that fails to mint (store, sealing or event bus failure) and an account
lookup that fails with anything but NotFound are now logged at ERROR (with the
user id where known, never the address). Before, an outage answered every request
with success and nothing reported that no link went out. The SPEC's reset rows now
describe the fixed behaviour (the token sweep inside the reset's transaction).

### A sign-in without a device proof says the client is outdated

- **`DEVICE_PROOF_REQUIRED` names its cause in the developer text**, which a client that does not know the code prints as it is — and a client too old to sign proofs is exactly such a client. A sign-in without a proof: the client does not sign one, so it is outdated or not this deployment's client — update it. A request without one: the token went as a plain Bearer or from a client that does not sign — send it with a proof by its key. The code and the user-facing message are unchanged.

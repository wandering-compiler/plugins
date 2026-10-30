### Retries after the provider forgets a key are recognised, and refusals say what they are

- A charge retried after the provider forgot its key is answered with the
  payment the key recorded, once that payment is past confirmation. It used to
  mint a second, unconfirmed intent at the provider and answer
  `AlreadyExists`. The same key with another amount or currency is
  `AlreadyExists` before the provider is asked.
- The provider customer and the plan's provider price are created under an
  idempotency key. A retried or racing create gets the object the first one
  made instead of leaving an orphan.
- Only the balance CHECKs read as "insufficient credit balance". Any other
  `INVALID_VALUE` on a credit apply goes back as the caller's input error.
- A usage report that would overflow the meter's total is refused as
  `FailedPrecondition` with a message that says so.
- The zero-decimal currency table is Stripe's whole documented list.

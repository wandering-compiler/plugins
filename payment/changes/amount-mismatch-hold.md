### A success for another amount than was asked is held, not trusted

- A payment the provider reports succeeded for another amount or currency
  than its row holds (its intent was changed at the provider by something
  other than this plugin) is held at the new status `AMOUNT_MISMATCH`, with
  what it took in `received_amount` / `received_currency`. It emits
  `PaymentAmountMismatch` once, and no `PaymentSucceeded`; a top-up grants no
  credit. The webhook and the provider reconciliation check the same way.
- What a payment took is read from the signed event (`amount_received`), or
  from the provider when the event does not say; a success nobody can check
  is redelivered, not trusted.
- No later event moves a held payment. `RefundPayment` returns up to what it
  took, in its currency, and takes back no credit for a held top-up.
- `Payment` gains `received_amount` and `received_currency`, and its status a
  value: consumer projects get a migration.

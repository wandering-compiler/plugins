### Partial refunds, refund outcomes, new payments and disputes are announced on the bus

- `PaymentCreated` — a payment was recorded, at its initial status.
- `RefundCreated` — a refund this plugin made, partial or full, with the
  provider's outcome. `PaymentRefunded` still announces the whole amount.
- `ProviderRefundRecorded` — a refund made at the provider directly, found by
  the webhook or the reconciliation. A subscriber that wants every refund
  listens to both refund events.
- `RefundStatusChanged` — a refund succeeded, failed or was canceled.
- `DisputeOpened` / `DisputeClosed` (`stripe_webhooks`) — a dispute was
  recorded, and it ended WON or LOST.
- Each is emitted once, by the write that records the fact. `Dispute` gains
  `closed_at`, set when the dispute's closing is announced.

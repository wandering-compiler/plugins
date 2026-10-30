### Refunds are checked against the plugin's own records before any provider is asked

- A refund past what remains of the payment (its amount less its pending and
  succeeded refunds) is refused as `InvalidArgument`, before the provider is
  asked. Two refunds of one payment run one after the other under the
  payment's row lock, so together they never exceed it, whatever the gateway
  does.
- A refund of a failed or canceled payment is refused as `FailedPrecondition`.
  One whose success webhook has not arrived is read from the provider first
  and goes ahead only when the provider reports it succeeded.
- Concurrent refunds of one top-up no longer both pass the credit check.
- The backend interface gains `GetPayment`. A driver for another provider
  must implement it.
- The plugin now needs the bundle's distributed-transaction client; a bundle
  without one fails at boot.

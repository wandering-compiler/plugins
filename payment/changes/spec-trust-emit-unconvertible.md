### Specified: the envelope trust boundary, event commit timing, unconvertible webhook amounts

SPEC only. `payment/principal-from-gateway` and base gap 1 say a request without the gateway envelope is trusted to name any user, so every client-facing surface must stamp it; `payment/events-after-commit` names the storage emit contract it rests on; the new `stripe_webhooks/unconvertible-amount-not-recorded` row says what a webhook amount that does not convert does (never recorded, the delivery fails and is redelivered).

### A subscription's first invoice is the client's to pay, and a plan is subscribed once (`subscriptions`) (read first)

- `Subscribe` starts the subscription with its first invoice waiting for the
  client, and **answers that payment's `client_secret`** (new field on
  `SubscriptionView`). The frontend confirms it the way it confirms a
  charge; the card it is paid with pays the renewals. The subscription reads
  `INCOMPLETE` until its payment lands. Before, the provider tried a card the
  plugin's customers never have, and the subscription expired unpaid.
- **One open subscription per principal and plan.** A second `Subscribe`
  while the first awaits its payment answers that subscription and its
  `client_secret`; one beside a live subscription (trialing, active, past
  due, paused, unpaid) is `AlreadyExists`. Concurrent subscribes start one.
  Another plan, or after a cancel, is a new subscription.
- The subscription calls pin Stripe API version `2024-06-20`.

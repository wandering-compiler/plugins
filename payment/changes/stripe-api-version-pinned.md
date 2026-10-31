### Every Stripe call is made under one API version, and a newer webhook's period end is read

- The Stripe driver sends `Stripe-Version: 2024-06-20` on every call, so the
  answers it parses no longer depend on the account's default API version.
- A webhook endpoint keeps the version it was created with. A subscription
  event rendered in API `2025-03-31` or later carries the period end on its
  item, and is now read there: before, `current_period_end` was stored empty
  on every such event. A running subscription whose event carries no period
  end in either place is logged with the event's `api_version`.

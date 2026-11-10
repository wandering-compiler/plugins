### A copy of a subscription event announces nothing twice

`MarkSubscriptionStatus` refuses an event as old as the one the subscription row already holds unless it changes the status or the period end. A `customer.subscription.*` event delivered again after its ledger write failed, or twice at once, used to rewrite the row and emit `SubscriptionStatusChanged` a second time for one transition. A newer event with the same status still applies (it carries the renewed period end).

### The refusals a person can act on are translatable

The refusals a person meets now carry a stable code and a sentence from the project's catalogs, listed in `plugin.yaml` `msgids:`:
- billing that is not theirs;
- an invalid e-mail, amount, currency or over-long description;
- a request key reused with different details;
- a declined or refused payment, and the provider being unavailable;
- an unknown plan, an existing subscription, or one waiting for its payment;
- too little credit, a top-up in another currency, a usage limit reached, and an invalid usage period.

Before, the caller got the generic sentence for the status code. A declined payment keeps the provider's reason as its code when the provider names one; without one, the code is now `PAYMENT_DECLINED` (it was none). The operator's text stays in the status message, now prefixed with `PaymentService:`.

### A success the provider reports without its received amount is not refunded

A refund of a payment whose success webhook has not arrived is refused (`FailedPrecondition`) when the provider reports the payment succeeded but not what it took, as the webhook path refuses the same success. It used to go ahead against the asked amount. Stripe always sends the field; the change matters for drivers and mocks that do not.

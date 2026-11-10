### A refund without an amount refunds what remains

`RefundPayment` with `amount` 0 refunds what remains of the payment, as the provider's own refund without an amount does. After a partial refund it used to ask for the whole payment and was refused as exceeding what remains; the caller had to compute the rest. With nothing left it is refused (`InvalidArgument`) before the provider is asked.

### A refund of a mismatched payment needs the amount it took

`LockPaymentForRefundResp.received_amount` and `received_currency` are declared `(w17.field).null`: the columns are recorded only for a payment held at `AMOUNT_MISMATCH`, and a generated query that can fill a field with SQL NULL must now say so. `refundAllowed` refuses (`FailedPrecondition`) a payment held at `AMOUNT_MISMATCH` that records no received amount, instead of judging the refund against an empty one.

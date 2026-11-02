### Every write returns its whole row

A generated query now fills every field of its response. That is a codegen
warning in this compiler release and an error in the next. Payment's writes
and lookups now return every column of the row they answer with, so a handler
never reads a zero standing in for a value it was not given:

- `CreatePayment` and every `MarkPayment*`;
- the dispute, refund and subscription writes;
- `CreateCreditTopup`;
- the subscription, dispute and usage lookups.

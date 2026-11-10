### A top-up refund that failed transiently and was never retried

Documented (prepaid gap 2) and proven: `RefundPayment` of a top-up takes the credit before the provider is asked and keeps it taken after a transient provider failure, for the retry. If the caller never retries, the credit stays taken with no refund made until the project's `ReconcileProvider` runs over a window covering the top-up, which gives it back. Run `ReconcileProvider` periodically.

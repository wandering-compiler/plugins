### Refund and subscribe guards no longer depend on the connection's isolation

The transaction that holds a payment's or a customer's row lock now asks for READ COMMITTED. On a database whose default isolation was REPEATABLE READ, the remaining-amount check of a refund that waited for another refund's lock read a snapshot without that refund, and both could pass.

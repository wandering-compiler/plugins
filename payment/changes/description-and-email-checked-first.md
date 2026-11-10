### A description or address the row cannot hold is refused before the provider

`CreatePayment` refuses a description longer than 500 characters, and `CreateCustomer` an e-mail that is not an address or is longer than 320 characters, with `InvalidArgument` before the provider is asked. They used to be refused by the local insert after the provider had created the intent or customer, and a retry under the same key failed the same way for ever.

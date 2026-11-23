package handlers

// The sentences a person reads when the payment plugin refuses them, and the
// stable codes beside them. Each is a msgid: the project's catalogs carry its
// translations (plugin.yaml's msgids: mirrors this block; `make
// plugin-msgids-sync`). The operator's copy of every refusal stays in the
// status message.
//
// Only refusals a person can act on are here: what they typed, what they
// asked for, whose billing it is. A refusal about the installation (a
// missing secret, a feature not staged) or an internal invariant keeps its
// operator text alone, and the caller gets the generic sentence for its code.

//w17:msgid
const (
	MsgBillingNotYours     = "You can manage only your own billing."
	MsgEmailInvalid        = "Enter a valid e-mail address."
	MsgAmountRequired      = "Enter an amount."
	MsgAmountNotPositive   = "The amount must be greater than zero."
	MsgDescriptionTooLong  = "The description can be at most {max} characters long."
	MsgCurrencyInvalid     = "The currency must be a three-letter code, such as EUR."
	MsgRequestReused       = "This request was already made with different details. Please start again."
	MsgPaymentDeclined     = "Your payment was declined. Please try another payment method."
	MsgPaymentRefused      = "The payment could not be processed. Please check the details and try again."
	MsgPaymentsUnavailable = "Payments are temporarily unavailable. Please try again in a moment."
	MsgPlanNotFound        = "This plan is not available."
	MsgAlreadySubscribed   = "You are already subscribed to this plan."
	MsgSubscriptionPending = "Your subscription to this plan is waiting for a payment that has not been completed yet."
	MsgInsufficientCredit  = "Your credit balance is too low for this."
	MsgTopUpCurrency       = "Credit can be topped up only in {currency}."
	MsgUsageLimitReached   = "This would exceed your usage limit, so nothing was recorded."
	MsgPeriodInvalid       = "This period is not valid."
)

// Stable codes for the refusals above (w17.ErrorDetail.code).
const (
	codeBillingNotYours     = "BILLING_NOT_YOURS"
	codeEmailInvalid        = "EMAIL_INVALID"
	codeAmountRequired      = "AMOUNT_REQUIRED"
	codeAmountNotPositive   = "AMOUNT_NOT_POSITIVE"
	codeDescriptionTooLong  = "DESCRIPTION_TOO_LONG"
	codeCurrencyInvalid     = "CURRENCY_INVALID"
	codeRequestReused       = "IDEMPOTENCY_KEY_REUSED"
	codePaymentDeclined     = "PAYMENT_DECLINED"
	codePaymentRefused      = "PAYMENT_REFUSED"
	codePaymentsUnavailable = "PAYMENT_PROVIDER_UNAVAILABLE"
	codePlanNotFound        = "PLAN_NOT_FOUND"
	codeAlreadySubscribed   = "ALREADY_SUBSCRIBED"
	codeSubscriptionPending = "SUBSCRIPTION_PAYMENT_PENDING"
	codeInsufficientCredit  = "INSUFFICIENT_CREDIT"
	codeTopUpCurrency       = "TOPUP_CURRENCY"
	codeUsageLimitReached   = "USAGE_LIMIT_REACHED"
	codePeriodInvalid       = "PERIOD_INVALID"
)

// methodPrefix names the service in an operator's copy of a refusal
// (grpcerr.ForUser prefixes it to the dev text).
const methodPrefix = "PaymentService"

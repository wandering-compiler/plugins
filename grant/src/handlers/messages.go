package handlers

// The codes a client branches on, beside the sentences a person reads.
const (
	CodeBackofficeOnly       = "BACKOFFICE_ONLY"
	CodeEnvelopeFieldInvalid = "ENVELOPE_FIELD_INVALID"
	CodeProposalPending      = "PROPOSAL_PENDING"
	CodeApprovedConcurrently = "APPROVED_CONCURRENTLY"
)

// The sentences a person reads when the grant plugin refuses them. Each is a
// msgid: plugin.yaml mirrors this set (make plugin-msgids-sync) so a project's
// catalogs carry them for translation.
//
//w17:msgid
const (
	MsgBackofficeOnly       = "Only the platform's backoffice can do this, and not from inside an organization."
	MsgEnvelopeNameRequired = "Give the organization's name."
	MsgEnvelopeLinkInvalid  = "A link must be a full https:// address."
	MsgEnvelopeColorInvalid = "The accent colour must be written as #rrggbb."
	MsgEnvelopeHostInvalid  = "The host must be a lower-case domain name, such as example.com."
	MsgProposalPending      = "Your organization already has a proposal waiting for a decision. Propose again once it has been decided."
	MsgApprovedConcurrently = "Another version of this organization's presentation was approved at the same time. Reload and decide again."
)

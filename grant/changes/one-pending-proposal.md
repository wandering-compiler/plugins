### One waiting proposal per organization (read first)

`ProposeEnvelope` now answers `FailedPrecondition` while another proposal of the same organization waits for the backoffice. An organization that wants to change a waiting proposal waits until it is approved or rejected, then proposes again; a client that proposed repeatedly to "update" a proposal must stop doing so. `ListEnvelopeProposals` answers at most the oldest 200 waiting proposals and `GetMyEnvelopes` the newest 100 versions of the organization. The new storage read `GetPendingEnvelope` needs the activation's storage regenerated.

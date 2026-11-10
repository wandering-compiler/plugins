### A contact write Brevo refuses is reported

A contact write Brevo refuses for its content (400, 422 — e.g. an address another contact already holds) is still dropped, but now goes to the bundle's error reporter (Sentry and the trace when configured) instead of only the log: the contact then lacks its address or sign-up date. SPEC gap 7 says what is not written again.

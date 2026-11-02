### An envelope not yet decided says so

`EnvelopeRow.decided_at` is declared `(w17.field).null`: a proposed envelope has no decision, and a generated query that can fill a field with SQL NULL must now say so. No wire or handler change.

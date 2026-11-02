### A contact without an address says so

`ContactRow.email` is declared `(w17.field).null`: an erased contact keeps no address, and a generated query that can fill a field with SQL NULL must now say so. The lookup by address is unchanged — its `WHERE c.email = :email` already guarantees one. No wire or handler change.

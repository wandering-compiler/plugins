### A consent event without `decided_at` is ignored

A `MarketingConsentChanged` without `decided_at` used to be dated by its handling, so a redelivered older decision overwrote a newer one. It is now acknowledged and changes nothing. auth always sets `decided_at`; a project that emits the mirror itself must set it too.

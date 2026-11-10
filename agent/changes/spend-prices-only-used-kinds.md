### A NULL rate no longer makes a call that did not use that kind unpriced

`GetScopeSpend` and `GetLabelSpend` price each kind of token (fresh input, cached
input, output) only when the call used it. A price that leaves a kind's rate empty —
a model with no cache, say — used to make every call of that model unpriced, so
every call of a scope with a spend cap was refused ("price the model"). Such calls
are now priced; a call that did use the unpriced kind stays unpriced, and a capped
scope still refuses it. Regenerate the storage from this release to pick it up.

### Usage counts clamp instead of wrapping, limits answer deterministically, logs keep the caller's text out

- `ModelUsage` token counts past 2^31 − 1 clamp at the bound instead of wrapping into a negative or small number. The persisted row keeps 64 bits.
- `GetScopeLimit` answers the limit set last when two share a scope, window and `valid_from`, instead of either one.
- The usage writer's failure log lines carry the counts and the kind of failure (the gRPC code), never the database error's text, which can quote a scope or label.

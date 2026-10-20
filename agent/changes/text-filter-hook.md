### Your own final-text filters

- **The `text_filter` hook** runs business methods of your domain on the final text, after the built-in `final_text_*` filters, in the order the activation binds them: `hooks: [ { slot: "text_filter", methods: [ "filters.Filters.Clean" ] } ]`. A method takes `TextFilterReq` (the text, the plugin method, the model, the usage scope and labels) and returns `TextFilterResp` (the text that replaces it), as the activation stages them. The deltas are never filtered.
- **A filter that fails or does not answer in time is skipped and logged** (its gRPC code, never the text): the answer still reaches the caller. `<DOMAIN>_AGENT_TEXT_FILTER_TIMEOUT_SECONDS` (default 5) bounds each. `FinalText.raw` skips them too.
- **Needs platform 1.14** (`requires_w17: ">=1.14"`): a console that knows plugin hooks. An activation that binds no hook behaves exactly as before.

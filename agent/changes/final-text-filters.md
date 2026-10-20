### The final text can be cleaned

- **Two filters for the answer a caller keeps** — `CompleteResp.text` and `Finished.text`; the deltas stay the model's own, so a stream is as fast as before and a caller swaps the streamed text for the clean one at the end. Both are off unless the activation switches them on:
  - `final_text_scripts` drops letters of every Unicode script the activation does not allow: `<DOMAIN>_AGENT_ALLOWED_SCRIPTS`, comma-separated Go script names, default `Latin`. A Thai token a model leaked into a Czech sentence goes; diacritics, digits, punctuation and emoji stay. An unknown script name refuses the boot.
  - `final_text_invisible` drops control and invisible characters: zero-width spaces, the byte-order mark, bidi overrides, U+FFFD. The zero-width joiner (emoji) stays.
- **A call has its say** with `FinalText` on `CompleteReq` and `RunAgentReq.Start`: `allowed_scripts` for an answer in another language, `raw` for none. A name the filter cannot use is refused before the model is called.
- `Finished.text` is no longer always exactly the deltas: with a filter on it is the cleaned text. Without one nothing changes: the same activation, the same env variables, no migration.

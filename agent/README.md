# agent

LLM calls for a w17 project: one model call in, text and token usage out.

The plugin is an engine, not a chat product. It has no conversation, no
history and no user. The service that calls it decides who is asking, keeps
the transcript, decides which tools exist and runs every tool call under its
own authorization.

- `Complete` returns the whole answer.
- `CompleteStream` sends the answer as the model writes it.
- `RunAgent` runs a tool-calling loop whose tools your project serves.

The provider is Azure OpenAI (`provider: azure_openai`). Activate the plugin in
the domain that calls the model, then set its `endpoint` and `api_key`, and
optionally `default_model` and the output and timeout limits. `plugin.yaml`
lists every setting and feature. [SPEC.md](SPEC.md) says what the plugin
guarantees and what remains the caller's job.

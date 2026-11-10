### Calls to tool names the model invented no longer spend `max_tool_calls`

`RunAgent` reserved a round's tool-call budget for every call the model made, including calls to names the caller never declared, which are answered "there is no tool named …" without running. A model that emitted many hallucinated calls in one round ended the run `ResourceExhausted` although no tool ran, the real calls in that round were not applied, and the model never heard its correction. Only calls to declared tools count now.

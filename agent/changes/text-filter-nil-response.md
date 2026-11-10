### A `text_filter` hook that returns no response is skipped

A project filter bound to the `text_filter` hook that returned no response and no error (an early return on a path it did not mean to take) replaced the final answer with the empty string, silently. It is now skipped and logged like a filter that failed, and the answer goes on with the text as it stood. An explicit empty text is still the filter's answer.

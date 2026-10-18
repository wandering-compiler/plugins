### Built on SDK go/v0.1.0-rc.24

- **The plugin's module requires `github.com/wandering-compiler/sdk/go` v0.1.0-rc.24.** A w17ctl that knows the request data annotations (`gdpr`, `sensitive`) generates a redaction plan next to every pb file of the plugin's `src/gen`, and that plan imports the SDK's `lib/redact`, which rc.24 is the first to have. The plugin's own code does not change.
- Nothing in your project changes: the same activation, the same env variables, no migration. Your project's own `go.mod` moves to rc.24 with the same w17ctl.

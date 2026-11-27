### The manifest names the SDK its handlers need

`plugin.yaml` now declares `requires_sdk: v0.1.0-rc.73`, the sdk/go version the
plugin's Go handlers are built against. A project whose sdk/go pin is older
is told at codegen to move it; a console refuses to sign a release of a
plugin with Go handlers that does not say this.

### Fixed

- **A project that activates the plugin generates again.** The subscription mirrors were in `proto/subscriptions/`, which is not a layer, so a project's codegen read it as a module inside the plugin's and refused it ("is a module … and also a group above module"). They are in `proto/types/auth_mirrors.proto` now; the messages are the same.

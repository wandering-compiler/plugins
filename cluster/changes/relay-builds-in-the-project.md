### The relay sandbox builds in the project

The `clusterrelay` sandbox now declares `build: { context: ., dockerfile: sandboxes/relay/Dockerfile }`, and the release ships the Dockerfile. A project's `compose.w17.yaml` builds the relay image from the vendored plugin (`<proto_dir>/plugins/cluster`) instead of trying to pull a tag no registry publishes; the build uses the plugin's generated pb, which `w17ctl codegen` writes there. Needs w17 platform 1.17 (`requires_w17: ">=1.17"`).

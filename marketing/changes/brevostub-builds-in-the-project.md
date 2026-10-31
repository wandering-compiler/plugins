### The brevostub sandbox builds in the project

The `brevostub` sandbox (the `brevo` feature's fake Brevo API) now declares `build: { context: sandboxes/brevostub }`, and the release ships its source. A project's `compose.w17.yaml` builds the image from the vendored plugin (`<proto_dir>/plugins/marketing/sandboxes/brevostub`) on `w17ctl stack build`, `stack up --build`, or the first `stack up` that finds no image, instead of trying to pull a tag no registry publishes. Needs w17 platform 1.17 (`requires_w17: ">=1.17"`).

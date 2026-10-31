// Standalone module: the brevostub sandbox is a self-contained dev-only
// binary built into its own Docker image (stdlib only, no deps). Kept
// out of the plugin's src/ module so it is never staged into the
// consuming project's bundle; the release ships it as build context only.
module github.com/wandering-compiler/plugins/marketing/sandboxes/brevostub

go 1.26

// Standalone module: the fakeidp sandbox is a self-contained dev-only
// binary built into its own Docker image (stdlib only, no deps). Kept
// out of the plugin's src/ module so it never enters the staged plugin
// tree or the consuming project's bundle.
module github.com/wandering-compiler/platform/plugins/auth/sandboxes/fakeidp

go 1.26

### The relay sandbox builds from a fresh clone, and a volume works

- The relay image's build stops with the command to run when the generated pb is missing (`w17ctl plugin gen-pb cluster`; `src/gen` is never committed), and the build instructions in `plugin.yaml` and the Dockerfile name that step. It used to fail inside `go build` with "no required module provides package …/cluster/gen/pb".
- The image creates `/var/lib/relay` owned by the relay user (uid 10001), so a volume mounted there is writable. Docker used to create the missing path as root's, and the relay could not write its key.
- `plugin.yaml` says where the plugin runs: in the domain's storage bundle, which serves ClusterService and reads `client_cert_path` / `client_key_path`.

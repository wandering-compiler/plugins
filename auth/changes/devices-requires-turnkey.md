### `devices` requires `authenticate_turnkey`

- **The `devices` feature now declares `requires: [authenticate_turnkey]`.** Its handlers read the caller's device from the turnkey identity answer (`AuthResp`), which only `authenticate_turnkey` stages. An activation that enabled `devices` without it got a bundle that did not compile (`undefined: pb.AuthResp`, in a file the project never wrote); it is now refused at activation with the missing feature named.
- An activation that already enables both (every known one) changes nothing: the same tables, env variables and endpoints, no migration.

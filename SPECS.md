# Plugin specifications

Every plugin in this repository has a behaviour specification, `<plugin>/SPEC.md`.
It is written before the plugin's example projects and end-to-end suites, and
they are measured against it. A plugin without one is not finished.

| plugin | specification |
|---|---|
| auth | [auth/SPEC.md](auth/SPEC.md) |
| payment | [payment/SPEC.md](payment/SPEC.md) |
| agent | [agent/SPEC.md](agent/SPEC.md) |
| cluster | [cluster/SPEC.md](cluster/SPEC.md) |
| grant | [grant/SPEC.md](grant/SPEC.md) |
| marketing | [marketing/SPEC.md](marketing/SPEC.md) |

## What a specification contains

1. **Features.** Every feature of the manifest, and the base tier that has none:
   its purpose, and what it adds — tables, storage and business RPCs, REST
   endpoints (which take no credential, and how the per-address limit charges
   them), events, environment knobs — with its `requires`, `conflicts_with` and
   combined files.
2. **Invariants per feature.** Each is a single MUST or MUST NOT about
   observable behaviour, with a stable id (`<feature>/<name>`), in one of four
   categories:
   - **Security** — authentication and authorization, what an attacker can and
     cannot learn or do, secrets at rest, replay, guess budgets.
   - **Consistency & concurrency** — single-use values, what two simultaneous
     requests may and may not both achieve, which writes share one transaction.
   - **Performance** — lookups served by an index, no write on a hot read path
     unless it is bounded.
   - **Failure & configuration** — what refuses at boot instead of at the first
     request, what a provider outage or a partial failure leaves behind.

   Invariants describe what the plugin must guarantee, not only what the code
   happens to do today. Where the two differ, that is a gap.
3. **Interactions.** Every pair (or set) of features that share a table, an
   RPC, a code path, or override each other's behaviour, as a matrix, plus the
   invariants that must hold when they are on together
   (`interaction/<a>-<b>-<name>`).
4. **Cross-cutting invariants** (`<plugin>/<name>`): secrets at rest,
   enumeration, events, rate limiting, transactions, boot checks.
5. **Proof.** For each invariant, what demonstrates it: a unit test by name, or
   `none`. A unit test against fake storage proves the handler's logic, not a
   database constraint, a conditional update under concurrency or a rollback;
   those are marked **unit (mock) only** with what a live test must show.
6. **Gaps and findings.** What the code does not enforce. A gap in Security or
   Consistency is a defect to fix, not documentation.

## From specification to examples

The live-only invariants — the ones a fake store cannot prove — are what the
example projects in
[wandering-compiler/examples](https://github.com/wandering-compiler/examples)
exist to cover. An example says which invariants its end-to-end suite proves,
so the coverage of each plugin can be read from the examples, and an invariant
no test and no example covers is visible as such.

## Writing rules

The specifications are public. They state technical reasons only: no names of
people or organizations, no private hosts, no ticket or review references, no
paths into other repositories, no dated anecdotes. The leak check,
`scripts/check-leaks.sh` in
[wandering-compiler/sdk](https://github.com/wandering-compiler/sdk), enforces
it; run it against this repository before publishing a specification.

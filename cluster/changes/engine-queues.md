### One queue per engine

A worker's slots count for the engines it announced (`AttachReq.engines`). A reservation for an engine is granted only while the slots held for that engine stay under what the ready workers running it can take. Workers that name no engine count for every engine.

- **Order.** A reservation for an engine that is full waits. Later reservations for engines with room are granted ahead of it. Within one engine the order is arrival order. The pool's total still caps everything held at once.
- **Position.** A queued place counts only the places ahead of it that it waits behind: those of its own engine, and those that bind none.
- **Library.**
  - The relay reports the per-engine split from `Backends.OnEngineCapacityChange` to `Pool.SetEngineCapacity`.
  - `Pool.DoneEngine(engine)` returns a running slot of an engine; `Done` is `DoneEngine("")`.
  - A relay whose workers announce no engines is one queue, as before.

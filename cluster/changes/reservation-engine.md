### A reservation can name the engine its work needs

`ReserveTaskReq.engine` names what the work needs the worker to run, an opaque string the pool's user defines. For a codegen pool it is the codegen engine's version. The pool compares the strings and interprets nothing.

- **Ticket.** A ticket carries its reservation's engine. The proxy refuses a call whose `w17-cluster-engine` header names another engine, with `ENGINE_MISMATCH`, and the ticket stays unspent. A call naming no engine is let through, so a client from before engines keeps working. The caller's header never reaches the worker: the relay drops it and forwards the reservation's engine under the same key, or none for a reservation that bound none. The worker routes on the relay's word, so a caller cannot pick an engine the control plane did not bind. `tunnel.Backend.Set` carries the keys a picker vouches for.
- **Workers.** A worker announces the engines it runs in `AttachReq.engines` (`workerconn.Config.Engines`). The proxy hands a ticket only to a worker that runs its engine. A worker naming none takes any work, as before.
- **Relay.** A relay refuses a reservation for an engine no attached worker runs, with `ENGINE_NOT_CARRIED`. The control plane falls through to the next relay. A relay with nobody attached still queues the reservation, as it queues any.

An empty engine binds nothing, so a control plane and workers from before the field behave as they always did. Capacity is still the sum over the fleet; per-engine queues are not part of this.

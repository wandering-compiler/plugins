### A panic on a relay or worker server no longer ends the process

The relay's management, worker-attach and proxy servers and the worker's server on its tunnel are built by hand, and carried no panic recovery: grpc-go lets a handler's panic end the process, so one bad request took a relay down with every queue, ticket, reservation, attached worker and running call on it. Each server now answers such a panic `INTERNAL` (the method name only), logs it with its stack, and keeps serving. A project passing its own options to `workerconn.ServeTunnel` keeps them; the recovery runs outside them.

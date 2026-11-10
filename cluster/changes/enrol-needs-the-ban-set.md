### A relay enrols no worker until it holds the ban set

`Enroll` now refuses with `BAN_SET_UNKNOWN` (`UNAVAILABLE`) while the relay holds no ban set — after a restart without a saved set, before a control plane has called it — as attach, tunnels and renewal already did. Until then a banned key holding a valid registration code was issued a fresh 30-day certificate in that window. The refusal does not spend the code, and a worker retries it with the same code at its usual pace instead of stopping.

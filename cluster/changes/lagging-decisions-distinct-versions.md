### Concurrent ban decisions on lagging replicas no longer share a version

A control-plane replica whose clock is behind the newest ban decision moved its own decision exactly 1 ms past it, so two such replicas deciding at once recorded the same ban-set version, and a relay could apply the set one of them read between the two commits — lifting the other's ban until the next set arrived (seconds, at most the 5-minute delivery). The step now carries a random microsecond part, which makes the collision rare; the residual case is stated as a gap in the SPEC.

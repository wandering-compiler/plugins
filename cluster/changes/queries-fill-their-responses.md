### The relay reads return their whole row

`RelayQuery.GetRelay` and `ListRelays` now select `removed_at` and
`ended_key`. A generated query fills every field of its response: that is a
codegen warning in this compiler release and an error in the next.

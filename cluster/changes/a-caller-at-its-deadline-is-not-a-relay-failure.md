### A caller reaching its deadline is no longer counted as the relay failing

Fixed: when a placement's caller timed out, the relay's `DeadlineExceeded`
could arrive at that very deadline before the caller's context was marked
done. The placement then recorded it as the relay failing on the relay's row
and retired the connection the other calls share. A caller at its deadline is
now the caller leaving, read from the deadline as well as from the context.
A relay that fails while the caller still has time is still recorded as a
failure.

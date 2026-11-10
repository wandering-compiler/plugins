### Banning or unbanning an unknown worker id is refused

`BanWorkers` and `UnbanWorkers` now resolve every selected id before writing. A selection holding an id the registry does not hold (a stale list, a mistyped id in an API call) is refused `NOT_FOUND`, naming the id, and nothing is decided. Until now the update matched no row for that id and the call answered success, so the admin reported a ban that never happened.

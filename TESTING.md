# Running a plugin's tests

> This file is **published to the root of the plugin registry** by
> `make render-plugin-catalogue`. It is written for a reader of that repository —
> which may be somebody outside the team, since the registry is public.

Every plugin here ships its own tests. They are real and they pass: the publish
gate (`make check-plugin-published-tests` in the source repository) rehydrates
this exact tree and runs them before a tag is cut, so what you are reading is not
a hopeful copy.

## Why the Go files end in `.src`

A plugin's sources are **inert data** in this repository and in a consumer's
project. They are not a Go module and are not compiled where they sit: a project
that installs a plugin has its own compiler stage the sources into a service
bundle with the import paths rewritten. A live `go.mod` under
`<project>/proto/plugins/<name>/src` would make the plugin a module inside that
project's own build, which it is not.

So every `.go`, `go.mod` and `go.sum` is suffixed. The client strips the suffix
when it places a tree, and the tests are dropped at that point — nothing in a
consumer runs them, and they are more than half the Go by volume.

## Running them

```sh
# 1. take a copy of the whole plugin directory, not just src/ —
#    several tests read ../../plugin.yaml and ../../proto/.
cp -r auth /tmp/auth && cd /tmp/auth

# 2. rehydrate: drop the .src suffixes
find . -name '*.src' -exec sh -c 'mv "$1" "${1%.src}"' _ {} \;

# 3. generate the pb the tests import. It is NOT published: it is generated
#    output, and a project's own codegen emits its own copy per activation.
w17ctl plugin gen-pb .

# 4. run
cd src && go test ./...
```

Step 3 needs a reachable w17 console, because compiling proto is the compiler's
job and `w17ctl` deliberately does none of it. If you have the pb from elsewhere,
drop it at `src/gen/pb/` and skip that step.

## What these tests are, and are not

They are **unit tests** — no database, no network, no console, no container. That
is not a policy applied to them after the fact; it is measured, and it is what
lets them run from this tree at all.

A plugin's integration behaviour is exercised in the source repository against
real databases and a real console, and cannot be published here: it needs the
compiler, the generated bundles and a stack. If a test here starts needing any of
that, the publish gate fails and it does not ship.

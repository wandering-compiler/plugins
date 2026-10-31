### 0.1.0-rc.50 does not build in a project (fixed)

0.1.0-rc.50 imported `filippo.io/age` from a file that is copied into your
service, whose `go.mod` does not require it: every build failed with
"imports filippo.io/age from implicitly required module". The sealing moved
into the plugin's own `lib/`, which brings its requirements along. Nothing to
do but install this release instead of 0.1.0-rc.50; the events and settings
are unchanged.

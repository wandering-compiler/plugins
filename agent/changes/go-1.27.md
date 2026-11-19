### Built with Go 1.27

The plugin's modules now declare `go 1.27.0`, and any sandbox image it ships
builds on `golang:1.27-alpine`. A project that vendors it needs Go 1.27 or newer, which
w17 0.1.0 generates for and builds with.

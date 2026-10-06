package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
)

// mint is `relay mint`: make (or keep) a pinned identity in a directory and
// print its fingerprint — what an operator puts on a deployment once, before
// anything starts:
//
//	relay mint --dir <d> --name relay --ca   # the relay: its identity and its worker CA
//	relay mint --dir <d> --name console      # the control plane's client identity
//
// IDEMPOTENT: an existing identity is loaded, never replaced, because every
// fingerprint printed here is pinned somewhere (the relay's row, the relay's
// RELAY_CONTROL_PLANE_FINGERPRINT, every worker chained to the CA).
func mint(args []string, out io.Writer) error {
	var dir, name string
	var ca bool
	fs := flag.NewFlagSet("relay mint", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&dir, "dir", "", "directory the identity lives in (<name>.crt / <name>.key)")
	fs.StringVar(&name, "name", "", "file name of the identity: relay, console, …")
	fs.BoolVar(&ca, "ca", false, "also make (or keep) the worker CA in the same directory (ca.crt / ca.key) — for a relay")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(dir) == "" || strings.TrimSpace(name) == "" {
		return errors.New("mint: --dir and --name are required")
	}
	id, err := identity.LoadOrCreateIdentity(dir, name)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "%s %s\n", name, id.Fingerprint); err != nil {
		return err
	}
	if ca {
		if _, err := identity.LoadOrCreateCA(dir); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "ca %s/ca.crt\n", dir); err != nil {
			return err
		}
	}
	return nil
}

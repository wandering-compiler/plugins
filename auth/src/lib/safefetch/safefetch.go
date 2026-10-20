// Package safefetch fetches a small document from a URL a stranger chose —
// an OAuth client's metadata document (CIMD), whose URL is the client_id
// anyone may send — without letting that stranger aim the server at its
// own network (SSRF).
//
// The address is checked where it is dialled, after resolution, so a name
// that resolves to a private address (or is re-resolved to one between a
// check and the connection — DNS rebinding) is refused. Redirects are not
// followed: a redirect is another URL to check, and a metadata document has
// no reason to move.
package safefetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrRefused is the cause of every refusal of the URL or its address.
var ErrRefused = errors.New("safefetch: refused")

// Options tune Get. The zero value is the safe default.
type Options struct {
	// MaxBytes caps the body (default 16 KiB); a larger one is an error.
	MaxBytes int64
	// Timeout bounds the whole fetch (default 5 s).
	Timeout time.Duration
	// Accept is the Accept header (default application/json).
	Accept string
	// AllowAddr, when set, replaces the public-address rule. Tests only.
	AllowAddr func(netip.Addr) bool

	// tlsConfig replaces the system roots. Tests only.
	tlsConfig *tls.Config
}

// Get fetches rawURL, which must be https on the default port or an
// explicit one, with a host that is a name (not an IP literal), and
// returns the body of a 200 answer.
func Get(ctx context.Context, rawURL string, opt Options) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("%w: %q is not an https URL", ErrRefused, rawURL)
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return nil, fmt.Errorf("%w: %q names an IP address, not a host", ErrRefused, rawURL)
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 16 << 10
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.Accept == "" {
		opt.Accept = "application/json"
	}
	allow := opt.AllowAddr
	if allow == nil {
		allow = Public
	}
	dialer := &net.Dialer{
		Timeout: opt.Timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allow(ap.Addr()) {
				return fmt.Errorf("%w: address %s is not public", ErrRefused, address)
			}
			return nil
		},
	}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   opt.Timeout,
		ResponseHeaderTimeout: opt.Timeout,
		DisableKeepAlives:     true,
		Proxy:                 nil,
		TLSClientConfig:       opt.tlsConfig,
	}
	cl := &http.Client{
		Transport:     tr,
		Timeout:       opt.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", opt.Accept)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("safefetch: %s answered %d", u.Host, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, opt.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > opt.MaxBytes {
		return nil, fmt.Errorf("safefetch: %s answered more than %d bytes", u.Host, opt.MaxBytes)
	}
	return body, nil
}

// cgnat is the shared address space (RFC 6598), private in all but name.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// translated are the IPv6 ranges that reach an IPv4 address through a
// translator or tunnel — NAT64 (RFC 6052, RFC 8215), 6to4 (RFC 3056) and
// Teredo (RFC 4380) — so a private IPv4 address hides behind a global-looking
// IPv6 one.
var translated = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

// Public reports whether a is an address on the public internet: not
// loopback, private, link-local, multicast, unspecified, shared (CGNAT) or
// reserved (IPv4 240/4, the IPv6 documentation and ULA ranges are covered by
// IsPrivate / the global-unicast check).
func Public(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a.IsUnspecified(), !a.IsGlobalUnicast():
		return false
	case a.Is4() && (cgnat.Contains(a) || a.As4()[0] >= 240 || a.As4()[0] == 0):
		return false
	}
	for _, p := range translated {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

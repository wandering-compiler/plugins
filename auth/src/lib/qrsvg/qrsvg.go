// Package qrsvg renders text as a QR code in a self-contained SVG document.
//
// The ENCODING (data bits, Reed-Solomon check bytes, the module matrix) is
// rsc.io/qr's: getting it wrong does not fail, it makes a code some phones
// cannot read, and it is the part not worth writing twice. The rendering is
// here — a matrix of modules becomes one path of unit squares on a white
// background, with the four-module quiet zone the standard requires (and the
// encoder's matrix does not include).
package qrsvg

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// quiet is the margin, in modules, ISO/IEC 18004 requires around a code.
const quiet = 4

// SVG encodes text at error-correction level M (the authenticator-app
// default: survives ~15% damage at a modest size) and returns the SVG. The
// viewBox is in modules, so it scales to any size without blurring; width
// and height are left to the page.
func SVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("qrsvg: %w", err)
	}
	return render(code.Size, code.Black), nil
}

func render(size int, black func(x, y int) bool) string {
	side := size + 2*quiet
	var path strings.Builder
	for y := 0; y < size; y++ {
		for x := 0; x < size; {
			if !black(x, y) {
				x++
				continue
			}
			// One rectangle per horizontal run keeps the document small: a
			// version-6 code is ~1700 modules, ~500 runs.
			run := 1
			for x+run < size && black(x+run, y) {
				run++
			}
			fmt.Fprintf(&path, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`+
		`<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="%s"/></svg>`,
		side, side, side, side, path.String())
}

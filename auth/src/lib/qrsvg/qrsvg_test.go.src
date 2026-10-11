package qrsvg

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"rsc.io/qr"
)

// The SVG paints exactly the encoder's black modules — every one of them,
// nothing else — offset by the quiet zone, inside a white square that
// includes it. Checked by parsing the path back into a module grid.
func TestSVG_PaintsExactlyTheEncodersModules(t *testing.T) {
	text := "otpauth://totp/Acme:a%40b.example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA1&digits=6&period=30"
	svg, err := SVG(text)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := qr.Encode(text, qr.M)
	side := code.Size + 2*quiet

	var doc struct {
		ViewBox string `xml:"viewBox,attr"`
		Rect    struct {
			Width int    `xml:"width,attr"`
			Fill  string `xml:"fill,attr"`
		} `xml:"rect"`
		Path struct {
			D string `xml:"d,attr"`
		} `xml:"path"`
	}
	if err := xml.Unmarshal([]byte(svg), &doc); err != nil {
		t.Fatalf("not well-formed XML: %v\n%s", err, svg)
	}
	if doc.ViewBox != fmt.Sprintf("0 0 %d %d", side, side) || doc.Rect.Width != side || doc.Rect.Fill != "#fff" {
		t.Errorf("viewBox %q / background %d %q, want %d with a white quiet zone", doc.ViewBox, doc.Rect.Width, doc.Rect.Fill, side)
	}

	painted := map[[2]int]bool{}
	for _, m := range regexp.MustCompile(`M(\d+) (\d+)h(\d+)v1h-(\d+)z`).FindAllStringSubmatch(doc.Path.D, -1) {
		x, _ := strconv.Atoi(m[1])
		y, _ := strconv.Atoi(m[2])
		w, _ := strconv.Atoi(m[3])
		for i := 0; i < w; i++ {
			painted[[2]int{x + i, y}] = true
		}
	}
	if strings.Count(doc.Path.D, "M") == 0 {
		t.Fatal("nothing painted")
	}
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			want := code.Black(x-quiet, y-quiet) // false in the quiet zone
			if painted[[2]int{x, y}] != want {
				t.Fatalf("module (%d,%d): painted=%v, encoder says %v", x, y, painted[[2]int{x, y}], want)
			}
		}
	}
}

func TestSVG_RefusesWhatDoesNotFit(t *testing.T) {
	if _, err := SVG(strings.Repeat("x", 5000)); err == nil {
		t.Error("a text beyond QR capacity was encoded")
	}
}

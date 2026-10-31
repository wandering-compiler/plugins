package handlers

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// usage gap 3: a usage period is one of the ISO 8601 windows, in one
// spelling; every other spelling is refused, never guessed at.
func TestCanonicalPeriod(t *testing.T) {
	ok := map[string]string{
		"2026":             "2026",
		"2026-06":          "2026-06",
		"2026-12":          "2026-12",
		"2026-W01":         "2026-W01",
		"2026-w23":         "2026-W23",
		"2026-W53":         "2026-W53", // 2026 has 53 ISO weeks
		"2026-06-15":       "2026-06-15",
		"2028-02-29":       "2028-02-29", // a leap day
		" 2026-06 ":        "2026-06",
		"2026-06-03/P7D":   "2026-06-03/P7D",
		"2026-06-03/p30d":  "2026-06-03/P30D",
		"2026-06-03/P007D": "2026-06-03/P7D",
		"2026-01-01/P366D": "2026-01-01/P366D",
	}
	for in, want := range ok {
		got, err := canonicalPeriod(in)
		if err != nil || got != want {
			t.Errorf("canonicalPeriod(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "   ",
		"2026/06", "2026-6", "202606", "June 2026", "06-2026",
		"2026-00", "2026-13", "0000", "0000-01", "26",
		"2025-W53", // 2025 has 52
		"2026-W00", "2026-W54", "2026-W5",
		"2026-02-30", "2027-02-29", "2026-6-15", "2026-06-15T00:00:00Z",
		"2026-06-03/P0D", "2026-06-03/P367D", "2026-06-03/P1W", "2026-06-03/PT24H",
		"2026-06-03/", "/P7D", "2026-06/P7D", "2026-06-03/P7D/P1D",
	} {
		if got, err := canonicalPeriod(in); err == nil {
			t.Errorf("canonicalPeriod(%q) = %q, want a refusal", in, got)
		} else if !strings.Contains(err.Error(), "ISO 8601") && !strings.Contains(err.Error(), "days") {
			t.Errorf("canonicalPeriod(%q) refused without saying what it takes: %v", in, err)
		}
	}
}

// One window is one meter: a report under another spelling of the same window
// counts on the same meter, and the read finds it under either.
func TestReportUsage_OneWindowIsOneMeter(t *testing.T) {
	r := newRig(t)
	for i, period := range []string{"2026-w23", "2026-W23", " 2026-W23 "} {
		v, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api", Period: period, Quantity: 2, IdempotencyKey: "k" + string(rune('a'+i))})
		if err != nil {
			t.Fatalf("report under %q: %v", period, err)
		}
		if v.GetPeriod() != "2026-W23" || v.GetTotal() != int64(2*(i+1)) {
			t.Errorf("report under %q answered %s total %d, want 2026-W23 total %d", period, v.GetPeriod(), v.GetTotal(), 2*(i+1))
		}
	}
	got, err := r.h.GetMyUsageMeter(asCaller("user-a"), &pb.GetMyUsageMeterReq{Meter: "api", Period: "2026-w23"})
	if err != nil || got.GetMeter().GetTotal() != 6 {
		t.Errorf("read under another spelling = %v, %v; want the one meter of 6", got.GetMeter(), err)
	}
}

// A spelling that is no window is refused on both paths, with what is taken.
func TestUsage_AnUnknownPeriodIsRefused(t *testing.T) {
	r := newRig(t)
	_, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api", Period: "2026/06", Quantity: 1, IdempotencyKey: "k"})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "2026-06") {
		t.Errorf("report under 2026/06 = %v, want InvalidArgument naming the shapes", err)
	}
	_, err = r.h.GetMyUsageMeter(asCaller("user-a"), &pb.GetMyUsageMeterReq{Meter: "api", Period: "June"})
	wantCode(t, err, codes.InvalidArgument, "a read under no window")
	if n := r.store.callCount("RecordUsage"); n != 0 {
		t.Errorf("a refused report reached the store (%d calls)", n)
	}
}

package handlers

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// periodShapes is what a usage period may be, said in every refusal.
const periodShapes = `an ISO 8601 window: a year "2026", a month "2026-06", an ISO week "2026-W23", a day "2026-06-15", or N days from a day "2026-06-03/P7D"`

// maxRollingDays bounds a rolling window: a year and a day. A meter over a
// longer window is a year's meter.
const maxRollingDays = 366

// canonicalPeriod parses a usage period and answers its one canonical
// spelling, so that one billing window is one meter. The column is a string,
// and every spelling of a window used to be a meter of its own: "2026-06",
// "2026/06" and "2026-6" counted June three times over.
//
// The accepted windows are ISO 8601:
//
//   - a calendar year, "2026";
//   - a month, "2026-06";
//   - an ISO week, which starts on a Monday, "2026-W23" (W53 only in a year
//     that has one);
//   - a day, "2026-06-15";
//   - N days from a day, "2026-06-03/P7D", an interval of a start and a
//     duration in days (1 to 366). A rolling window is not a calendar one:
//     "2026-W23" is Monday to Sunday, "2026-06-03/P7D" is the seven days from
//     the 3rd.
//
// Canonical means: the letters W, P and D upper case, no leading zeros in the
// day count, no surrounding space. Anything else — another separator, a
// one-digit month, a date that does not exist, a time of day — is refused,
// never guessed at.
func canonicalPeriod(s string) (string, error) {
	p := strings.TrimSpace(s)
	if p == "" {
		return "", fmt.Errorf("period is required: %s", periodShapes)
	}
	if start, dur, ok := strings.Cut(p, "/"); ok {
		day, err := canonicalDay(start)
		if err != nil {
			return "", err
		}
		n, err := rollingDays(dur)
		if err != nil {
			return "", fmt.Errorf("period %q: %w", s, err)
		}
		return day + "/P" + strconv.Itoa(n) + "D", nil
	}
	switch {
	case isDigits(p) && len(p) == 4:
		if p == "0000" {
			return "", fmt.Errorf("period %q is not a year: %s", s, periodShapes)
		}
		return p, nil
	case len(p) == 7 && p[4] == '-' && isDigits(p[:4]) && isDigits(p[5:]):
		if _, err := time.Parse("2006-01", p); err != nil || p[:4] == "0000" {
			return "", fmt.Errorf("period %q is not a month: %s", s, periodShapes)
		}
		return p, nil
	case len(p) == 8 && p[4] == '-' && (p[5] == 'W' || p[5] == 'w') && isDigits(p[:4]) && isDigits(p[6:]):
		year, _ := strconv.Atoi(p[:4])
		week, _ := strconv.Atoi(p[6:])
		if year == 0 || week < 1 || week > isoWeeksIn(year) {
			return "", fmt.Errorf("period %q is not an ISO week of %04d (it has %d): %s", s, year, isoWeeksIn(year), periodShapes)
		}
		return p[:4] + "-W" + p[6:], nil
	case len(p) == 10:
		return canonicalDay(p)
	}
	return "", fmt.Errorf("period %q is not %s", s, periodShapes)
}

// canonicalDay checks a "YYYY-MM-DD" that exists in the calendar.
func canonicalDay(s string) (string, error) {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' || !isDigits(s[:4]) || !isDigits(s[5:7]) || !isDigits(s[8:]) || s[:4] == "0000" {
		return "", fmt.Errorf("period %q is not a day: %s", s, periodShapes)
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return "", fmt.Errorf("period %q is not a day of the calendar: %s", s, periodShapes)
	}
	return s, nil
}

// rollingDays reads an ISO 8601 duration in whole days, "P7D".
func rollingDays(d string) (int, error) {
	u := strings.ToUpper(d)
	if len(u) < 3 || u[0] != 'P' || u[len(u)-1] != 'D' || !isDigits(u[1:len(u)-1]) {
		return 0, fmt.Errorf("the duration %q is not a number of days (\"P7D\")", d)
	}
	n, err := strconv.Atoi(u[1 : len(u)-1])
	if err != nil || n < 1 || n > maxRollingDays {
		return 0, fmt.Errorf("the duration %q must be 1 to %d days", d, maxRollingDays)
	}
	return n, nil
}

// isoWeeksIn is the number of ISO weeks in year: 28 December is always in
// its last one.
func isoWeeksIn(year int) int {
	_, w := time.Date(year, time.December, 28, 0, 0, 0, 0, time.UTC).ISOWeek()
	return w
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

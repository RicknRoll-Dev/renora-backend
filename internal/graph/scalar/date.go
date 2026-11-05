package scalar

import (
	"fmt"
	"io"
	"strconv"
	"time"
)

// Date is a calendar day with no time or zone, `2026-11-30`.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// DateOf is the calendar day of t in Asia/Jakarta.
func DateOf(t time.Time) Date {
	y, m, d := t.In(Jakarta).Date()
	return Date{y, m, d}
}

func ParseDate(s string) (Date, error) {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return Date{}, invalid("Date must be YYYY-MM-DD", "Date harus berformat YYYY-MM-DD")
	}
	return Date{t.Year(), t.Month(), t.Day()}, nil
}

func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day) }

// IsZero reports whether d is the zero Date.
func (d Date) IsZero() bool { return d == Date{} }

// Start is midnight of d in Asia/Jakarta.
func (d Date) Start() time.Time { return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, Jakarta) }

func (d Date) MarshalGQL(w io.Writer) { _, _ = io.WriteString(w, strconv.Quote(d.String())) }

func (d *Date) UnmarshalGQL(v any) error {
	s, ok := v.(string)
	if !ok {
		return invalid("Date must be a YYYY-MM-DD string", "Date harus berupa teks YYYY-MM-DD")
	}
	parsed, err := ParseDate(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

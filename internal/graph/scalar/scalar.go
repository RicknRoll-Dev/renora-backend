// Package scalar implements the contract's custom scalars (schema/schema.graphql):
// Money, Bps, DateTime and Date.
package scalar

import (
	"encoding/json"
	"io"
	"math"
	"strconv"
	"time"
	_ "time/tzdata" // the distroless image ships no zoneinfo

	"github.com/99designs/gqlgen/graphql"

	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/i18n"
)

// invalid is a BAD_USER_INPUT error: a malformed scalar is the client's mistake,
// so it must not be masked as INTERNAL.
func invalid(en, id string) error { return apperr.BadUserInput(i18n.T(en, id)) }

// Jakarta is the zone DateTime values are written in. Clients format in it too.
var Jakarta = mustLoad("Asia/Jakarta")

func mustLoad(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

// maxSafe is 2^53-1: the contract keeps Money below it so JavaScript numbers hold it exactly.
const maxSafe = 1<<53 - 1

// MarshalMoney writes whole rupiah as a JSON integer.
func MarshalMoney(v int64) graphql.Marshaler {
	return graphql.WriterFunc(func(w io.Writer) {
		_, _ = io.WriteString(w, strconv.FormatInt(v, 10))
	})
}

// UnmarshalMoney accepts a JSON integer within ±(2^53-1). Strings and fractions are rejected;
// whether a field may be negative is the field's rule, not the scalar's.
func UnmarshalMoney(v any) (int64, error) {
	n, err := integer(v, "Money")
	if err != nil {
		return 0, err
	}
	if n > maxSafe || n < -maxSafe {
		return 0, invalid("Money must be below 2^53", "Money harus di bawah 2^53")
	}
	return n, nil
}

// MarshalBps writes integer basis points (2000 = 20%).
func MarshalBps(v int) graphql.Marshaler {
	return graphql.WriterFunc(func(w io.Writer) {
		_, _ = io.WriteString(w, strconv.Itoa(v))
	})
}

func UnmarshalBps(v any) (int, error) {
	n, err := integer(v, "Bps")
	if err != nil {
		return 0, err
	}
	if n > math.MaxInt32 || n < math.MinInt32 {
		return 0, invalid("Bps is out of range", "Bps di luar rentang")
	}
	return int(n), nil
}

// MarshalDateTime writes RFC 3339 in Asia/Jakarta with its offset: 2026-11-11T10:00:00+07:00.
func MarshalDateTime(t time.Time) graphql.Marshaler {
	return graphql.WriterFunc(func(w io.Writer) {
		_, _ = io.WriteString(w, strconv.Quote(t.In(Jakarta).Format(time.RFC3339)))
	})
}

// UnmarshalDateTime accepts RFC 3339 with an offset or Z. A time without an offset is ambiguous and rejected.
func UnmarshalDateTime(v any) (time.Time, error) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, invalid("DateTime must be an RFC 3339 string", "DateTime harus berupa teks RFC 3339")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, invalid(
			"DateTime must be RFC 3339 with an offset, e.g. 2026-11-11T10:00:00+07:00",
			"DateTime harus RFC 3339 dengan offset, mis. 2026-11-11T10:00:00+07:00",
		)
	}
	return t, nil
}

func integer(v any, name string) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case int32:
		return int64(n), nil
	case json.Number:
		i, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			return 0, wholeNumber(name)
		}
		return i, nil
	case float64:
		// Variables decoded without UseNumber arrive as float64.
		if n != math.Trunc(n) || math.IsInf(n, 0) || math.IsNaN(n) || math.Abs(n) > maxSafe {
			return 0, wholeNumber(name)
		}
		return int64(n), nil
	default:
		return 0, invalid(name+" must be a JSON integer", name+" harus berupa bilangan bulat JSON")
	}
}

func wholeNumber(name string) error {
	return invalid(name+" must be a whole number", name+" harus bilangan bulat")
}

package scalar

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/renora/renora-api/internal/apperr"
)

func TestMoney(t *testing.T) {
	var b bytes.Buffer
	MarshalMoney(12125000).MarshalGQL(&b)
	if b.String() != "12125000" {
		t.Errorf("marshal = %s, want a bare JSON integer", b.String())
	}

	ok := []any{int64(12125000), 48500000, json.Number("-6000000"), float64(9700000), json.Number("9007199254740991")}
	for _, v := range ok {
		if _, err := UnmarshalMoney(v); err != nil {
			t.Errorf("UnmarshalMoney(%#v): %v", v, err)
		}
	}
	bad := []any{"12125000", "Rp 12.125.000", json.Number("1.5"), float64(1.5), json.Number("9007199254740992"), nil, true}
	for _, v := range bad {
		if _, err := UnmarshalMoney(v); err == nil {
			t.Errorf("UnmarshalMoney(%#v): want error", v)
		}
	}
}

func TestBps(t *testing.T) {
	if n, err := UnmarshalBps(json.Number("2000")); err != nil || n != 2000 {
		t.Errorf("UnmarshalBps(2000) = %d, %v", n, err)
	}
	if _, err := UnmarshalBps(json.Number("20.5")); err == nil {
		t.Error("fractional bps should be rejected")
	}
}

func TestDateTime(t *testing.T) {
	var b bytes.Buffer
	MarshalDateTime(time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)).MarshalGQL(&b)
	if b.String() != `"2026-11-11T10:00:00+07:00"` {
		t.Errorf("marshal = %s, want WIB with offset", b.String())
	}

	got, err := UnmarshalDateTime("2026-11-11T10:00:00+07:00")
	if err != nil || !got.Equal(time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)) {
		t.Errorf("UnmarshalDateTime = %v, %v", got, err)
	}
	for _, v := range []any{"2026-11-11T10:00:00", "2026-11-11", 1731294000} {
		if _, err := UnmarshalDateTime(v); err == nil {
			t.Errorf("UnmarshalDateTime(%#v): want error", v)
		}
	}
}

func TestDate(t *testing.T) {
	var d Date
	if err := d.UnmarshalGQL("2026-11-30"); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	d.MarshalGQL(&b)
	if b.String() != `"2026-11-30"` {
		t.Errorf("marshal = %s", b.String())
	}
	if err := d.UnmarshalGQL("30/11/2026"); err == nil {
		t.Error("want error for a non-ISO date")
	}
	// 23:30 UTC on 29 Nov is already 30 Nov in Jakarta.
	if got := DateOf(time.Date(2026, 11, 29, 23, 30, 0, 0, time.UTC)); got.String() != "2026-11-30" {
		t.Errorf("DateOf = %s, want the Jakarta calendar day", got)
	}
}

// A malformed scalar is the client's mistake: it must reach the client as
// BAD_USER_INPUT, not be masked as INTERNAL.
func TestErrorsAreBadUserInput(t *testing.T) {
	var d Date
	errs := []error{
		func() error { _, err := UnmarshalMoney("12125000"); return err }(),
		func() error { _, err := UnmarshalBps(json.Number("1.5")); return err }(),
		func() error { _, err := UnmarshalDateTime("tomorrow"); return err }(),
		d.UnmarshalGQL("30/11/2026"),
	}
	for _, err := range errs {
		ae, ok := apperr.As(err)
		if !ok || ae.Code != apperr.CodeBadUserInput || ae.Message.ID == "" {
			t.Errorf("%v: want a bilingual BAD_USER_INPUT apperr", err)
		}
	}
}

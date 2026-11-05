package account

import (
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	} {
		if got := totpAt(secret, unix/totpPeriod); got != want {
			t.Errorf("TOTP at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPMatch(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	step := now.Unix() / totpPeriod
	if s, ok := totpMatch(secret, totpAt(secret, step-1), now, 0); !ok || s != step-1 {
		t.Error("the previous step's code should pass (clock skew)")
	}
	if _, ok := totpMatch(secret, totpAt(secret, step-2), now, 0); ok {
		t.Error("a code two steps old must fail")
	}
	if _, ok := totpMatch(secret, totpAt(secret, step), now, step); ok {
		t.Error("a code already used must fail")
	}
}

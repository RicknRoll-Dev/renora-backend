package account

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// Authenticator codes: RFC 6238 with the parameters every authenticator app
// supports (HMAC-SHA1, 6 digits, 30-second steps).
const (
	totpPeriod = 30
	// totpSkew accepts the step before and after, for a phone clock a little off.
	totpSkew = 1
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// totpAt is the code for one time step.
func totpAt(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // steps are positive
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}

// totpMatch finds the step a code belongs to, near now and after the last
// accepted step (so a code is used once). ok is false when none matches.
func totpMatch(secret []byte, code string, now time.Time, after int64) (step int64, ok bool) {
	cur := now.Unix() / totpPeriod
	for s := cur - totpSkew; s <= cur+totpSkew; s++ {
		if s > after && hmac.Equal([]byte(totpAt(secret, s)), []byte(code)) {
			return s, true
		}
	}
	return 0, false
}

// totpURI is what the authenticator app scans: otpauth://totp/Renora:email?...
func totpURI(secret []byte, email string) string {
	q := url.Values{}
	q.Set("secret", totpEncoding.EncodeToString(secret))
	q.Set("issuer", "Renora")
	q.Set("period", fmt.Sprint(totpPeriod))
	q.Set("digits", "6")
	q.Set("algorithm", "SHA1")
	return "otpauth://totp/" + url.PathEscape("Renora:"+email) + "?" + q.Encode()
}

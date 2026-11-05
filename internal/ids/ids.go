// Package ids makes the prefixed identifiers the contract uses (usr_…, ses_…)
// and the secret tokens handed to clients.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
)

// crockford is Crockford's base32 alphabet: no I, L, O or U, so an ID read
// aloud or copied by hand is not mistaken.
var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// New returns prefix_ followed by 16 random characters (80 bits), e.g. usr_7M2K9Q4XH1D8B3TW.
func New(prefix string) string {
	b := make([]byte, 10)
	_, _ = rand.Read(b) // never fails (crypto/rand panics on failure)
	return prefix + "_" + crockford.EncodeToString(b)
}

// Token returns a 256-bit secret, base64url without padding, for session and
// CSRF tokens.
func Token() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash is how a token is stored: SHA-256. Tokens carry 256 bits, so a plain
// hash is enough; a database copy cannot be turned back into a token.
func Hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

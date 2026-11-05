// Package problem defines domain problems: outcomes a mutation returns as data in
// its result union (`NotFound`, `Conflict`, `InvalidInput`, `QuotaReached`), never
// as GraphQL errors. Domain code returns a *Problem; the GraphQL layer turns it into
// the union member. Codes are the contract's `ProblemCode` wire values.
package problem

import (
	"fmt"

	"github.com/renora/renora-api/internal/i18n"
)

type Kind int

const (
	KindNotFound Kind = iota + 1
	KindConflict
	KindInvalidInput
	KindQuotaReached
)

func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "NotFound"
	case KindConflict:
		return "Conflict"
	case KindInvalidInput:
		return "InvalidInput"
	case KindQuotaReached:
		return "QuotaReached"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

type Problem struct {
	Kind    Kind
	Code    string    // a ProblemCode wire value: "not_found", "already_funded", ...
	Message i18n.Text // safe to show, in both languages
	Field   string    // InvalidInput only: input path, "signature.code", "lines.0.quantity"
	Reason  string    // InvalidInput only: "required", "wrong_code", "band_rules", ...
}

// Error lets a *Problem travel through code that returns error; it is still data
// to the GraphQL layer, never a top-level error.
func (p *Problem) Error() string { return fmt.Sprintf("%s %s: %s", p.Kind, p.Code, p.Message.EN) }

func NotFound(msg i18n.Text) *Problem {
	return &Problem{Kind: KindNotFound, Code: "not_found", Message: msg}
}

// LinkExpired is the NotFound a personal link answers once it has expired or been replaced.
func LinkExpired(msg i18n.Text) *Problem {
	return &Problem{Kind: KindNotFound, Code: "link_expired", Message: msg}
}

func Conflict(code string, msg i18n.Text) *Problem {
	return &Problem{Kind: KindConflict, Code: code, Message: msg}
}

// Invalid is an InvalidInput with code invalid_input.
func Invalid(field, reason string, msg i18n.Text) *Problem {
	return &Problem{Kind: KindInvalidInput, Code: "invalid_input", Field: field, Reason: reason, Message: msg}
}

// InvalidCode is an InvalidInput with a specific code (`wrong_code`, `challenge_expired`).
func InvalidCode(code, field, reason string, msg i18n.Text) *Problem {
	return &Problem{Kind: KindInvalidInput, Code: code, Field: field, Reason: reason, Message: msg}
}

func QuotaReached(msg i18n.Text) *Problem {
	return &Problem{Kind: KindQuotaReached, Code: "quota_exhausted", Message: msg}
}

// IdempotencyMismatch answers a key reused with a different input.
func IdempotencyMismatch() *Problem {
	return Conflict("idempotency_mismatch", i18n.T(
		"This key was used for a different request",
		"Kunci ini sudah dipakai untuk permintaan lain",
	))
}

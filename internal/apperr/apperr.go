// Package apperr defines transport and auth errors, the ones the contract puts in
// `errors[].extensions.code`. Domain problems are not errors: they are data in a
// mutation's result union (see package problem). Anything that is neither is
// treated as internal and masked.
package apperr

import (
	"errors"
	"fmt"

	"github.com/renora/renora-api/internal/i18n"
)

// Code is one of the contract's transport codes.
type Code string

const (
	CodeUnauthenticated Code = "UNAUTHENTICATED"
	CodeForbidden       Code = "FORBIDDEN"
	CodeCSRFFailed      Code = "CSRF_FAILED"
	CodeRateLimited     Code = "RATE_LIMITED"
	CodeBadUserInput    Code = "BAD_USER_INPUT"
	CodeInternal        Code = "INTERNAL"
)

type Error struct {
	Code    Code
	Message i18n.Text // shown to the client in the request's language; never secrets or SQL
	Err     error     // cause, logged but never shown
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message.EN, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message.EN)
}

func (e *Error) Unwrap() error { return e.Err }

func New(code Code, msg i18n.Text) *Error { return &Error{Code: code, Message: msg} }

// The messages match the contract's mock, so the apps show the same words.
func Unauthenticated() *Error {
	return New(CodeUnauthenticated, i18n.T("Sign in first", "Masuk dulu"))
}

func Forbidden() *Error {
	return New(CodeForbidden, i18n.T("Not allowed for your role", "Tidak diizinkan untuk peran Anda"))
}

func CSRFFailed() *Error {
	return New(CodeCSRFFailed, i18n.T("Refresh the page and try again", "Muat ulang halaman lalu coba lagi"))
}

func RateLimited() *Error {
	return New(CodeRateLimited, i18n.T("Too many tries. Wait a moment and try again", "Terlalu banyak percobaan. Tunggu sebentar lalu coba lagi"))
}

func BadUserInput(msg i18n.Text) *Error { return New(CodeBadUserInput, msg) }

// Internal wraps an unexpected failure; the client sees only a generic message.
func Internal(err error) *Error {
	return &Error{Code: CodeInternal, Message: i18n.T("Something went wrong. Try again", "Ada yang salah. Coba lagi"), Err: err}
}

// As returns the *Error in err's chain, if any.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

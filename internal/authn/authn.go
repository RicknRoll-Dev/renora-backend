// Package authn finds who is calling. It reads the credentials the contract
// defines and resolves them to a session; it does not decide what the caller
// may do (that is the GraphQL layer's @public / @allow / @private).
//
//   - Mobile sends `Authorization: Bearer <token>`.
//   - Web sends the httpOnly `renora_session` cookie, and on every mutation
//     `X-CSRF-Token` equal to the `renora_csrf` cookie.
//   - Link pages send neither: the link token in the operation's arguments is
//     the permission.
package authn

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/renora/renora-api/internal/i18n"
)

const (
	SessionCookie = "renora_session"
	CSRFCookie    = "renora_csrf"
	CSRFHeader    = "X-CSRF-Token"
)

// Role is a contract `Role` wire value: the role a session signed in as.
type Role string

const (
	RoleOwner      Role = "owner"
	RoleContractor Role = "contractor"
	RoleSupplier   Role = "supplier"
	RoleOps        Role = "ops"
	RoleCrew       Role = "crew"
	RoleDriver     Role = "driver"
)

type Client string

const (
	ClientWeb    Client = "web"
	ClientMobile Client = "mobile"
)

type Session struct {
	ID        string
	UserID    string
	Role      Role
	Client    Client
	CSRFToken string // web sessions only
	Language  i18n.Lang
	ExpiresAt time.Time
	Guest     bool // read-only session from an owner link; signing needs a phone code
}

// SessionStore resolves a presented session token. It returns (nil, nil) for a
// token that is unknown, expired or signed out, and an error only when it could
// not tell (the database is down).
type SessionStore interface {
	Lookup(ctx context.Context, token string) (*Session, error)
}

// Viewer is the caller of one request.
type Viewer struct {
	Session *Session // nil when anonymous
	// ViaCookie is true when the session came from the cookie, so mutations need
	// the CSRF header. A bearer token cannot be sent cross-site by a browser.
	ViaCookie bool
	// CSRF is the X-CSRF-Token header the request carried.
	CSRF string
	// UserAgent names the device in the person's list of signed-in sessions.
	UserAgent string
}

// SignedIn reports whether the request carries a live session.
func (v Viewer) SignedIn() bool { return v.Session != nil }

// CSRFValid reports whether a cookie session's mutation carries the matching CSRF token.
// Requests authenticated by bearer token always pass.
func (v Viewer) CSRFValid() bool {
	if !v.ViaCookie || v.Session == nil {
		return true
	}
	want := v.Session.CSRFToken
	return want != "" && subtle.ConstantTimeCompare([]byte(v.CSRF), []byte(want)) == 1
}

type ctxKey struct{}

func WithViewer(ctx context.Context, v Viewer) context.Context {
	return context.WithValue(ctx, ctxKey{}, v)
}

// From returns the request's viewer; anonymous when none was set.
func From(ctx context.Context) Viewer {
	v, _ := ctx.Value(ctxKey{}).(Viewer)
	return v
}

// ErrUnavailable means the session store could not answer. The request must
// fail as a server error, never as UNAUTHENTICATED: that would sign people out
// of the apps during an outage.
var ErrUnavailable = errors.New("session store unavailable")

// Resolve finds the session for a bearer token (preferred) or the session cookie.
func Resolve(ctx context.Context, store SessionStore, r *http.Request) (Viewer, error) {
	token, viaCookie := credentials(r)
	v := Viewer{CSRF: r.Header.Get(CSRFHeader), UserAgent: r.UserAgent()}
	if token == "" {
		return v, nil
	}
	s, err := store.Lookup(ctx, token)
	if err != nil {
		return v, errors.Join(ErrUnavailable, err)
	}
	if s != nil {
		v.Session, v.ViaCookie = s, viaCookie
	}
	return v, nil
}

// ResolveBearer finds the session for an `Authorization` value ("Bearer <token>"),
// as sent in a WebSocket's connectionParams.
func ResolveBearer(ctx context.Context, store SessionStore, authorization string) (*Session, error) {
	token, ok := bearer(authorization)
	if !ok {
		return nil, nil
	}
	s, err := store.Lookup(ctx, token)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return s, nil
}

func credentials(r *http.Request) (token string, viaCookie bool) {
	if t, ok := bearer(r.Header.Get("Authorization")); ok {
		return t, false
	}
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		return c.Value, true
	}
	return "", false
}

func bearer(h string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// NoSessions is a store where every token is unknown: only @public operations answer.
type NoSessions struct{}

func (NoSessions) Lookup(context.Context, string) (*Session, error) { return nil, nil }

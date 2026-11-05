package authn

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// CookieConfig shapes the web session cookies.
type CookieConfig struct {
	// Secure must be on in production. Browsers treat http://localhost as secure,
	// so it can stay on in development too.
	Secure bool
	// Domain is empty for a host-only cookie. Set it (renora.id) when the web app
	// and the API are on different subdomains of one site.
	Domain string
}

type responseKey struct{}

// WithResponseWriter lets a resolver set cookies on the HTTP response, as
// verifyCode and signOut must. The GraphQL HTTP transports write the response
// only after the operation has run, so a cookie set by a resolver is sent.
func WithResponseWriter(ctx context.Context, w http.ResponseWriter) context.Context {
	return context.WithValue(ctx, responseKey{}, w)
}

// ErrNoResponse means the request has no HTTP response to set cookies on: it
// came over a WebSocket.
var ErrNoResponse = errors.New("no HTTP response to set cookies on")

// CanSetCookies reports whether the request has an HTTP response to set cookies on.
func CanSetCookies(ctx context.Context) bool {
	_, ok := ctx.Value(responseKey{}).(http.ResponseWriter)
	return ok
}

// SetSessionCookies starts a web session: the httpOnly session cookie and the
// CSRF cookie the web app reads and echoes in X-CSRF-Token.
func SetSessionCookies(ctx context.Context, cfg CookieConfig, token, csrf string, expires time.Time) error {
	w, ok := ctx.Value(responseKey{}).(http.ResponseWriter)
	if !ok {
		return ErrNoResponse
	}
	http.SetCookie(w, cookie(cfg, SessionCookie, token, expires, true))
	http.SetCookie(w, cookie(cfg, CSRFCookie, csrf, expires, false))
	return nil
}

// SetQRCookie binds a QR sign-in to this browser (see account.CreateQRSignIn).
func SetQRCookie(ctx context.Context, cfg CookieConfig, secret string, expires time.Time) error {
	w, ok := ctx.Value(responseKey{}).(http.ResponseWriter)
	if !ok {
		return ErrNoResponse
	}
	http.SetCookie(w, cookie(cfg, QRCookie, secret, expires, true))
	return nil
}

// ClearSessionCookies ends a web session in the browser.
func ClearSessionCookies(ctx context.Context, cfg CookieConfig) {
	w, ok := ctx.Value(responseKey{}).(http.ResponseWriter)
	if !ok {
		return
	}
	for _, name := range []string{SessionCookie, CSRFCookie} {
		c := cookie(cfg, name, "", time.Unix(0, 0), name == SessionCookie)
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
}

func cookie(cfg CookieConfig, name, value string, expires time.Time, httpOnly bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   cfg.Domain,
		Expires:  expires,
		Secure:   cfg.Secure,
		HttpOnly: httpOnly,
		SameSite: http.SameSiteLaxMode,
	}
}

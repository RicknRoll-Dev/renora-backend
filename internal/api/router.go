// Package api assembles the public HTTP surface: probes and /graphql.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/config"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/platform/health"
	"github.com/renora/renora-api/internal/platform/httpx"
)

type Deps struct {
	Config   config.Config
	Logger   *slog.Logger
	Health   *health.Checker
	Metrics  *httpx.Metrics
	Sessions authn.SessionStore
	GraphQL  http.Handler
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(
		httpx.ClientIP(d.Config.HTTP.TrustedProxyHops),
		httpx.RequestID,
		httpx.AccessLog(d.Logger),
		httpx.Recover(d.Logger),
		d.Metrics.Middleware,
		httpx.SecurityHeaders,
	)

	r.Get("/healthz", health.Live)
	r.Get("/readyz", d.Health.Ready)

	r.Group(func(r chi.Router) {
		r.Use(
			corsMiddleware(d.Config.HTTP.CORSAllowedOrigins),
			httpx.MaxBody(d.Config.HTTP.MaxBodyBytes),
			requestTimeout(d.Config.HTTP.RequestTimeout),
			viewer(d.Sessions, d.Logger),
		)
		r.Handle("/graphql", d.GraphQL)
	})

	if *d.Config.GraphQL.Playground {
		r.Get("/", playground.Handler("Renora GraphQL", "/graphql"))
	}

	// otelhttp sits outermost so the span covers the whole request and the
	// request ID middleware already sees the trace context.
	return otelhttp.NewHandler(r, "http.server",
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/healthz" && r.URL.Path != "/readyz"
		}),
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// corsMiddleware allows the web app's origins. The web app sends its session
// cookie (credentials: "include") and echoes the CSRF cookie in X-CSRF-Token.
func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	return cors.New(cors.Options{
		AllowedOrigins:   origins,
		AllowCredentials: true,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowedHeaders: []string{
			"Authorization", "Content-Type", "Accept-Language",
			authn.CSRFHeader, httpx.RequestIDHeader,
		},
		ExposedHeaders: []string{httpx.RequestIDHeader},
		MaxAge:         600,
	}).Handler
}

// requestTimeout bounds ordinary requests. A WebSocket lives for as long as the
// app is open, so it skips the deadline, which would close it when it fires.
// (The server's read/write timeouts need no handling: net/http clears them when
// the connection is hijacked for the upgrade.)
func requestTimeout(d time.Duration) func(http.Handler) http.Handler {
	timeout := middleware.Timeout(d)
	return func(next http.Handler) http.Handler {
		bounded := timeout(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isWebSocketUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}
			bounded.ServeHTTP(w, r)
		})
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// viewer resolves the caller's session and the request's language, and lets
// resolvers set cookies on the response. When the
// session store cannot answer, the request fails with 503 rather than running
// signed out, so an outage never signs anyone out of the apps.
func viewer(sessions authn.SessionStore, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			v, err := authn.Resolve(ctx, sessions, r)
			if err != nil {
				logger.ErrorContext(ctx, "resolve session", "error", err)
				lang := i18n.Resolve(r.Header.Get("Accept-Language"), "")
				writeGraphQLError(w, http.StatusServiceUnavailable, apperr.Internal(err), lang)
				return
			}
			var userLang i18n.Lang
			if v.Session != nil {
				userLang = v.Session.Language
			}
			ctx = authn.WithViewer(ctx, v)
			ctx = i18n.WithLang(ctx, i18n.Resolve(r.Header.Get("Accept-Language"), userLang))
			// Resolvers set the web session cookies on this response (verifyCode,
			// signOut). A WebSocket's upgrade response is gone once the socket is
			// open, so operations over it get none.
			if !isWebSocketUpgrade(r) {
				ctx = authn.WithResponseWriter(ctx, w)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// writeGraphQLError answers outside the GraphQL executor in the GraphQL
// response shape, so clients read one error format.
func writeGraphQLError(w http.ResponseWriter, status int, e *apperr.Error, lang i18n.Lang) {
	var body struct {
		Errors []map[string]any `json:"errors"`
	}
	body.Errors = []map[string]any{{
		"message":    e.Message.In(lang),
		"extensions": map[string]any{"code": string(e.Code)},
	}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// OriginHosts turns CORS origins ("https://app.renora.id") into the host
// patterns the WebSocket origin check takes ("app.renora.id").
func OriginHosts(origins []string) []string {
	hosts := make([]string, 0, len(origins))
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			continue
		}
		hosts = append(hosts, u.Host)
	}
	return hosts
}

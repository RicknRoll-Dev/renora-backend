package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/config"
	"github.com/renora/renora-api/internal/graph"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/platform/health"
	"github.com/renora/renora-api/internal/platform/httpx"
)

const appOrigin = "https://app.renora.id"

// sessions stands in for the session table: Bu Dewi on the web (cookie), Arif
// from ops on a phone (bearer). Token "outage" makes the store fail.
type sessions map[string]*authn.Session

func (s sessions) Lookup(_ context.Context, token string) (*authn.Session, error) {
	if token == "outage" {
		return nil, errors.New("connection refused")
	}
	return s[token], nil
}

var testSessions = sessions{
	"dewi-web": {ID: "ses_1", UserID: "usr_dewi", Role: authn.RoleOwner, Client: authn.ClientWeb, CSRFToken: "csrf-dewi", Language: i18n.ID},
	"arif-ops": {ID: "ses_2", UserID: "usr_arif", Role: authn.RoleOps, Client: authn.ClientMobile, Language: i18n.EN},
}

type serverOpts struct {
	introspection  bool
	depthLimit     int
	requestTimeout time.Duration
	writeTimeout   time.Duration
	// accounts, when set, replaces the fake sessions with the real account service.
	accounts *account.Service
}

func newTestServer(t *testing.T, o serverOpts) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	off := false
	if o.depthLimit == 0 {
		o.depthLimit = 12
	}
	if o.requestTimeout == 0 {
		o.requestTimeout = 5 * time.Second
	}
	gqlCfg := config.GraphQL{ComplexityLimit: 1000, DepthLimit: o.depthLimit, Introspection: &o.introspection, Playground: &off}
	cfg := config.Config{
		HTTP: config.HTTP{
			MaxBodyBytes:       1 << 20,
			RequestTimeout:     o.requestTimeout,
			CORSAllowedOrigins: []string{appOrigin},
		},
		GraphQL: gqlCfg,
	}
	fixed := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	var store authn.SessionStore = testSessions
	resolver := &graph.Resolver{Now: func() time.Time { return fixed }, Cookies: authn.CookieConfig{Secure: true}}
	if o.accounts != nil {
		store, resolver.Accounts = o.accounts, o.accounts
	}
	gql := graph.NewHandler(resolver, graph.ServerOptions{
		Config:      gqlCfg,
		Logger:      logger,
		APQCache:    graphql.MapCache[string]{},
		Sessions:    store,
		OriginHosts: OriginHosts(cfg.HTTP.CORSAllowedOrigins),
	})
	h := NewRouter(Deps{
		Config:   cfg,
		Logger:   logger,
		Health:   health.NewChecker(map[string]health.CheckFunc{"postgres": func(context.Context) error { return nil }}),
		Metrics:  httpx.NewMetrics(prometheus.NewRegistry()),
		Sessions: store,
		GraphQL:  gql,
	})
	srv := httptest.NewUnstartedServer(h)
	srv.Config.WriteTimeout = o.writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

type gqlResponse struct {
	Data   map[string]any `json:"data"`
	Errors []struct {
		Message    string         `json:"message"`
		Extensions map[string]any `json:"extensions"`
	} `json:"errors"`
}

func (r gqlResponse) code() any {
	if len(r.Errors) == 0 {
		return nil
	}
	return r.Errors[0].Extensions["code"]
}

type call struct {
	query   string
	bearer  string
	cookie  string
	csrf    string
	lang    string
	rawBody string
	cookies []*http.Cookie
}

func do(t *testing.T, srv *httptest.Server, c call) (*http.Response, gqlResponse) {
	t.Helper()
	body := c.rawBody
	if body == "" {
		b, _ := json.Marshal(map[string]string{"query": c.query})
		body = string(b)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: c.cookie})
	}
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	if c.csrf != "" {
		req.Header.Set(authn.CSRFHeader, c.csrf)
	}
	if c.lang != "" {
		req.Header.Set("Accept-Language", c.lang)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out gqlResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp, out
}

func TestServerTimeIsPublicAndInWIB(t *testing.T) {
	srv := newTestServer(t, serverOpts{})

	resp, out := do(t, srv, call{query: "{ serverTime }"})
	if len(out.Errors) > 0 {
		t.Fatalf("errors: %+v", out.Errors)
	}
	if out.Data["serverTime"] != "2026-11-11T10:00:00+07:00" {
		t.Errorf("serverTime = %v, want WIB with offset", out.Data["serverTime"])
	}
	if resp.Header.Get(httpx.RequestIDHeader) == "" {
		t.Error("response is missing X-Request-ID")
	}
}

func TestAccessRules(t *testing.T) {
	srv := newTestServer(t, serverOpts{})

	tests := []struct {
		name     string
		call     call
		wantCode any
		wantMsg  string
	}{
		{
			name:     "signed-in field without a session",
			call:     call{query: "{ me { id } }"},
			wantCode: "UNAUTHENTICATED",
			wantMsg:  "Sign in first",
		},
		{
			name:     "unknown token is anonymous",
			call:     call{query: "{ me { id } }", bearer: "stolen-or-expired"},
			wantCode: "UNAUTHENTICATED",
		},
		{
			name:     "the message follows Accept-Language",
			call:     call{query: "{ me { id } }", lang: "id-ID,id;q=0.9"},
			wantCode: "UNAUTHENTICATED",
			wantMsg:  "Masuk dulu",
		},
		{
			name:     "@allow refuses another role",
			call:     call{query: "{ opsOverview { activeJobs } }", cookie: "dewi-web"},
			wantCode: "FORBIDDEN",
		},
		{
			name:     "without Accept-Language the user's language answers",
			call:     call{query: "{ opsOverview { activeJobs } }", cookie: "dewi-web"},
			wantCode: "FORBIDDEN",
			wantMsg:  "Tidak diizinkan untuk peran Anda",
		},
		{
			name:     "cookie mutation without the CSRF header",
			call:     call{query: "mutation { closeAccount { __typename } }", cookie: "dewi-web"},
			wantCode: "CSRF_FAILED",
		},
		{
			name:     "cookie mutation with the wrong CSRF header",
			call:     call{query: "mutation { closeAccount { __typename } }", cookie: "dewi-web", csrf: "guess"},
			wantCode: "CSRF_FAILED",
		},
		{
			// Passing every rule reaches the resolver, which is not built yet.
			name:     "cookie mutation with the CSRF header passes the guard",
			call:     call{query: "mutation { closeAccount { __typename } }", cookie: "dewi-web", csrf: "csrf-dewi"},
			wantCode: "INTERNAL",
		},
		{
			name:     "bearer mutations need no CSRF header",
			call:     call{query: "mutation { closeAccount { __typename } }", bearer: "arif-ops"},
			wantCode: "INTERNAL",
		},
		{
			name:     "@allow admits the role",
			call:     call{query: "{ opsOverview { activeJobs } }", bearer: "arif-ops"},
			wantCode: "INTERNAL",
		},
		{
			name:     "@public needs no session",
			call:     call{query: `{ link(token: "lnk_crew_8KQ2") { kind } }`},
			wantCode: "INTERNAL",
		},
		{
			name:     "a malformed scalar argument is the client's mistake",
			call:     call{query: `{ ledger(date: "30/11/2026") { totalCount } }`, bearer: "arif-ops"},
			wantCode: "BAD_USER_INPUT",
		},
		{
			name:     "an unknown field is BAD_USER_INPUT",
			call:     call{query: "{ nope }"},
			wantCode: "BAD_USER_INPUT",
		},
		{
			name:     "unparseable query is BAD_USER_INPUT",
			call:     call{query: "{ serverTime "},
			wantCode: "BAD_USER_INPUT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, out := do(t, srv, tt.call)
			if out.code() != tt.wantCode {
				t.Fatalf("code = %v, want %v (errors %+v)", out.code(), tt.wantCode, out.Errors)
			}
			if tt.wantMsg != "" && out.Errors[0].Message != tt.wantMsg {
				t.Errorf("message = %q, want %q", out.Errors[0].Message, tt.wantMsg)
			}
		})
	}
}

func TestInternalErrorsAreMasked(t *testing.T) {
	srv := newTestServer(t, serverOpts{})
	_, out := do(t, srv, call{query: "{ opsOverview { activeJobs } }", bearer: "arif-ops"})
	if msg := out.Errors[0].Message; strings.Contains(msg, "not implemented") || strings.Contains(msg, "panic") {
		t.Errorf("internal detail leaked: %q", msg)
	}
}

func TestSessionStoreOutageIsNotSignedOut(t *testing.T) {
	srv := newTestServer(t, serverOpts{})

	resp, out := do(t, srv, call{query: "{ me { id } }", bearer: "outage"})
	if resp.StatusCode != http.StatusServiceUnavailable || out.code() != "INTERNAL" {
		t.Fatalf("status %d code %v, want 503 INTERNAL (never UNAUTHENTICATED, which signs people out)", resp.StatusCode, out.code())
	}
}

func TestDepthLimitRejectsDeepQuery(t *testing.T) {
	srv := newTestServer(t, serverOpts{depthLimit: 1})

	_, out := do(t, srv, call{query: "{ me { id } }"})
	if out.code() != "BAD_USER_INPUT" || !strings.Contains(out.Errors[0].Message, "depth") {
		t.Fatalf("want a depth refusal as BAD_USER_INPUT, got %+v", out.Errors)
	}
}

func TestIntrospectionDisabled(t *testing.T) {
	srv := newTestServer(t, serverOpts{introspection: false})
	if _, out := do(t, srv, call{query: "{ __schema { queryType { name } } }"}); len(out.Errors) == 0 {
		t.Fatal("introspection should be rejected when disabled")
	}

	srv = newTestServer(t, serverOpts{introspection: true})
	if _, out := do(t, srv, call{query: "{ __schema { queryType { name } } }"}); len(out.Errors) > 0 {
		t.Fatalf("introspection should answer when enabled: %+v", out.Errors)
	}
}

func TestPersistedQueryNotFound(t *testing.T) {
	srv := newTestServer(t, serverOpts{})
	const hash = "c0b8a1ca2bd2c3a7d4c3a0b5c1a8f8e7c1f2b6b1a0c7e7e0e1d4b3c2a1f0e9d8" // never seen
	_, out := do(t, srv, call{rawBody: `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"` + hash + `"}}}`})
	if len(out.Errors) == 0 || out.Errors[0].Message != "PersistedQueryNotFound" {
		t.Fatalf("first call should ask for the full query, got %+v", out.Errors)
	}
}

func TestCORS(t *testing.T) {
	srv := newTestServer(t, serverOpts{})

	for origin, allowed := range map[string]bool{appOrigin: true, "https://evil.example": false} {
		req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/graphql", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", "accept-language,content-type,x-csrf-token") // browsers send these lowercase and sorted
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()

		if got := resp.Header.Get("Access-Control-Allow-Origin") == origin; got != allowed {
			t.Errorf("origin %s allowed = %v, want %v", origin, got, allowed)
		}
		if allowed && resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
			t.Error("the web app sends its session cookie, so credentials must be allowed")
		}
	}
}

// --- graphql-ws ---

type wsMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func dialWS(t *testing.T, srv *httptest.Server, h http.Header) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/graphql"
	return websocket.Dial(ctx, url, &websocket.DialOptions{
		Subprotocols: []string{"graphql-transport-ws"},
		HTTPHeader:   h,
	})
}

// subscribe opens a connection, inits it with params, starts a subscription and
// returns the first message about it.
func subscribe(t *testing.T, c *websocket.Conn, params map[string]any, query string, wait time.Duration) wsMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second+wait)
	defer cancel()

	init, _ := json.Marshal(params)
	if err := wsjson.Write(ctx, c, wsMessage{Type: "connection_init", Payload: init}); err != nil {
		t.Fatal(err)
	}
	var ack wsMessage
	if err := wsjson.Read(ctx, c, &ack); err != nil || ack.Type != "connection_ack" {
		t.Fatalf("ack = %+v, %v", ack, err)
	}
	time.Sleep(wait)

	payload, _ := json.Marshal(map[string]string{"query": query})
	if err := wsjson.Write(ctx, c, wsMessage{ID: "1", Type: "subscribe", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	for {
		var m wsMessage
		if err := wsjson.Read(ctx, c, &m); err != nil {
			t.Fatalf("read: %v", err)
		}
		if m.ID == "1" {
			return m
		}
	}
}

func errorCode(t *testing.T, m wsMessage) any {
	t.Helper()
	var errs []struct {
		Extensions map[string]any `json:"extensions"`
	}
	if m.Type == "next" {
		var p struct {
			Errors json.RawMessage `json:"errors"`
		}
		_ = json.Unmarshal(m.Payload, &p)
		_ = json.Unmarshal(p.Errors, &errs)
	} else {
		_ = json.Unmarshal(m.Payload, &errs)
	}
	if len(errs) == 0 {
		t.Fatalf("no errors in %s %s", m.Type, m.Payload)
	}
	return errs[0].Extensions["code"]
}

func TestWebSocketAuth(t *testing.T) {
	srv := newTestServer(t, serverOpts{})

	t.Run("anonymous subscription is refused", func(t *testing.T) {
		c, _, err := dialWS(t, srv, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.CloseNow() }()
		if code := errorCode(t, subscribe(t, c, nil, "subscription { notificationAdded { id } }", 0)); code != "UNAUTHENTICATED" {
			t.Errorf("code = %v, want UNAUTHENTICATED", code)
		}
	})

	t.Run("bearer in connectionParams signs in", func(t *testing.T) {
		c, _, err := dialWS(t, srv, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.CloseNow() }()
		// Past the guard, the unbuilt resolver answers INTERNAL.
		m := subscribe(t, c, map[string]any{"Authorization": "Bearer arif-ops"}, "subscription { notificationAdded { id } }", 0)
		if code := errorCode(t, m); code != "INTERNAL" {
			t.Errorf("code = %v, want the guard to pass (INTERNAL from the stub)", code)
		}
	})

	t.Run("cookie on the upgrade request signs in", func(t *testing.T) {
		h := http.Header{"Origin": {appOrigin}, "Cookie": {authn.SessionCookie + "=dewi-web"}}
		c, _, err := dialWS(t, srv, h)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.CloseNow() }()
		m := subscribe(t, c, nil, "subscription { notificationAdded { id } }", 0)
		if code := errorCode(t, m); code != "INTERNAL" {
			t.Errorf("code = %v, want the guard to pass", code)
		}
	})

	t.Run("a cookie session cannot run mutations over the socket", func(t *testing.T) {
		h := http.Header{"Origin": {appOrigin}, "Cookie": {authn.SessionCookie + "=dewi-web"}}
		c, _, err := dialWS(t, srv, h)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.CloseNow() }()
		if code := errorCode(t, subscribe(t, c, nil, "mutation { closeAccount { __typename } }", 0)); code != "CSRF_FAILED" {
			t.Errorf("code = %v, want CSRF_FAILED", code)
		}
	})

	t.Run("a web sign-in needs HTTP, which can set its cookies", func(t *testing.T) {
		c, _, err := dialWS(t, srv, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.CloseNow() }()
		m := subscribe(t, c, nil, `mutation { verifyCode(input: { requestId: "otp_1", code: "123456", client: web }) { __typename } }`, 0)
		if code := errorCode(t, m); code != "BAD_USER_INPUT" {
			t.Errorf("code = %v, want BAD_USER_INPUT", code)
		}
	})

	t.Run("Accept-Language in connectionParams", func(t *testing.T) {
		c, _, err := dialWS(t, srv, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.CloseNow() }()
		m := subscribe(t, c, map[string]any{"Accept-Language": "id"}, "subscription { notificationAdded { id } }", 0)
		if !strings.Contains(string(m.Payload), "Masuk dulu") {
			t.Errorf("payload = %s, want the Bahasa message", m.Payload)
		}
	})
}

func TestWebSocketRejectsForeignOrigin(t *testing.T) {
	srv := newTestServer(t, serverOpts{})
	h := http.Header{"Origin": {"https://evil.example"}, "Cookie": {authn.SessionCookie + "=dewi-web"}}
	_, resp, err := dialWS(t, srv, h)
	if err == nil {
		t.Fatal("a foreign origin must not open a cookie-authenticated socket")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %v, want 403", resp)
	}
}

func TestWebSocketOutlivesRequestTimeouts(t *testing.T) {
	srv := newTestServer(t, serverOpts{requestTimeout: 300 * time.Millisecond, writeTimeout: 300 * time.Millisecond})
	c, _, err := dialWS(t, srv, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()

	// Idle past both the request deadline and the server's write timeout, then use the socket.
	m := subscribe(t, c, map[string]any{"Authorization": "Bearer arif-ops"}, "subscription { notificationAdded { id } }", time.Second)
	if m.Type == "" {
		t.Fatal("no answer after idling past the timeouts")
	}
}

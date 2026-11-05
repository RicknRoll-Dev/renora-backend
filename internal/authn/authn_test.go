package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeStore map[string]*Session

func (f fakeStore) Lookup(_ context.Context, token string) (*Session, error) {
	if token == "boom" {
		return nil, errors.New("connection refused")
	}
	return f[token], nil
}

var store = fakeStore{
	"web-tok":    {ID: "ses_1", UserID: "usr_dewi", Role: RoleOwner, Client: ClientWeb, CSRFToken: "csrf-1"},
	"mobile-tok": {ID: "ses_2", UserID: "usr_joko", Role: RoleContractor, Client: ClientMobile},
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name       string
		bearer     string
		cookie     string
		wantUser   string
		wantCookie bool
		wantErr    bool
	}{
		{name: "anonymous"},
		{name: "bearer", bearer: "Bearer mobile-tok", wantUser: "usr_joko"},
		{name: "bearer scheme is case-insensitive", bearer: "bearer mobile-tok", wantUser: "usr_joko"},
		{name: "cookie", cookie: "web-tok", wantUser: "usr_dewi", wantCookie: true},
		{name: "bearer wins over cookie", bearer: "Bearer mobile-tok", cookie: "web-tok", wantUser: "usr_joko"},
		{name: "unknown token is anonymous", bearer: "Bearer nope"},
		{name: "basic auth is ignored", bearer: "Basic dXNlcjpwYXNz"},
		{name: "store outage is an error, not anonymous", bearer: "Bearer boom", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
			if tt.bearer != "" {
				r.Header.Set("Authorization", tt.bearer)
			}
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: SessionCookie, Value: tt.cookie})
			}
			v, err := Resolve(context.Background(), store, r)
			if tt.wantErr {
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("err = %v, want ErrUnavailable", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gotUser := ""
			if v.Session != nil {
				gotUser = v.Session.UserID
			}
			if gotUser != tt.wantUser || v.ViaCookie != tt.wantCookie {
				t.Errorf("user=%q viaCookie=%v, want %q %v", gotUser, v.ViaCookie, tt.wantUser, tt.wantCookie)
			}
		})
	}
}

func TestCSRFValid(t *testing.T) {
	web := store["web-tok"]
	tests := []struct {
		name string
		v    Viewer
		want bool
	}{
		{"cookie with matching header", Viewer{Session: web, ViaCookie: true, CSRF: "csrf-1"}, true},
		{"cookie without header", Viewer{Session: web, ViaCookie: true}, false},
		{"cookie with wrong header", Viewer{Session: web, ViaCookie: true, CSRF: "csrf-2"}, false},
		{"bearer needs no header", Viewer{Session: store["mobile-tok"]}, true},
		{"cookie session missing its token never passes", Viewer{Session: &Session{}, ViaCookie: true}, false},
	}
	for _, tt := range tests {
		if got := tt.v.CSRFValid(); got != tt.want {
			t.Errorf("%s: CSRFValid = %v, want %v", tt.name, got, tt.want)
		}
	}
}

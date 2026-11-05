package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/ratelimit"
	"github.com/renora/renora-api/internal/testdb"
)

// phone is the inbox of every number codes are sent to.
type phone struct {
	mu    sync.Mutex
	codes map[string]string
}

func (p *phone) Send(_ context.Context, c account.Code) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[c.Phone] = c.Code
	return nil
}

func (p *phone) code(number string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.codes[number]
}

func newAuthServer(t *testing.T) (*httptest.Server, *phone) {
	srv, inbox, _ := newAuthServerWith(t)
	return srv, inbox
}

func newAuthServerWith(t *testing.T) (*httptest.Server, *phone, *account.Service) {
	t.Helper()
	inbox := &phone{codes: map[string]string{}}
	accounts := account.New(account.Options{
		Pool:    testdb.Pool(t),
		Limiter: ratelimit.New(testdb.Redis(t)),
		Sender:  inbox,
		Secret:  []byte("test-secret-test-secret-test-secret"),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return newTestServer(t, serverOpts{accounts: accounts}), inbox, accounts
}

func gqlBody(query string, vars map[string]any) string {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	return string(b)
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func field(t *testing.T, data map[string]any, path ...string) any {
	t.Helper()
	var v any = data
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%v: no %q in %v", path, p, v)
		}
		v = m[p]
	}
	return v
}

const (
	requestCode = `mutation($p: String!) { requestCode(input: { phone: $p }) {
		__typename ... on RequestCodePayload { challenge { requestId phoneMasked channel } } } }`
	verifyCode = `mutation($r: ID!, $c: String!, $k: ClientKind!, $role: Role) {
		verifyCode(input: { requestId: $r, code: $c, client: $k, role: $role }) {
		__typename
		... on VerifyCodePayload { session { token csrfToken guest viewer { id roles language } } }
		... on InvalidInput { code field reason message } } }`
)

// signIn runs requestCode and verifyCode for a new number and returns the
// verifyCode response.
func signIn(t *testing.T, srv *httptest.Server, inbox *phone, client string, lang string) (*http.Response, gqlResponse) {
	t.Helper()
	number := fmt.Sprintf("+62898%08d", rand.IntN(100_000_000))
	_, sent := do(t, srv, call{rawBody: gqlBody(requestCode, map[string]any{"p": number})})
	if len(sent.Errors) > 0 {
		t.Fatalf("requestCode: %+v", sent.Errors)
	}
	rid := field(t, sent.Data, "requestCode", "challenge", "requestId")
	return do(t, srv, call{lang: lang, rawBody: gqlBody(verifyCode, map[string]any{
		"r": rid, "c": inbox.code(number), "k": client, "role": "owner",
	})})
}

func TestWebSignInSetsCookies(t *testing.T) {
	srv, inbox := newAuthServer(t)

	resp, out := signIn(t, srv, inbox, "web", "id")
	if len(out.Errors) > 0 {
		t.Fatalf("verifyCode: %+v", out.Errors)
	}
	session := field(t, out.Data, "verifyCode", "session").(map[string]any)
	if session["token"] != nil {
		t.Error("a web session must not return the token: it lives only in the httpOnly cookie")
	}
	if lang := field(t, session, "viewer", "language"); lang != "id" {
		t.Errorf("new account language = %v, want the request's (id)", lang)
	}

	sc := cookieNamed(resp, authn.SessionCookie)
	csrf := cookieNamed(resp, authn.CSRFCookie)
	if sc == nil || csrf == nil {
		t.Fatalf("cookies = %v, want %s and %s", resp.Cookies(), authn.SessionCookie, authn.CSRFCookie)
	}
	if !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" {
		t.Errorf("session cookie = %+v, want httpOnly, Secure, SameSite=Lax", sc)
	}
	if csrf.HttpOnly || !csrf.Secure || csrf.Value != session["csrfToken"] {
		t.Errorf("csrf cookie = %+v, want readable by the app and equal to csrfToken %v", csrf, session["csrfToken"])
	}
	if until := time.Until(sc.Expires); until < 29*24*time.Hour {
		t.Errorf("session cookie expires in %v, want 30 days", until)
	}

	me := `{ me { id displayName initials roles person { role phoneMasked } signedInSessions { label current } shops { staffRole } consents { aiProcessing } } }`
	_, got := do(t, srv, call{query: me, cookie: sc.Value})
	if len(got.Errors) > 0 {
		t.Fatalf("me: %+v", got.Errors)
	}
	if field(t, got.Data, "me", "id") != field(t, session, "viewer", "id") || field(t, got.Data, "me", "person", "role") != "owner" {
		t.Errorf("me = %v", got.Data["me"])
	}
	sessions := field(t, got.Data, "me", "signedInSessions").([]any)
	if len(sessions) != 1 || sessions[0].(map[string]any)["current"] != true {
		t.Errorf("signedInSessions = %v, want this one, current", sessions)
	}

	update := `mutation { updateMe(input: { displayName: "Bu Dewi" }) { ... on UpdateMePayload { me { displayName initials } } } }`
	if _, r := do(t, srv, call{query: update, cookie: sc.Value}); r.code() != "CSRF_FAILED" {
		t.Fatalf("cookie mutation without X-CSRF-Token: code = %v, want CSRF_FAILED", r.code())
	}
	_, r := do(t, srv, call{query: update, cookie: sc.Value, csrf: csrf.Value})
	if len(r.Errors) > 0 || field(t, r.Data, "updateMe", "me", "initials") != "BD" {
		t.Fatalf("updateMe = %v %+v", r.Data, r.Errors)
	}

	resp, r = do(t, srv, call{query: `mutation { signOut { ... on SignOutPayload { signedOut } } }`, cookie: sc.Value, csrf: csrf.Value})
	if len(r.Errors) > 0 || field(t, r.Data, "signOut", "signedOut") != true {
		t.Fatalf("signOut = %v %+v", r.Data, r.Errors)
	}
	if c := cookieNamed(resp, authn.SessionCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("signOut must clear the session cookie, got %+v", c)
	}
	if _, r := do(t, srv, call{query: "{ me { id } }", cookie: sc.Value}); r.code() != "UNAUTHENTICATED" {
		t.Errorf("old cookie after sign-out: code = %v, want UNAUTHENTICATED", r.code())
	}
}

func TestMobileSignInReturnsBearerToken(t *testing.T) {
	srv, inbox := newAuthServer(t)

	resp, out := signIn(t, srv, inbox, "mobile", "")
	if len(out.Errors) > 0 {
		t.Fatalf("verifyCode: %+v", out.Errors)
	}
	if len(resp.Cookies()) > 0 {
		t.Errorf("mobile sign-in set cookies %v", resp.Cookies())
	}
	session := field(t, out.Data, "verifyCode", "session").(map[string]any)
	token, _ := session["token"].(string)
	if token == "" || session["csrfToken"] != nil {
		t.Fatalf("session = %v, want a token and no csrfToken", session)
	}

	// Bearer mutations need no CSRF header.
	_, r := do(t, srv, call{query: `mutation { updateConsents(input: { aiProcessing: true }) { ... on UpdateConsentsPayload { consents { aiProcessing aiProcessingAt } } } }`, bearer: token})
	if len(r.Errors) > 0 || field(t, r.Data, "updateConsents", "consents", "aiProcessing") != true {
		t.Fatalf("updateConsents = %v %+v", r.Data, r.Errors)
	}

	do(t, srv, call{query: `mutation { signOut { __typename } }`, bearer: token})
	if _, r := do(t, srv, call{query: "{ me { id } }", bearer: token}); r.code() != "UNAUTHENTICATED" {
		t.Errorf("token after sign-out: code = %v, want UNAUTHENTICATED", r.code())
	}
}

func TestVerifyCodeProblemsAreData(t *testing.T) {
	srv, _ := newAuthServer(t)
	number := fmt.Sprintf("+62898%08d", rand.IntN(100_000_000))
	_, sent := do(t, srv, call{rawBody: gqlBody(requestCode, map[string]any{"p": number})})
	if got := field(t, sent.Data, "requestCode", "challenge", "phoneMasked"); got != "+62 898 •••• "+number[len(number)-4:] {
		t.Errorf("phoneMasked = %v", got)
	}
	rid := field(t, sent.Data, "requestCode", "challenge", "requestId")

	_, out := do(t, srv, call{lang: "id", rawBody: gqlBody(verifyCode, map[string]any{"r": rid, "c": "000000", "k": "mobile"})})
	got := field(t, out.Data, "verifyCode").(map[string]any)
	if got["__typename"] != "InvalidInput" || got["code"] != "wrong_code" || got["field"] != "code" ||
		got["message"] != "Kode itu salah. Cek WhatsApp lalu coba lagi." {
		t.Errorf("wrong code = %v, want InvalidInput wrong_code in Bahasa", got)
	}

	_, bad := do(t, srv, call{rawBody: gqlBody(requestCode, map[string]any{"p": "0812"})})
	if r := field(t, bad.Data, "requestCode").(map[string]any); r["__typename"] != "InvalidInput" {
		t.Errorf("local number = %v, want InvalidInput", r)
	}

	// Asking again within 30 s is RATE_LIMITED, a transport error.
	if _, again := do(t, srv, call{rawBody: gqlBody(requestCode, map[string]any{"p": number})}); again.code() != "RATE_LIMITED" {
		t.Errorf("resend: code = %v, want RATE_LIMITED", again.code())
	}
}

func TestQRSignInOverHTTP(t *testing.T) {
	srv, inbox := newAuthServer(t)
	_, out := signIn(t, srv, inbox, "mobile", "")
	token := field(t, out.Data, "verifyCode", "session", "token").(string)

	// The web page: anonymous, gets the QR and the renora_qr cookie.
	resp, created := do(t, srv, call{query: `mutation { createQrSignIn { ... on CreateQrSignInPayload { qrSignIn { id payload status } } } }`})
	qr := cookieNamed(resp, authn.QRCookie)
	if len(created.Errors) > 0 || qr == nil || !qr.HttpOnly {
		t.Fatalf("createQrSignIn = %v %+v, cookie %+v", created.Data, created.Errors, qr)
	}
	id := field(t, created.Data, "createQrSignIn", "qrSignIn", "id").(string)
	if field(t, created.Data, "createQrSignIn", "qrSignIn", "payload") != "renora://auth/qr/"+id {
		t.Errorf("payload = %v", created.Data)
	}

	// The phone approves.
	approve := fmt.Sprintf(`mutation { approveQrSignIn(input: { qrSignInId: %q }) { __typename } }`, id)
	if _, r := do(t, srv, call{query: approve, bearer: token}); field(t, r.Data, "approveQrSignIn", "__typename") != "ApproveQrSignInPayload" {
		t.Fatalf("approve = %v %+v", r.Data, r.Errors)
	}

	poll := fmt.Sprintf(`{ qrSignIn(id: %q) { status session { csrfToken viewer { roles } } } }`, id)
	// Another browser that read the QR off the screen: status only.
	if resp, r := do(t, srv, call{query: poll}); field(t, r.Data, "qrSignIn", "session") != nil || cookieNamed(resp, authn.SessionCookie) != nil {
		t.Fatalf("poll without the QR cookie = %v", r.Data)
	}
	// The browser that showed it: the session and its cookies.
	resp, r := do(t, srv, call{query: poll, cookies: []*http.Cookie{qr}})
	sc := cookieNamed(resp, authn.SessionCookie)
	if field(t, r.Data, "qrSignIn", "status") != "approved" || sc == nil || field(t, r.Data, "qrSignIn", "session", "csrfToken") == nil {
		t.Fatalf("poll with the QR cookie = %v %+v", r.Data, r.Errors)
	}
	if _, me := do(t, srv, call{query: "{ me { roles } }", cookie: sc.Value}); len(me.Errors) > 0 {
		t.Errorf("me on the QR session: %+v", me.Errors)
	}
}

func TestStaffSignInOverHTTP(t *testing.T) {
	srv, _, accounts := newAuthServerWith(t)
	ctx := context.Background()
	email := fmt.Sprintf("ops%d@renora.id", rand.IntN(1_000_000_000))
	if _, err := accounts.AddStaff(ctx, account.NewStaff{Email: email, Name: "Arif", Role: "lead", Permissions: []string{"read_money"}}); err != nil {
		t.Fatal(err)
	}
	uri, err := accounts.EnrollAuthenticator(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(uri)
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))

	_, started := do(t, srv, call{query: fmt.Sprintf(`mutation { startStaffSignIn(input: { email: %q }) {
		... on StartStaffSignInPayload { challenge { challengeId methods securityKeys { label } } } } }`, email)})
	ch := field(t, started.Data, "startStaffSignIn", "challenge").(map[string]any)
	if fmt.Sprint(ch["methods"]) != "[authenticator]" {
		t.Errorf("methods = %v", ch["methods"])
	}

	resp, out := do(t, srv, call{query: fmt.Sprintf(`mutation { verifyStaffSignIn(input: { challengeId: %q, method: authenticator, code: %q }) {
		... on VerifyStaffSignInPayload { session { csrfToken } } } }`, ch["challengeId"], totpNow(secret))})
	sc := cookieNamed(resp, authn.SessionCookie)
	if len(out.Errors) > 0 || sc == nil {
		t.Fatalf("verifyStaffSignIn = %v %+v", out.Data, out.Errors)
	}
	// Staff reach @allow(roles: [ops]) fields; their own profile says what they may do.
	_, me := do(t, srv, call{query: "{ me { roles phone staff { staffRole permissions } } }", cookie: sc.Value})
	if len(me.Errors) > 0 || field(t, me.Data, "me", "staff", "staffRole") != "lead" || field(t, me.Data, "me", "phone") != nil {
		t.Errorf("me = %v %+v", me.Data, me.Errors)
	}
	if _, r := do(t, srv, call{query: "{ opsOverview { activeJobs } }", cookie: sc.Value}); r.code() == "FORBIDDEN" {
		t.Error("an ops session must pass @allow(roles: [ops])")
	}
}

func totpNow(secret []byte) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30)) //nolint:gosec
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

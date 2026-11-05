package account_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/ratelimit"
	"github.com/renora/renora-api/internal/testdb"
)

// inbox is the phone: it keeps the last code sent to each number.
type inbox struct {
	mu    sync.Mutex
	codes map[string]account.Code
}

func (b *inbox) Send(_ context.Context, c account.Code) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.codes[c.Phone] = c
	return nil
}

func (b *inbox) last(t *testing.T, phone string) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.codes[phone]
	if !ok {
		t.Fatalf("no code sent to %s", phone)
	}
	return c.Code
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

type harness struct {
	pool  *pgxpool.Pool
	svc   *account.Service
	inbox *inbox
	clock *clock
}

func newHarness(t *testing.T) harness {
	t.Helper()
	pool := testdb.Pool(t)
	rdb := testdb.Redis(t)
	h := harness{
		pool:  pool,
		inbox: &inbox{codes: map[string]account.Code{}},
		// The real time, so rows written with now() defaults and this clock agree.
		clock: &clock{t: time.Now().Truncate(time.Microsecond)},
	}
	h.svc = account.New(account.Options{
		Pool:    h.pool,
		Limiter: ratelimit.New(rdb),
		Sender:  h.inbox,
		Secret:  []byte("test-secret-test-secret-test-secret"),
		Now:     h.clock.now,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return h
}

// newPhone is a number no other test uses, so accounts and rate limits do not collide.
func newPhone() string { return fmt.Sprintf("+62899%08d", rand.IntN(100_000_000)) }

func newIP() string {
	return fmt.Sprintf("10.%d.%d.%d", rand.IntN(256), rand.IntN(256), rand.IntN(256))
}

func (h harness) request(t *testing.T, phone string) account.Challenge {
	t.Helper()
	ch, p, err := h.svc.RequestCode(context.Background(), account.RequestCodeInput{
		Phone: phone, Channel: account.ChannelWhatsApp, Purpose: account.PurposeSignIn, ClientIP: newIP(),
	})
	if err != nil || p != nil {
		t.Fatalf("RequestCode: %v %v", p, err)
	}
	return ch
}

func role(r authn.Role) *authn.Role { return &r }

func (h harness) verify(ctx context.Context, requestID, code string, client authn.Client, r *authn.Role) (account.Started, string, error) {
	st, p, err := h.svc.VerifyCode(ctx, account.VerifyCodeInput{
		RequestID: requestID, Code: code, Client: client, Role: r,
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
		ClientIP:  newIP(),
	})
	if p != nil {
		return st, p.Code + ":" + p.Field + ":" + p.Reason, err
	}
	return st, "", err
}

// signUp makes a fresh account and returns its first session.
func (h harness) signUp(t *testing.T, client authn.Client, r authn.Role) account.Started {
	t.Helper()
	phone := newPhone()
	ch := h.request(t, phone)
	st, p, err := h.verify(context.Background(), ch.RequestID, h.inbox.last(t, phone), client, role(r))
	if err != nil || p != "" {
		t.Fatalf("sign up: %v %v", p, err)
	}
	return st
}

func TestRequestCodeRejectsALocalNumber(t *testing.T) {
	h := newHarness(t)
	_, p, err := h.svc.RequestCode(context.Background(), account.RequestCodeInput{Phone: "0812", Channel: account.ChannelWhatsApp, Purpose: account.PurposeSignIn})
	if err != nil || p == nil || p.Field != "phone" || p.Reason != "invalid_format" {
		t.Fatalf("got %+v %v, want invalid_format on phone", p, err)
	}
}

func TestRequestCodeChallenge(t *testing.T) {
	h := newHarness(t)
	ch := h.request(t, newPhone())
	if ch.Channel != account.ChannelWhatsApp || ch.ExpiresAt.Sub(h.clock.now()) != account.CodeTTL || ch.ResendAt.Sub(h.clock.now()) != account.ResendAfter {
		t.Errorf("challenge = %+v", ch)
	}
	if len(h.inbox.codes) != 1 {
		t.Errorf("sent %d codes, want 1", len(h.inbox.codes))
	}
}

// The contract's sign-in flow (test/rules.test.ts): a wrong code, the right
// one, then signing out ends the token.
func TestSignInFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	phone := newPhone()

	ch := h.request(t, phone)
	if _, p, _ := h.verify(ctx, ch.RequestID, "000000", authn.ClientMobile, role(authn.RoleOwner)); p != "wrong_code:code:wrong_code" {
		t.Fatalf("wrong code: problem = %q", p)
	}
	st, p, err := h.verify(ctx, ch.RequestID, h.inbox.last(t, phone), authn.ClientMobile, role(authn.RoleOwner))
	if err != nil || p != "" {
		t.Fatalf("verify: %v %v", p, err)
	}
	if st.Token == "" || st.Session.CSRFToken != "" || st.Session.Role != authn.RoleOwner {
		t.Errorf("mobile session = %+v, want a token and no CSRF token", st.Session)
	}
	if st.Session.ExpiresAt.Sub(h.clock.now()) != account.SessionTTL {
		t.Errorf("expires in %v, want %v", st.Session.ExpiresAt.Sub(h.clock.now()), account.SessionTTL)
	}

	got, err := h.svc.Lookup(ctx, st.Token)
	if err != nil || got == nil || got.UserID != st.User.ID {
		t.Fatalf("Lookup = %+v %v, want the session", got, err)
	}
	if err := h.svc.SignOut(ctx, got.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := h.svc.Lookup(ctx, st.Token); err != nil || got != nil {
		t.Fatalf("after sign-out Lookup = %+v %v, want nil", got, err)
	}

	// The code was used up.
	if _, p, _ := h.verify(ctx, ch.RequestID, h.inbox.last(t, phone), authn.ClientMobile, nil); p != "challenge_expired:requestId:expired" {
		t.Errorf("reused code: problem = %q", p)
	}
}

// test/followups.test.ts: a new number is asked who it is, keeps its code, and
// signs up in that role and the request's language.
func TestNewNumberChoosesRole(t *testing.T) {
	h := newHarness(t)
	ctx := i18n.WithLang(context.Background(), i18n.ID)
	phone := newPhone()
	ch := h.request(t, phone)
	code := h.inbox.last(t, phone)

	if _, p, _ := h.verify(ctx, ch.RequestID, code, authn.ClientMobile, nil); p != "invalid_input:role:required" {
		t.Fatalf("no role: problem = %q", p)
	}
	if _, p, _ := h.verify(ctx, ch.RequestID, code, authn.ClientMobile, role(authn.RoleOps)); p != "invalid_input:role:required" {
		t.Fatalf("ops cannot sign up by phone: problem = %q", p)
	}
	st, p, err := h.verify(ctx, ch.RequestID, code, authn.ClientMobile, role(authn.RoleContractor))
	if err != nil || p != "" {
		t.Fatalf("with role: %v %v", p, err)
	}
	if st.User.Language != i18n.ID || len(st.User.Roles) != 1 || st.User.Roles[0] != authn.RoleContractor || *st.User.Phone != phone {
		t.Errorf("user = %+v", st.User)
	}

	// Next time the number is known: the role is ignored.
	h.waitResend(t, phone)
	ch = h.request(t, phone)
	st2, p, err := h.verify(ctx, ch.RequestID, h.inbox.last(t, phone), authn.ClientWeb, role(authn.RoleOwner))
	if err != nil || p != "" || st2.User.ID != st.User.ID || st2.Session.Role != authn.RoleContractor {
		t.Fatalf("second sign-in = %+v %v %v, want the same contractor", st2.User, p, err)
	}
	if st2.Session.CSRFToken == "" {
		t.Error("a web session needs a CSRF token")
	}
}

// waitResend lets the number ask for another code at once.
func (h harness) waitResend(t *testing.T, phone string) {
	t.Helper()
	// The resend limit lives in Redis with a real expiry; tests cannot move
	// Redis's clock, so clear the key instead.
	rdb := testdb.Redis(t)
	if err := rdb.Del(context.Background(), "rl:code.resend:"+phone).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestWrongGuessesUseUpTheCode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	phone := newPhone()
	ch := h.request(t, phone)
	for i := range account.MaxAttempts {
		if _, p, _ := h.verify(ctx, ch.RequestID, "12345x", authn.ClientMobile, role(authn.RoleOwner)); p != "wrong_code:code:wrong_code" {
			t.Fatalf("guess %d: problem = %q", i, p)
		}
	}
	if _, p, _ := h.verify(ctx, ch.RequestID, h.inbox.last(t, phone), authn.ClientMobile, role(authn.RoleOwner)); p != "challenge_expired:requestId:expired" {
		t.Fatalf("right code after %d wrong guesses: problem = %q, want challenge_expired", account.MaxAttempts, p)
	}
}

func TestCodeExpires(t *testing.T) {
	h := newHarness(t)
	phone := newPhone()
	ch := h.request(t, phone)
	h.clock.add(account.CodeTTL + time.Second)
	if _, p, _ := h.verify(context.Background(), ch.RequestID, h.inbox.last(t, phone), authn.ClientMobile, role(authn.RoleOwner)); p != "challenge_expired:requestId:expired" {
		t.Fatalf("problem = %q, want challenge_expired", p)
	}
}

func TestUnknownRequestID(t *testing.T) {
	h := newHarness(t)
	if _, p, _ := h.verify(context.Background(), "otp_NOPE", "123456", authn.ClientMobile, nil); p != "challenge_expired:requestId:expired" {
		t.Fatalf("problem = %q", p)
	}
}

func TestResendIsRateLimited(t *testing.T) {
	h := newHarness(t)
	phone := newPhone()
	h.request(t, phone)
	_, p, err := h.svc.RequestCode(context.Background(), account.RequestCodeInput{
		Phone: phone, Channel: account.ChannelWhatsApp, Purpose: account.PurposeSignIn, ClientIP: newIP(),
	})
	if ae, ok := apperr.As(err); !ok || ae.Code != apperr.CodeRateLimited || p != nil {
		t.Fatalf("second code within %v: err = %v, want RATE_LIMITED", account.ResendAfter, err)
	}
}

func TestSigningCodesNeedAChallenge(t *testing.T) {
	h := newHarness(t)
	id := "sch_unknown"
	_, p, err := h.svc.RequestCode(context.Background(), account.RequestCodeInput{
		Phone: newPhone(), Channel: account.ChannelWhatsApp, Purpose: account.PurposeSign, ChallengeID: &id,
	})
	if err != nil || p == nil || p.Code != "challenge_expired" || p.Field != "challengeId" {
		t.Fatalf("got %+v %v, want challenge_expired on challengeId", p, err)
	}
}

func TestSessionsLastUntilExpiry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	st := h.signUp(t, authn.ClientWeb, authn.RoleOwner)

	h.clock.add(account.SessionTTL - time.Minute)
	if got, err := h.svc.Lookup(ctx, st.Token); err != nil || got == nil {
		t.Fatalf("a minute before expiry: %+v %v, want the session", got, err)
	}
	h.clock.add(2 * time.Minute)
	if got, err := h.svc.Lookup(ctx, st.Token); err != nil || got != nil {
		t.Fatalf("after expiry: %+v %v, want nil", got, err)
	}
}

func TestStaffSessionsEndWhenIdle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	st := h.signUp(t, authn.ClientWeb, authn.RoleOwner)
	// Staff sign-in (email + security key) is not built yet; make this one an ops session.
	if _, err := h.pool.Exec(ctx, `UPDATE app.sessions SET role = 'ops' WHERE id = $1`, st.Session.ID); err != nil {
		t.Fatal(err)
	}

	// Each request keeps it alive.
	for range 3 {
		h.clock.add(account.StaffIdle - time.Minute)
		if got, err := h.svc.Lookup(ctx, st.Token); err != nil || got == nil {
			t.Fatalf("active staff session ended: %+v %v", got, err)
		}
	}
	h.clock.add(account.StaffIdle + time.Minute)
	if got, err := h.svc.Lookup(ctx, st.Token); err != nil || got != nil {
		t.Fatalf("after %v idle: %+v %v, want nil", account.StaffIdle, got, err)
	}
}

func TestSignedInSessions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	st := h.signUp(t, authn.ClientWeb, authn.RoleOwner)

	list, err := h.svc.Sessions(ctx, st.User.ID)
	if err != nil || len(list) != 1 || list[0].ID != st.Session.ID || list[0].Label != "Chrome on Mac" {
		t.Fatalf("Sessions = %+v %v", list, err)
	}
	if p, err := h.svc.RevokeSession(ctx, "usr_someone_else", st.Session.ID); err != nil || p == nil || p.Code != "not_found" {
		t.Fatalf("revoking another person's session: %+v %v, want not_found", p, err)
	}
	if p, err := h.svc.RevokeSession(ctx, st.User.ID, st.Session.ID); err != nil || p != nil {
		t.Fatalf("RevokeSession: %+v %v", p, err)
	}
	if got, _ := h.svc.Lookup(ctx, st.Token); got != nil {
		t.Error("a revoked session must stop working")
	}
	if list, _ := h.svc.Sessions(ctx, st.User.ID); len(list) != 0 {
		t.Errorf("Sessions after revoke = %+v, want none", list)
	}
}

func TestUpdateMe(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	st := h.signUp(t, authn.ClientMobile, authn.RoleOwner)
	s := func(v string) *string { return &v }

	for _, tt := range []struct {
		in     account.UpdateMe
		field  string
		reason string
	}{
		{account.UpdateMe{Name: s("   ")}, "name", "required"},
		{account.UpdateMe{DisplayName: s(string(make([]rune, 81)))}, "displayName", "out_of_range"},
		{account.UpdateMe{Email: s("dewi@")}, "email", "invalid_format"},
		{account.UpdateMe{PreferredVABank: s("other")}, "preferredVaBank", "unknown_option"},
	} {
		if _, p, err := h.svc.UpdateMe(ctx, st.User.ID, tt.in); err != nil || p == nil || p.Field != tt.field || p.Reason != tt.reason {
			t.Errorf("UpdateMe(%+v) = %+v %v, want %s %s", tt.in, p, err, tt.field, tt.reason)
		}
	}

	en := i18n.EN
	u, p, err := h.svc.UpdateMe(ctx, st.User.ID, account.UpdateMe{
		Name: s(" Dewi  Lestari "), DisplayName: s("bu dewi"), Email: s("dewi@example.com"),
		Language: &en, PreferredVABank: s("BCA"),
	})
	if err != nil || p != nil {
		t.Fatalf("UpdateMe: %v %v", p, err)
	}
	if u.Name != "Dewi Lestari" || u.DisplayName != "bu dewi" || u.Initials() != "BD" || *u.Email != "dewi@example.com" ||
		u.Language != i18n.EN || *u.PreferredVABank != "BCA" {
		t.Errorf("user = %+v", u)
	}
	// Unset fields stay; an empty email clears it.
	u, _, _ = h.svc.UpdateMe(ctx, st.User.ID, account.UpdateMe{Email: s("")})
	if u.Name != "Dewi Lestari" || u.Email != nil {
		t.Errorf("user = %+v, want the name kept and the email cleared", u)
	}
}

func TestUpdateConsents(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	st := h.signUp(t, authn.ClientMobile, authn.RoleContractor)
	yes, no := true, false

	c, err := h.svc.UpdateConsents(ctx, st.User.ID, account.UpdateConsents{AIProcessing: &yes})
	if err != nil || !c.AIProcessing || c.AIProcessingAt == nil || !c.AIProcessingAt.Equal(h.clock.now()) || c.PriceBookSharing {
		t.Fatalf("consents = %+v %v", c, err)
	}
	c, err = h.svc.UpdateConsents(ctx, st.User.ID, account.UpdateConsents{AIProcessing: &no, PriceBookSharing: &yes})
	if err != nil || c.AIProcessing || c.AIProcessingAt == nil || !c.PriceBookSharing {
		t.Fatalf("consents = %+v %v, want AI off, the last yes kept, price book on", c, err)
	}
}

package account_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/problem"
)

// authenticatorApp reads an otpauth:// URI and makes codes, as the staff
// member's phone would.
type authenticatorApp []byte

func scan(t *testing.T, uri string) authenticatorApp {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" {
		t.Fatalf("not an otpauth URI: %q", uri)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func (a authenticatorApp) code(at time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30)) //nolint:gosec
	m := hmac.New(sha1.New, a)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func newStaff(t *testing.T, h harness) (string, authenticatorApp) {
	t.Helper()
	ctx := context.Background()
	email := fmt.Sprintf("staff%d@renora.id", rand.IntN(1_000_000_000))
	if _, err := h.svc.AddStaff(ctx, account.NewStaff{Email: email, Name: "Arif", Role: "lead", Permissions: []string{"read_money", "decide_cases"}}); err != nil {
		t.Fatal(err)
	}
	uri, err := h.svc.EnrollAuthenticator(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "issuer=Renora") {
		t.Errorf("uri = %s", uri)
	}
	return email, scan(t, uri)
}

func TestStaffSignIn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	email, app := newStaff(t, h)

	if _, p, err := h.svc.StartStaffSignIn(ctx, "nobody@renora.id", newIP()); err != nil || p == nil || p.Field != "email" {
		t.Fatalf("unknown email: %+v %v", p, err)
	}
	ch, p, err := h.svc.StartStaffSignIn(ctx, strings.ToUpper(email), newIP())
	if err != nil || p != nil || len(ch.Methods) != 1 || ch.Methods[0] != account.FactorAuthenticator {
		t.Fatalf("start: %+v %v %v", ch, p, err)
	}

	verify := func(method account.StaffFactor, code string) (account.Started, *problem.Problem) {
		st, p, err := h.svc.VerifyStaffSignIn(ctx, account.VerifyStaffInput{
			ChallengeID: ch.ID, Method: method, Code: code, ClientIP: newIP(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return st, p
	}
	if _, p := verify(account.FactorSecurityKey, ""); p == nil || p.Field != "method" {
		t.Errorf("security key without one registered: %+v", p)
	}
	if _, p := verify(account.FactorAuthenticator, "000000"); p == nil || p.Code != "wrong_code" {
		t.Errorf("wrong code: %+v", p)
	}
	code := app.code(h.clock.now())
	st, p := verify(account.FactorAuthenticator, code)
	if p != nil || st.Session.Role != authn.RoleOps || st.Session.Client != authn.ClientWeb || st.Session.CSRFToken == "" {
		t.Fatalf("verify: %+v %+v", st.Session, p)
	}
	if got := st.Session.ExpiresAt.Sub(h.clock.now()); got != account.StaffSessionTTL {
		t.Errorf("staff session lasts %v, want %v", got, account.StaffSessionTTL)
	}
	if sp, err := h.svc.Staff(ctx, st.User.ID); err != nil || sp == nil || sp.Role != "lead" || len(sp.Permissions) != 2 {
		t.Errorf("staff profile = %+v %v", sp, err)
	}

	// The challenge and the code are used up.
	if _, p := verify(account.FactorAuthenticator, code); p == nil || p.Code != "challenge_expired" {
		t.Errorf("reused challenge: %+v", p)
	}
	ch, _, _ = h.svc.StartStaffSignIn(ctx, email, newIP())
	if _, p := verify(account.FactorAuthenticator, code); p == nil || p.Code != "wrong_code" {
		t.Errorf("reused authenticator code: %+v, want wrong_code", p)
	}
}

func TestStaffEmailIsUnique(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	email := fmt.Sprintf("dup%d@renora.id", rand.IntN(1_000_000_000))
	a, err := h.svc.AddStaff(ctx, account.NewStaff{Email: email, Name: "Rina", Role: "support"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.svc.AddStaff(ctx, account.NewStaff{Email: strings.ToUpper(email[:1]) + email[1:], Name: "Rina S", Role: "mediator"})
	if err != nil || a != b {
		t.Fatalf("second add = %s %v, want the same account %s updated", b, err, a)
	}
	if _, err := h.svc.AddStaff(ctx, account.NewStaff{Email: email, Name: "Rina", Role: "boss"}); err == nil {
		t.Error("an unknown staff role must be refused")
	}
}

func TestQRSignIn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	phone := h.signUp(t, authn.ClientMobile, authn.RoleContractor)

	q, secret, err := h.svc.CreateQRSignIn(ctx, newIP())
	if err != nil || q.Status != account.QRWaiting || q.Payload() != "renora://auth/qr/"+q.ID {
		t.Fatalf("create: %+v %v", q, err)
	}
	if got, st, found, _ := h.svc.PollQRSignIn(ctx, q.ID, secret, ""); !found || got.Status != account.QRWaiting || st != nil {
		t.Fatalf("poll before approval: %+v %v", got, st)
	}

	if _, p, _ := h.svc.ApproveQRSignIn(ctx, phone.Session, "qr_unknown"); p == nil || p.Code != "not_found" {
		t.Errorf("unknown QR: %+v", p)
	}
	if got, p, err := h.svc.ApproveQRSignIn(ctx, phone.Session, q.ID); err != nil || p != nil || got.Status != account.QRApproved {
		t.Fatalf("approve: %+v %+v %v", got, p, err)
	}
	if _, p, _ := h.svc.ApproveQRSignIn(ctx, phone.Session, q.ID); p == nil || p.Code != "already_answered" {
		t.Errorf("second approve: %+v", p)
	}

	// Someone who only saw the QR gets the status, never the session.
	if got, st, _, _ := h.svc.PollQRSignIn(ctx, q.ID, "", ""); got.Status != account.QRApproved || st != nil {
		t.Errorf("poll without the browser's secret: %+v %v", got, st)
	}
	if _, st, _, _ := h.svc.PollQRSignIn(ctx, q.ID, "guess", ""); st != nil {
		t.Error("a wrong secret must not collect the session")
	}
	_, st, _, err := h.svc.PollQRSignIn(ctx, q.ID, secret, "")
	if err != nil || st == nil || st.User.ID != phone.User.ID || st.Session.Client != authn.ClientWeb || st.Session.Role != authn.RoleContractor {
		t.Fatalf("collect: %+v %v", st, err)
	}
	if _, again, _, _ := h.svc.PollQRSignIn(ctx, q.ID, secret, ""); again != nil {
		t.Error("the session is collected once")
	}
	if got, err := h.svc.Lookup(ctx, st.Token); err != nil || got == nil {
		t.Errorf("collected web session does not work: %v %v", got, err)
	}
}

func TestQRExpires(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	phone := h.signUp(t, authn.ClientMobile, authn.RoleOwner)
	q, secret, _ := h.svc.CreateQRSignIn(ctx, newIP())
	h.clock.add(account.QRTTL + time.Second)
	if got, _, _, _ := h.svc.PollQRSignIn(ctx, q.ID, secret, ""); got.Status != account.QRExpired {
		t.Errorf("status = %s, want expired", got.Status)
	}
	if _, p, _ := h.svc.ApproveQRSignIn(ctx, phone.Session, q.ID); p == nil || p.Code != "not_found" {
		t.Errorf("approving an expired QR: %+v, want not_found", p)
	}
}

// signer is a phone with a device key.
type signer struct {
	st   account.Started
	key  ed25519.PrivateKey
	kid  string
	h    harness
	user string
}

func newSigner(t *testing.T, h harness) signer {
	t.Helper()
	st := h.signUp(t, authn.ClientMobile, authn.RoleContractor)
	pub, priv, _ := ed25519.GenerateKey(nil)
	k, p, err := h.svc.RegisterDeviceKey(context.Background(), st.Session, "android", base64.RawURLEncoding.EncodeToString(pub), nil)
	if err != nil || p != nil {
		t.Fatalf("register key: %+v %v", p, err)
	}
	return signer{st: st, key: priv, kid: k.ID, h: h, user: st.User.ID}
}

func (s signer) challenge(t *testing.T, purpose, subject string) account.SigningChallenge {
	t.Helper()
	ch, err := s.h.svc.CreateSigningChallenge(context.Background(), s.st.Session, purpose, subject)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func (s signer) device(ch account.SigningChallenge) *account.SignatureInput {
	sig := ed25519.Sign(s.key, []byte(ch.Nonce))
	return &account.SignatureInput{Device: &account.DeviceAssertion{
		ChallengeID: ch.ID, KeyID: s.kid, Assertion: base64.RawURLEncoding.EncodeToString(sig),
	}}
}

// sign runs a signing action that commits when the signature holds.
func (h harness) sign(t *testing.T, userID string, in *account.SignatureInput, purpose, subject string) (account.Signature, string) {
	t.Helper()
	var (
		sig account.Signature
		p   *problem.Problem
	)
	err := pgx.BeginFunc(context.Background(), h.pool, func(tx pgx.Tx) error {
		var err error
		sig, p, err = h.svc.Sign(context.Background(), tx, userID, in, purpose, subject, "signature")
		if p != nil {
			return errStop
		}
		return err
	})
	if p != nil {
		return sig, p.Code + ":" + p.Field + ":" + p.Reason
	}
	if err != nil {
		t.Fatal(err)
	}
	return sig, ""
}

var errStop = fmt.Errorf("problem: roll back")

func TestRegisterDeviceKeyChecksTheKey(t *testing.T) {
	h := newHarness(t)
	st := h.signUp(t, authn.ClientMobile, authn.RoleOwner)
	if _, p, _ := h.svc.RegisterDeviceKey(context.Background(), st.Session, "ios", "c2hvcnQ", nil); p == nil || p.Field != "publicKey" {
		t.Errorf("short key: %+v", p)
	}
}

// test/followups.test.ts: "signs only the action, subject and user a signature
// was made for, and only once".
func TestDeviceSignature(t *testing.T) {
	h := newHarness(t)
	joko := newSigner(t, h)
	dewi := newSigner(t, h)
	const other = "invalid_input:signature.device:wrong_subject"

	ch := joko.challenge(t, "change_order", "co_8KQ2_1")
	if !ch.DeviceKeyRegistered || ch.Fallback != account.ChannelWhatsApp {
		t.Errorf("challenge = %+v", ch)
	}
	if _, p := h.sign(t, joko.user, joko.device(ch), "bank_account", joko.user); p != other {
		t.Errorf("another action: %q", p)
	}
	if _, p := h.sign(t, joko.user, joko.device(joko.challenge(t, "bank_account", "usr_dewi")), "bank_account", joko.user); p != other {
		t.Errorf("another subject: %q", p)
	}
	if _, p := h.sign(t, joko.user, dewi.device(dewi.challenge(t, "bank_account", joko.user)), "bank_account", joko.user); p != other {
		t.Errorf("another person's challenge: %q", p)
	}

	right := joko.challenge(t, "bank_account", joko.user)
	forged := joko.device(right)
	forged.Device.Assertion = base64.RawURLEncoding.EncodeToString(ed25519.Sign(dewi.key, []byte(right.Nonce)))
	if _, p := h.sign(t, joko.user, forged, "bank_account", joko.user); p != "wrong_code:signature.device:wrong_code" {
		t.Errorf("signed with another key: %q", p)
	}
	sig, p := h.sign(t, joko.user, joko.device(right), "bank_account", joko.user)
	if p != "" || sig.Method != "device_biometric" || sig.UserID != joko.user {
		t.Fatalf("right signature: %+v %q", sig, p)
	}
	if _, p := h.sign(t, joko.user, joko.device(right), "bank_account", joko.user); p != "challenge_expired:signature.device:expired" {
		t.Errorf("signed twice: %q", p)
	}

	// Signing out of the phone retires its key.
	if err := h.svc.SignOut(context.Background(), joko.st.Session.ID); err != nil {
		t.Fatal(err)
	}
	later := joko.challenge(t, "bank_account", joko.user)
	if _, p := h.sign(t, joko.user, joko.device(later), "bank_account", joko.user); p != "wrong_code:signature.device:wrong_code" {
		t.Errorf("key of a signed-out phone: %q", p)
	}
}

func TestCodeSignature(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	joko := newSigner(t, h)
	dewi := newSigner(t, h)
	phone := *joko.st.User.Phone

	ask := func(s signer, challengeID *string) (account.Challenge, *problem.Problem) {
		h.waitResend(ctx, t, *s.st.User.Phone)
		ch, p, err := h.svc.RequestCode(ctx, account.RequestCodeInput{
			Phone: "+6281200000000", Channel: account.ChannelWhatsApp, Purpose: account.PurposeSign,
			ChallengeID: challengeID, UserID: s.user, ClientIP: newIP(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return ch, p
	}
	answer := func(requestID string) *account.SignatureInput {
		return &account.SignatureInput{Code: &account.CodeAnswer{RequestID: requestID, Code: h.inbox.last(t, phone)}}
	}

	// The code goes to the signer's own number, not the one typed.
	ch := joko.challenge(t, "bank_account", joko.user)
	sent, p := ask(joko, &ch.ID)
	if p != nil || sent.PhoneMasked != account.MaskPhone(phone) {
		t.Fatalf("sign code: %+v %+v", sent, p)
	}
	sig, perr := h.sign(t, joko.user, answer(sent.RequestID), "bank_account", joko.user)
	if perr != "" || sig.Method != "otp_whatsapp" {
		t.Fatalf("code signature: %+v %q", sig, perr)
	}
	if _, perr := h.sign(t, joko.user, answer(sent.RequestID), "bank_account", joko.user); perr != "challenge_expired:signature.code:expired" {
		t.Errorf("code used twice: %q", perr)
	}

	// A loose sign code never signs; one for another challenge signs only that.
	loose, _ := ask(joko, nil)
	if _, perr := h.sign(t, joko.user, answer(loose.RequestID), "bank_account", joko.user); perr != "invalid_input:signature.code:challenge_required" {
		t.Errorf("loose code: %q", perr)
	}
	handover := joko.challenge(t, "handover", "job_8KQ2")
	forHandover, _ := ask(joko, &handover.ID)
	if _, perr := h.sign(t, joko.user, answer(forHandover.RequestID), "bank_account", joko.user); perr != "invalid_input:signature.code:wrong_subject" {
		t.Errorf("code for another challenge: %q", perr)
	}
	// Someone else's challenge cannot be asked for.
	theirs := dewi.challenge(t, "bank_account", joko.user)
	if _, p := ask(joko, &theirs.ID); p == nil || p.Code != "challenge_expired" || p.Field != "challengeId" {
		t.Errorf("another person's challenge: %+v", p)
	}
	// Signed out, nothing can be asked for.
	if _, p, _ := h.svc.RequestCode(ctx, account.RequestCodeInput{Phone: phone, Channel: account.ChannelWhatsApp, Purpose: account.PurposeSign}); p == nil || p.Code != "challenge_expired" {
		t.Errorf("anonymous sign code: %+v", p)
	}

	// A sign-in code never signs.
	h.waitResend(ctx, t, phone)
	signIn := h.request(t, phone)
	if _, perr := h.sign(t, joko.user, answer(signIn.RequestID), "bank_account", joko.user); perr != "invalid_input:signature.code:wrong_subject" {
		t.Errorf("sign-in code: %q", perr)
	}
	// And a sign code never signs in.
	ch = joko.challenge(t, "release", "stg_1")
	sent, _ = ask(joko, &ch.ID)
	if _, p, _ := h.verify(ctx, sent.RequestID, h.inbox.last(t, phone), authn.ClientMobile, nil); p != "challenge_expired:requestId:expired" {
		t.Errorf("sign code used to sign in: %q", p)
	}
}

// Wrong guesses count even though the signing action rolls back.
func TestCodeSignatureGuessesAreCounted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	joko := newSigner(t, h)
	phone := *joko.st.User.Phone
	ch := joko.challenge(t, "release", "stg_1")
	h.waitResend(ctx, t, phone)
	sent, _, err := h.svc.RequestCode(ctx, account.RequestCodeInput{
		Phone: phone, Channel: account.ChannelSMS, Purpose: account.PurposeSign, ChallengeID: &ch.ID, UserID: joko.user, ClientIP: newIP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong := &account.SignatureInput{Code: &account.CodeAnswer{RequestID: sent.RequestID, Code: "999999"}}
	if h.inbox.last(t, phone) == "999999" {
		wrong.Code.Code = "999998"
	}
	for range account.MaxAttempts {
		if _, p := h.sign(t, joko.user, wrong, "release", "stg_1"); p != "wrong_code:signature.code:wrong_code" {
			t.Fatalf("guess: %q", p)
		}
	}
	right := &account.SignatureInput{Code: &account.CodeAnswer{RequestID: sent.RequestID, Code: h.inbox.last(t, phone)}}
	if _, p := h.sign(t, joko.user, right, "release", "stg_1"); p != "challenge_expired:signature.code:expired" {
		t.Errorf("right code after %d wrong: %q, want challenge_expired", account.MaxAttempts, p)
	}
}

func TestSignatureNeedsExactlyOneMethod(t *testing.T) {
	h := newHarness(t)
	joko := newSigner(t, h)
	if _, p := h.sign(t, joko.user, nil, "release", "stg_1"); p != "invalid_input:signature:required" {
		t.Errorf("no signature: %q", p)
	}
}

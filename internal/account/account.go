// Package account owns people and their sign-in: phone codes, sessions and the
// account settings behind `me`. The GraphQL layer maps its results to the
// contract's types; this package knows nothing about GraphQL.
package account

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/ratelimit"
)

const (
	// CodeTTL is how long a phone code works (contract: CodeChallenge.expiresAt).
	CodeTTL = 10 * time.Minute
	// ResendAfter is when the app may ask for another code (CodeChallenge.resendAt).
	ResendAfter = 30 * time.Second
	// MaxAttempts is how many wrong guesses a code takes before it stops working.
	// With 6 digits that leaves a 1 in 200,000 chance per code.
	MaxAttempts = 5
	// SessionTTL is how long a session lasts, with no refresh (contract README, Auth).
	SessionTTL = 30 * 24 * time.Hour
	// StaffIdle ends a staff (ops) session after this long without a request.
	StaffIdle = 30 * time.Minute
	// touchEvery limits how often a session's last-active time is written.
	touchEvery = 5 * time.Minute
)

// Rate limits on sending and checking codes. Each code costs a WhatsApp or SMS
// message, so sending is limited per number and per client address.
var (
	limitResend    = ratelimit.Rule{Name: "code.resend", Limit: 1, Window: ResendAfter}
	limitPhoneHour = ratelimit.Rule{Name: "code.phone", Limit: 5, Window: time.Hour}
	limitIPHour    = ratelimit.Rule{Name: "code.ip", Limit: 30, Window: time.Hour}
	limitVerifyIP  = ratelimit.Rule{Name: "verify.ip", Limit: 60, Window: 10 * time.Minute}
)

// PhonePattern is an E.164 Indonesian number. The apps normalise what people
// type (08…, 8…, 62…) before sending it.
var PhonePattern = regexp.MustCompile(`^\+62[0-9]{8,13}$`)

type Channel string

const (
	ChannelWhatsApp  Channel = "whatsapp"
	ChannelSMS       Channel = "sms"
	ChannelVoiceCall Channel = "voice_call"
)

type Purpose string

const (
	PurposeSignIn Purpose = "sign_in"
	PurposeSign   Purpose = "sign"
)

// Service is the account domain. It is safe for concurrent use.
type Service struct {
	pool    *pgxpool.Pool
	limiter *ratelimit.Limiter
	sender  Sender
	secret  []byte
	now     func() time.Time
	logger  *slog.Logger
}

type Options struct {
	Pool    *pgxpool.Pool
	Limiter *ratelimit.Limiter
	Sender  Sender
	// Secret keys the HMAC of stored codes.
	Secret []byte
	Now    func() time.Time
	Logger *slog.Logger
}

func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{pool: o.Pool, limiter: o.Limiter, sender: o.Sender, secret: o.Secret, now: o.Now, logger: o.Logger}
}

// User is a person's account.
type User struct {
	ID              string
	Phone           *string
	Email           *string
	Name            string
	DisplayName     string
	Language        i18n.Lang
	PreferredVABank *string
	VoiceHelp       bool
	Roles           []authn.Role
	Consents        Consents
	CreatedAt       time.Time
}

// Initials fill the avatar: the first letter of the first two words of the
// display name ("Bu Dewi" → "BD").
func (u User) Initials() string { return Initials(u.DisplayName) }

func Initials(name string) string {
	var b strings.Builder
	for i, w := range strings.Fields(name) {
		if i == 2 {
			break
		}
		r := []rune(w)
		b.WriteRune(unicode.ToUpper(r[0]))
	}
	return b.String()
}

type Consents struct {
	AIProcessing     bool
	AIProcessingAt   *time.Time
	AITrainingPhotos bool
	PriceBookSharing bool
}

// MaskPhone shows a number without its middle: +62 812 •••• 4471.
func MaskPhone(phone string) string {
	if !PhonePattern.MatchString(phone) {
		return phone
	}
	return "+62 " + phone[3:6] + " •••• " + phone[len(phone)-4:]
}

// signInRole is the role a phone sign-in starts the session as: the account's
// first role that signs in by phone. Ops staff sign in by email.
func signInRole(roles []authn.Role) authn.Role {
	for _, r := range roles {
		if r != authn.RoleOps {
			return r
		}
	}
	return roles[0]
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

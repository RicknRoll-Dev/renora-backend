package account

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/ids"
	"github.com/renora/renora-api/internal/problem"
	"github.com/renora/renora-api/internal/ratelimit"
)

type RequestCodeInput struct {
	Phone          string
	Channel        Channel
	Purpose        Purpose
	ChallengeID    *string
	AndroidAppHash string
	// ClientIP is the caller's address, for the per-address limit.
	ClientIP string
}

// Challenge is what the app shows while the person waits for the code.
type Challenge struct {
	RequestID   string
	Channel     Channel
	PhoneMasked string
	ExpiresAt   time.Time
	ResendAt    time.Time
}

var (
	msgPhoneFormat = i18n.T("Use a number like 0812 1880 4471.", "Gunakan nomor seperti 0812 1880 4471.")
	msgCodeExpired = i18n.T("Ask for a new code.", "Minta kode baru.")
	msgWrongCode   = i18n.T("That code is not right. Check WhatsApp and try again.",
		"Kode itu salah. Cek WhatsApp lalu coba lagi.")
	msgChallengeExpired = i18n.T("Ask for a new signing challenge.", "Minta tantangan tanda tangan baru.")
	msgRoleRequired     = i18n.T("This number is new to Renora. Choose home owner, contractor or shop.",
		"Nomor ini baru di Renora. Pilih pemilik rumah, kontraktor, atau toko.")
)

// RequestCode sends a 6-digit sign-in code. Problems: invalid_input (phone),
// challenge_expired (challengeId). Too many requests return RATE_LIMITED.
func (s *Service) RequestCode(ctx context.Context, in RequestCodeInput) (Challenge, *problem.Problem, error) {
	if !PhonePattern.MatchString(in.Phone) {
		return Challenge{}, problem.Invalid("phone", "invalid_format", msgPhoneFormat), nil
	}
	if in.Purpose == PurposeSign {
		// A signing code answers a signing challenge (createSigningChallenge), which
		// does not exist yet: every challenge id is unknown.
		return Challenge{}, problem.InvalidCode("challenge_expired", "challengeId", "expired", msgChallengeExpired), nil
	}
	if err := s.allow(ctx,
		check{limitResend, in.Phone},
		check{limitPhoneHour, in.Phone},
		check{limitIPHour, in.ClientIP},
	); err != nil {
		return Challenge{}, nil, err
	}

	code, err := sixDigits()
	if err != nil {
		return Challenge{}, nil, err
	}
	now := s.now()
	ch := Challenge{
		RequestID:   ids.New("otp"),
		Channel:     in.Channel,
		PhoneMasked: MaskPhone(in.Phone),
		ExpiresAt:   now.Add(CodeTTL),
		ResendAt:    now.Add(ResendAfter),
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO app.sign_in_codes (id, phone, purpose, channel, code_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ch.RequestID, in.Phone, in.Purpose, in.Channel, s.codeHash(ch.RequestID, code), ch.ExpiresAt, now,
	); err != nil {
		return Challenge{}, nil, fmt.Errorf("store code: %w", err)
	}
	if err := s.sender.Send(ctx, Code{
		Phone: in.Phone, Channel: in.Channel, Code: code,
		Lang: i18n.From(ctx), AndroidAppHash: in.AndroidAppHash,
	}); err != nil {
		return Challenge{}, nil, fmt.Errorf("send code: %w", err)
	}
	return ch, nil, nil
}

type VerifyCodeInput struct {
	RequestID string
	Code      string
	Client    authn.Client
	// Role is chosen on sign-up; ignored for an existing account.
	Role      *authn.Role
	UserAgent string
	ClientIP  string
}

// Started is a new session. Token goes to a mobile app or into the web cookie;
// it is never stored.
type Started struct {
	Session authn.Session
	Token   string
	User    User
}

var signUpRoles = []authn.Role{authn.RoleOwner, authn.RoleContractor, authn.RoleSupplier}

var codeFormat = regexp.MustCompile(`^[0-9]{6}$`)

// VerifyCode checks a sign-in code and starts a session, signing the number up
// when Renora does not know it. Problems: wrong_code (code), challenge_expired
// (requestId), invalid_input (role, required) for a new number without a role:
// the code stays usable, so the app asks who they are and sends it again.
func (s *Service) VerifyCode(ctx context.Context, in VerifyCodeInput) (Started, *problem.Problem, error) {
	if err := s.allow(ctx, check{limitVerifyIP, in.ClientIP}); err != nil {
		return Started{}, nil, err
	}
	var (
		out Started
		p   *problem.Problem
	)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now()
		var (
			phone    string
			purpose  Purpose
			hash     []byte
			attempts int
		)
		// FOR UPDATE: two guesses at one code take turns, so the attempt count holds.
		err := tx.QueryRow(ctx, `
			SELECT phone, purpose, code_hash, attempts FROM app.sign_in_codes
			WHERE id = $1 AND used_at IS NULL AND expires_at > $2
			FOR UPDATE`, in.RequestID, now,
		).Scan(&phone, &purpose, &hash, &attempts)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (purpose != PurposeSignIn || attempts >= MaxAttempts) {
			p = problem.InvalidCode("challenge_expired", "requestId", "expired", msgCodeExpired)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load code: %w", err)
		}

		if !codeFormat.MatchString(in.Code) || !hmac.Equal(hash, s.codeHash(in.RequestID, in.Code)) {
			if _, err := tx.Exec(ctx, `UPDATE app.sign_in_codes SET attempts = attempts + 1 WHERE id = $1`, in.RequestID); err != nil {
				return fmt.Errorf("count attempt: %w", err)
			}
			p = problem.InvalidCode("wrong_code", "code", "wrong_code", msgWrongCode)
			return nil // commit the count
		}

		user, found, err := userByPhone(ctx, tx, phone)
		if err != nil {
			return err
		}
		if !found {
			if in.Role == nil || !slices.Contains(signUpRoles, *in.Role) {
				p = problem.Invalid("role", "required", msgRoleRequired)
				return errRollback // the code is not used up
			}
			if user, err = signUp(ctx, tx, phone, *in.Role, i18n.From(ctx), now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE app.sign_in_codes SET used_at = $2 WHERE id = $1`, in.RequestID, now); err != nil {
			return fmt.Errorf("use code: %w", err)
		}
		sess, token, err := startSession(ctx, tx, user, signInRole(user.Roles), in.Client, deviceLabel(in.UserAgent, in.Client), now)
		if err != nil {
			return err
		}
		out = Started{Session: sess, Token: token, User: user}
		return nil
	})
	if errors.Is(err, errRollback) {
		err = nil
	}
	if err != nil {
		return Started{}, nil, err
	}
	return out, p, nil
}

// errRollback ends a transaction without committing; it is not a failure.
var errRollback = errors.New("rollback")

func signUp(ctx context.Context, tx pgx.Tx, phone string, role authn.Role, lang i18n.Lang, now time.Time) (User, error) {
	// ON CONFLICT: two codes for one new number verified at once sign up once.
	if _, err := tx.Exec(ctx, `
		INSERT INTO app.users (id, phone, language, roles, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (phone) DO NOTHING`,
		ids.New("usr"), phone, string(lang), []string{string(role)}, now,
	); err != nil {
		return User{}, fmt.Errorf("sign up: %w", err)
	}
	u, _, err := userByPhone(ctx, tx, phone)
	return u, err
}

func (s *Service) codeHash(requestID, code string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(requestID))
	m.Write([]byte{0})
	m.Write([]byte(code))
	return m.Sum(nil)
}

func sixDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

type check struct {
	rule ratelimit.Rule
	key  string
}

// allow records a hit on every check and fails with RATE_LIMITED if any is over
// its limit. It fails closed: when Redis cannot count, no code is sent, since
// each one is a paid message.
func (s *Service) allow(ctx context.Context, checks ...check) error {
	for _, c := range checks {
		if c.key == "" {
			continue
		}
		ok, err := s.limiter.Allow(ctx, c.rule, c.key)
		if err != nil {
			return err
		}
		if !ok {
			return apperr.RateLimited()
		}
	}
	return nil
}

package account

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/ids"
	"github.com/renora/renora-api/internal/problem"
	"github.com/renora/renora-api/internal/ratelimit"
)

const (
	// StaffChallengeTTL is how long the second step of a staff sign-in waits.
	StaffChallengeTTL = 5 * time.Minute
	// StaffSessionTTL caps a staff session even when it stays active.
	StaffSessionTTL = 12 * time.Hour
	totpSealPurpose = "totp"
)

var limitStaffStartIP = ratelimit.Rule{Name: "staff.start.ip", Limit: 20, Window: 10 * time.Minute}

type StaffFactor string

const (
	FactorSecurityKey   StaffFactor = "security_key"
	FactorAuthenticator StaffFactor = "authenticator"
)

// StaffProfile is what an ops account may do.
type StaffProfile struct {
	Role        string
	Permissions []string
}

// StaffChallenge is the second step of a staff sign-in.
type StaffChallenge struct {
	ID      string
	Methods []StaffFactor
}

var (
	msgStaffEmail   = i18n.T("Use your Renora work email.", "Gunakan email kerja Renora Anda.")
	msgStaffExpired = i18n.T("Start again.", "Mulai lagi.")
	msgStaffCode    = i18n.T("That code is not right. Try the next one.", "Kode itu salah. Coba kode berikutnya.")
	msgStaffMethod  = i18n.T("Use your authenticator app.", "Gunakan aplikasi authenticator Anda.")
)

// StartStaffSignIn opens a staff sign-in for a work email. Problems:
// invalid_input (email, unknown) when no staff account with a second factor
// has that email.
func (s *Service) StartStaffSignIn(ctx context.Context, email, clientIP string) (StaffChallenge, *problem.Problem, error) {
	if err := s.allow(ctx, check{limitStaffStartIP, clientIP}); err != nil {
		return StaffChallenge{}, nil, err
	}
	var (
		userID  string
		hasTOTP bool
	)
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, st.totp_secret IS NOT NULL
		FROM app.users u JOIN app.staff st ON st.user_id = u.id
		WHERE u.phone IS NULL AND lower(u.email) = lower($1) AND 'ops' = ANY (u.roles)`,
		strings.TrimSpace(email)).Scan(&userID, &hasTOTP)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !hasTOTP {
		return StaffChallenge{}, problem.Invalid("email", "unknown", msgStaffEmail), nil
	}
	if err != nil {
		return StaffChallenge{}, nil, fmt.Errorf("find staff: %w", err)
	}
	ch := StaffChallenge{ID: ids.New("stc"), Methods: []StaffFactor{FactorAuthenticator}}
	now := s.now()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO app.staff_challenges (id, user_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
		ch.ID, userID, now.Add(StaffChallengeTTL), now); err != nil {
		return StaffChallenge{}, nil, fmt.Errorf("start staff sign-in: %w", err)
	}
	return ch, nil, nil
}

type VerifyStaffInput struct {
	ChallengeID string
	Method      StaffFactor
	Code        string
	UserAgent   string
	ClientIP    string
}

// VerifyStaffSignIn checks the second factor and starts an ops web session.
// Problems: challenge_expired (challengeId), wrong_code (code), invalid_input
// (method) for a factor the account has not set up.
func (s *Service) VerifyStaffSignIn(ctx context.Context, in VerifyStaffInput) (Started, *problem.Problem, error) {
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
			userID   string
			attempts int
			sealed   []byte
			lastStep int64
		)
		err := tx.QueryRow(ctx, `
			SELECT c.user_id, c.attempts, st.totp_secret, st.totp_step
			FROM app.staff_challenges c JOIN app.staff st ON st.user_id = c.user_id
			WHERE c.id = $1 AND c.used_at IS NULL AND c.expires_at > $2
			FOR UPDATE OF c, st`, in.ChallengeID, now,
		).Scan(&userID, &attempts, &sealed, &lastStep)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && attempts >= MaxAttempts {
			p = problem.InvalidCode("challenge_expired", "challengeId", "expired", msgStaffExpired)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load staff challenge: %w", err)
		}
		// Security keys need a way to register them, which the contract does not have yet.
		if in.Method != FactorAuthenticator || sealed == nil {
			p = problem.Invalid("method", "unknown_option", msgStaffMethod)
			return nil
		}
		secret, err := s.open(totpSealPurpose, sealed)
		if err != nil {
			return fmt.Errorf("open authenticator secret: %w", err)
		}
		step, ok := totpMatch(secret, in.Code, now, lastStep)
		if !codeFormat.MatchString(in.Code) || !ok {
			if _, err := tx.Exec(ctx, `UPDATE app.staff_challenges SET attempts = attempts + 1 WHERE id = $1`, in.ChallengeID); err != nil {
				return fmt.Errorf("count attempt: %w", err)
			}
			p = problem.InvalidCode("wrong_code", "code", "wrong_code", msgStaffCode)
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE app.staff_challenges SET used_at = $2 WHERE id = $1`, in.ChallengeID, now); err != nil {
			return fmt.Errorf("use staff challenge: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE app.staff SET totp_step = $2 WHERE user_id = $1`, userID, step); err != nil {
			return fmt.Errorf("record authenticator step: %w", err)
		}
		u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM app.users WHERE id = $1`, userID))
		if err != nil {
			return fmt.Errorf("load staff user: %w", err)
		}
		sess, token, err := startSessionTTL(ctx, tx, u, authn.RoleOps, authn.ClientWeb,
			deviceLabel(in.UserAgent, authn.ClientWeb), now, StaffSessionTTL)
		if err != nil {
			return err
		}
		out = Started{Session: sess, Token: token, User: u}
		return nil
	})
	if err != nil {
		return Started{}, nil, err
	}
	return out, p, nil
}

// Staff returns an account's staff profile, or nil when it is not staff.
func (s *Service) Staff(ctx context.Context, userID string) (*StaffProfile, error) {
	var sp StaffProfile
	err := s.pool.QueryRow(ctx, `SELECT staff_role, permissions FROM app.staff WHERE user_id = $1`, userID).
		Scan(&sp.Role, &sp.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load staff profile: %w", err)
	}
	return &sp, nil
}

// NewStaff is an ops account to create (cmd/staff).
type NewStaff struct {
	Email       string
	Name        string
	Role        string
	Permissions []string
}

var staffRoles = regexp.MustCompile(`^(mediator|support|finance|lead|verification)$`)

// AddStaff creates an ops account, or updates the profile of the one with
// that email. It returns the account id.
func (s *Service) AddStaff(ctx context.Context, in NewStaff) (string, error) {
	a, err := mail.ParseAddress(in.Email)
	if err != nil || a.Address != in.Email {
		return "", fmt.Errorf("email %q is not an address", in.Email)
	}
	if !staffRoles.MatchString(in.Role) {
		return "", fmt.Errorf("role %q: want mediator, support, finance, lead or verification", in.Role)
	}
	name := strings.Join(strings.Fields(in.Name), " ")
	if name == "" {
		return "", errors.New("name is required")
	}
	if in.Permissions == nil {
		in.Permissions = []string{}
	}
	var id string
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO app.users (id, email, name, display_name, language, roles)
			VALUES ($1, $2, $3, $3, 'en', ARRAY['ops'])
			ON CONFLICT (lower(email)) WHERE phone IS NULL
			DO UPDATE SET name = EXCLUDED.name, display_name = EXCLUDED.display_name
			RETURNING id`, ids.New("usr"), in.Email, name).Scan(&id)
		if err != nil {
			return fmt.Errorf("staff account: %w", err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO app.staff (user_id, staff_role, permissions) VALUES ($1, $2, $3)
			ON CONFLICT (user_id) DO UPDATE SET staff_role = EXCLUDED.staff_role, permissions = EXCLUDED.permissions`,
			id, in.Role, in.Permissions)
		if err != nil {
			return fmt.Errorf("staff profile: %w", err)
		}
		return nil
	})
	return id, err
}

// EnrollAuthenticator gives a staff account a new authenticator secret and
// returns the otpauth:// URI to scan. Any earlier authenticator stops working.
func (s *Service) EnrollAuthenticator(ctx context.Context, email string) (string, error) {
	secret := make([]byte, 20)
	_, _ = rand.Read(secret)
	sealed, err := s.seal(totpSealPurpose, secret)
	if err != nil {
		return "", err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE app.staff st SET totp_secret = $2, totp_step = 0
		FROM app.users u
		WHERE u.id = st.user_id AND u.phone IS NULL AND lower(u.email) = lower($1)`, email, sealed)
	if err != nil {
		return "", fmt.Errorf("enroll authenticator: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("no staff account with email %q", email)
	}
	return totpURI(secret, email), nil
}

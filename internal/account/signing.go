package account

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/ids"
	"github.com/renora/renora-api/internal/problem"
)

// SigningChallengeTTL is how long a signing nonce waits for its signature.
const SigningChallengeTTL = 5 * time.Minute

// SigningPurposes are the contract's SigningPurpose values.
var SigningPurposes = []string{"agreement", "change_order", "handover", "partial_release", "end_job",
	"progress_count", "release", "mediation", "bank_account", "owner_seat"}

type DeviceKey struct {
	ID        string
	Platform  string
	Label     *string
	CreatedAt time.Time
}

var msgPublicKey = i18n.T("The device key must be a 32-byte Ed25519 public key.", "Kunci perangkat harus kunci publik Ed25519 32 byte.")

// RegisterDeviceKey stores this phone's Ed25519 public key (raw 32 bytes,
// base64url). It belongs to the session: signing out retires it. Problems:
// invalid_input (publicKey).
func (s *Service) RegisterDeviceKey(ctx context.Context, sess authn.Session, platform, publicKey string, label *string) (DeviceKey, *problem.Problem, error) {
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(publicKey, "="))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return DeviceKey{}, problem.Invalid("publicKey", "invalid_format", msgPublicKey), nil
	}
	k := DeviceKey{ID: ids.New("dk"), Platform: platform, Label: label, CreatedAt: s.now()}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO app.device_keys (id, user_id, session_id, platform, public_key, label, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		k.ID, sess.UserID, sess.ID, platform, pub, label, k.CreatedAt); err != nil {
		return DeviceKey{}, nil, fmt.Errorf("register device key: %w", err)
	}
	return k, nil, nil
}

type SigningChallenge struct {
	ID                  string
	Purpose             string
	SubjectID           string
	Nonce               string
	ExpiresAt           time.Time
	DeviceKeyRegistered bool
	Fallback            Channel
}

// CreateSigningChallenge makes a one-time nonce to sign purpose and subject.
// Whether the subject exists and the caller may sign it is the signing
// action's check (agreements, change orders, ...), made when it is signed.
func (s *Service) CreateSigningChallenge(ctx context.Context, sess authn.Session, purpose, subjectID string) (SigningChallenge, error) {
	if !slices.Contains(SigningPurposes, purpose) {
		return SigningChallenge{}, fmt.Errorf("unknown signing purpose %q", purpose)
	}
	now := s.now()
	ch := SigningChallenge{
		ID:        ids.New("sch"),
		Purpose:   purpose,
		SubjectID: subjectID,
		Nonce:     ids.Token(),
		ExpiresAt: now.Add(SigningChallengeTTL),
		Fallback:  ChannelWhatsApp,
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO app.signing_challenges (id, user_id, purpose, subject_id, nonce, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			ch.ID, sess.UserID, purpose, subjectID, ch.Nonce, ch.ExpiresAt, now); err != nil {
			return fmt.Errorf("create signing challenge: %w", err)
		}
		return tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM app.device_keys WHERE session_id = $1 AND revoked_at IS NULL)`,
			sess.ID).Scan(&ch.DeviceKeyRegistered)
	})
	return ch, err
}

// SignatureInput is the contract's SignatureInput: exactly one of Device or Code.
type SignatureInput struct {
	Device *DeviceAssertion
	Code   *CodeAnswer
}

type DeviceAssertion struct {
	ChallengeID string
	KeyID       string
	Assertion   string // base64url Ed25519 signature over the nonce
}

type CodeAnswer struct {
	RequestID string
	Code      string
}

// Signature is who signed and how, for the signing action to record.
type Signature struct {
	UserID   string
	Name     string
	SignedAt time.Time
	Method   string // the contract's SignatureMethod: device_biometric, otp_whatsapp, otp_sms
}

var (
	msgWrongSubject = i18n.T("This signature is for something else. Sign this again.",
		"Tanda tangan ini untuk hal lain. Tanda tangani ini lagi.")
	msgChallengeRequired = i18n.T("Ask for the code from this signature's step.",
		"Minta kode dari langkah tanda tangan ini.")
	msgBadSignature = i18n.T("The signature did not check out. Unlock and sign again.",
		"Tanda tangan tidak cocok. Buka kunci lalu tanda tangani lagi.")
	msgSignatureRequired = i18n.T("Sign this first.", "Tanda tangani ini dulu.")
)

// Sign checks a signature for one action: purpose and subject, by userID,
// once. Run it in the signing action's transaction: the challenge is used up
// only if the action commits. field is the input path ("signature").
//
// Problems (InvalidInput on field.device or field.code): challenge_expired,
// wrong_subject (made for another action, subject or person, or a sign-in
// code), challenge_required (a code asked for without its challenge),
// wrong_code.
func (s *Service) Sign(ctx context.Context, tx pgx.Tx, userID string, in *SignatureInput, purpose, subjectID, field string) (Signature, *problem.Problem, error) {
	switch {
	case in == nil || (in.Device == nil) == (in.Code == nil):
		return Signature{}, problem.Invalid(field, "required", msgSignatureRequired), nil
	case in.Device != nil:
		return s.signDevice(ctx, tx, userID, in.Device, purpose, subjectID, field+".device")
	default:
		return s.signCode(ctx, tx, userID, in.Code, purpose, subjectID, field+".code")
	}
}

func (s *Service) signDevice(ctx context.Context, tx pgx.Tx, userID string, d *DeviceAssertion, purpose, subjectID, field string) (Signature, *problem.Problem, error) {
	now := s.now()
	ch, found, err := liveChallenge(ctx, tx, d.ChallengeID, now)
	if err != nil {
		return Signature{}, nil, err
	}
	if !found {
		return Signature{}, problem.InvalidCode("challenge_expired", field, "expired", msgChallengeExpired), nil
	}
	if ch.purpose != purpose || ch.subjectID != subjectID || ch.userID != userID {
		return Signature{}, problem.Invalid(field, "wrong_subject", msgWrongSubject), nil
	}
	var pub []byte
	err = tx.QueryRow(ctx, `
		SELECT public_key FROM app.device_keys WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		d.KeyID, userID).Scan(&pub)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Signature{}, nil, fmt.Errorf("load device key: %w", err)
	}
	sig, decErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(d.Assertion, "="))
	if errors.Is(err, pgx.ErrNoRows) || decErr != nil || !ed25519.Verify(pub, []byte(ch.nonce), sig) {
		return Signature{}, problem.InvalidCode("wrong_code", field, "wrong_code", msgBadSignature), nil
	}
	if p, err := useChallenge(ctx, tx, ch.id, now, field); p != nil || err != nil {
		return Signature{}, p, err
	}
	return s.signed(ctx, tx, userID, "device_biometric", now)
}

func (s *Service) signCode(ctx context.Context, tx pgx.Tx, userID string, c *CodeAnswer, purpose, subjectID, field string) (Signature, *problem.Problem, error) {
	now := s.now()
	expired := problem.InvalidCode("challenge_expired", field, "expired", msgCodeExpired)

	// The guess is counted on its own connection, so a rolled-back action does
	// not undo it: a code takes MaxAttempts tries in all, the right one included.
	var (
		codePurpose Purpose
		channel     Channel
		challengeID *string
		hash        []byte
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE app.sign_in_codes SET attempts = attempts + 1
		WHERE id = $1 AND used_at IS NULL AND expires_at > $2 AND attempts < $3
		RETURNING purpose, channel, challenge_id, code_hash`,
		c.RequestID, now, MaxAttempts).Scan(&codePurpose, &channel, &challengeID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Signature{}, expired, nil
	}
	if err != nil {
		return Signature{}, nil, fmt.Errorf("load code: %w", err)
	}
	if codePurpose != PurposeSign {
		return Signature{}, problem.Invalid(field, "wrong_subject", msgWrongSubject), nil
	}
	if challengeID == nil {
		return Signature{}, problem.Invalid(field, "challenge_required", msgChallengeRequired), nil
	}
	ch, found, err := liveChallenge(ctx, tx, *challengeID, now)
	if err != nil {
		return Signature{}, nil, err
	}
	if !found {
		return Signature{}, expired, nil
	}
	if ch.purpose != purpose || ch.subjectID != subjectID || ch.userID != userID {
		return Signature{}, problem.Invalid(field, "wrong_subject", msgWrongSubject), nil
	}
	if !codeFormat.MatchString(c.Code) || !hmac.Equal(hash, s.codeHash(c.RequestID, c.Code)) {
		return Signature{}, problem.InvalidCode("wrong_code", field, "wrong_code", msgWrongCode), nil
	}
	tag, err := tx.Exec(ctx, `UPDATE app.sign_in_codes SET used_at = $2 WHERE id = $1 AND used_at IS NULL`, c.RequestID, now)
	if err != nil {
		return Signature{}, nil, fmt.Errorf("use code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Signature{}, expired, nil
	}
	if p, err := useChallenge(ctx, tx, ch.id, now, field); p != nil || err != nil {
		return Signature{}, p, err
	}
	method := "otp_whatsapp"
	if channel != ChannelWhatsApp {
		method = "otp_sms"
	}
	return s.signed(ctx, tx, userID, method, now)
}

type challengeRow struct {
	id, userID, purpose, subjectID, nonce string
}

func liveChallenge(ctx context.Context, tx pgx.Tx, id string, now time.Time) (challengeRow, bool, error) {
	ch := challengeRow{id: id}
	err := tx.QueryRow(ctx, `
		SELECT user_id, purpose, subject_id, nonce FROM app.signing_challenges
		WHERE id = $1 AND used_at IS NULL AND expires_at > $2
		FOR UPDATE`, id, now).Scan(&ch.userID, &ch.purpose, &ch.subjectID, &ch.nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return ch, false, nil
	}
	if err != nil {
		return ch, false, fmt.Errorf("load signing challenge: %w", err)
	}
	return ch, true, nil
}

func useChallenge(ctx context.Context, tx pgx.Tx, id string, now time.Time, field string) (*problem.Problem, error) {
	tag, err := tx.Exec(ctx, `UPDATE app.signing_challenges SET used_at = $2 WHERE id = $1 AND used_at IS NULL`, id, now)
	if err != nil {
		return nil, fmt.Errorf("use signing challenge: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return problem.InvalidCode("challenge_expired", field, "expired", msgChallengeExpired), nil
	}
	return nil, nil
}

func (s *Service) signed(ctx context.Context, tx pgx.Tx, userID, method string, now time.Time) (Signature, *problem.Problem, error) {
	sig := Signature{UserID: userID, SignedAt: now, Method: method}
	if err := tx.QueryRow(ctx, `SELECT name FROM app.users WHERE id = $1`, userID).Scan(&sig.Name); err != nil {
		return Signature{}, nil, fmt.Errorf("load signer: %w", err)
	}
	return sig, nil, nil
}

// signingChallengeOf finds a live signing challenge the user asked for, for a
// `sign` code to answer.
func signingChallengeOf(ctx context.Context, q querier, id, userID string, now time.Time) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT true FROM app.signing_challenges
		WHERE id = $1 AND user_id = $2 AND used_at IS NULL AND expires_at > $3`, id, userID, now).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}

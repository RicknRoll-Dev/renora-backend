package account

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/ids"
	"github.com/renora/renora-api/internal/problem"
	"github.com/renora/renora-api/internal/ratelimit"
)

const (
	// QRTTL is how long a sign-in QR waits for a phone, as in the mock.
	QRTTL = 42 * time.Second
	// qrCollectWithin is how long an approved QR waits for its browser's poll.
	qrCollectWithin = 2 * time.Minute
)

var limitQRIP = ratelimit.Rule{Name: "qr.ip", Limit: 60, Window: 10 * time.Minute}

type QRStatus string

const (
	QRWaiting  QRStatus = "waiting"
	QRApproved QRStatus = "approved"
	QRExpired  QRStatus = "expired"
)

type QRSignIn struct {
	ID        string
	Status    QRStatus
	ExpiresAt time.Time
}

// Payload is what the web page shows as the QR code.
func (q QRSignIn) Payload() string { return "renora://auth/qr/" + q.ID }

var (
	msgQRExpired = i18n.T("This code has expired. Show a new one.", "Kode ini sudah kedaluwarsa. Tampilkan yang baru.")
	msgQRUsed    = i18n.T("This code was already used", "Kode ini sudah dipakai")
)

// CreateQRSignIn starts a web sign-in by QR. The secret goes into the
// browser's renora_qr cookie: only that browser collects the session, so a
// photo of the QR on someone's screen signs nobody in.
func (s *Service) CreateQRSignIn(ctx context.Context, clientIP string) (QRSignIn, string, error) {
	if err := s.allow(ctx, check{limitQRIP, clientIP}); err != nil {
		return QRSignIn{}, "", err
	}
	now := s.now()
	q := QRSignIn{ID: ids.New("qr"), Status: QRWaiting, ExpiresAt: now.Add(QRTTL)}
	secret := ids.Token()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO app.qr_sign_ins (id, secret_hash, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
		q.ID, ids.Hash(secret), q.ExpiresAt, now); err != nil {
		return QRSignIn{}, "", fmt.Errorf("create QR sign-in: %w", err)
	}
	return q, secret, nil
}

// ApproveQRSignIn is the signed-in phone saying yes to a QR on a screen. The
// web session will be the approver's, in the role the phone is signed in as.
// Problems: not_found (unknown or expired), already_answered.
func (s *Service) ApproveQRSignIn(ctx context.Context, approver authn.Session, id string) (QRSignIn, *problem.Problem, error) {
	now := s.now()
	var (
		q          = QRSignIn{ID: id}
		approvedAt *time.Time
	)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT expires_at, approved_at FROM app.qr_sign_ins WHERE id = $1 FOR UPDATE`, id).
			Scan(&q.ExpiresAt, &approvedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load QR sign-in: %w", err)
		}
		if approvedAt != nil || !now.Before(q.ExpiresAt) {
			return nil
		}
		_, err = tx.Exec(ctx, `
			UPDATE app.qr_sign_ins SET approved_by = $2, approved_role = $3, approved_at = $4 WHERE id = $1`,
			id, approver.UserID, string(approver.Role), now)
		if err != nil {
			return fmt.Errorf("approve QR sign-in: %w", err)
		}
		q.Status = QRApproved
		return nil
	})
	switch {
	case err != nil:
		return QRSignIn{}, nil, err
	case q.Status == QRApproved:
		return q, nil, nil
	case approvedAt != nil:
		return QRSignIn{}, problem.Conflict("already_answered", msgQRUsed), nil
	}
	return QRSignIn{}, problem.NotFound(msgQRExpired), nil
}

// PollQRSignIn answers the web page's poll. Once approved, the poll from the
// browser holding the secret starts the web session, once; any other caller
// sees the status only. found is false for an unknown id.
func (s *Service) PollQRSignIn(ctx context.Context, id, secret, userAgent string) (q QRSignIn, started *Started, found bool, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now()
		var (
			hash                    []byte
			approvedBy, role        *string
			approvedAt, collectedAt *time.Time
		)
		q.ID = id
		err := tx.QueryRow(ctx, `
			SELECT secret_hash, expires_at, approved_by, approved_role, approved_at, collected_at
			FROM app.qr_sign_ins WHERE id = $1 FOR UPDATE`, id,
		).Scan(&hash, &q.ExpiresAt, &approvedBy, &role, &approvedAt, &collectedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load QR sign-in: %w", err)
		}
		found = true
		switch {
		case approvedAt == nil && now.Before(q.ExpiresAt):
			q.Status = QRWaiting
			return nil
		case approvedAt == nil || collectedAt == nil && now.Sub(*approvedAt) > qrCollectWithin:
			q.Status = QRExpired
			return nil
		}
		q.Status = QRApproved
		if collectedAt != nil || secret == "" || subtle.ConstantTimeCompare(hash, ids.Hash(secret)) != 1 {
			return nil
		}
		u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM app.users WHERE id = $1`, *approvedBy))
		if err != nil {
			return fmt.Errorf("load approver: %w", err)
		}
		r := authn.Role(*role)
		ttl := SessionTTL
		if r == authn.RoleOps {
			ttl = StaffSessionTTL
		}
		sess, token, err := startSessionTTL(ctx, tx, u, r, authn.ClientWeb, deviceLabel(userAgent, authn.ClientWeb), now, ttl)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE app.qr_sign_ins SET collected_at = $2 WHERE id = $1`, id, now); err != nil {
			return fmt.Errorf("collect QR sign-in: %w", err)
		}
		started = &Started{Session: sess, Token: token, User: u}
		return nil
	})
	return q, started, found, err
}

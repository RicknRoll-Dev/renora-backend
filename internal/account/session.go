package account

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/ids"
	"github.com/renora/renora-api/internal/problem"
)

func startSession(ctx context.Context, q querier, u User, role authn.Role, client authn.Client, label string, now time.Time) (authn.Session, string, error) {
	return startSessionTTL(ctx, q, u, role, client, label, now, SessionTTL)
}

func startSessionTTL(ctx context.Context, q querier, u User, role authn.Role, client authn.Client, label string, now time.Time, ttl time.Duration) (authn.Session, string, error) {
	token := ids.Token()
	sess := authn.Session{
		ID:        ids.New("ses"),
		UserID:    u.ID,
		Role:      role,
		Client:    client,
		Language:  u.Language,
		ExpiresAt: now.Add(ttl),
	}
	var csrf *string
	if client == authn.ClientWeb {
		sess.CSRFToken = ids.Token()
		csrf = &sess.CSRFToken
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO app.sessions (id, user_id, token_hash, role, client, csrf_token, label, created_at, last_active_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)`,
		sess.ID, sess.UserID, ids.Hash(token), sess.Role, sess.Client, csrf, label, now, sess.ExpiresAt,
	); err != nil {
		return authn.Session{}, "", fmt.Errorf("start session: %w", err)
	}
	return sess, token, nil
}

// Lookup implements authn.SessionStore: the live session for a token, or nil.
func (s *Service) Lookup(ctx context.Context, token string) (*authn.Session, error) {
	now := s.now()
	var (
		sess       authn.Session
		csrf       *string
		lang       string
		lastActive time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT s.id, s.user_id, s.role, s.client, s.csrf_token, s.expires_at, s.guest, s.last_active_at, u.language
		FROM app.sessions s JOIN app.users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > $2`,
		ids.Hash(token), now,
	).Scan(&sess.ID, &sess.UserID, &sess.Role, &sess.Client, &csrf, &sess.ExpiresAt, &sess.Guest, &lastActive, &lang)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("look up session: %w", err)
	}
	if sess.Role == authn.RoleOps && now.Sub(lastActive) > StaffIdle {
		return nil, nil
	}
	if csrf != nil {
		sess.CSRFToken = *csrf
	}
	sess.Language = i18n.Lang(lang)

	// The last-active time feeds the signed-in devices list and the staff idle
	// limit; writing it at most every few minutes keeps reads cheap.
	if now.Sub(lastActive) > touchEvery || sess.Role == authn.RoleOps {
		if _, err := s.pool.Exec(ctx, `UPDATE app.sessions SET last_active_at = $2 WHERE id = $1`, sess.ID, now); err != nil {
			s.logger.WarnContext(ctx, "touch session", "error", err)
		}
	}
	return &sess, nil
}

// SignOut ends a session; its token stops working at once.
func (s *Service) SignOut(ctx context.Context, sessionID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return endSession(ctx, tx, sessionID, s.now()) })
}

// endSession revokes a session and the device keys it registered: a phone that
// signed out signs nothing.
func endSession(ctx context.Context, tx pgx.Tx, sessionID string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE app.sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, sessionID, now); err != nil {
		return fmt.Errorf("sign out: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE app.device_keys SET revoked_at = $2 WHERE session_id = $1 AND revoked_at IS NULL`, sessionID, now); err != nil {
		return fmt.Errorf("retire device keys: %w", err)
	}
	return nil
}

// SignedInSession is one device in the person's list of signed-in sessions.
type SignedInSession struct {
	ID           string
	Label        string
	Place        *string
	LastActiveAt time.Time
}

// Sessions lists a user's live sessions, most recently used first.
func (s *Service) Sessions(ctx context.Context, userID string) ([]SignedInSession, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, label, place, last_active_at FROM app.sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
		ORDER BY last_active_at DESC, id`, userID, s.now())
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (SignedInSession, error) {
		var x SignedInSession
		err := r.Scan(&x.ID, &x.Label, &x.Place, &x.LastActiveAt)
		return x, err
	})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return list, nil
}

var msgSessionNotFound = i18n.T("That device is already signed out.", "Perangkat itu sudah keluar.")

// RevokeSession signs one of the user's devices out. Problems: not_found.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) (*problem.Problem, error) {
	now := s.now()
	var p *problem.Problem
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var live bool
		err := tx.QueryRow(ctx, `
			SELECT true FROM app.sessions
			WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > $3`,
			sessionID, userID, now).Scan(&live)
		if errors.Is(err, pgx.ErrNoRows) {
			p = problem.NotFound(msgSessionNotFound)
			return nil
		}
		if err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		return endSession(ctx, tx, sessionID, now)
	})
	return p, err
}

// deviceLabel names a session for the signed-in devices list: "Chrome on Mac".
func deviceLabel(userAgent string, client authn.Client) string {
	ua := strings.ToLower(userAgent)
	os := ""
	for _, o := range []struct{ match, name string }{
		{"iphone", "iPhone"}, {"ipad", "iPad"}, {"android", "Android"},
		{"mac os", "Mac"}, {"macintosh", "Mac"}, {"windows", "Windows"},
		{"cros", "Chromebook"}, {"linux", "Linux"},
	} {
		if strings.Contains(ua, o.match) {
			os = o.name
			break
		}
	}
	if client == authn.ClientMobile {
		if os == "" {
			return "Renora app"
		}
		return "Renora app on " + os
	}
	browser := ""
	// Order matters: Edge and Opera say Chrome, Chrome says Safari.
	for _, b := range []struct{ match, name string }{
		{"edg/", "Edge"}, {"opr/", "Opera"}, {"samsungbrowser", "Samsung Internet"},
		{"firefox/", "Firefox"}, {"fxios", "Firefox"}, {"crios", "Chrome"}, {"chrome/", "Chrome"},
		{"safari/", "Safari"},
	} {
		if strings.Contains(ua, b.match) {
			browser = b.name
			break
		}
	}
	switch {
	case browser != "" && os != "":
		return browser + " on " + os
	case browser != "":
		return browser
	case os != "":
		return "Browser on " + os
	}
	return "Browser"
}

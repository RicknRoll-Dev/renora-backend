package account

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

// Sign-in codes are kept a day after they expire, for support questions
// ("I never got the code"). Ended sessions are kept 30 days.
const (
	codeRetention    = 24 * time.Hour
	sessionRetention = 30 * 24 * time.Hour
)

type PurgeArgs struct{}

func (PurgeArgs) Kind() string { return "account.purge" }

// PurgeWorker deletes old sign-in codes, QR and signing challenges, and ended sessions.
type PurgeWorker struct {
	river.WorkerDefaults[PurgeArgs]
	Pool *pgxpool.Pool
}

func (w *PurgeWorker) Work(ctx context.Context, _ *river.Job[PurgeArgs]) error {
	if _, err := w.Pool.Exec(ctx,
		`DELETE FROM app.sign_in_codes WHERE expires_at < now() - make_interval(secs => $1)`,
		codeRetention.Seconds()); err != nil {
		return fmt.Errorf("purge sign-in codes: %w", err)
	}
	for _, q := range []string{
		`DELETE FROM app.qr_sign_ins WHERE expires_at < now() - make_interval(secs => $1)`,
		`DELETE FROM app.staff_challenges WHERE expires_at < now() - make_interval(secs => $1)`,
		`DELETE FROM app.signing_challenges WHERE expires_at < now() - make_interval(secs => $1)`,
	} {
		if _, err := w.Pool.Exec(ctx, q, codeRetention.Seconds()); err != nil {
			return fmt.Errorf("purge challenges: %w", err)
		}
	}
	if _, err := w.Pool.Exec(ctx,
		`DELETE FROM app.sessions WHERE LEAST(expires_at, COALESCE(revoked_at, 'infinity')) < now() - make_interval(secs => $1)`,
		sessionRetention.Seconds()); err != nil {
		return fmt.Errorf("purge sessions: %w", err)
	}
	return nil
}

// PurgePeriodicJob runs the purge daily.
func PurgePeriodicJob() *river.PeriodicJob {
	return river.NewPeriodicJob(
		river.PeriodicInterval(24*time.Hour),
		func() (river.JobArgs, *river.InsertOpts) {
			return PurgeArgs{}, &river.InsertOpts{UniqueOpts: river.UniqueOpts{ByPeriod: 24 * time.Hour}}
		},
		&river.PeriodicJobOpts{RunOnStart: true},
	)
}

package idempotency

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

// Retention is how long a key is remembered. Apps retry within minutes and the
// offline queue within days; a month covers both with room to spare.
const Retention = 30 * 24 * time.Hour

type PurgeArgs struct{}

func (PurgeArgs) Kind() string { return "idempotency.purge" }

// PurgeWorker deletes keys older than Retention.
type PurgeWorker struct {
	river.WorkerDefaults[PurgeArgs]
	Pool *pgxpool.Pool
}

func (w *PurgeWorker) Work(ctx context.Context, _ *river.Job[PurgeArgs]) error {
	if _, err := w.Pool.Exec(ctx,
		`DELETE FROM app.idempotency_keys WHERE created_at < now() - make_interval(secs => $1)`,
		Retention.Seconds()); err != nil {
		return fmt.Errorf("purge idempotency keys: %w", err)
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

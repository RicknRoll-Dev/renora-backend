// Command worker runs background jobs from the River queue: step clocks
// (auto-release, bid close), notifications and AI calls.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/riverqueue/river"
	"golang.org/x/sync/errgroup"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/api"
	"github.com/renora/renora-api/internal/config"
	"github.com/renora/renora-api/internal/idempotency"
	"github.com/renora/renora-api/internal/platform/health"
	"github.com/renora/renora-api/internal/platform/httpx"
	"github.com/renora/renora-api/internal/platform/logging"
	"github.com/renora/renora-api/internal/platform/postgres"
	"github.com/renora/renora-api/internal/platform/queue"
	"github.com/renora/renora-api/internal/platform/telemetry"
	"github.com/renora/renora-api/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "worker:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger, err := logging.New(os.Stdout, cfg.Log.Level, cfg.Log.Format,
		"service", cfg.ServiceName, "component", "worker", "version", version.Version)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := telemetry.SetupTracing(ctx, cfg.ServiceName, version.Version, string(cfg.Env))
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(flushCtx)
	}()

	pool, err := postgres.Open(ctx, cfg.Database, cfg.ServiceName+"-worker")
	if err != nil {
		return err
	}
	defer pool.Close()

	reg := telemetry.NewRegistry()

	// Domain modules register their workers and periodic jobs here as they are built.
	workers := river.NewWorkers()
	river.AddWorker(workers, queue.NewHeartbeatWorker(reg))
	river.AddWorker(workers, &idempotency.PurgeWorker{Pool: pool})
	river.AddWorker(workers, &account.PurgeWorker{Pool: pool})
	periodic := []*river.PeriodicJob{
		queue.HeartbeatPeriodicJob(),
		idempotency.PurgePeriodicJob(),
		account.PurgePeriodicJob(),
	}

	client, err := queue.NewWorker(pool, logger, workers, periodic, cfg.Worker.Concurrency)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}

	checker := health.NewChecker(map[string]health.CheckFunc{"postgres": pool.Ping})
	adminSrv := httpx.NewServer(cfg.HTTP.AdminAddr, api.NewAdminRouter(reg, checker), cfg.HTTP, logger)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return httpx.Serve(gctx, adminSrv, cfg.HTTP.ShutdownTimeout, logger) })
	g.Go(func() error {
		if err := client.Start(gctx); err != nil {
			return fmt.Errorf("start river: %w", err)
		}
		<-gctx.Done()
		checker.SetDraining()

		// Let running jobs finish; after the timeout, cancel them so they are
		// retried by another worker instead of being cut off mid-write.
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(gctx), cfg.HTTP.ShutdownTimeout)
		defer cancel()
		if err := client.Stop(stopCtx); err != nil {
			logger.Warn("graceful stop timed out, cancelling running jobs", "error", err)
			hardCtx, hardCancel := context.WithTimeout(context.WithoutCancel(gctx), 5*time.Second)
			defer hardCancel()
			return client.StopAndCancel(hardCtx)
		}
		logger.Info("worker stopped")
		return nil
	})
	return g.Wait()
}

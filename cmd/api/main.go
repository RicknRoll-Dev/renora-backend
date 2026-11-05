// Command api serves the public GraphQL API.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/api"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/config"
	"github.com/renora/renora-api/internal/graph"
	"github.com/renora/renora-api/internal/platform/health"
	"github.com/renora/renora-api/internal/platform/httpx"
	"github.com/renora/renora-api/internal/platform/logging"
	"github.com/renora/renora-api/internal/platform/postgres"
	"github.com/renora/renora-api/internal/platform/queue"
	"github.com/renora/renora-api/internal/platform/redisclient"
	"github.com/renora/renora-api/internal/platform/telemetry"
	"github.com/renora/renora-api/internal/ratelimit"
	"github.com/renora/renora-api/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "api:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger, err := logging.New(os.Stdout, cfg.Log.Level, cfg.Log.Format,
		"service", cfg.ServiceName, "component", "api", "version", version.Version)
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
	defer flush(shutdownTracing, logger)

	pool, err := postgres.Open(ctx, cfg.Database, cfg.ServiceName+"-api")
	if err != nil {
		return err
	}
	defer pool.Close()

	rdb, err := redisclient.Open(ctx, cfg.Redis.URL)
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()

	inserter, err := queue.NewInserter(pool, logger)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}

	reg := telemetry.NewRegistry()
	checker := health.NewChecker(map[string]health.CheckFunc{
		"postgres": pool.Ping,
		"redis":    func(ctx context.Context) error { return rdb.Ping(ctx).Err() },
	})

	secret, err := authSecret(cfg, logger)
	if err != nil {
		return err
	}
	accounts := account.New(account.Options{
		Pool:    pool,
		Limiter: ratelimit.New(rdb),
		Sender:  account.LogSender{Logger: logger}, // config allows only "log" until a provider is wired
		Secret:  secret,
		Logger:  logger,
	})
	var sessions authn.SessionStore = accounts

	resolver := &graph.Resolver{
		Queue:    inserter,
		Now:      time.Now,
		Accounts: accounts,
		Cookies:  authn.CookieConfig{Secure: cfg.Auth.CookieSecure, Domain: cfg.Auth.CookieDomain},
	}
	gql := graph.NewHandler(resolver, graph.ServerOptions{
		Config:      cfg.GraphQL,
		Logger:      logger,
		APQCache:    graph.NewAPQCache(rdb, cfg.GraphQL.APQTTL),
		Sessions:    sessions,
		OriginHosts: api.OriginHosts(cfg.HTTP.CORSAllowedOrigins),
	})

	publicSrv := httpx.NewServer(cfg.HTTP.Addr, api.NewRouter(api.Deps{
		Config:   cfg,
		Logger:   logger,
		Health:   checker,
		Metrics:  httpx.NewMetrics(reg),
		Sessions: sessions,
		GraphQL:  gql,
	}), cfg.HTTP, logger)
	adminSrv := httpx.NewServer(cfg.HTTP.AdminAddr, api.NewAdminRouter(reg, checker), cfg.HTTP, logger)

	// On SIGTERM: fail readiness, wait for the load balancer to notice, then
	// stop accepting connections and drain in-flight requests.
	serveCtx, cancelServe := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelServe()
	go func() {
		<-ctx.Done()
		logger.Info("shutdown signal received", "delay", cfg.HTTP.ShutdownDelay)
		checker.SetDraining()
		time.Sleep(cfg.HTTP.ShutdownDelay)
		cancelServe()
	}()

	g, gctx := errgroup.WithContext(serveCtx)
	g.Go(func() error { return httpx.Serve(gctx, publicSrv, cfg.HTTP.ShutdownTimeout, logger) })
	g.Go(func() error { return httpx.Serve(gctx, adminSrv, cfg.HTTP.ShutdownTimeout, logger) })
	return g.Wait()
}

// authSecret is AUTH_SECRET. In development it may be left out: a random secret
// is made for this process, so codes sent before a restart stop working.
func authSecret(cfg config.Config, logger *slog.Logger) ([]byte, error) {
	if cfg.Auth.Secret != "" {
		return []byte(cfg.Auth.Secret), nil
	}
	if cfg.Env != config.EnvDevelopment {
		return nil, errors.New("AUTH_SECRET is required") // config.Load already refuses this
	}
	logger.Warn("AUTH_SECRET is empty: using a random secret for this process")
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func flush(shutdown func(context.Context) error, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		logger.Warn("flush traces", "error", err)
	}
}

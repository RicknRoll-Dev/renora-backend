// Package config loads process configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

type Env string

const (
	EnvDevelopment Env = "development"
	EnvStaging     Env = "staging"
	EnvProduction  Env = "production"
)

type Config struct {
	Env         Env    `env:"APP_ENV" envDefault:"development"`
	ServiceName string `env:"OTEL_SERVICE_NAME" envDefault:"renora-backend"`

	Log      Log
	HTTP     HTTP
	Database Database
	Redis    Redis
	GraphQL  GraphQL
	Worker   Worker
	Auth     Auth
}

type Log struct {
	Level  string `env:"LOG_LEVEL" envDefault:"info"`
	Format string `env:"LOG_FORMAT" envDefault:"json"`
}

type HTTP struct {
	Addr      string `env:"HTTP_ADDR" envDefault:":8080"`
	AdminAddr string `env:"ADMIN_ADDR" envDefault:":9090"`

	ReadHeaderTimeout time.Duration `env:"HTTP_READ_HEADER_TIMEOUT" envDefault:"5s"`
	ReadTimeout       time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout      time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"30s"`
	IdleTimeout       time.Duration `env:"HTTP_IDLE_TIMEOUT" envDefault:"120s"`
	RequestTimeout    time.Duration `env:"HTTP_REQUEST_TIMEOUT" envDefault:"20s"`
	ShutdownTimeout   time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"25s"`
	// ShutdownDelay is how long readiness fails before the server stops
	// accepting connections; match it to the load balancer's probe interval.
	ShutdownDelay time.Duration `env:"HTTP_SHUTDOWN_DELAY" envDefault:"0s"`
	MaxBodyBytes  int64         `env:"HTTP_MAX_BODY_BYTES" envDefault:"1048576"`

	CORSAllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:","`
	// TrustedProxyHops is how many proxies in front of us append to
	// X-Forwarded-For (e.g. 1 for a single load balancer). 0 ignores the header.
	TrustedProxyHops int `env:"HTTP_TRUSTED_PROXY_HOPS" envDefault:"0"`
}

type Database struct {
	URL             string        `env:"DATABASE_URL,required,notEmpty"`
	MaxConns        int32         `env:"DB_MAX_CONNS" envDefault:"20"`
	MinConns        int32         `env:"DB_MIN_CONNS" envDefault:"2"`
	MaxConnLifetime time.Duration `env:"DB_MAX_CONN_LIFETIME" envDefault:"30m"`
	MaxConnIdleTime time.Duration `env:"DB_MAX_CONN_IDLE_TIME" envDefault:"5m"`
}

type Redis struct {
	URL string `env:"REDIS_URL,required,notEmpty"`
}

type GraphQL struct {
	ComplexityLimit int `env:"GRAPHQL_COMPLEXITY_LIMIT" envDefault:"1000"`
	DepthLimit      int `env:"GRAPHQL_DEPTH_LIMIT" envDefault:"12"`
	// Introspection and Playground default to on outside production; see Load.
	Introspection *bool         `env:"GRAPHQL_INTROSPECTION"`
	Playground    *bool         `env:"GRAPHQL_PLAYGROUND"`
	APQTTL        time.Duration `env:"GRAPHQL_APQ_TTL" envDefault:"24h"`
}

type Auth struct {
	// Secret keys the HMAC of sign-in codes. At least 32 bytes; required outside
	// development. Rotating it voids the codes in flight (10 minutes' worth).
	Secret string `env:"AUTH_SECRET"`
	// CodeSender delivers sign-in codes. "log" writes them to the log, for
	// development and staging testers, and is refused in production.
	CodeSender string `env:"AUTH_CODE_SENDER" envDefault:"log"`
	// CookieSecure marks the web session cookies Secure. Browsers treat
	// http://localhost as secure, so it stays on in development.
	CookieSecure bool `env:"SESSION_COOKIE_SECURE" envDefault:"true"`
	// CookieDomain is empty for host-only cookies.
	CookieDomain string `env:"SESSION_COOKIE_DOMAIN"`
}

type Worker struct {
	Concurrency int `env:"WORKER_CONCURRENCY" envDefault:"50"`
}

func Load() (Config, error) {
	cfg, err := parse()
	if err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parse reads the environment and fills the defaults that depend on APP_ENV.
func parse() (Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return Config{}, fmt.Errorf("parse env: %w", err)
	}
	devDefault := cfg.Env != EnvProduction
	if cfg.GraphQL.Introspection == nil {
		cfg.GraphQL.Introspection = &devDefault
	}
	if cfg.GraphQL.Playground == nil {
		cfg.GraphQL.Playground = &devDefault
	}
	return cfg, nil
}

func (c Config) IsProduction() bool { return c.Env == EnvProduction }

func (c Config) validate() error {
	var errs []error
	switch c.Env {
	case EnvDevelopment, EnvStaging, EnvProduction:
	default:
		errs = append(errs, fmt.Errorf("APP_ENV must be development, staging or production, got %q", c.Env))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("LOG_FORMAT must be json or text, got %q", c.Log.Format))
	}
	if c.Database.MinConns > c.Database.MaxConns {
		errs = append(errs, errors.New("DB_MIN_CONNS must not exceed DB_MAX_CONNS"))
	}
	if c.HTTP.TrustedProxyHops < 0 {
		errs = append(errs, errors.New("HTTP_TRUSTED_PROXY_HOPS must not be negative"))
	}
	if c.GraphQL.ComplexityLimit <= 0 || c.GraphQL.DepthLimit <= 0 {
		errs = append(errs, errors.New("GRAPHQL_COMPLEXITY_LIMIT and GRAPHQL_DEPTH_LIMIT must be positive"))
	}
	switch c.Auth.CodeSender {
	case "log":
		if c.IsProduction() {
			errs = append(errs, errors.New("AUTH_CODE_SENDER=log writes codes to the log and is refused in production"))
		}
	default:
		errs = append(errs, fmt.Errorf("AUTH_CODE_SENDER must be log, got %q", c.Auth.CodeSender))
	}
	if c.Env != EnvDevelopment && len(c.Auth.Secret) < 32 {
		errs = append(errs, errors.New("AUTH_SECRET must be at least 32 bytes outside development"))
	}
	if c.IsProduction() {
		if !c.Auth.CookieSecure {
			errs = append(errs, errors.New("SESSION_COOKIE_SECURE must be on in production"))
		}
		if *c.GraphQL.Playground {
			errs = append(errs, errors.New("GRAPHQL_PLAYGROUND must be off in production"))
		}
		for _, o := range c.HTTP.CORSAllowedOrigins {
			if o == "*" {
				errs = append(errs, errors.New("CORS_ALLOWED_ORIGINS must not contain * in production"))
			}
		}
	}
	return errors.Join(errs...)
}

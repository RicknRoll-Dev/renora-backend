package config

import (
	"strings"
	"testing"
)

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://localhost/renora")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
}

func TestLoadDefaults(t *testing.T) {
	setRequired(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != EnvDevelopment {
		t.Errorf("Env = %q, want development", cfg.Env)
	}
	if !*cfg.GraphQL.Introspection || !*cfg.GraphQL.Playground {
		t.Error("introspection and playground should default on outside production")
	}
}

func TestLoadProductionDefaults(t *testing.T) {
	setRequired(t)
	t.Setenv("APP_ENV", "production")

	cfg, err := parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *cfg.GraphQL.Introspection || *cfg.GraphQL.Playground {
		t.Error("introspection and playground should default off in production")
	}
}

func TestLoadRejectsUnsafeProduction(t *testing.T) {
	// Each case breaks one rule on top of an otherwise valid production setup,
	// except the code sender: no provider is wired yet, so production refuses to
	// start until one is (nobody could sign in).
	tests := map[string]struct {
		vars map[string]string
		want string
	}{
		"playground on":    {map[string]string{"GRAPHQL_PLAYGROUND": "true"}, "GRAPHQL_PLAYGROUND"},
		"wildcard cors":    {map[string]string{"CORS_ALLOWED_ORIGINS": "https://app.renora.id,*"}, "CORS_ALLOWED_ORIGINS"},
		"codes in the log": {map[string]string{}, "AUTH_CODE_SENDER"},
		"short secret":     {map[string]string{"AUTH_SECRET": "short"}, "AUTH_SECRET"},
		"insecure cookie":  {map[string]string{"SESSION_COOKIE_SECURE": "false"}, "SESSION_COOKIE_SECURE"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			setRequired(t)
			t.Setenv("APP_ENV", "production")
			t.Setenv("AUTH_SECRET", strings.Repeat("s", 32))
			for k, v := range tt.vars {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load: err = %v, want one naming %s", err, tt.want)
			}
		})
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("DATABASE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load: want error for empty DATABASE_URL")
	}
}

func TestLoadStagingNeedsSecret(t *testing.T) {
	setRequired(t)
	t.Setenv("APP_ENV", "staging")
	if _, err := Load(); err == nil {
		t.Fatal("Load: want error without AUTH_SECRET")
	}
	t.Setenv("AUTH_SECRET", strings.Repeat("s", 32))
	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

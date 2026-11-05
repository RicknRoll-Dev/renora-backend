package testdb

import (
	"context"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
)

// Redis returns a client on TEST_REDIS_URL, or skips the test when it is not set.
// Keys are shared across packages: give them a unique part rather than flushing.
func Redis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("TEST_REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// Package ratelimit counts attempts in fixed windows in Redis, so every API
// instance shares the same count.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Rule allows Limit hits per Window for one key.
type Rule struct {
	Name   string // part of the Redis key: "code.phone"
	Limit  int
	Window time.Duration
}

type Limiter struct {
	rdb redis.Scripter
}

func New(rdb redis.Scripter) *Limiter { return &Limiter{rdb: rdb} }

// hit increments the counter and starts its window on the first hit, atomically.
var hit = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if n == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[1]) end
return n
`)

// Allow records one hit for key under rule and reports whether it is within the limit.
// An error means Redis could not answer; callers decide whether to fail open or closed.
func (l *Limiter) Allow(ctx context.Context, rule Rule, key string) (bool, error) {
	n, err := hit.Run(ctx, l.rdb, []string{"rl:" + rule.Name + ":" + key}, rule.Window.Milliseconds()).Int()
	if err != nil {
		return false, fmt.Errorf("rate limit %s: %w", rule.Name, err)
	}
	return n <= rule.Limit, nil
}

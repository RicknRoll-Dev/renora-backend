package idempotency_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/idempotency"
	"github.com/renora/renora-api/internal/problem"
	"github.com/renora/renora-api/internal/testdb"
)

type funded struct {
	StageID string `json:"stageId"`
	Seq     int64  `json:"seq"`
}

// fundStage stands in for a money mutation: it counts its runs and writes a row
// in the transaction, so a rollback is observable.
type fundStage struct {
	runs atomic.Int64
}

func (f *fundStage) run(ctx context.Context, stageID string) func(tx pgx.Tx) (funded, *problem.Problem, error) {
	return func(tx pgx.Tx) (funded, *problem.Problem, error) {
		n := f.runs.Add(1)
		var seq int64
		if err := tx.QueryRow(ctx, `SELECT $1::bigint`, n).Scan(&seq); err != nil {
			return funded{}, nil, err
		}
		return funded{StageID: stageID, Seq: seq}, nil, nil
	}
}

func key(t *testing.T, scope, value string, input any) idempotency.Key {
	t.Helper()
	fp, err := idempotency.Fingerprint("fundStage", input)
	if err != nil {
		t.Fatal(err)
	}
	return idempotency.Key{Scope: scope, Kind: idempotency.KindKey, Operation: "fundStage", Value: value, Fingerprint: fp}
}

func newScope() string { return "usr_test_" + uuid.NewString() }

func TestReplayReturnsFirstResult(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	f := &fundStage{}
	k := key(t, newScope(), uuid.NewString(), map[string]any{"stageId": "stg_4", "bank": "BCA"})

	first, p, err := idempotency.Do(ctx, pool, k, f.run(ctx, "stg_4"))
	if err != nil || p != nil {
		t.Fatalf("first: %v %v", p, err)
	}
	second, p, err := idempotency.Do(ctx, pool, k, f.run(ctx, "stg_4"))
	if err != nil || p != nil {
		t.Fatalf("replay: %v %v", p, err)
	}
	if second != first {
		t.Errorf("replay = %+v, want first result %+v", second, first)
	}
	if f.runs.Load() != 1 {
		t.Errorf("fn ran %d times, want 1", f.runs.Load())
	}
}

func TestSameKeyDifferentInputIsMismatch(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	f := &fundStage{}
	scope, value := newScope(), uuid.NewString()

	if _, _, err := idempotency.Do(ctx, pool, key(t, scope, value, map[string]any{"bank": "BCA"}), f.run(ctx, "stg_4")); err != nil {
		t.Fatal(err)
	}
	_, p, err := idempotency.Do(ctx, pool, key(t, scope, value, map[string]any{"bank": "BRI"}), f.run(ctx, "stg_4"))
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || p.Code != "idempotency_mismatch" || p.Kind != problem.KindConflict {
		t.Fatalf("problem = %+v, want Conflict idempotency_mismatch", p)
	}
	if f.runs.Load() != 1 {
		t.Errorf("fn ran %d times, want 1", f.runs.Load())
	}
}

func TestProblemIsNotStored(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	k := key(t, newScope(), uuid.NewString(), map[string]any{"stageId": "stg_4"})

	notFunded := func(pgx.Tx) (funded, *problem.Problem, error) {
		return funded{}, problem.Conflict("not_funded", i18n.T("Fund the stage first", "Danai tahap ini dulu")), nil
	}
	if _, p, _ := idempotency.Do(ctx, pool, k, notFunded); p == nil {
		t.Fatal("want the problem back")
	}

	// A corrected retry may reuse the key.
	f := &fundStage{}
	got, p, err := idempotency.Do(ctx, pool, k, f.run(ctx, "stg_4"))
	if err != nil || p != nil || got.StageID != "stg_4" {
		t.Fatalf("retry = %+v %v %v, want it to run", got, p, err)
	}
}

func TestErrorRollsBackTheKey(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	k := key(t, newScope(), uuid.NewString(), nil)

	boom := errors.New("partner timeout")
	if _, _, err := idempotency.Do(ctx, pool, k, func(pgx.Tx) (funded, *problem.Problem, error) {
		return funded{}, nil, boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}

	f := &fundStage{}
	if _, _, err := idempotency.Do(ctx, pool, k, f.run(ctx, "stg_4")); err != nil || f.runs.Load() != 1 {
		t.Fatalf("retry after error should run once: runs=%d err=%v", f.runs.Load(), err)
	}
}

func TestScopesAreIsolated(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	value := uuid.NewString()
	f := &fundStage{}

	a, _, err := idempotency.Do(ctx, pool, key(t, newScope(), value, nil), f.run(ctx, "stg_a"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := idempotency.Do(ctx, pool, key(t, newScope(), value, nil), f.run(ctx, "stg_b"))
	if err != nil {
		t.Fatal(err)
	}
	if a.StageID == b.StageID || f.runs.Load() != 2 {
		t.Errorf("another caller's key must not replay: a=%+v b=%+v runs=%d", a, b, f.runs.Load())
	}
}

func TestClientRefReplaysWithoutComparingInput(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	f := &fundStage{}
	k := idempotency.Key{Scope: newScope(), Kind: idempotency.KindRef, Operation: "sendDailyReport", Value: uuid.NewString()}

	first, _, err := idempotency.Do(ctx, pool, k, f.run(ctx, "rpt_1"))
	if err != nil {
		t.Fatal(err)
	}
	k.Fingerprint = []byte("a different body") // ignored for clientRef
	again, p, err := idempotency.Do(ctx, pool, k, f.run(ctx, "rpt_2"))
	if err != nil || p != nil || again != first || f.runs.Load() != 1 {
		t.Fatalf("clientRef replay = %+v %v %v runs=%d, want first result", again, p, err, f.runs.Load())
	}

	// The same ref on another operation is a different write.
	k.Operation = "sendMessage"
	if _, _, err := idempotency.Do(ctx, pool, k, f.run(ctx, "msg_1")); err != nil || f.runs.Load() != 2 {
		t.Fatalf("ref on another operation should run: runs=%d err=%v", f.runs.Load(), err)
	}
}

func TestConcurrentRequestsRunOnce(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	f := &fundStage{}
	k := key(t, newScope(), uuid.NewString(), map[string]any{"stageId": "stg_4"})

	const n = 8
	results := make([]funded, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { results[i], _, errs[i] = idempotency.Do(ctx, pool, k, f.run(ctx, "stg_4")) })
	}
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("request %d: %v", i, errs[i])
		}
		if results[i] != results[0] {
			t.Errorf("request %d got %+v, want %+v", i, results[i], results[0])
		}
	}
	if f.runs.Load() != 1 {
		t.Errorf("fn ran %d times for one key, want 1", f.runs.Load())
	}
}

func TestKeyValidation(t *testing.T) {
	pool := testdb.Pool(t)
	bad := []idempotency.Key{
		{Kind: idempotency.KindKey, Value: "k", Fingerprint: []byte{1}},
		{Scope: "s", Kind: "other", Value: "k"},
		{Scope: "s", Kind: idempotency.KindRef, Value: "k"},
		{Scope: "s", Kind: idempotency.KindKey, Value: "", Fingerprint: []byte{1}},
		{Scope: "s", Kind: idempotency.KindKey, Value: "k"},
	}
	for _, k := range bad {
		ctx := context.Background()
		if _, _, err := idempotency.Do(ctx, pool, k, (&fundStage{}).run(ctx, "x")); err == nil {
			t.Errorf("Do(%+v): want a validation error", k)
		}
	}
}

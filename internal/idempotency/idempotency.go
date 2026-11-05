// Package idempotency makes mutations safe to retry, as the contract requires:
//
//   - idempotencyKey (money moves, bids, wages): a replay with the same input
//     returns the first result; the same key with a different input is
//     Conflict idempotency_mismatch.
//   - clientRef (offline-queued writes): a replay returns the first result.
//
// Problems are not stored, so a corrected retry may reuse the key.
//
// The key is claimed and its result stored in the same transaction as the
// change, never around it: a crash between "write" and "remember" would
// otherwise run a payment twice on retry.
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/problem"
)

type Kind string

const (
	KindKey Kind = "key" // idempotencyKey
	KindRef Kind = "ref" // clientRef
)

type Key struct {
	// Scope is the caller: a user id, or a link for link pages. Keys never
	// collide across callers, so one caller can never replay another's result.
	Scope string
	Kind  Kind
	// Operation is the mutation name. Required for KindRef; for KindKey it only
	// feeds the fingerprint, since a key is unique across operations.
	Operation string
	Value     string
	// Fingerprint identifies the request (see Fingerprint). Compared for KindKey only.
	Fingerprint []byte
}

// Fingerprint hashes the operation name and its input, with the key itself left
// out of input by the caller.
func Fingerprint(operation string, input any) ([]byte, error) {
	b, err := json.Marshal([]any{operation, input})
	if err != nil {
		return nil, fmt.Errorf("fingerprint %s: %w", operation, err)
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// TxStarter is satisfied by *pgxpool.Pool and pgx.Tx.
type TxStarter interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Do runs fn at most once per key and returns its result, replaying the stored
// result for a repeated key. fn runs inside the transaction that records the
// key; it must do all its writes on tx. When fn returns a problem or an error,
// everything rolls back, the key included.
//
// R is what gets stored and replayed: keep it to small references (ids, a
// status), and let the resolver read current state from them.
func Do[R any](ctx context.Context, db TxStarter, k Key, fn func(tx pgx.Tx) (R, *problem.Problem, error)) (R, *problem.Problem, error) {
	var zero R
	if err := k.validate(); err != nil {
		return zero, nil, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return zero, nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	operation := k.Operation
	if k.Kind == KindKey {
		operation = ""
	}
	fingerprint := k.Fingerprint
	if fingerprint == nil {
		fingerprint = []byte{} // a clientRef needs none; the column is NOT NULL
	}

	// Claim the key. A concurrent request holding the same key makes this wait
	// until it commits (then the row exists) or rolls back (then we claim it).
	tag, err := tx.Exec(ctx, `
		INSERT INTO app.idempotency_keys (scope, kind, operation, key, request_hash)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`,
		k.Scope, string(k.Kind), operation, k.Value, fingerprint)
	if err != nil {
		return zero, nil, fmt.Errorf("claim idempotency key: %w", err)
	}

	if tag.RowsAffected() == 0 {
		var hash, stored []byte
		err := tx.QueryRow(ctx, `
			SELECT request_hash, result FROM app.idempotency_keys
			WHERE scope = $1 AND kind = $2 AND operation = $3 AND key = $4`,
			k.Scope, string(k.Kind), operation, k.Value).Scan(&hash, &stored)
		if err != nil {
			return zero, nil, fmt.Errorf("read idempotency key: %w", err)
		}
		if k.Kind == KindKey && !bytes.Equal(hash, k.Fingerprint) {
			return zero, problem.IdempotencyMismatch(), nil
		}
		if stored == nil {
			return zero, nil, errors.New("idempotency key committed without a result")
		}
		var r R
		if err := json.Unmarshal(stored, &r); err != nil {
			return zero, nil, fmt.Errorf("decode stored result: %w", err)
		}
		return r, nil, nil
	}

	r, p, err := fn(tx)
	if err != nil || p != nil {
		return zero, p, err
	}
	stored, err := json.Marshal(r)
	if err != nil {
		return zero, nil, fmt.Errorf("encode result: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE app.idempotency_keys SET result = $5
		WHERE scope = $1 AND kind = $2 AND operation = $3 AND key = $4`,
		k.Scope, string(k.Kind), operation, k.Value, stored); err != nil {
		return zero, nil, fmt.Errorf("store result: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, nil, fmt.Errorf("commit: %w", err)
	}
	return r, nil, nil
}

func (k Key) validate() error {
	switch {
	case k.Scope == "":
		return errors.New("idempotency: scope is required")
	case k.Kind != KindKey && k.Kind != KindRef:
		return fmt.Errorf("idempotency: unknown kind %q", k.Kind)
	case k.Kind == KindRef && k.Operation == "":
		return errors.New("idempotency: operation is required for a clientRef")
	case k.Value == "" || len(k.Value) > 128:
		return errors.New("idempotency: key must be 1 to 128 characters")
	case k.Kind == KindKey && len(k.Fingerprint) == 0:
		return errors.New("idempotency: fingerprint is required for an idempotencyKey")
	}
	return nil
}

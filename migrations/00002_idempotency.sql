-- +goose Up
-- Replay protection for mutations (contract README, "Idempotency"):
--   kind 'key': idempotencyKey on money moves, bids, wages. A replay with the same
--     input returns the first result; a different input is Conflict idempotency_mismatch.
--     Unique per caller across operations, so operation is ''.
--   kind 'ref': clientRef on offline-queued writes. A replay returns the first
--     result, input is not compared. Unique per caller and operation.
-- A row is written in the same transaction as the change it guards, so a
-- committed change always has its key and a rolled-back one never does.
CREATE TABLE app.idempotency_keys (
  scope        text        NOT NULL, -- the caller: a user id, or a link for link pages
  kind         text        NOT NULL CHECK (kind IN ('key', 'ref')),
  operation    text        NOT NULL,
  key          text        NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
  request_hash bytea       NOT NULL,
  -- Null only inside the claiming transaction: the row is inserted first, so a
  -- concurrent request with the same key waits on it, then filled before commit.
  result       jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, kind, operation, key)
);

-- The daily purge deletes by age.
CREATE INDEX idempotency_keys_created_at ON app.idempotency_keys (created_at);

-- +goose Down
DROP TABLE app.idempotency_keys;

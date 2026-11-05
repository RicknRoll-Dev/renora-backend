-- +goose Up
-- Schemas: app = Renora's own tables (owned by this service),
-- river = job queue tables (owned by River's migrator).
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS river;

-- Keeps updated_at honest without trusting every UPDATE statement.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS app.set_updated_at();
DROP SCHEMA IF EXISTS river;
DROP SCHEMA IF EXISTS app;

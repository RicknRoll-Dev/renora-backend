-- +goose Up
-- Accounts and sign-in (contract schema/auth.graphql, schema/me.graphql).

-- One row per person who signs in. A person can hold several roles (owner,
-- contractor, shop staff, ops); a session signs in as one of them.
CREATE TABLE app.users (
  id                 text        PRIMARY KEY,
  -- E.164 (+62…). Null for staff, who sign in by email.
  phone              text        UNIQUE CHECK (phone ~ '^\+62[0-9]{8,13}$'),
  -- Contact email; not unique (two people can share a family address). Staff
  -- sign-in by email arrives with its own lookup.
  email              text,
  -- Empty until the person enters it after sign-up. Initials are derived from
  -- display_name, so they never drift from it.
  name               text        NOT NULL DEFAULT '',
  display_name       text        NOT NULL DEFAULT '',
  language           text        NOT NULL CHECK (language IN ('id', 'en')),
  preferred_va_bank  text        CHECK (preferred_va_bank IN ('BCA', 'BRI', 'Mandiri', 'BNI')),
  voice_help         boolean     NOT NULL DEFAULT false,
  roles              text[]      NOT NULL CHECK (cardinality(roles) > 0
                                   AND roles <@ ARRAY['owner', 'contractor', 'supplier', 'ops']),
  ai_processing      boolean     NOT NULL DEFAULT false,
  ai_processing_at   timestamptz,
  ai_training_photos boolean     NOT NULL DEFAULT false,
  price_book_sharing boolean     NOT NULL DEFAULT false,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (phone IS NOT NULL OR email IS NOT NULL)
);

CREATE TRIGGER users_updated_at BEFORE UPDATE ON app.users
  FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

-- Phone codes from requestCode. Only an HMAC of the code is kept, so a database
-- copy cannot be used to sign in.
CREATE TABLE app.sign_in_codes (
  id         text        PRIMARY KEY,
  phone      text        NOT NULL,
  purpose    text        NOT NULL CHECK (purpose IN ('sign_in', 'sign')),
  channel    text        NOT NULL CHECK (channel IN ('whatsapp', 'sms', 'voice_call')),
  code_hash  bytea       NOT NULL,
  -- Wrong guesses so far; the code stops working at the limit.
  attempts   integer     NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sign_in_codes_created_at ON app.sign_in_codes (created_at);

-- A signed-in device. Only a SHA-256 of the session token is kept.
CREATE TABLE app.sessions (
  id             text        PRIMARY KEY,
  user_id        text        NOT NULL REFERENCES app.users (id) ON DELETE CASCADE,
  token_hash     bytea       NOT NULL UNIQUE,
  role           text        NOT NULL CHECK (role IN ('owner', 'contractor', 'supplier', 'ops')),
  client         text        NOT NULL CHECK (client IN ('web', 'mobile')),
  -- Web only: the renora_csrf cookie value every mutation echoes in X-CSRF-Token.
  csrf_token     text,
  -- What the person sees in their list of signed-in devices ("Chrome on Mac").
  label          text        NOT NULL,
  place          text,
  guest          boolean     NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_active_at timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  revoked_at     timestamptz,
  CHECK ((client = 'web') = (csrf_token IS NOT NULL))
);

CREATE INDEX sessions_user_live ON app.sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires_at ON app.sessions (expires_at);

-- +goose Down
DROP TABLE app.sessions;
DROP TABLE app.sign_in_codes;
DROP TABLE app.users;

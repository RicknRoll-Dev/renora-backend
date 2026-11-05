-- +goose Up
-- The rest of sign-in (contract schema/auth.graphql): QR sign-in for the web,
-- staff sign-in, device keys and signing challenges.

-- Web sign-in by QR. The browser that shows the QR holds a secret cookie
-- (renora_qr); only that browser collects the session once a phone approves.
-- No session token is stored: the session is created when it is collected.
CREATE TABLE app.qr_sign_ins (
  id             text        PRIMARY KEY,
  secret_hash    bytea       NOT NULL,
  expires_at     timestamptz NOT NULL,
  approved_by    text        REFERENCES app.users (id) ON DELETE CASCADE,
  approved_role  text,
  approved_at    timestamptz,
  collected_at   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CHECK ((approved_by IS NULL) = (approved_at IS NULL))
);

CREATE INDEX qr_sign_ins_created_at ON app.qr_sign_ins (created_at);

-- Ops staff. Their account has no phone; they sign in by email plus a second factor.
CREATE TABLE app.staff (
  user_id     text        PRIMARY KEY REFERENCES app.users (id) ON DELETE CASCADE,
  staff_role  text        NOT NULL CHECK (staff_role IN ('mediator', 'support', 'finance', 'lead', 'verification')),
  permissions text[]      NOT NULL DEFAULT '{}' CHECK (permissions <@ ARRAY[
                            'read_money', 'retry_payouts', 'decide_cases', 'verify_users', 'edit_price_book', 'reply_support']),
  -- Authenticator (TOTP) secret, sealed with a key derived from AUTH_SECRET.
  totp_secret bytea,
  -- The last time step accepted, so a code cannot be used twice.
  totp_step   bigint      NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER staff_updated_at BEFORE UPDATE ON app.staff
  FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

-- Staff sign in by email, so it names one account. Accounts with a phone keep
-- email as a contact field, which need not be unique.
CREATE UNIQUE INDEX users_staff_email ON app.users (lower(email)) WHERE phone IS NULL;

-- The second step of a staff sign-in, between startStaffSignIn and verifyStaffSignIn.
CREATE TABLE app.staff_challenges (
  id         text        PRIMARY KEY,
  user_id    text        NOT NULL REFERENCES app.users (id) ON DELETE CASCADE,
  attempts   integer     NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX staff_challenges_created_at ON app.staff_challenges (created_at);

-- A phone's Ed25519 signing key. It belongs to the session that registered it:
-- "this phone". Signing out of that session retires it.
CREATE TABLE app.device_keys (
  id         text        PRIMARY KEY,
  user_id    text        NOT NULL REFERENCES app.users (id) ON DELETE CASCADE,
  session_id text        NOT NULL REFERENCES app.sessions (id) ON DELETE CASCADE,
  platform   text        NOT NULL CHECK (platform IN ('ios', 'android')),
  public_key bytea       NOT NULL CHECK (length(public_key) = 32),
  label      text,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE INDEX device_keys_session_live ON app.device_keys (session_id) WHERE revoked_at IS NULL;

-- A one-time nonce to sign one purpose and subject, for one user, once.
CREATE TABLE app.signing_challenges (
  id         text        PRIMARY KEY,
  user_id    text        NOT NULL REFERENCES app.users (id) ON DELETE CASCADE,
  purpose    text        NOT NULL CHECK (purpose IN ('agreement', 'change_order', 'handover', 'partial_release',
                            'end_job', 'progress_count', 'release', 'mediation', 'bank_account', 'owner_seat')),
  subject_id text        NOT NULL,
  nonce      text        NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX signing_challenges_created_at ON app.signing_challenges (created_at);

-- A `sign` code answers one signing challenge.
ALTER TABLE app.sign_in_codes
  ADD COLUMN challenge_id text REFERENCES app.signing_challenges (id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE app.sign_in_codes DROP COLUMN challenge_id;
DROP TABLE app.signing_challenges;
DROP TABLE app.device_keys;
DROP TABLE app.staff_challenges;
DROP INDEX app.users_staff_email;
DROP TABLE app.staff;
DROP TABLE app.qr_sign_ins;

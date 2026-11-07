-- Phase 1: dashboard-managed integration credentials.
-- Every secret column holds an AES-256-GCM envelope; plaintext is never stored.

-- Minimal tenancy tables so authorization and isolation are enforceable.
CREATE TABLE IF NOT EXISTS workspaces (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id                TEXT PRIMARY KEY,
  email             TEXT NOT NULL UNIQUE,
  is_app_owner      INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id  TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role          TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  PRIMARY KEY (workspace_id, user_id)
);

-- Provider application credentials (developer app, NOT user tokens).
-- workspace_id NULL  => global, application-owner scope.
-- workspace_id set   => workspace scope.
CREATE TABLE IF NOT EXISTS integration_credentials (
  id                    TEXT PRIMARY KEY,
  workspace_id          TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
  provider              TEXT NOT NULL
                        CHECK (provider IN ('meta','linkedin','x','google','tiktok')),
  configuration_name    TEXT NOT NULL,
  encrypted_credentials TEXT NOT NULL,          -- versioned envelope string
  encryption_version    INTEGER NOT NULL,
  -- Non-secret, UI-safe hints so masked display never needs decryption
  -- (for example the App ID, which is an identifier, not a secret).
  public_config         TEXT NOT NULL DEFAULT '{}',
  enabled               INTEGER NOT NULL DEFAULT 0,
  validation_status     TEXT NOT NULL DEFAULT 'unvalidated'
                        CHECK (validation_status IN
                          ('unvalidated','incomplete','valid','invalid')),
  last_validated_at     TEXT,
  last_error            TEXT,
  created_by            TEXT,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ic_provider_ws
  ON integration_credentials (provider, workspace_id);

-- At most one enabled configuration per (scope, provider, name).
CREATE UNIQUE INDEX IF NOT EXISTS uq_ic_scope_provider_name
  ON integration_credentials (COALESCE(workspace_id, '__global__'), provider, configuration_name);

-- Connected social accounts. Tokens are per-account and encrypted; each row
-- pins the provider configuration used to authorize it, so editing or
-- rotating app credentials never silently re-points an existing connection.
CREATE TABLE IF NOT EXISTS social_accounts (
  id                        TEXT PRIMARY KEY,
  workspace_id              TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider                  TEXT NOT NULL,
  provider_account_id       TEXT NOT NULL,
  display_name              TEXT,
  credential_config_id      TEXT NOT NULL REFERENCES integration_credentials(id),
  encrypted_access_token    TEXT NOT NULL,
  encrypted_refresh_token   TEXT,
  token_expires_at          TEXT,
  scopes                    TEXT,
  status                    TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','expired','revoked','error')),
  last_error                TEXT,
  created_at                TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at                TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (workspace_id, provider, provider_account_id)
);

CREATE INDEX IF NOT EXISTS idx_sa_config ON social_accounts (credential_config_id);

-- Short-lived OAuth state (CSRF) and PKCE verifier. Verifier is encrypted.
CREATE TABLE IF NOT EXISTS oauth_states (
  state                 TEXT PRIMARY KEY,
  workspace_id          TEXT NOT NULL,
  user_id               TEXT NOT NULL,
  provider              TEXT NOT NULL,
  credential_config_id  TEXT NOT NULL,
  encrypted_code_verifier TEXT,
  expires_at            TEXT NOT NULL,
  created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Webhook subscriptions and delivery logs.
-- webhook_key is an unguessable per-configuration path segment, so incoming
-- requests resolve their configuration from it, never from a client-supplied
-- workspace ID.
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id                    TEXT PRIMARY KEY,
  credential_config_id  TEXT NOT NULL REFERENCES integration_credentials(id) ON DELETE CASCADE,
  webhook_key           TEXT NOT NULL UNIQUE,
  status                TEXT NOT NULL DEFAULT 'inactive'
                        CHECK (status IN ('inactive','pending','active','error')),
  last_event_at         TEXT,
  last_error            TEXT,
  created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhook_events (
  id                    TEXT PRIMARY KEY,
  credential_config_id  TEXT NOT NULL,
  provider              TEXT NOT NULL,
  received_at           TEXT NOT NULL DEFAULT (datetime('now')),
  signature_valid       INTEGER NOT NULL,
  status                TEXT NOT NULL,         -- accepted | rejected | error
  error                 TEXT,
  payload_hash          TEXT                   -- SHA-256 hex; raw payload is not retained here
);

CREATE INDEX IF NOT EXISTS idx_we_config_time
  ON webhook_events (credential_config_id, received_at DESC);

-- Append-only audit of every credential change. Never contains secret values.
CREATE TABLE IF NOT EXISTS credential_audit_log (
  id                    TEXT PRIMARY KEY,
  credential_config_id  TEXT,
  workspace_id          TEXT,
  actor_user_id         TEXT,
  action                TEXT NOT NULL,         -- create|update|enable|disable|validate|delete|rotate|read_internal
  changed_fields        TEXT,                  -- JSON array of field NAMES only
  created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cal_config ON credential_audit_log (credential_config_id, created_at DESC);

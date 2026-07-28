-- App-local TOTP MFA (kitgit UI; Authentik stays backend-only)

CREATE TABLE user_mfa (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- base32 TOTP secret; only set when enabled=true
    totp_secret TEXT,
    -- pending enrollment secret until confirmed with a valid code
    pending_secret TEXT,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    -- SHA-256 hex hashes of unused recovery codes
    recovery_code_hashes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mfa_pending_logins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mfa_pending_logins_expires_at_idx ON mfa_pending_logins(expires_at);
CREATE INDEX mfa_pending_logins_user_id_idx ON mfa_pending_logins(user_id);

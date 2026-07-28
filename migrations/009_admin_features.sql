-- Suspended users cannot log in or use Git (HTTP/SSH).
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS users_is_suspended_idx ON users(is_suspended) WHERE is_suspended = TRUE;

-- Site-wide announcement / maintenance banner (separate from MOTD).
INSERT INTO site_settings (key, value) VALUES ('announcement', '')
ON CONFLICT (key) DO NOTHING;

-- Single-use invite codes for signup when public signups are disabled.
CREATE TABLE IF NOT EXISTS invite_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_by UUID REFERENCES users(id) ON DELETE SET NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS invite_codes_unused_idx
    ON invite_codes(created_at DESC)
    WHERE used_at IS NULL AND revoked_at IS NULL;

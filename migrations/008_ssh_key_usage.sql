-- SSH keys may be used for git authentication, commit signing, or both.
ALTER TABLE ssh_keys
    ADD COLUMN IF NOT EXISTS key_usage TEXT NOT NULL DEFAULT 'authentication'
        CHECK (key_usage IN ('authentication', 'signing', 'both'));

CREATE INDEX IF NOT EXISTS ssh_keys_key_usage_idx ON ssh_keys (key_usage);

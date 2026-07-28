-- Pull mirrors: fetch from a remote into the local bare repository.
CREATE TABLE IF NOT EXISTS repo_mirrors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL UNIQUE REFERENCES repositories(id) ON DELETE CASCADE,
    remote_url TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_synced_at TIMESTAMPTZ,
    last_error TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT repo_mirrors_remote_url_nonempty CHECK (char_length(trim(remote_url)) > 0)
);
CREATE INDEX IF NOT EXISTS repo_mirrors_enabled_idx
    ON repo_mirrors(enabled) WHERE enabled = TRUE;

-- Repo-scoped SSH deploy keys (read-only or read-write).
CREATE TABLE IF NOT EXISTS deploy_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'deploy',
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    read_only BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS deploy_keys_repo_id_idx ON deploy_keys(repo_id);
CREATE INDEX IF NOT EXISTS deploy_keys_fingerprint_idx ON deploy_keys(fingerprint);
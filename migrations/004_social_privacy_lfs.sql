-- Social, privacy, branch rules, LFS metadata

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS show_email BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS vigilant_mode BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ip_address TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS fork_of_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS stars_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS watches_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS forks_count INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS repositories_fork_of_id_idx ON repositories(fork_of_id);

CREATE TABLE IF NOT EXISTS user_emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, email)
);
CREATE INDEX IF NOT EXISTS user_emails_user_id_idx ON user_emails(user_id);
CREATE INDEX IF NOT EXISTS user_emails_email_idx ON user_emails(email);

CREATE TABLE IF NOT EXISTS gpg_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'gpg',
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS gpg_keys_user_id_idx ON gpg_keys(user_id);

CREATE TABLE IF NOT EXISTS repo_stars (
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, user_id)
);

CREATE TABLE IF NOT EXISTS repo_watches (
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, user_id)
);

CREATE TABLE IF NOT EXISTS comment_reactions (
    comment_id UUID NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (comment_id, user_id, emoji),
    CONSTRAINT comment_reactions_emoji CHECK (emoji IN ('+1', '-1', 'laugh', 'hooray', 'confused', 'heart', 'rocket', 'eyes'))
);
CREATE INDEX IF NOT EXISTS comment_reactions_comment_id_idx ON comment_reactions(comment_id);

CREATE TABLE IF NOT EXISTS branch_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    require_pr BOOLEAN NOT NULL DEFAULT FALSE,
    block_force_push BOOLEAN NOT NULL DEFAULT TRUE,
    allow_deletions BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repo_id, pattern)
);
CREATE INDEX IF NOT EXISTS branch_rules_repo_id_idx ON branch_rules(repo_id);

CREATE TABLE IF NOT EXISTS lfs_objects (
    oid TEXT PRIMARY KEY,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lfs_repo_objects (
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    oid TEXT NOT NULL REFERENCES lfs_objects(oid) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, oid)
);
ALTER TABLE pull_requests
    ADD COLUMN IF NOT EXISTS source_repo_id UUID REFERENCES repositories(id) ON DELETE SET NULL;

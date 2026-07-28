-- In-app notifications for watched repos and thread participants

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    href TEXT NOT NULL DEFAULT '',
    repo_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS notifications_user_id_created_at_idx
    ON notifications (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS notifications_user_id_unread_idx
    ON notifications (user_id)
    WHERE read_at IS NULL;

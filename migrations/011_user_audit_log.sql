-- Per-user security / account audit trail (separate from activity_events social feed).
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_user_id_created_at_idx
    ON audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_created_at_idx
    ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_idx
    ON audit_log(action);

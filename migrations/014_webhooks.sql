-- Repository webhooks + delivery log

CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL DEFAULT '',
    events TEXT[] NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT webhooks_url_http CHECK (url ~* '^https?://')
);
CREATE INDEX webhooks_repo_id_idx ON webhooks(repo_id);

CREATE TABLE webhook_deliveries (
    id BIGSERIAL PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL DEFAULT FALSE,
    status_code INT,
    error TEXT,
    duration_ms INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webhook_deliveries_webhook_id_idx ON webhook_deliveries(webhook_id);
CREATE INDEX webhook_deliveries_created_at_idx ON webhook_deliveries(created_at DESC);
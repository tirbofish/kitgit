CREATE TABLE IF NOT EXISTS site_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

INSERT INTO site_settings (key, value) VALUES ('motd', '')
ON CONFLICT (key) DO NOTHING;

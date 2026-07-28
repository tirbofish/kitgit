-- Per-user appearance preference: light | dark | system

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS theme TEXT NOT NULL DEFAULT 'system';

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_theme_check;

ALTER TABLE users
    ADD CONSTRAINT users_theme_check CHECK (theme IN ('light', 'dark', 'system'));

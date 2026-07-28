-- Draft / prerelease flags and update timestamp for releases

ALTER TABLE releases
    ADD COLUMN IF NOT EXISTS is_prerelease BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

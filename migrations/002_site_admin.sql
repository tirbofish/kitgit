-- site admins (forge-wide, not repo ACL)
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_site_admin BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS users_is_site_admin_idx ON users(is_site_admin) WHERE is_site_admin = TRUE;

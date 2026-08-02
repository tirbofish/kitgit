-- Organizations share the user namespace.  Organization rows live in users
-- with account_type = 'organization'; the companion table stores org-only
-- profile data.  Keeping one namespace table makes /{owner}/{repo} lookup
-- unambiguous for both users and organizations.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS account_type TEXT NOT NULL DEFAULT 'user'
        CHECK (account_type IN ('user', 'organization'));

CREATE INDEX IF NOT EXISTS users_account_type_idx ON users(account_type);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organization_memberships (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('public', 'private')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS organization_memberships_user_idx
    ON organization_memberships(user_id);

CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    invitee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    inviter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled', 'expired')),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    responded_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS organization_invitations_pending_idx
    ON organization_invitations(organization_id, invitee_id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS organization_invitations_invitee_idx
    ON organization_invitations(invitee_id, created_at DESC);

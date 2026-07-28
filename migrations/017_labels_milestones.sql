-- Labels and milestones for issues and pull requests.

-- Replace the legacy text-only issue_labels table with proper label entities.
DROP TABLE IF EXISTS issue_labels;

CREATE TABLE labels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '0969da',
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repo_id, name),
    CONSTRAINT labels_name_len CHECK (char_length(name) BETWEEN 1 AND 50),
    CONSTRAINT labels_color_format CHECK (color ~ '^[0-9a-fA-F]{6}$')
);
CREATE INDEX labels_repo_id_idx ON labels(repo_id);

CREATE TABLE milestones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    due_on DATE,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    UNIQUE (repo_id, title),
    CONSTRAINT milestones_title_len CHECK (char_length(title) BETWEEN 1 AND 120)
);
CREATE INDEX milestones_repo_id_idx ON milestones(repo_id);
CREATE INDEX milestones_repo_state_idx ON milestones(repo_id, state);

ALTER TABLE issues
    ADD COLUMN IF NOT EXISTS milestone_id UUID REFERENCES milestones(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS issues_milestone_id_idx ON issues(milestone_id);

ALTER TABLE pull_requests
    ADD COLUMN IF NOT EXISTS milestone_id UUID REFERENCES milestones(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS pull_requests_milestone_id_idx ON pull_requests(milestone_id);

CREATE TABLE issue_labels (
    issue_id UUID NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label_id UUID NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, label_id)
);
CREATE INDEX issue_labels_label_id_idx ON issue_labels(label_id);

CREATE TABLE pull_labels (
    pull_id UUID NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    label_id UUID NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (pull_id, label_id)
);
CREATE INDEX pull_labels_label_id_idx ON pull_labels(label_id);

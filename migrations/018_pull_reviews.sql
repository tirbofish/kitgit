CREATE TABLE IF NOT EXISTS pull_reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pull_id UUID NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
  reviewer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('approved','changes_requested','commented')),
  body TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pull_reviews_pull_id_idx ON pull_reviews(pull_id);

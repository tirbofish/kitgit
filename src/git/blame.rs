//! Blame and path history helpers (git2).

use anyhow::{anyhow, Result};
use git2::{BlameOptions, Commit, Oid, Repository as G2Repo, Sort};
use std::collections::HashMap;
use std::path::Path;

use super::repo::{read_blob, resolve_ref, CommitInfo};

/// One displayed line in a blame view.
#[derive(Debug, Clone)]
pub struct BlameLine {
    pub line_no: usize,
    pub content: String,
    pub commit_id: String,
    pub short_id: String,
    pub author: String,
    pub time: i64,
    pub summary: String,
    /// First line of a contiguous blame hunk (same final commit).
    pub hunk_start: bool,
}

/// Commits that introduced a change to `path` (blob OID differs from parent), newest first.
pub fn list_commits_for_path(
    repo: &G2Repo,
    reference: &str,
    path: &str,
    limit: usize,
) -> Result<Vec<CommitInfo>> {
    let oid = resolve_ref(repo, reference)?;
    let mut revwalk = repo.revwalk()?;
    revwalk.push(oid)?;
    revwalk.set_sorting(Sort::TIME)?;
    let mut out = Vec::new();
    for id in revwalk {
        let id = id?;
        let c = repo.find_commit(id)?;
        if !path_changed_in_commit(&c, path)? {
            continue;
        }
        let author = c.author();
        out.push(CommitInfo {
            id: id.to_string(),
            short_id: id.to_string()[..7.min(id.to_string().len())].to_string(),
            message: c.summary().unwrap_or("").to_string(),
            author: author.name().unwrap_or("").to_string(),
            email: author.email().unwrap_or("").to_string(),
            time: author.when().seconds(),
        });
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

fn path_changed_in_commit(commit: &Commit, path: &str) -> Result<bool> {
    let tree = commit.tree()?;
    let new_id = tree.get_path(Path::new(path)).ok().map(|e| e.id());
    if commit.parent_count() == 0 {
        return Ok(new_id.is_some());
    }
    let parent_tree = commit.parent(0)?.tree()?;
    let old_id = parent_tree.get_path(Path::new(path)).ok().map(|e| e.id());
    Ok(old_id != new_id)
}

/// Per-line blame for a text file at `reference`:`path`.
pub fn blame_file(repo: &G2Repo, reference: &str, path: &str) -> Result<Vec<BlameLine>> {
    let (data, binary) = read_blob(repo, reference, path)?;
    if binary {
        return Err(anyhow!("binary file"));
    }
    let oid = resolve_ref(repo, reference)?;
    let mut opts = BlameOptions::new();
    opts.newest_commit(oid);
    let blame = repo.blame_file(Path::new(path), Some(&mut opts))?;

    let text = String::from_utf8_lossy(&data);
    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }

    let mut summaries: HashMap<Oid, String> = HashMap::new();
    let mut out = Vec::with_capacity(lines.len());
    let mut prev_commit: Option<Oid> = None;

    for (i, line) in lines.iter().enumerate() {
        let line_no = i + 1;
        let Some(hunk) = blame.get_line(line_no) else {
            out.push(BlameLine {
                line_no,
                content: (*line).to_string(),
                commit_id: String::new(),
                short_id: String::new(),
                author: String::new(),
                time: 0,
                summary: String::new(),
                hunk_start: true,
            });
            continue;
        };
        let commit_oid = hunk.final_commit_id();
        let commit_id = commit_oid.to_string();
        let short_id = commit_id[..7.min(commit_id.len())].to_string();
        let sig = hunk.final_signature();
        let author = sig.name().unwrap_or("").to_string();
        let time = sig.when().seconds();
        let summary = summaries
            .entry(commit_oid)
            .or_insert_with(|| {
                repo.find_commit(commit_oid)
                    .ok()
                    .and_then(|c| c.summary().map(|s| s.to_string()))
                    .unwrap_or_default()
            })
            .clone();
        let hunk_start = prev_commit != Some(commit_oid);
        prev_commit = Some(commit_oid);
        out.push(BlameLine {
            line_no,
            content: (*line).to_string(),
            commit_id,
            short_id,
            author,
            time,
            summary,
            hunk_start,
        });
    }
    Ok(out)
}

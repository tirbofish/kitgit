use anyhow::{anyhow, Context, Result};
use git2::{
    BranchType, Commit, DiffOptions, ObjectType, Oid, Repository as G2Repo, Signature, Sort, Tree,
    TreeWalkMode, TreeWalkResult,
};
use std::path::{Path, PathBuf};

pub fn bare_path(repos_root: &Path, owner: &str, name: &str) -> PathBuf {
    repos_root.join(owner).join(format!("{name}.git"))
}

pub fn init_bare(repos_root: &Path, owner: &str, name: &str, default_branch: &str) -> Result<PathBuf> {
    let path = bare_path(repos_root, owner, name);
    if path.exists() {
        return Err(anyhow!("repository already exists on disk"));
    }
    std::fs::create_dir_all(path.parent().unwrap())?;
    let repo = G2Repo::init_bare(&path)?;
    repo.set_head(&format!("refs/heads/{default_branch}"))?;
    // Allow HTTP push receive
    repo.config()?.set_bool("http.receivepack", true)?;
    repo.config()?.set_bool("http.uploadpack", true)?;
    // Git LFS pointer filter (clients still need git-lfs installed)
    repo.config()?.set_bool("lfs.locksverify", false)?;
    sync_branch_protection(&path, default_branch, false, true)?;
    Ok(path)
}

/// Create an initial README commit on `branch` so the default branch exists.
pub fn seed_initial_commit(
    repos_root: &Path,
    owner: &str,
    name: &str,
    branch: &str,
    author_name: &str,
    author_email: &str,
) -> Result<String> {
    let readme = format!(
        "# {name}\n\nInitialized on kitgit.\n"
    );
    commit_file(
        repos_root,
        owner,
        name,
        branch,
        "README.md",
        readme.as_bytes(),
        author_name,
        author_email,
        "Initial commit",
    )
}

pub fn ahead_behind(repo: &G2Repo, branch: &str, base: &str) -> Result<(usize, usize)> {
    let local = resolve_ref(repo, branch)?;
    let upstream = resolve_ref(repo, base)?;
    Ok(repo.graph_ahead_behind(local, upstream)?)
}

pub fn branch_tip_time(repo: &G2Repo, branch: &str) -> Result<i64> {
    let oid = resolve_ref(repo, branch)?;
    let c = repo.find_commit(oid)?;
    Ok(c.time().seconds())
}

pub fn delete_branch(repo: &G2Repo, branch: &str) -> Result<()> {
    let mut b = repo
        .find_branch(branch, BranchType::Local)
        .with_context(|| format!("branch {branch}"))?;
    b.delete()?;
    Ok(())
}

pub fn rename_branch(repo: &G2Repo, old: &str, new: &str) -> Result<()> {
    let mut b = repo
        .find_branch(old, BranchType::Local)
        .with_context(|| format!("branch {old}"))?;
    b.rename(new, false)?;
    Ok(())
}

/// Whether `url` is an allowed remote for pull-mirroring (no local/file paths).
pub fn is_safe_mirror_url(url: &str) -> bool {
    let url = url.trim();
    if url.is_empty() || url.contains('\0') || url.contains('\n') || url.contains('\r') {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("file:")
        || lower.starts_with('/')
        || lower.starts_with("\\\\")
        || (url.len() >= 2 && url.as_bytes()[1] == b':')
    {
        return false;
    }
    lower.starts_with("https://")
        || lower.starts_with("http://")
        || lower.starts_with("git://")
        || lower.starts_with("ssh://")
        || (url.contains('@') && url.contains(':') && !lower.contains("://"))
}

/// Fetch refs from `remote_url` into the existing bare repo (pull mirror).
pub fn mirror_fetch(repos_root: &Path, owner: &str, name: &str, remote_url: &str) -> Result<()> {
    if !is_safe_mirror_url(remote_url) {
        return Err(anyhow!("unsupported or unsafe mirror URL"));
    }
    let path = bare_path(repos_root, owner, name);
    if !path.exists() {
        return Err(anyhow!("local bare repository missing"));
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("repository path is not valid UTF-8"))?;
    let url = remote_url.trim();

    // Dedicated remote so we do not clobber a user's `origin`.
    let _ = std::process::Command::new("git")
        .args(["-C", path_str, "remote", "remove", "kitgit-mirror"])
        .output();
    let add = std::process::Command::new("git")
        .args(["-C", path_str, "remote", "add", "kitgit-mirror", url])
        .output()
        .with_context(|| "git remote add")?;
    if !add.status.success() {
        return Err(anyhow!(
            "git remote add failed: {}",
            String::from_utf8_lossy(&add.stderr).trim()
        ));
    }

    let fetch = std::process::Command::new("git")
        .args([
            "-C",
            path_str,
            "fetch",
            "kitgit-mirror",
            "+refs/heads/*:refs/heads/*",
            "+refs/tags/*:refs/tags/*",
            "--prune",
            "--force",
        ])
        .output()
        .with_context(|| "git fetch mirror")?;
    if !fetch.status.success() {
        return Err(anyhow!(
            "git fetch failed: {}",
            String::from_utf8_lossy(&fetch.stderr).trim()
        ));
    }

    if let Ok(repo) = G2Repo::open_bare(&path) {
        let _ = repo.config()?.set_bool("http.receivepack", true);
        let _ = repo.config()?.set_bool("http.uploadpack", true);
    }
    Ok(())
}

/// Copy a bare repository on disk (for forks).
pub fn clone_bare(src: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        return Err(anyhow!("destination already exists"));
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--bare",
            "--quiet",
            src.to_str().unwrap(),
            dest.to_str().unwrap(),
        ])
        .status()?;
    if !status.success() {
        return Err(anyhow!("git clone --bare failed"));
    }
    let repo = G2Repo::open_bare(dest)?;
    repo.config()?.set_bool("http.receivepack", true)?;
    repo.config()?.set_bool("http.uploadpack", true)?;
    Ok(())
}

/// Install/update an `update` hook that blocks force-pushes to the default branch.
pub fn sync_branch_protection(
    bare: &Path,
    default_branch: &str,
    protect: bool,
    block_force: bool,
) -> Result<()> {
    let hooks = bare.join("hooks");
    std::fs::create_dir_all(&hooks)?;
    let update = hooks.join("update");
    if protect && block_force {
        let script = format!(
            r#"#!/bin/sh
refname="$1"
oldrev="$2"
newrev="$3"
default="{default_branch}"
zero="0000000000000000000000000000000000000000"
if [ "$refname" = "refs/heads/$default" ] && [ "$oldrev" != "$zero" ] && [ "$newrev" != "$zero" ]; then
  if ! git merge-base --is-ancestor "$oldrev" "$newrev" 2>/dev/null; then
    echo "kitgit: force-push to protected branch '$default' denied" >&2
    exit 1
  fi
fi
exit 0
"#
        );
        std::fs::write(&update, script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&update)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&update, perms)?;
        }
    } else if update.exists() {
        let _ = std::fs::remove_file(&update);
    }
    Ok(())
}

pub fn remove_bare(repos_root: &Path, owner: &str, name: &str) -> Result<()> {
    let path = bare_path(repos_root, owner, name);
    if path.exists() {
        std::fs::remove_dir_all(&path)?;
    }
    Ok(())
}

pub fn open_bare(repos_root: &Path, owner: &str, name: &str) -> Result<G2Repo> {
    let path = bare_path(repos_root, owner, name);
    G2Repo::open_bare(&path).with_context(|| format!("open {}", path.display()))
}

#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub mode: String,
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub id: String,
    pub short_id: String,
    pub message: String,
    pub author: String,
    pub email: String,
    pub time: i64,
}

pub fn list_branches(repo: &G2Repo) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for b in repo.branches(Some(BranchType::Local))? {
        let (branch, _) = b?;
        if let Some(name) = branch.name()? {
            out.push(name.to_string());
        }
    }
    out.sort();
    Ok(out)
}

pub fn resolve_ref(repo: &G2Repo, reference: &str) -> Result<Oid> {
    let obj = repo.revparse_single(reference)?;
    Ok(obj.peel_to_commit()?.id())
}

pub fn list_tree(repo: &G2Repo, reference: &str, path: &str) -> Result<Vec<TreeEntry>> {
    let commit = repo.revparse_single(reference)?.peel_to_commit()?;
    let tree = commit.tree()?;
    let tree = if path.is_empty() || path == "/" {
        tree
    } else {
        let entry = tree
            .get_path(Path::new(path))
            .with_context(|| format!("path {path}"))?;
        entry
            .to_object(repo)?
            .peel_to_tree()
            .context("not a directory")?
    };

    let mut entries = Vec::new();
    for i in 0..tree.len() {
        let e = tree.get(i).unwrap();
        let name = e.name().unwrap_or("").to_string();
        let is_dir = e.kind() == Some(ObjectType::Tree);
        let child_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}/{name}")
        };
        entries.push(TreeEntry {
            name,
            path: child_path,
            is_dir,
            mode: format!("{:o}", e.filemode()),
        });
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
    Ok(entries)
}

pub fn read_blob(repo: &G2Repo, reference: &str, path: &str) -> Result<(Vec<u8>, bool)> {
    let commit = repo.revparse_single(reference)?.peel_to_commit()?;
    let tree = commit.tree()?;
    let entry = tree.get_path(Path::new(path))?;
    let blob = entry.to_object(repo)?.peel_to_blob()?;
    let data = blob.content().to_vec();
    let binary = data.iter().any(|&b| b == 0);
    Ok((data, binary))
}

/// Whether `path` is a tree (directory) at `reference`. Missing paths are not trees.
pub fn path_is_dir(repo: &G2Repo, reference: &str, path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    let Ok(commit) = repo.revparse_single(reference).and_then(|o| o.peel_to_commit()) else {
        return false;
    };
    let Ok(tree) = commit.tree() else {
        return false;
    };
    let Ok(entry) = tree.get_path(Path::new(path)) else {
        return false;
    };
    entry.kind() == Some(ObjectType::Tree)
}

/// Find a README in `dir` only (GitHub-style). Empty `dir` = repo root.
/// Does not fall back to parent/root READMEs when browsing a subdirectory.
pub fn find_readme(
    repo: &G2Repo,
    reference: &str,
    dir: &str,
) -> Result<Option<(String, String)>> {
    let names = [
        "README.md",
        "Readme.md",
        "readme.md",
        "README.MD",
        "README",
        "README.txt",
    ];
    let dir = dir.trim_matches('/');
    for n in names {
        let path = if dir.is_empty() {
            n.to_string()
        } else {
            format!("{dir}/{n}")
        };
        if let Ok((data, binary)) = read_blob(repo, reference, &path) {
            if !binary {
                return Ok(Some((n.to_string(), String::from_utf8_lossy(&data).into())));
            }
        }
    }
    Ok(None)
}

pub fn list_commits(repo: &G2Repo, reference: &str, limit: usize) -> Result<Vec<CommitInfo>> {
    let oid = resolve_ref(repo, reference)?;
    let mut revwalk = repo.revwalk()?;
    revwalk.push(oid)?;
    revwalk.set_sorting(Sort::TIME)?;
    let mut out = Vec::new();
    for (i, id) in revwalk.enumerate() {
        if i >= limit {
            break;
        }
        let id = id?;
        let c = repo.find_commit(id)?;
        let msg = c.summary().unwrap_or("").to_string();
        let author = c.author();
        out.push(CommitInfo {
            id: id.to_string(),
            short_id: id.to_string()[..7.min(id.to_string().len())].to_string(),
            message: msg,
            author: author.name().unwrap_or("").to_string(),
            email: author.email().unwrap_or("").to_string(),
            time: author.when().seconds(),
        });
    }
    Ok(out)
}

pub fn get_commit(repo: &G2Repo, id: &str) -> Result<CommitInfo> {
    let oid = Oid::from_str(id)?;
    let c = repo.find_commit(oid)?;
    let author = c.author();
    Ok(CommitInfo {
        id: oid.to_string(),
        short_id: oid.to_string()[..7].to_string(),
        message: c.message().unwrap_or("").to_string(),
        author: author.name().unwrap_or("").to_string(),
        email: author.email().unwrap_or("").to_string(),
        time: author.when().seconds(),
    })
}

pub fn commit_diff(repo: &G2Repo, id: &str) -> Result<String> {
    let oid = Oid::from_str(id)?;
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let parent_tree = if commit.parent_count() > 0 {
        Some(commit.parent(0)?.tree()?)
    } else {
        None
    };
    let mut opts = DiffOptions::new();
    let diff = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut opts))?;
    let mut buf = String::new();
    diff.print(git2::DiffFormat::Patch, |_delta, _hunk, line| {
        let origin = line.origin();
        let content = std::str::from_utf8(line.content()).unwrap_or("");
        match origin {
            '+' | '-' | ' ' | '@' => {
                buf.push(origin);
                buf.push_str(content);
            }
            _ => buf.push_str(content),
        }
        true
    })?;
    Ok(buf)
}

pub fn branch_diff(repo: &G2Repo, source: &str, target: &str) -> Result<String> {
    let src = repo.revparse_single(source)?.peel_to_tree()?;
    let tgt = repo.revparse_single(target)?.peel_to_tree()?;
    let mut opts = DiffOptions::new();
    let diff = repo.diff_tree_to_tree(Some(&tgt), Some(&src), Some(&mut opts))?;
    let mut buf = String::new();
    diff.print(git2::DiffFormat::Patch, |_d, _h, line| {
        let origin = line.origin();
        let content = std::str::from_utf8(line.content()).unwrap_or("");
        match origin {
            '+' | '-' | ' ' | '@' => {
                buf.push(origin);
                buf.push_str(content);
            }
            _ => buf.push_str(content),
        }
        true
    })?;
    Ok(buf)
}

pub fn commits_between(repo: &G2Repo, source: &str, target: &str, limit: usize) -> Result<Vec<CommitInfo>> {
    let src = resolve_ref(repo, source)?;
    let tgt = resolve_ref(repo, target)?;
    let mut revwalk = repo.revwalk()?;
    revwalk.push(src)?;
    revwalk.hide(tgt)?;
    revwalk.set_sorting(Sort::TIME)?;
    let mut out = Vec::new();
    for (i, id) in revwalk.enumerate() {
        if i >= limit {
            break;
        }
        let id = id?;
        let c = repo.find_commit(id)?;
        let author = c.author();
        out.push(CommitInfo {
            id: id.to_string(),
            short_id: id.to_string()[..7].to_string(),
            message: c.summary().unwrap_or("").to_string(),
            author: author.name().unwrap_or("").to_string(),
            email: author.email().unwrap_or("").to_string(),
            time: author.when().seconds(),
        });
    }
    Ok(out)
}

pub fn merge_branches(
    repos_root: &Path,
    owner: &str,
    name: &str,
    source: &str,
    target: &str,
    style: &str,
    message: &str,
    author_name: &str,
    author_email: &str,
) -> Result<String> {
    // Clone bare repo into a temp worktree, merge there, push back.
    // After clone only the default branch exists locally; source/target must
    // be resolved via origin/* (or created as local tracking branches).
    let bare = bare_path(repos_root, owner, name);
    let tmp = tempfile_dir()?;
    let cleanup = |dir: &Path| {
        let _ = std::fs::remove_dir_all(dir);
    };

    let clone = std::process::Command::new("git")
        .args([
            "clone",
            "--quiet",
            bare.to_str().unwrap(),
            tmp.to_str().unwrap(),
        ])
        .output()
        .with_context(|| format!("clone {}", bare.display()))?;
    if !clone.status.success() {
        cleanup(&tmp);
        return Err(anyhow!(
            "clone for merge failed: {}",
            String::from_utf8_lossy(&clone.stderr).trim()
        ));
    }

    let run = |args: &[&str]| -> Result<()> {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&tmp)
            .output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stderr = stderr.trim();
            if stderr.is_empty() {
                return Err(anyhow!("git {} failed", args.join(" ")));
            }
            return Err(anyhow!("git {} failed: {}", args.join(" "), stderr));
        }
        Ok(())
    };

    // Identity required for merge/squash/rebase commits.
    let committer_name = if author_name.trim().is_empty() {
        "kitgit"
    } else {
        author_name.trim()
    };
    let committer_email = if author_email.trim().is_empty() {
        "kitgit@localhost"
    } else {
        author_email.trim()
    };
    if let Err(e) = (|| -> Result<()> {
        run(&["config", "user.name", committer_name])?;
        run(&["config", "user.email", committer_email])?;

        let origin_source = format!("origin/{source}");
        let origin_target = format!("origin/{target}");

        // Materialize local target from the remote-tracking ref.
        run(&["checkout", "-B", target, &origin_target])?;

        match style {
            "squash" => {
                run(&["merge", "--squash", &origin_source])?;
                run(&["commit", "-m", message])?;
            }
            "rebase" => {
                run(&["checkout", "-B", source, &origin_source])?;
                run(&["rebase", target])?;
                run(&["checkout", target])?;
                run(&["merge", source])?;
            }
            _ => {
                run(&["merge", "--no-ff", "-m", message, &origin_source])?;
            }
        }
        run(&["push", "origin", target])?;
        Ok(())
    })() {
        cleanup(&tmp);
        return Err(e);
    }

    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&tmp)
        .output()?;
    cleanup(&tmp);
    if !out.status.success() {
        return Err(anyhow!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn tempfile_dir() -> Result<PathBuf> {
    let p = std::env::temp_dir().join(format!("kitgit-merge-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

/// Point HEAD at `refs/heads/{branch}` (creates the symbolic ref if needed).
pub fn set_head_branch(repo: &G2Repo, branch: &str) -> Result<()> {
    let name = format!("refs/heads/{branch}");
    repo.set_head(&name)?;
    Ok(())
}

/// Commit a single file into `branch` at `path` (relative to repo root).
pub fn commit_file(
    repos_root: &Path,
    owner: &str,
    name: &str,
    branch: &str,
    path: &str,
    content: &[u8],
    author_name: &str,
    author_email: &str,
    message: &str,
) -> Result<String> {
    let path = path.trim_matches('/');
    if path.is_empty() || path.contains("..") {
        anyhow::bail!("invalid path");
    }
    let repo = open_bare(repos_root, owner, name)?;
    let sig = Signature::now(author_name, author_email)?;

    let parent = match resolve_ref(&repo, branch) {
        Ok(oid) => Some(repo.find_commit(oid)?),
        Err(_) => None,
    };
    let parent_tree = parent.as_ref().and_then(|c| c.tree().ok());

    let mut builder = match &parent_tree {
        Some(t) => repo.treebuilder(Some(t))?,
        None => repo.treebuilder(None)?,
    };

    // Build nested trees for path components.
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        anyhow::bail!("invalid path");
    }
    fn insert_path(
        repo: &G2Repo,
        parent_builder: &mut git2::TreeBuilder<'_>,
        parent_tree: Option<&Tree>,
        parts: &[&str],
        blob_oid: Oid,
    ) -> Result<()> {
        if parts.len() == 1 {
            parent_builder.insert(parts[0], blob_oid, 0o100644)?;
            return Ok(());
        }
        let dirname = parts[0];
        let rest = &parts[1..];
        let child_tree = parent_tree
            .and_then(|t| t.get_name(dirname))
            .filter(|e| e.kind() == Some(ObjectType::Tree))
            .and_then(|e| e.to_object(repo).ok())
            .and_then(|o| o.peel_to_tree().ok());
        let mut child_builder = match &child_tree {
            Some(t) => repo.treebuilder(Some(t))?,
            None => repo.treebuilder(None)?,
        };
        insert_path(
            repo,
            &mut child_builder,
            child_tree.as_ref(),
            rest,
            blob_oid,
        )?;
        let child_oid = child_builder.write()?;
        parent_builder.insert(dirname, child_oid, 0o040000)?;
        Ok(())
    }

    let blob_oid = repo.blob(content)?;
    insert_path(
        &repo,
        &mut builder,
        parent_tree.as_ref(),
        &parts,
        blob_oid,
    )?;
    let tree_oid = builder.write()?;
    let tree = repo.find_tree(tree_oid)?;

    let parents: Vec<&Commit> = parent.as_ref().into_iter().collect();
    let oid = repo.commit(
        Some(&format!("refs/heads/{branch}")),
        &sig,
        &sig,
        message,
        &tree,
        &parents,
    )?;
    Ok(oid.to_string())
}

/// Create a zip archive of `reference` via `git archive`.
/// When `path` is `Some`, only that subtree is included (same as `git archive <ref> <path>`).
pub fn archive_zip(
    repos_root: &Path,
    owner: &str,
    name: &str,
    reference: &str,
    path: Option<&str>,
) -> Result<Vec<u8>> {
    let bare = bare_path(repos_root, owner, name);
    let mut cmd = std::process::Command::new("git");
    cmd.args(["archive", "--format=zip", reference])
        .current_dir(&bare);
    if let Some(p) = path {
        let p = p.trim_matches('/');
        if !p.is_empty() {
            if p.contains("..") || p.starts_with('/') || p.contains('\\') {
                anyhow::bail!("invalid archive path");
            }
            cmd.arg(p);
        }
    }
    let out = cmd.output()?;
    if !out.status.success() {
        anyhow::bail!(
            "git archive failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(out.stdout)
}

pub fn walk_files(repo: &G2Repo, reference: &str) -> Result<Vec<(String, usize)>> {
    let commit = repo.revparse_single(reference)?.peel_to_commit()?;
    let tree = commit.tree()?;
    let mut files = Vec::new();
    tree.walk(TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            let name = entry.name().unwrap_or("");
            let path = format!("{root}{name}");
            if let Ok(obj) = entry.to_object(repo) {
                if let Ok(blob) = obj.peel_to_blob() {
                    files.push((path, blob.size()));
                }
            }
        }
        TreeWalkResult::Ok
    })?;
    Ok(files)
}

#[derive(Debug, Clone)]
pub struct TagInfo {
    pub name: String,
    pub target: String,
    pub short_id: String,
    pub message: String,
    pub time: i64,
    pub is_annotated: bool,
}

pub fn list_tags(repo: &G2Repo) -> Result<Vec<TagInfo>> {
    let names = repo.tag_names(None)?;
    let mut out = Vec::new();
    for name in names.iter().flatten() {
        let obj = match repo.revparse_single(name) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let (is_annotated, message, time) = if let Ok(tag) = obj.peel_to_tag() {
            let msg = tag.message().unwrap_or("").trim().to_string();
            let t = tag
                .tagger()
                .map(|s| s.when().seconds())
                .unwrap_or(0);
            (true, msg, t)
        } else {
            (false, String::new(), 0)
        };
        let commit = match obj.peel_to_commit() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let oid = commit.id();
        let time = if time == 0 {
            commit.time().seconds()
        } else {
            time
        };
        let message = if message.is_empty() {
            commit.summary().unwrap_or("").to_string()
        } else {
            message
        };
        out.push(TagInfo {
            name: name.to_string(),
            target: oid.to_string(),
            short_id: oid.to_string().chars().take(7).collect(),
            message,
            time,
            is_annotated,
        });
    }
    out.sort_by(|a, b| b.time.cmp(&a.time).then(a.name.cmp(&b.name)));
    Ok(out)
}

pub fn tag_exists(repo: &G2Repo, tag: &str) -> bool {
    repo.revparse_single(&format!("refs/tags/{tag}")).is_ok()
        || repo.revparse_single(tag).is_ok()
}

pub fn delete_tag(repo: &G2Repo, tag: &str) -> Result<()> {
    let name = tag.trim_start_matches("refs/tags/");
    repo.tag_delete(name)
        .with_context(|| format!("delete tag {name}"))?;
    Ok(())
}

/// Rename a tag by recreating it at the same target (annotated when possible).
pub fn rename_tag(repo: &G2Repo, old: &str, new: &str) -> Result<()> {
    let old = old.trim_start_matches("refs/tags/");
    let new = new.trim_start_matches("refs/tags/");
    if old == new {
        return Ok(());
    }
    if tag_exists(repo, new) {
        return Err(anyhow!("tag {new} already exists"));
    }
    let obj = repo
        .revparse_single(&format!("refs/tags/{old}"))
        .or_else(|_| repo.revparse_single(old))
        .with_context(|| format!("tag {old}"))?;
    let commit = obj.peel_to_commit()?;
    let message = obj
        .peel_to_tag()
        .ok()
        .and_then(|t| t.message().map(|m| m.to_string()))
        .unwrap_or_default();
    let bare = repo.path();
    create_tag_at(bare, new, &commit.id().to_string(), &message)?;
    delete_tag(repo, old)?;
    Ok(())
}

/// Create an annotated tag at HEAD (or lightweight fallback).
pub fn create_tag(repos_root: &Path, owner: &str, name: &str, tag: &str, message: &str) -> Result<()> {
    let bare = bare_path(repos_root, owner, name);
    create_tag_at(&bare, tag, "HEAD", message)
}

/// Create a tag pointing at `target` (commit SHA, branch, or other rev).
pub fn create_tag_at(bare: &Path, tag: &str, target: &str, message: &str) -> Result<()> {
    let git_dir = bare.to_str().ok_or_else(|| anyhow!("invalid git path"))?;
    let msg = if message.trim().is_empty() {
        tag
    } else {
        message
    };
    let status = std::process::Command::new("git")
        .args([
            "--git-dir",
            git_dir,
            "tag",
            "-a",
            tag,
            target,
            "-m",
            msg,
        ])
        .status()?;
    if !status.success() {
        let status = std::process::Command::new("git")
            .args(["--git-dir", git_dir, "tag", tag, target])
            .status()?;
        if !status.success() {
            return Err(anyhow!("failed to create tag {tag}"));
        }
    }
    Ok(())
}

/// Move an existing tag to a new target (delete + recreate).
pub fn retarget_tag(bare: &Path, tag: &str, target: &str, message: &str) -> Result<()> {
    let repo = open_bare_path(bare)?;
    if tag_exists(&repo, tag) {
        delete_tag(&repo, tag)?;
    }
    create_tag_at(bare, tag, target, message)
}

pub fn open_bare_path(bare: &Path) -> Result<G2Repo> {
    Ok(G2Repo::open_bare(bare)?)
}

// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//!
//! Experimental forensic evidence v0.1. Independent of the legacy FactSet:
//! observe in-scope repository bytes without interpreting a policy verdict.
//! See docs/forensic-evidence-v0.1.adoc for scope, limits and seam contracts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "0.1.0";

/// Deliberate exclusions in this schema version (never hide governance trees).
const EXCLUDED_DIRS: &[&str] = &[".git", "target", "node_modules", "vendor", "_build", "deps"];

/// Epistemic truth for future forensic consumers; not wired into policy v0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTruth {
    True,
    False,
    Unknown,
}

impl EvidenceTruth {
    pub fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Strong Kleene conjunction: False dominates Unknown.
    pub fn all(values: impl IntoIterator<Item = Self>) -> Self {
        let mut unknown = false;
        for value in values {
            match value {
                Self::False => return Self::False,
                Self::Unknown => unknown = true,
                Self::True => {}
            }
        }
        if unknown {
            Self::Unknown
        } else {
            Self::True
        }
    }

    /// Strong Kleene disjunction: True dominates Unknown.
    pub fn any(values: impl IntoIterator<Item = Self>) -> Self {
        let mut unknown = false;
        for value in values {
            match value {
                Self::True => return Self::True,
                Self::Unknown => unknown = true,
                Self::False => {}
            }
        }
        if unknown {
            Self::Unknown
        } else {
            Self::False
        }
    }
}

/// Every in-scope path is accounted for, including paths that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathEvidence {
    Regular { size: u64, sha256: String },
    Symlink { target: String },
    Unknown { reason: IssueKind },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    TraversalFailed,
    InvalidUtf8Path,
    ReadFailed,
    ChangedDuringRead,
    InvalidUtf8SymlinkTarget,
    UnsupportedFileType,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObservationIssue {
    pub path: String,
    pub kind: IssueKind,
}

/// Git identity is independent of file-content observations. Never treat a
/// symbolic HEAD branch name as the underlying commit identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GitHead {
    NotRepository,
    Resolved {
        reference: Option<String>,
        commit: String,
    },
    Unknown {
        reference: Option<String>,
        reason: GitProblem,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitProblem {
    ExternalGitDirectory,
    UnreadableHead,
    InvalidHead,
    MissingReference,
    InvalidObjectId,
}

/// Scope completeness does NOT mean whole-repository completeness:
/// excluded directories are separately enumerated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicSnapshot {
    pub schema_version: String,
    pub root: String,
    pub exclusion_policy: String,
    pub paths: BTreeMap<String, PathEvidence>,
    pub excluded_paths: BTreeSet<String>,
    pub issues: Vec<ObservationIssue>,
    pub scope_complete: bool,
    pub git: GitHead,
}

#[derive(Debug, Error)]
pub enum ForensicError {
    #[error("forensic root does not exist: {0}")]
    MissingRoot(String),
    #[error("forensic root must be a real directory, not a symlink or file: {0}")]
    InvalidRoot(String),
    #[error("cannot inspect forensic root: {0}")]
    Io(#[from] io::Error),
}

/// A pure comparison of two forensic observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathChange {
    pub before: Option<PathEvidence>,
    pub after: Option<PathEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicDiff {
    pub schema_version: String,
    pub paths_changed: BTreeMap<String, PathChange>,
    pub exclusions_changed: bool,
    pub issues_changed: bool,
    pub scope_completeness_changed: bool,
    pub git_changed: bool,
}

impl ForensicDiff {
    pub fn is_empty(&self) -> bool {
        self.paths_changed.is_empty()
            && !self.exclusions_changed
            && !self.issues_changed
            && !self.scope_completeness_changed
            && !self.git_changed
    }
}

/// Compare observations, rejecting incompatible version identifiers.
pub fn diff_forensic(
    before: &ForensicSnapshot,
    after: &ForensicSnapshot,
) -> Result<ForensicDiff, &'static str> {
    if before.schema_version != SCHEMA_VERSION || after.schema_version != SCHEMA_VERSION {
        return Err("unsupported forensic schema version");
    }
    if before.exclusion_policy != after.exclusion_policy {
        return Err("forensic exclusion policies differ");
    }

    let mut paths_changed = BTreeMap::new();
    let keys: BTreeSet<_> = before.paths.keys().chain(after.paths.keys()).collect();
    for path in keys {
        let b = before.paths.get(path);
        let a = after.paths.get(path);
        if b != a {
            paths_changed.insert(
                path.clone(),
                PathChange {
                    before: b.cloned(),
                    after: a.cloned(),
                },
            );
        }
    }
    Ok(ForensicDiff {
        schema_version: SCHEMA_VERSION.to_owned(),
        paths_changed,
        exclusions_changed: before.excluded_paths != after.excluded_paths,
        issues_changed: before.issues != after.issues,
        scope_completeness_changed: before.scope_complete != after.scope_complete,
        git_changed: before.git != after.git,
    })
}

fn normalized_relative(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut segments = Vec::new();
    for segment in relative.components() {
        segments.push(segment.as_os_str().to_str()?);
    }
    Some(segments.join("/"))
}

/// Resolve every component through an owned directory handle. Non-Unix
/// platforms fail closed until an equivalent no-follow implementation exists.
#[cfg(unix)]
fn open_directory(path: &Path) -> io::Result<File> {
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::path::Component;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = File::from(open(".", flags, Mode::empty())?);
    for component in path.components() {
        let name = match component {
            Component::RootDir => Path::new("/"),
            Component::CurDir => continue,
            Component::ParentDir => Path::new(".."),
            Component::Normal(name) => Path::new(name),
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        };
        dir = File::from(openat(&dir, name, flags, Mode::empty())?);
    }
    Ok(dir)
}

#[cfg(not(unix))]
fn open_directory(_: &Path) -> io::Result<File> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(unix)]
fn open_relative(dir: &File, relative: &Path) -> io::Result<File> {
    use rustix::fs::{openat, Mode, OFlags};
    let mut dir = dir.try_clone()?;
    let mut parts = relative.components().peekable();
    while let Some(part) = parts.next() {
        let std::path::Component::Normal(name) = part else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if parts.peek().is_some() {
            flags |= OFlags::DIRECTORY;
        }
        dir = File::from(openat(&dir, name, flags, Mode::empty())?);
    }
    if !dir.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(dir)
}

#[cfg(not(unix))]
fn open_relative(_: &File, _: &Path) -> io::Result<File> {
    Err(io::ErrorKind::Unsupported.into())
}

fn same_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return false;
        }
    }
    before.is_file()
        && after.is_file()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
}

/// SHA-256 digest of exact bytes with bounded memory, not a text decoding.
fn hash_regular_file(
    root: &File,
    relative: &Path,
    path: &Path,
) -> Result<(u64, String), IssueKind> {
    let before = fs::symlink_metadata(path).map_err(|_| IssueKind::ReadFailed)?;
    let mut file = open_relative(root, relative).map_err(|_| IssueKind::ReadFailed)?;
    let opened = file.metadata().map_err(|_| IssueKind::ReadFailed)?;
    if !same_file(&before, &opened) {
        return Err(IssueKind::ChangedDuringRead);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let n = file.read(&mut buffer).map_err(|_| IssueKind::ReadFailed)?;
        if n == 0 {
            break;
        }
        size = size.checked_add(n as u64).ok_or(IssueKind::ReadFailed)?;
        hasher.update(&buffer[..n]);
    }
    let after = fs::symlink_metadata(path).map_err(|_| IssueKind::ReadFailed)?;
    if !same_file(
        &before,
        &file.metadata().map_err(|_| IssueKind::ReadFailed)?,
    ) || !same_file(&before, &after)
        || size != before.len()
        || size != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(IssueKind::ChangedDuringRead);
    }
    Ok((size, format!("{:x}", hasher.finalize())))
}

/// Read-only observation of the declared scope. Never dereferences symlinks.
pub fn collect_forensic(root: &Path) -> Result<ForensicSnapshot, ForensicError> {
    let meta = match fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(ForensicError::MissingRoot(root.display().to_string()))
        }
        Err(e) => return Err(ForensicError::Io(e)),
    };
    if !meta.is_dir() {
        return Err(ForensicError::InvalidRoot(root.display().to_string()));
    }

    let root_handle = open_directory(root)?;
    let mut paths = BTreeMap::new();
    let mut excluded_paths = BTreeSet::new();
    let mut issues = Vec::new();
    // The walker filter borrows this independently from per-entry issues.
    let mut exclusion_issues = Vec::new();
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            // A Git worktree's .git is a *file*, not a directory. It is
            // still administrative state, not source data to hash.
            let excluded = entry.file_name().to_str().is_some_and(|name| {
                name == ".git" || (entry.file_type().is_dir() && EXCLUDED_DIRS.contains(&name))
            });
            if excluded {
                if let Some(path) = normalized_relative(root, entry.path()) {
                    excluded_paths.insert(path);
                } else {
                    exclusion_issues.push(ObservationIssue {
                        path: entry.path().to_string_lossy().into_owned(),
                        kind: IssueKind::InvalidUtf8Path,
                    });
                }
            }
            !excluded
        });

    for next in walker {
        let entry = match next {
            Ok(entry) => entry,
            Err(error) => {
                let path = error.path().map_or_else(
                    || "<unknown-walk-path>".to_owned(),
                    |path| {
                        path.strip_prefix(root)
                            .unwrap_or(path)
                            .to_string_lossy()
                            .into_owned()
                    },
                );
                issues.push(ObservationIssue {
                    path,
                    kind: IssueKind::TraversalFailed,
                });
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let Some(path) = normalized_relative(root, entry.path()) else {
            issues.push(ObservationIssue {
                path: entry.path().to_string_lossy().into_owned(),
                kind: IssueKind::InvalidUtf8Path,
            });
            continue;
        };
        if entry.file_type().is_dir() {
            continue;
        }
        let evidence = if entry.file_type().is_file() {
            match hash_regular_file(&root_handle, Path::new(&path), entry.path()) {
                Ok((size, sha256)) => PathEvidence::Regular { size, sha256 },
                Err(reason) => {
                    issues.push(ObservationIssue {
                        path: path.clone(),
                        kind: reason,
                    });
                    PathEvidence::Unknown { reason }
                }
            }
        } else if entry.file_type().is_symlink() {
            match fs::read_link(entry.path()) {
                Ok(target) => match target.to_str() {
                    Some(target) => PathEvidence::Symlink {
                        target: target.to_owned(),
                    },
                    None => {
                        issues.push(ObservationIssue {
                            path: path.clone(),
                            kind: IssueKind::InvalidUtf8SymlinkTarget,
                        });
                        PathEvidence::Unknown {
                            reason: IssueKind::InvalidUtf8SymlinkTarget,
                        }
                    }
                },
                Err(_) => {
                    issues.push(ObservationIssue {
                        path: path.clone(),
                        kind: IssueKind::ReadFailed,
                    });
                    PathEvidence::Unknown {
                        reason: IssueKind::ReadFailed,
                    }
                }
            }
        } else {
            issues.push(ObservationIssue {
                path: path.clone(),
                kind: IssueKind::UnsupportedFileType,
            });
            PathEvidence::Unknown {
                reason: IssueKind::UnsupportedFileType,
            }
        };
        paths.insert(path, evidence);
    }

    issues.extend(exclusion_issues);
    issues.sort();
    let scope_complete = issues.is_empty();
    Ok(ForensicSnapshot {
        schema_version: SCHEMA_VERSION.to_owned(),
        root: root.display().to_string(),
        exclusion_policy: "v0.1-default".to_owned(),
        paths,
        excluded_paths,
        issues,
        scope_complete,
        git: read_git_head(root),
    })
}

fn valid_oid(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
}

/// Read only a regular administrative file without following any symbolic
/// link in its path. A repository must not redirect the auditor outside its
/// declared Git directory using malicious ref or HEAD symlinks.
fn read_git_text(dir: &File, relative: &str) -> io::Result<String> {
    let mut file = open_relative(dir, Path::new(relative))?;
    let before = file.metadata()?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    if !same_file(&before, &file.metadata()?) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(text)
}

fn read_reference(dir: &File, reference: &str) -> Option<String> {
    // Ref names are untrusted repository content; disallow absolute paths,
    // traversal, empty segments and special components.
    if !reference.starts_with("refs/")
        || !reference
            .bytes()
            .all(|byte| byte > b' ' && byte != 127 && !b"~^:?*[\\".contains(&byte))
        || reference
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == ".." || s.starts_with('.'))
    {
        return None;
    }
    match read_git_text(dir, reference) {
        Ok(oid) => {
            let oid = oid.trim();
            return valid_oid(oid).then(|| oid.to_owned());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    let packed = read_git_text(dir, "packed-refs").ok()?;
    packed
        .lines()
        .filter(|line| !line.starts_with('#') && !line.starts_with('^'))
        .filter_map(|line| line.split_once(' '))
        .find_map(|(oid, name)| (name == reference && valid_oid(oid)).then(|| oid.to_owned()))
}

fn read_git_head(root: &Path) -> GitHead {
    let dotgit = root.join(".git");
    let meta = match fs::symlink_metadata(&dotgit) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return GitHead::NotRepository,
        Err(_) => {
            return GitHead::Unknown {
                reference: None,
                reason: GitProblem::UnreadableHead,
            };
        }
    };
    // Worktrees often use .git pointer files to an external administrative
    // tree. Do not follow arbitrary pointers supplied by untrusted repos.
    if !meta.is_dir() {
        return GitHead::Unknown {
            reference: None,
            reason: GitProblem::ExternalGitDirectory,
        };
    }
    let dir = match open_directory(&dotgit) {
        Ok(dir) => dir,
        Err(_) => {
            return GitHead::Unknown {
                reference: None,
                reason: GitProblem::UnreadableHead,
            }
        }
    };
    let head = match read_git_text(&dir, "HEAD") {
        Ok(head) => head,
        Err(_) => {
            return GitHead::Unknown {
                reference: None,
                reason: GitProblem::UnreadableHead,
            }
        }
    };
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        let reference = reference.to_owned();
        return match read_reference(&dir, &reference) {
            Some(commit) => GitHead::Resolved {
                reference: Some(reference),
                commit,
            },
            None => GitHead::Unknown {
                reference: Some(reference),
                reason: GitProblem::MissingReference,
            },
        };
    }
    if valid_oid(head) {
        GitHead::Resolved {
            reference: None,
            commit: head.to_owned(),
        }
    } else {
        GitHead::Unknown {
            reference: None,
            reason: GitProblem::InvalidHead,
        }
    }
}

#[cfg(all(test, unix))]
mod handle_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn refuses_final_and_parent_symlinks_before_reading() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file"), "redirected").unwrap();
        let root = open_directory(temp.path()).unwrap();
        symlink(outside.path().join("file"), temp.path().join("file")).unwrap();
        symlink(outside.path(), temp.path().join("parent")).unwrap();
        assert!(open_relative(&root, Path::new("file")).is_err());
        assert!(open_relative(&root, Path::new("parent/file")).is_err());
        assert!(read_git_text(&root, "file").is_err());
        assert!(read_git_text(&root, "parent/file").is_err());
    }

    #[test]
    fn pinned_directory_survives_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("git")).unwrap();
        fs::write(temp.path().join("git/HEAD"), "original").unwrap();
        fs::write(outside.path().join("HEAD"), "redirected").unwrap();
        let dir = open_directory(&temp.path().join("git")).unwrap();
        fs::rename(temp.path().join("git"), temp.path().join("saved")).unwrap();
        symlink(outside.path(), temp.path().join("git")).unwrap();
        assert_eq!(read_git_text(&dir, "HEAD").unwrap(), "original");
    }

    #[test]
    fn detects_replacement_even_with_matching_length() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        fs::write(&path, "old").unwrap();
        let before = fs::symlink_metadata(&path).unwrap();
        fs::rename(&path, temp.path().join("old")).unwrap();
        fs::write(&path, "new").unwrap();
        assert!(!same_file(&before, &fs::metadata(path).unwrap()));
    }
}

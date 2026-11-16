// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
// Regression tests for the separate, opt-in forensic evidence contract.

use plasma_engine::forensic::{
    collect_forensic, diff_forensic, EvidenceTruth, ForensicSnapshot, GitHead, GitProblem,
    PathEvidence,
};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn write(path: &Path, content: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn sha256_of<'a>(snapshot: &'a ForensicSnapshot, path: &str) -> &'a str {
    match snapshot.paths.get(path).expect("observed path") {
        PathEvidence::Regular { sha256, .. } => sha256,
        other => panic!("expected exact observed bytes, got {other:?}"),
    }
}

#[test]
fn includes_hidden_governance_paths_and_reports_exclusions() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join(".github/workflows/gate.yml"),
        b"name: Gate\n",
    );
    write(
        &temp.path().join(".machine_readable/contract.deed"),
        b"(repo-deed)\n",
    );
    write(&temp.path().join(".claude/CLAUDE.md"), b"agents\n");
    write(&temp.path().join("src/main.rs"), b"fn main() {}\n");
    write(&temp.path().join("target/generated.rs"), b"generated\n");
    write(&temp.path().join(".git/objects/ignore"), b"git internals\n");
    let s = collect_forensic(temp.path()).unwrap();
    for expected in [
        ".github/workflows/gate.yml",
        ".machine_readable/contract.deed",
        ".claude/CLAUDE.md",
        "src/main.rs",
    ] {
        assert!(s.paths.contains_key(expected), "missing {expected}");
    }
    assert!(!s.paths.contains_key("target/generated.rs"));
    assert!(!s.paths.contains_key(".git/objects/ignore"));
    assert!(s.excluded_paths.contains("target"));
    assert!(s.excluded_paths.contains(".git"));
    assert!(s.scope_complete);
    assert!(s.issues.is_empty());
}

#[test]
fn detects_same_length_content_only_edits_without_header_changes() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("src/example.rs");
    write(
        &path,
        b"// SPDX-License-Identifier: MPL-2.0\nfn alpha() {}\n",
    );
    let before = collect_forensic(temp.path()).unwrap();
    write(
        &path,
        b"// SPDX-License-Identifier: MPL-2.0\nfn omega() {}\n",
    );
    let after = collect_forensic(temp.path()).unwrap();
    assert_ne!(
        sha256_of(&before, "src/example.rs"),
        sha256_of(&after, "src/example.rs")
    );
    let diff = diff_forensic(&before, &after).unwrap();
    assert_eq!(diff.paths_changed.len(), 1);
    assert!(diff.paths_changed.contains_key("src/example.rs"));
    assert!(!diff.is_empty());
}

#[test]
fn hashes_binary_bytes_and_produces_stable_json_on_stable_input() {
    let temp = tempdir().unwrap();
    write(&temp.path().join("assets/binary.bin"), [0u8, 0xff, 0, 0x80]);
    let before = collect_forensic(temp.path()).unwrap();
    let after = collect_forensic(temp.path()).unwrap();
    assert_eq!(sha256_of(&before, "assets/binary.bin").len(), 64);
    assert_eq!(before, after);
    assert_eq!(
        serde_json::to_string(&before).unwrap(),
        serde_json::to_string(&after).unwrap()
    );
    assert!(diff_forensic(&before, &after).unwrap().is_empty());
}

#[test]
fn reports_git_head_commit_change_with_unchanged_symbolic_ref() {
    let temp = tempdir().unwrap();
    write(&temp.path().join(".git/HEAD"), b"ref: refs/heads/main\n");
    write(
        &temp.path().join(".git/refs/heads/main"),
        format!("{}\n", "a".repeat(40)),
    );
    let before = collect_forensic(temp.path()).unwrap();
    assert_eq!(
        before.git,
        GitHead::Resolved {
            reference: Some("refs/heads/main".into()),
            commit: "a".repeat(40)
        }
    );
    write(
        &temp.path().join(".git/refs/heads/main"),
        format!("{}\n", "b".repeat(40)),
    );
    let after = collect_forensic(temp.path()).unwrap();
    assert_eq!(
        after.git,
        GitHead::Resolved {
            reference: Some("refs/heads/main".into()),
            commit: "b".repeat(40)
        }
    );
    let diff = diff_forensic(&before, &after).unwrap();
    assert!(diff.git_changed);
    assert!(diff.paths_changed.is_empty());
    assert!(before.scope_complete && after.scope_complete);
}

#[test]
fn resolves_detached_and_packed_heads_without_process_execution() {
    let detached = tempdir().unwrap();
    write(
        &detached.path().join(".git/HEAD"),
        format!("{}\n", "c".repeat(40)),
    );
    let s = collect_forensic(detached.path()).unwrap();
    assert_eq!(
        s.git,
        GitHead::Resolved {
            reference: None,
            commit: "c".repeat(40)
        }
    );
    let packed = tempdir().unwrap();
    write(&packed.path().join(".git/HEAD"), b"ref: refs/heads/main\n");
    write(
        &packed.path().join(".git/packed-refs"),
        format!("# pack-refs\n{} refs/heads/main\n", "d".repeat(40)),
    );
    let p = collect_forensic(packed.path()).unwrap();
    assert_eq!(
        p.git,
        GitHead::Resolved {
            reference: Some("refs/heads/main".into()),
            commit: "d".repeat(40)
        }
    );
}

#[test]
fn reports_external_gitdir_as_unresolved_not_trusted() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join(".git"),
        b"gitdir: /some/external/location\n",
    );
    let snapshot = collect_forensic(temp.path()).unwrap();
    assert!(!snapshot.paths.contains_key(".git"));
    assert!(snapshot.excluded_paths.contains(".git"));
    assert_eq!(
        snapshot.git,
        GitHead::Unknown {
            reference: None,
            reason: GitProblem::ExternalGitDirectory
        }
    );
}

#[test]
fn uncertainty_is_never_inverted_to_a_boolean_pass() {
    use EvidenceTruth::{False, True, Unknown};
    assert_eq!(Unknown.negate(), Unknown);
    assert_eq!(EvidenceTruth::all([True, Unknown]), Unknown);
    assert_eq!(EvidenceTruth::all([Unknown, False]), False);
    assert_eq!(EvidenceTruth::any([False, Unknown]), Unknown);
    assert_eq!(EvidenceTruth::any([Unknown, True]), True);
    assert_eq!(EvidenceTruth::all([]), True);
    assert_eq!(EvidenceTruth::any([]), False);
}

#[test]
fn diff_rejects_unknown_versions_and_incompatible_scopes() {
    let temp = tempdir().unwrap();
    let a = collect_forensic(temp.path()).unwrap();
    let mut other = a.clone();
    other.schema_version = "999.0".to_owned();
    assert!(diff_forensic(&a, &other).is_err());
    other = a.clone();
    other.exclusion_policy = "other-scope".to_owned();
    assert!(diff_forensic(&a, &other).is_err());
}

#[test]
fn missing_root_cannot_be_claimed_as_a_clean_snapshot() {
    let temp = tempdir().unwrap();
    assert!(collect_forensic(&temp.path().join("missing")).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_is_recorded_but_never_dereferenced() {
    use std::os::unix::fs::symlink;
    let outside = tempdir().unwrap();
    let private = outside.path().join("private.txt");
    write(&private, b"never include these bytes\n");
    let repo = tempdir().unwrap();
    symlink(&private, repo.path().join("link")).unwrap();
    let snapshot = collect_forensic(repo.path()).unwrap();
    assert!(snapshot.scope_complete);
    assert!(matches!(
        snapshot.paths.get("link"),
        Some(PathEvidence::Symlink { .. })
    ));
    assert_eq!(snapshot.paths.len(), 1);
}

#[cfg(unix)]
#[test]
fn git_administrative_symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let outside = tempdir().unwrap();
    let secret = outside.path().join("outside-ref");
    write(&secret, format!("{}\n", "a".repeat(40)));
    let repo = tempdir().unwrap();
    write(&repo.path().join(".git/HEAD"), b"ref: refs/heads/main\n");
    fs::create_dir_all(repo.path().join(".git/refs/heads")).unwrap();
    symlink(&secret, repo.path().join(".git/refs/heads/main")).unwrap();
    let snapshot = collect_forensic(repo.path()).unwrap();
    assert_eq!(
        snapshot.git,
        GitHead::Unknown {
            reference: Some("refs/heads/main".into()),
            reason: GitProblem::MissingReference
        }
    );
}

#[cfg(unix)]
#[test]
fn unsupported_socket_is_visible_as_incomplete_evidence() {
    use std::os::unix::net::UnixListener;
    let repo = tempdir().unwrap();
    let _listener = UnixListener::bind(repo.path().join("socket")).unwrap();
    let snapshot = collect_forensic(repo.path()).unwrap();
    assert!(!snapshot.scope_complete);
    assert!(matches!(
        snapshot.paths.get("socket"),
        Some(PathEvidence::Unknown { .. })
    ));
    assert_eq!(snapshot.issues.len(), 1);
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_are_not_silently_normalised() {
    use std::os::unix::ffi::OsStringExt;
    let repo = tempdir().unwrap();
    let name = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
    write(&repo.path().join(name), b"bytes\n");
    let snapshot = collect_forensic(repo.path()).unwrap();
    assert!(!snapshot.scope_complete);
    assert!(!snapshot.issues.is_empty());
}

#[test]
fn sha256_matches_published_known_answer() {
    let repo = tempdir().unwrap();
    write(&repo.path().join("bytes"), b"abc");
    let snapshot = collect_forensic(repo.path()).unwrap();
    assert_eq!(
        sha256_of(&snapshot, "bytes"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn resolves_plus_branch_from_loose_and_packed_refs() {
    for packed in [false, true] {
        let temp = tempdir().unwrap();
        let git = temp.path().join(".git");
        write(&git.join("HEAD"), "ref: refs/heads/topic+fix\n");
        let oid = "a".repeat(40);
        if packed {
            write(
                &git.join("packed-refs"),
                format!("{oid} refs/heads/topic+fix\n"),
            );
        } else {
            write(&git.join("refs/heads/topic+fix"), &oid);
        }
        assert_eq!(
            collect_forensic(temp.path()).unwrap().git,
            GitHead::Resolved {
                reference: Some("refs/heads/topic+fix".into()),
                commit: oid,
            }
        );
    }
}

#[test]
fn malformed_loose_ref_does_not_fall_back_to_packed() {
    let temp = tempdir().unwrap();
    let git = temp.path().join(".git");
    write(&git.join("HEAD"), "ref: refs/heads/main\n");
    write(&git.join("refs/heads/main"), "invalid");
    write(
        &git.join("packed-refs"),
        format!("{} refs/heads/main\n", "a".repeat(40)),
    );
    assert!(matches!(
        collect_forensic(temp.path()).unwrap().git,
        GitHead::Unknown { .. }
    ));
}

#[cfg(unix)]
#[test]
fn refused_loose_refs_do_not_fall_back_to_packed() {
    use std::os::unix::fs::symlink;
    for dangling in [false, true] {
        let temp = tempdir().unwrap();
        let git = temp.path().join(".git");
        write(&git.join("HEAD"), "ref: refs/heads/main\n");
        write(
            &git.join("packed-refs"),
            format!("{} refs/heads/main\n", "a".repeat(40)),
        );
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        let target = temp.path().join("target-ref");
        if !dangling {
            write(&target, "b".repeat(40));
        }
        symlink(&target, git.join("refs/heads/main")).unwrap();
        assert!(matches!(
            collect_forensic(temp.path()).unwrap().git,
            GitHead::Unknown { .. }
        ));
    }
}

#[cfg(unix)]
#[test]
fn invalid_utf8_empty_directory_marks_scope_incomplete() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempdir().unwrap();
    fs::create_dir(temp.path().join(std::ffi::OsStr::from_bytes(b"bad-\xff"))).unwrap();
    let snapshot = collect_forensic(temp.path()).unwrap();
    assert!(!snapshot.scope_complete);
    assert!(snapshot
        .issues
        .iter()
        .any(|issue| issue.kind == plasma_engine::forensic::IssueKind::InvalidUtf8Path));
}

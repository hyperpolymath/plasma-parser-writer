// SPDX-License-Identifier: MPL-2.0
// Regression contract candidates for plasma's forensic assurance boundary.
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// These tests intentionally separate confirmed strictness defects (active,
// expected RED on the inspected baseline) from new forensic-mode contracts
// (ignored pending a distinct API/versioned contract). Do not weaken the
// production policy-mode semantics merely to make these tests pass.

use plasma_engine::ast::{
    ActionKind, Condition, Modality, Policy, PolicyVersion, Resource, Rule, Subject,
};
use plasma_engine::facts::{collect, FactSet};
use plasma_engine::finding::{FindingStatus, Severity};
use plasma_engine::{diff, evaluate};
use plasma_parser::spdx::lexer::{Lexer, Token};
use plasma_parser::spdx::parse_spdx_expr;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

fn facts(paths: &[&str]) -> FactSet {
    FactSet {
        root: "fixture".to_owned(),
        files: paths
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>(),
        spdx_headers: BTreeMap::new(),
        metadata: BTreeMap::new(),
        git: Default::default(),
        file_contents: BTreeMap::new(),
    }
}

fn policy_for(
    subject: Subject,
    condition: Condition,
    resource: Resource,
    action: ActionKind,
) -> Policy {
    Policy {
        schema_version: PolicyVersion { major: 0, minor: 1 },
        id: "forensic-regression".to_owned(),
        version: PolicyVersion { major: 0, minor: 1 },
        rules: vec![Rule {
            id: "r1".to_owned(),
            modality: Modality::Obligation,
            severity: Severity::Error,
            subject,
            resource,
            condition,
            action,
            rationale: None,
            source: None,
        }],
        overlays: Vec::new(),
    }
}

// NEGATIVE CONTROLS: active tests. They should FAIL on the inspected baseline.
// Passing these without modifying the lexer/parser warrants investigation.

#[test]
fn rejects_unrecognised_spdx_punctuation_instead_of_dropping_it() {
    let actual = parse_spdx_expr("MIT@");
    assert!(
        actual.is_err(),
        "invalid trailing '@' must not vanish: parser returned {actual:?}"
    );
}

#[test]
fn rejects_overflowing_spdx_number_instead_of_substituting_zero() {
    let tokens = Lexer::new("Apache-4294967296.9").tokenize();
    assert!(
        !tokens.iter().any(|token| matches!(token, Token::Number(0))),
        "overflow silently became Number(0): {tokens:?}"
    );
    assert!(
        parse_spdx_expr("Apache-4294967296.9").is_err(),
        "overflowing numeric component must reject rather than admit a different identifier"
    );
}

#[test]
fn reserved_action_does_not_silently_produce_a_pass() {
    // Direct evaluate() currently accepts a Policy struct, bypassing the
    // validation that load_policy_str() applies. An eventual ValidatedPolicy
    // boundary should make this call unrepresentable instead of merely
    // changing the verdict to Violation. This test pins the immediate hazard.
    let p = policy_for(
        Subject::Repo,
        Condition::True,
        Resource::File {
            path: "LICENSE".to_owned(),
        },
        ActionKind::ConsistentWith {
            id: "external-decision".to_owned(),
        },
    );
    let result = evaluate(&p, &facts(&["LICENSE"]));
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.status != FindingStatus::Pass),
        "reserved/unvalidated action must not emit positive assurance: {result:?}"
    );
}

// POSITIVE CONTROLS: active tests. These should PASS on the baseline.

#[test]
fn accepts_an_ordinary_compound_spdx_expression() {
    assert!(parse_spdx_expr("MIT OR Apache-2.0").is_ok());
}

#[test]
fn findings_summary_matches_actual_pass_and_violation_counts() {
    let mut p = policy_for(
        Subject::Repo,
        Condition::True,
        Resource::File {
            path: "README.md".to_owned(),
        },
        ActionKind::Present,
    );
    let mut second = p.rules[0].clone();
    second.id = "r2".to_owned();
    second.resource = Resource::File {
        path: "LICENSE".to_owned(),
    };
    p.rules.push(second);
    let e = evaluate(&p, &facts(&["README.md"]));
    assert_eq!(e.findings.len(), 2);
    assert_eq!(e.summary.errors, 1);
    assert_eq!(e.summary.warnings, 0);
    assert_eq!(e.summary.info, 0);
    assert_eq!(e.summary.passes, 1);
    assert_eq!(e.findings[0].rule_id, "r1");
    assert_eq!(e.findings[1].rule_id, "r2");
    assert_eq!(e, evaluate(&p, &facts(&["README.md"])));
}

#[test]
fn existing_policy_collector_discovers_regular_visible_files() {
    let d = tempfile::tempdir().expect("temp fixture");
    fs::write(d.path().join("visible.rs"), "fn example() {}\n").expect("fixture file");
    let snap = collect(d.path()).expect("collect baseline facts");
    assert!(snap.files.contains("visible.rs"));
}

// FORENSIC-MODE TARGETS: intentionally IGNORED in the default suite.
// Current v0 contracts deliberately exclude these facts or define unknown
// input as false. Re-enable these ONLY for a new, explicitly versioned
// forensic observation/evaluation API, or run with `--ignored` to confirm
// the existing limitations before designing that API.

#[test]
#[ignore = "new forensic collector required; existing policy collector skips dot-directories by specification"]
fn forensic_view_includes_governance_directories() {
    let d = tempfile::tempdir().expect("temp fixture");
    let workflows = d.path().join(".github").join("workflows");
    fs::create_dir_all(&workflows).expect("fixture dir");
    fs::write(workflows.join("gate.yml"), "name: Gate\n").expect("fixture file");
    let snap = collect(d.path()).expect("collect baseline facts");
    assert!(
        snap.files.contains(".github/workflows/gate.yml"),
        "forensic view may not omit governance paths"
    );
}

#[test]
#[ignore = "new forensic snapshot-diff contract required; current diff intentionally compares selected facts, not source bytes"]
fn forensic_diff_detects_content_only_mutations() {
    let mut before = facts(&["src/main.rs"]);
    before
        .file_contents
        .insert("src/main.rs".to_owned(), "fn a() {}\n".to_owned());
    let mut after = before.clone();
    after
        .file_contents
        .insert("src/main.rs".to_owned(), "fn b() {}\n".to_owned());
    let observed = diff(&before, &after);
    assert!(
        !observed.is_empty(),
        "source bytes changed but diff claimed identical: {observed:?}"
    );
}

#[test]
#[ignore = "forensic evidence needs explicit Unknown; v0 boolean predicates intentionally use false for uncollected content"]
fn negated_unavailable_evidence_cannot_emit_a_clean_pass() {
    let p = policy_for(
        Subject::Repo,
        Condition::Not {
            of: Box::new(Condition::FileMatchesPattern {
                path: "src/main.rs".to_owned(),
                pattern: "secret".to_owned(),
            }),
        },
        Resource::File {
            path: "LICENSE".to_owned(),
        },
        ActionKind::Present,
    );
    let e = evaluate(&p, &facts(&["src/main.rs", "LICENSE"]));
    assert!(
        e.findings.iter().all(|f| f.status != FindingStatus::Pass),
        "uncollected content cannot justify positive forensic assurance: {e:?}"
    );
}

#[test]
#[ignore = "new Git snapshot fidelity contract required; v0 stores symbolic HEAD reference only"]
fn forensic_git_facts_distinguish_two_commits_on_the_same_branch() {
    let d = tempfile::tempdir().expect("temp fixture");
    let ref_dir = d.path().join(".git").join("refs").join("heads");
    fs::create_dir_all(&ref_dir).expect("fixture git refs");
    fs::write(d.path().join(".git").join("HEAD"), "ref: refs/heads/main\n").expect("HEAD");
    fs::write(ref_dir.join("main"), format!("{}\n", "a".repeat(40))).expect("ref");
    let before = collect(d.path()).expect("before");
    fs::write(ref_dir.join("main"), format!("{}\n", "b".repeat(40))).expect("updated ref");
    let after = collect(d.path()).expect("after");
    assert_ne!(
        before.git, after.git,
        "HEAD commit changed but GitFacts did not"
    );
}

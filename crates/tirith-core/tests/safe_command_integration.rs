//! End-to-end coverage for the M6 ch5 safe-command transforms.
//!
//! Each transform ships one positive and one negative test. The
//! `sudo-narrow` family now ships four: two negatives carried forward
//! from M6 (`sudo rm -rf /` still flagging, `sudo sh` triggering the
//! interactive-shell remediation) plus two M8 ch4 cases — the deferred
//! positive (`sudo apt update`, where the stripped leader is benign)
//! and a new negative that pins the M6 ch5 invariant that an
//! interactive-shell leader NEVER yields a mechanical rewrite, even
//! when the sudo-only rules added in M8 ch4 are what made the verdict
//! fire.

use tirith_core::safe_command::{suggest, SafeSuggestion};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

fn finding(rule_id: RuleId) -> Finding {
    Finding {
        rule_id,
        severity: Severity::High,
        title: "t".into(),
        description: "d".into(),
        evidence: vec![Evidence::Text { detail: "e".into() }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn typosquat_finding(name: &str, target: &str) -> Finding {
    Finding {
        rule_id: RuleId::ThreatPackageTyposquat,
        severity: Severity::High,
        title: format!("Confirmed typosquat: {name} → {target}"),
        description: format!("Package '{name}' is a confirmed typosquat of '{target}'."),
        evidence: vec![Evidence::Text {
            detail: format!("package={name} typosquat_of={target}"),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn verdict_with(findings: Vec<Finding>) -> Verdict {
    Verdict::from_findings(findings, 3, Timings::default())
}

fn find_by_rule<'a>(out: &'a [SafeSuggestion], rule: &str) -> Option<&'a SafeSuggestion> {
    out.iter().find(|s| s.rule_id == rule)
}

// ── 1. typosquat-rewrite ──────────────────────────────────────────────────

#[test]
fn typosquat_positive_npm_install_unambiguous_target() {
    let cmd = "npm install reqeusts";
    let v = verdict_with(vec![typosquat_finding("reqeusts", "requests")]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "threat_package_typosquat").expect("rule entry");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("typosquat: target is unambiguous, rewrite should fire");
    assert_eq!(sc, "npm install requests");
    assert!(!entry.remediation.is_empty());
}

#[test]
fn typosquat_negative_ambiguous_target_no_rewrite() {
    // Finding has no arrow + no typosquat_of= evidence → target is ambiguous.
    let mut f = typosquat_finding("reqeusts", "requests");
    f.title = "Confirmed typosquat".to_string(); // strip the arrow
    f.evidence = vec![Evidence::Text {
        detail: "no_target_field_here".to_string(),
    }];

    let cmd = "npm install reqeusts";
    let v = verdict_with(vec![f]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "threat_package_typosquat").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "ambiguous target must not produce a rewrite"
    );
    assert!(!entry.remediation.is_empty());
}

// ── 2. sudo-narrow (negative tests only in M6) ────────────────────────────

#[test]
fn sudo_narrow_negative_sudo_rm_rf_root_no_rewrite() {
    // `sudo rm -rf /` — stripping sudo still gives `rm -rf /`, which the
    // engine flags. sudo-narrow MUST return None in that case (per-finding
    // suggestions already describe the underlying issue).
    let cmd = "sudo rm -rf /";
    let v = verdict_with(vec![finding(RuleId::CommandNetworkDeny)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow");
    assert!(
        entry.is_none(),
        "sudo-narrow must not fire when the stripped inner command still flags; got {entry:?}"
    );
}

#[test]
fn sudo_narrow_negative_sudo_sh_returns_interactive_shell_remediation() {
    // `sudo sh` — stripped leader is `sh`, an interactive shell. sudo-narrow
    // must emit a None-suggestion with the canonical remediation text.
    let cmd = "sudo sh";
    let v = verdict_with(vec![finding(RuleId::PipeToInterpreter)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow").expect("sudo_narrow entry must be present");
    assert!(
        entry.safe_command.is_none(),
        "sudo sh must yield no rewrite — got {:?}",
        entry.safe_command
    );
    assert!(
        entry
            .rationale
            .contains("no safe mechanical rewrite available"),
        "rationale should advertise no rewrite: {}",
        entry.rationale
    );
    assert!(
        entry.rationale.contains("avoid interactive root shells"),
        "rationale should warn about interactive root shells: {}",
        entry.rationale
    );
}

// ── 2a. sudo-narrow (M8 ch4 deferred POSITIVE) ───────────────────────────
//
// M6 ch5 had a sudo-narrow positive case marked DEFERRED to M8 ch4
// because no stable benign-target fixture existed. M8 ch4 ships the
// sudo rule family — including `SudoShellSpawn`, which finally gives
// us a clean way to construct the positive: a sudo command that
// fires a sudo-ONLY rule (no inner-command finding), so stripping
// sudo leaves an Allow path.
//
// `sudo apt update` is the textbook positive — `apt update` alone
// is Allow under the default engine. We DON'T drive this through
// `tirith_core::engine::analyze` because the verdict-construction
// in this test runs the suggester directly with a synthetic verdict;
// the engine call inside `build_sudo_narrow_suggestion` re-analyzes
// the stripped inner command and is what produces the rewrite.

#[test]
fn sudo_narrow_positive_sudo_apt_update_strips_sudo() {
    // `sudo apt update` — the inner command `apt update` is Allow,
    // and the leader (`apt`) is NOT an interactive shell. sudo-narrow
    // must emit a rewrite to the bare inner command.
    let cmd = "sudo apt update";
    // Synthetic finding to keep the call path uniform with the other
    // sudo-narrow tests — any finding triggers the command-shape
    // transforms.
    let v = verdict_with(vec![finding(RuleId::CommandNetworkDeny)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow")
        .expect("sudo_narrow entry must be present for sudo apt update");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("sudo apt update: stripped leader is benign, rewrite should fire");
    assert_eq!(
        sc, "apt update",
        "sudo-narrow should emit the bare inner command, got: {sc}"
    );
    assert!(
        entry.rationale.contains("safe to run without sudo"),
        "rationale should explain the strip: {}",
        entry.rationale
    );
}

// ── 2b. sudo-narrow (M8 ch4 NEGATIVE — interactive shell invariant) ──────
//
// Pins the M6 ch5 invariant: an interactive-shell leader NEVER
// yields a mechanical rewrite, even when the M8 ch4 sudo rules are
// what made the verdict fire. The simpler `sudo sh` case above
// drives this via a synthetic PipeToInterpreter; this version drives
// it with the M8 ch4 `SudoShellSpawn` finding to confirm that
// adding the sudo rules has NOT loosened the invariant.

#[test]
fn sudo_narrow_negative_sudo_shell_spawn_keeps_no_rewrite() {
    let cmd = "sudo sh";
    let v = verdict_with(vec![finding(RuleId::SudoShellSpawn)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow")
        .expect("sudo_narrow entry must be present for sudo sh + SudoShellSpawn");
    assert!(
        entry.safe_command.is_none(),
        "sudo sh + SudoShellSpawn must NOT mechanically rewrite — got {:?}",
        entry.safe_command
    );
    assert!(
        entry
            .rationale
            .contains("no safe mechanical rewrite available"),
        "rationale should advertise no rewrite: {}",
        entry.rationale
    );
    assert!(
        entry.rationale.contains("avoid interactive root shells"),
        "rationale should mention interactive root shells: {}",
        entry.rationale
    );
}

// ── 3. env-scrub ──────────────────────────────────────────────────────────

// env_scrub end-to-end tests were intentionally dropped: they required
// `std::env::set_var` / `remove_var` to set / clear sensitive variables, and
// libc's environ mutation is not thread-safe on macOS / Windows even under
// our internal `ENV_LOCK` (parallel readers in unrelated tests can observe a
// torn write). The coverage they provided is preserved by:
//   * `safe_command::tests::is_simple_command_for_env_scrub` direct-call
//     unit tests (pipeline / redirection / && / ; / backtick / $() etc.) —
//     these exercise the guard that controls env_scrub firing, without
//     touching the real environment.
//   * `safe_command::tests::build_env_scrub_suggestion_*` direct-call unit
//     tests in the same module that drive the suggestion builder with a
//     stub var list.
// If a future change needs a real-env end-to-end test, gate the whole
// integration target with `harness = false` and a custom `--test-threads=1`
// runner, or inject env access via a parameter.

// ── 4. archive-list-before-extract ────────────────────────────────────────

#[test]
fn archive_list_first_positive_tar_xzf() {
    let cmd = "tar -xzf foo.tar.gz -C ~/";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("archive-list-first should rewrite a known tar invocation");
    // The preview uses `tar -tf` (no compression flag) so it works for
    // .tar / .tar.gz / .tar.bz2 / .tar.xz / .tar.zst — modern GNU/BSD tar
    // auto-detects compression from the archive's magic bytes. Hard-coding
    // `-tzf` would have broken the preview step for every non-gzip variant.
    assert!(
        sc.starts_with("tar -tf foo.tar.gz | head"),
        "expected preview-first sequence with `tar -tf`, got: {sc}"
    );
    assert!(
        sc.contains(" && tar -xzf foo.tar.gz"),
        "expected the original extract on the && tail: {sc}"
    );
}

#[test]
fn archive_list_first_positive_tar_bz2_uses_universal_tf() {
    // .tar.bz2 must NOT use `-tjf` either — the universal `tar -tf` form
    // covers it via tar's magic-byte auto-detection.
    let cmd = "tar -xjf foo.tar.bz2";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    let sc = entry.safe_command.as_deref().expect("rewrite expected");
    assert!(
        sc.starts_with("tar -tf foo.tar.bz2 | head"),
        "expected universal `tar -tf` preview for bz2, got: {sc}"
    );
}

#[test]
fn archive_list_first_negative_non_archive_leader_no_rewrite() {
    // `ls foo.tar.gz` is not an archive command. Even with a synthetic
    // ArchiveExtract finding (which would not fire in practice), the transform
    // must refuse to invent a rewrite.
    let cmd = "ls foo.tar.gz";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "non-archive leader must yield no rewrite"
    );
}

// ── 5. dotfile-redirect ───────────────────────────────────────────────────

// dotfile-redirect end-to-end tests were dropped for the same libc-environ
// race reason described above for env_scrub: they had to set `HOME` so the
// `expand_dotfile_to_fs_path` check resolved to a controlled directory, and
// `std::env::set_var("HOME", ...)` is not thread-safe on macOS / Windows
// even under our internal ENV_LOCK. The transform's structural correctness
// (it only fires when the target exists, the rewrite is `cp X X.bak && ...`,
// only single-segment commands, only `>` / `>>` to `~/.` or `$HOME/.`) is
// pinned by unit tests on `dotfile_redirect_target` and
// `rewrite_dotfile_backup_first` in `safe_command::tests`. The on-disk
// existence check is the only branch we lose dedicated coverage on; if
// regression risk grows there, gate the integration target with a custom
// `--test-threads=1` harness or inject `home_dir()` for testability.

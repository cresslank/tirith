//! `tirith path audit|watch|which` (M9 ch5).
//!
//! `$PATH` shadowing analysis. `audit` enumerates the full `$PATH` and flags
//! repo-local / `/tmp` / writable-before-system dirs and duplicate command
//! names. `watch` re-runs `audit` on an interval. `which <cmd> [--secure]`
//! resolves a command across `$PATH` and, with `--secure`, exits 1 when the
//! first-resolved copy is NOT a system binary.
//!
//! All of this is the COLD side — it reads `$PATH` and the filesystem directly
//! and never runs on the engine hot path (the hot path's three cheap rules
//! live in [`tirith_core::path_audit::classify_leader_path`]).
//!
//! Tests pass `$PATH` as a string and never mutate the process environment.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tirith_core::path_audit::{self, PathAuditReport, PathDirRisk};
use tirith_core::policy;

use super::write_json_stdout;

/// The `$PATH` value from the environment, or empty when unset.
fn env_path() -> String {
    std::env::var("PATH").unwrap_or_default()
}

/// The `/tmp`-equivalent roots used by the audit (`/tmp` + `$TMPDIR`).
fn tmp_roots() -> Vec<std::path::PathBuf> {
    let mut roots = vec![std::path::PathBuf::from("/tmp")];
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        let p = std::path::PathBuf::from(tmp);
        if !p.as_os_str().is_empty() {
            roots.push(p);
        }
    }
    roots
}

/// `tirith path audit` — audit the live `$PATH`. Exit 1 if any High-class
/// finding (a `/tmp` dir or a writable-before-system dir) is present, else 0.
pub fn audit(json: bool) -> i32 {
    let path_value = env_path();
    let repo_root = policy::find_repo_root(None);
    let report = path_audit::audit_path_str(&path_value, repo_root.as_deref(), &tmp_roots());

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "path_dirs": report.path_dirs,
            "findings": report.findings,
            "has_high": report.has_high(),
        });
        if !write_json_stdout(&body, "tirith path audit: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_audit(&report);
    }

    if report.has_high() {
        1
    } else {
        0
    }
}

/// `tirith path watch --interval N` — re-run the audit every `N` seconds until
/// SIGINT, printing only when the set of findings changes. Exit 0 on SIGINT.
pub fn watch(interval: u64, json: bool) -> i32 {
    let interval = interval.max(1);
    install_sigint_handler();

    if !json {
        eprintln!("tirith path watch: auditing $PATH every {interval}s (Ctrl-C to stop).");
    }

    let repo_root = policy::find_repo_root(None);
    let tmp = tmp_roots();
    let mut last_signature: Option<String> = None;
    let mut polls: u64 = 0;

    while !STOP.load(Ordering::Relaxed) {
        // Sleep in 200ms slices so Ctrl-C stays responsive.
        let step = Duration::from_millis(200);
        let target = Duration::from_secs(interval);
        let mut slept = Duration::ZERO;
        while slept < target && !STOP.load(Ordering::Relaxed) {
            std::thread::sleep(step);
            slept += step;
        }
        if STOP.load(Ordering::Relaxed) {
            break;
        }

        polls += 1;
        let report = path_audit::audit_path_str(&env_path(), repo_root.as_deref(), &tmp);
        let signature = signature_of(&report);
        if last_signature.as_deref() != Some(signature.as_str()) {
            if json {
                let body = serde_json::json!({
                    "schema_version": 1,
                    "poll": polls,
                    "findings": report.findings,
                    "has_high": report.has_high(),
                });
                let _ = write_json_stdout(&body, "tirith path watch: failed to write JSON");
            } else {
                eprintln!("\n[poll {polls}] $PATH audit changed:");
                print_human_audit(&report);
            }
            last_signature = Some(signature);
        }
    }

    if !json {
        eprintln!("\ntirith path watch: stopped after {polls} poll(s).");
    }
    0
}

/// `tirith path which <cmd> [--secure]` — resolve `cmd` across `$PATH`.
/// Without `--secure`: print every hit, exit 0 (or 2 if unresolved).
/// With `--secure`: exit 1 when the FIRST-resolved copy (what the shell runs)
/// is NOT under a system dir — i.e. a non-system binary wins.
pub fn which(cmd: &str, secure: bool, json: bool) -> i32 {
    let path_value = env_path();
    let hits = path_audit::which_all(cmd, &path_value);
    let first_is_system = hits.first().map(|p| path_audit::is_system_path(p));
    let insecure = secure && matches!(first_is_system, Some(false));

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "command": cmd,
            "secure": secure,
            "resolved": !hits.is_empty(),
            "hits": hits.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "first_is_system": first_is_system,
            "insecure": insecure,
        });
        if !write_json_stdout(&body, "tirith path which: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_which(cmd, &hits, secure, insecure);
    }

    if hits.is_empty() {
        return 2;
    }
    if insecure {
        1
    } else {
        0
    }
}

/// A stable string summarizing a report's findings, for change detection in
/// `watch`. Order-independent within a poll because `audit_path_str` emits in
/// a deterministic order.
fn signature_of(report: &PathAuditReport) -> String {
    report
        .findings
        .iter()
        .map(|e| format!("{}|{}|{}", e.dir, risk_str(e.risk), e.command))
        .collect::<Vec<_>>()
        .join("\n")
}

fn risk_str(risk: PathDirRisk) -> &'static str {
    match risk {
        PathDirRisk::InRepo => "in_repo",
        PathDirRisk::InTmp => "in_tmp",
        PathDirRisk::WritableBeforeSystem => "writable_before_system",
        PathDirRisk::DuplicateCommand => "duplicate_command",
    }
}

fn risk_label(risk: PathDirRisk) -> &'static str {
    match risk {
        PathDirRisk::InRepo => "repo-local PATH dir",
        PathDirRisk::InTmp => "/tmp PATH dir (HIGH)",
        PathDirRisk::WritableBeforeSystem => "user-writable, precedes system path (HIGH)",
        PathDirRisk::DuplicateCommand => "duplicate command",
    }
}

// ─── human output ────────────────────────────────────────────────────────────

fn print_human_audit(report: &PathAuditReport) {
    eprintln!(
        "tirith path audit: {} PATH dir(s), {} finding(s).",
        report.path_dirs.len(),
        report.findings.len()
    );
    if report.findings.is_empty() {
        eprintln!("  $PATH is clean (no repo-local / /tmp / writable-before-system dirs, no duplicate commands).");
        return;
    }
    for e in &report.findings {
        match e.risk {
            PathDirRisk::DuplicateCommand => {
                eprintln!(
                    "  [{}] {} (shadowed copy in {})",
                    risk_label(e.risk),
                    e.command,
                    e.dir
                );
            }
            _ => {
                eprintln!("  [{}] {}", risk_label(e.risk), e.dir);
            }
        }
    }
    eprintln!("\nReorder $PATH so system dirs precede user-writable ones; run `tirith path which <cmd>` to see what wins.");
}

fn print_human_which(cmd: &str, hits: &[std::path::PathBuf], secure: bool, insecure: bool) {
    if hits.is_empty() {
        eprintln!("tirith path which: `{cmd}` not found on $PATH.");
        return;
    }
    eprintln!("tirith path which `{cmd}`:");
    for (i, h) in hits.iter().enumerate() {
        let sys = if path_audit::is_system_path(h) {
            " [system]"
        } else {
            ""
        };
        let marker = if i == 0 { "→" } else { " " };
        eprintln!("  {marker} {}{sys}", h.display());
    }
    if secure {
        if insecure {
            eprintln!(
                "\n--secure: FAIL — `{cmd}` resolves to a non-system binary ({}).",
                hits[0].display()
            );
        } else {
            eprintln!("\n--secure: ok — `{cmd}` resolves to a system binary.");
        }
    }
}

// ─── SIGINT handling ──────────────────────────────────────────────────────────

/// Set by the SIGINT handler to break the `watch` poll loop.
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn install_sigint_handler() {
    extern "C" fn handle(_sig: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }
    // SAFETY: `handle` only performs an async-signal-safe atomic store.
    unsafe {
        libc::signal(libc::SIGINT, handle as *const () as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_sigint_handler() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_unresolved_exits_2() {
        // Guaranteed-absent command.
        assert_eq!(which("tirith-no-such-cmd-xyz-9999", false, true), 2);
    }

    #[test]
    fn risk_str_round_trip() {
        assert_eq!(risk_str(PathDirRisk::InTmp), "in_tmp");
        assert_eq!(
            risk_str(PathDirRisk::WritableBeforeSystem),
            "writable_before_system"
        );
    }

    #[test]
    fn signature_changes_with_findings() {
        let empty = PathAuditReport::default();
        let mut one = PathAuditReport::default();
        one.findings.push(tirith_core::path_audit::PathAuditEntry {
            dir: "/tmp/x".into(),
            risk: PathDirRisk::InTmp,
            command: String::new(),
        });
        assert_ne!(signature_of(&empty), signature_of(&one));
    }
}

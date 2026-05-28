//! `tirith exec check|provenance` (M9 ch5).
//!
//! The COLD, off-hot-path provenance surface. `check <bin>` resolves a bare
//! command name against `$PATH` (taking the first hit, what the shell runs),
//! then reports the full provenance record plus shadowing. `provenance <path>`
//! inspects a specific path directly. Both run the expensive probes (stat,
//! `file --brief`, `codesign`) that NEVER run on the engine hot path — see
//! [`tirith_core::exec_provenance`] and the `engine::analyze` doc-comment.

use std::path::{Path, PathBuf};

use tirith_core::exec_provenance::{self, Provenance};
use tirith_core::path_audit;
use tirith_core::verdict::{Finding, Severity};

use super::write_json_stdout;

/// `tirith exec check <bin>` — resolve `bin` on `$PATH`, report provenance +
/// shadowing. Exit 1 if any High-severity finding fires (recently-modified,
/// world-writable, writable-dir-before-system path hijack), 0 otherwise, 2 if
/// the command does not resolve on `$PATH` at all.
pub fn check(bin: &str, json: bool) -> i32 {
    let path_value = std::env::var("PATH").unwrap_or_default();
    let hits = path_audit::which_all(bin, &path_value);

    let Some(first) = hits.first().cloned() else {
        if json {
            let body = serde_json::json!({
                "schema_version": 1,
                "command": bin,
                "resolved": false,
                "message": "not found on PATH",
            });
            let _ = write_json_stdout(&body, "tirith exec check: failed to write JSON output");
        } else {
            eprintln!("tirith exec check: `{bin}` was not found on $PATH.");
        }
        return 2;
    };

    let prov = exec_provenance::provenance_of(&first);
    let mut findings = prov.findings();
    if let Some(shadow) = exec_provenance::shadow_finding(bin, &first) {
        findings.push(shadow);
    }

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "command": bin,
            "resolved": true,
            "resolved_path": first.display().to_string(),
            "all_path_hits": hits.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "provenance": prov,
            "findings": findings,
        });
        if !write_json_stdout(&body, "tirith exec check: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_check(bin, &first, &hits, &prov, &findings);
    }

    exit_for(&findings)
}

/// `tirith exec provenance <path>` — inspect a specific path's provenance.
/// Exit 1 on a High-severity finding, 0 otherwise, 2 if the path is not a file.
pub fn provenance(path: &str, json: bool) -> i32 {
    let p = expand_path(path);
    let prov = exec_provenance::provenance_of(&p);

    if !prov.exists {
        if json {
            let body = serde_json::json!({
                "schema_version": 1,
                "path": p.display().to_string(),
                "exists": false,
            });
            let _ = write_json_stdout(&body, "tirith exec provenance: failed to write JSON output");
        } else {
            eprintln!(
                "tirith exec provenance: `{}` is not a regular file.",
                p.display()
            );
        }
        return 2;
    }

    let findings = prov.findings();

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "path": p.display().to_string(),
            "provenance": prov,
            "findings": findings,
        });
        if !write_json_stdout(&body, "tirith exec provenance: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_provenance(&prov, &findings);
    }

    exit_for(&findings)
}

/// Expand a leading `~/` against the home dir; otherwise return the path as-is
/// (relative paths resolve against the process cwd via the FS later).
fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// Exit 1 when any High/Critical finding is present, else 0.
fn exit_for(findings: &[Finding]) -> i32 {
    let high = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::High | Severity::Critical));
    if high {
        1
    } else {
        0
    }
}

// ─── human output ────────────────────────────────────────────────────────────

fn print_human_check(
    bin: &str,
    resolved: &Path,
    hits: &[PathBuf],
    prov: &Provenance,
    findings: &[Finding],
) {
    eprintln!("tirith exec check `{bin}`:");
    eprintln!("  resolves to: {}", resolved.display());
    if hits.len() > 1 {
        eprintln!("  also on PATH ({} total):", hits.len());
        for h in hits.iter().skip(1) {
            eprintln!("    {}", h.display());
        }
    }
    print_provenance_body(prov);
    print_findings(findings);
}

fn print_human_provenance(prov: &Provenance, findings: &[Finding]) {
    eprintln!("tirith exec provenance `{}`:", prov.path);
    print_provenance_body(prov);
    print_findings(findings);
}

fn print_provenance_body(prov: &Provenance) {
    eprintln!(
        "  package manager: {}",
        prov.package_owner
            .as_ref()
            .map(|o| format!("{} ({})", o.manager, o.root))
            .unwrap_or_else(|| "none (not under a known install root)".to_string())
    );
    eprintln!("  signature: {}", prov.signature.as_str());
    eprintln!(
        "  file type: {}",
        prov.file_type.as_deref().unwrap_or("unknown")
    );
    if let Some(mode) = &prov.mode {
        eprintln!(
            "  mode: {mode}{}",
            if prov.world_writable {
                " (WORLD-WRITABLE)"
            } else {
                ""
            }
        );
    }
    if let Some(secs) = prov.modified_secs_ago {
        eprintln!(
            "  modified: {secs}s ago{}",
            if prov.recently_modified {
                " (RECENT — within 5 min)"
            } else {
                ""
            }
        );
    }
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        eprintln!("  no provenance concerns.");
        return;
    }
    eprintln!("\n  {} finding(s):", findings.len());
    for f in findings {
        eprintln!("    [{}] {} — {}", f.severity, f.rule_id, f.title);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_path_handles_tilde_and_plain() {
        // Plain path unchanged.
        assert_eq!(expand_path("/usr/bin/git"), PathBuf::from("/usr/bin/git"));
        // ~/ expands when home resolves (it does in CI).
        if let Some(home) = home::home_dir() {
            assert_eq!(expand_path("~/bin/x"), home.join("bin/x"));
        }
    }

    #[test]
    fn exit_for_high_is_1_else_0() {
        let high = vec![Finding {
            rule_id: tirith_core::verdict::RuleId::ExecWorldWritable,
            severity: Severity::High,
            title: "t".into(),
            description: "d".into(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(exit_for(&high), 1);
        assert_eq!(exit_for(&[]), 0);
    }

    #[test]
    fn check_nonexistent_command_exits_2() {
        // A command guaranteed not on PATH → exit 2 (not resolved).
        assert_eq!(check("tirith-no-such-bin-xyz-9999", true), 2);
    }
}

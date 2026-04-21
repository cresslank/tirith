use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::policy::{ApprovalRule, Policy};
use crate::verdict::Verdict;

/// Approval/warn-ack temp files older than this are considered abandoned
/// (e.g. a `tirith check --approval-check` invoked from a terminal without
/// a hook on the receiving end) and removed opportunistically on the next
/// write. A live hook normally reads + deletes its own file within seconds,
/// so an hour is a safe bound that won't race.
const STALE_APPROVAL_TTL: Duration = Duration::from_secs(3600);

/// Best-effort cleanup of leaked approval/warn-ack temp files in `$TEMP`.
/// Called before each fresh write so a leak from a prior CLI test doesn't
/// accumulate forever. Errors are silently ignored — this is housekeeping,
/// not a hard requirement.
fn cleanup_stale_temp_files() {
    let dir = std::env::temp_dir();
    let now = SystemTime::now();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".env") {
            continue;
        }
        if !(name.starts_with("tirith-approval-") || name.starts_with("tirith-warnack-")) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age > STALE_APPROVAL_TTL {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Approval metadata extracted from a verdict + policy.
#[derive(Debug, Clone)]
pub struct ApprovalMetadata {
    pub requires_approval: bool,
    pub timeout_secs: u64,
    pub fallback: String,
    pub rule_id: String,
    pub description: String,
}

/// Check whether a verdict triggers any approval rules from the policy.
///
/// Returns `Some(ApprovalMetadata)` if approval is required, `None` otherwise.
/// This is a Team-tier feature: callers should gate on tier before calling.
pub fn check_approval(verdict: &Verdict, policy: &Policy) -> Option<ApprovalMetadata> {
    if policy.approval_rules.is_empty() {
        return None;
    }

    for finding in &verdict.findings {
        let finding_rule_str = finding.rule_id.to_string();
        for approval_rule in &policy.approval_rules {
            if approval_rule_matches(&finding_rule_str, approval_rule) {
                let description = if finding.description.is_empty() {
                    finding.title.clone()
                } else {
                    finding.description.clone()
                };
                return Some(ApprovalMetadata {
                    requires_approval: true,
                    timeout_secs: approval_rule.timeout_secs,
                    fallback: approval_rule.fallback.clone(),
                    rule_id: finding_rule_str,
                    description: sanitize_description(&description),
                });
            }
        }
    }

    None
}

/// Apply approval metadata to a verdict (mutates in place).
pub fn apply_approval(verdict: &mut Verdict, metadata: &ApprovalMetadata) {
    verdict.requires_approval = Some(metadata.requires_approval);
    verdict.approval_timeout_secs = Some(metadata.timeout_secs);
    verdict.approval_fallback = Some(metadata.fallback.clone());
    verdict.approval_rule = Some(metadata.rule_id.clone());
    verdict.approval_description = Some(metadata.description.clone());
}

/// Write approval metadata to a secure temp file.
///
/// Returns the path to the temp file. The caller is responsible for printing
/// this path to stdout. The temp file is persisted (not auto-deleted) so
/// shell hooks can read it after tirith exits.
///
/// Per ADR-7: file is created with O_EXCL + O_CREAT (via tempfile crate),
/// mode 0600 on Unix, and `.keep()` is called before returning.
pub fn write_approval_file(metadata: &ApprovalMetadata) -> Result<PathBuf, std::io::Error> {
    cleanup_stale_temp_files();
    let mut tmp = tempfile::Builder::new()
        .prefix("tirith-approval-")
        .suffix(".env")
        .tempfile()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    writeln!(
        tmp,
        "TIRITH_REQUIRES_APPROVAL={}",
        if metadata.requires_approval {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(tmp, "TIRITH_APPROVAL_TIMEOUT={}", metadata.timeout_secs)?;
    writeln!(
        tmp,
        "TIRITH_APPROVAL_FALLBACK={}",
        sanitize_fallback(&metadata.fallback)
    )?;
    writeln!(
        tmp,
        "TIRITH_APPROVAL_RULE={}",
        sanitize_rule_id(&metadata.rule_id)
    )?;
    writeln!(
        tmp,
        "TIRITH_APPROVAL_DESCRIPTION={}",
        sanitize_description(&metadata.description)
    )?;

    tmp.flush()?;

    // `.keep()` prevents auto-delete on drop so shell hooks can read the file after tirith exits.
    let (_, path) = tmp.keep().map_err(|e| e.error)?;
    Ok(path)
}

/// Write a "no approval required" temp file for the common case.
pub fn write_no_approval_file() -> Result<PathBuf, std::io::Error> {
    cleanup_stale_temp_files();
    let mut tmp = tempfile::Builder::new()
        .prefix("tirith-approval-")
        .suffix(".env")
        .tempfile()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    writeln!(tmp, "TIRITH_REQUIRES_APPROVAL=no")?;
    tmp.flush()?;

    let (_, path) = tmp.keep().map_err(|e| e.error)?;
    Ok(path)
}

/// Write warn-ack metadata to a secure temp file for hook-driven strict_warn.
///
/// The shell hook reads this file to know how many warnings need acknowledgement
/// and the maximum severity. Follows the same security pattern as
/// `write_approval_file()`: O_EXCL + O_CREAT, mode 0600, `.keep()` before return.
pub fn write_warn_ack_file(
    finding_count: usize,
    max_severity: &crate::verdict::Severity,
) -> Result<PathBuf, std::io::Error> {
    cleanup_stale_temp_files();
    let mut tmp = tempfile::Builder::new()
        .prefix("tirith-warnack-")
        .suffix(".env")
        .tempfile()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    writeln!(tmp, "TIRITH_WARN_ACK_REQUIRED=yes")?;
    writeln!(tmp, "TIRITH_WARN_ACK_FINDINGS={finding_count}")?;
    writeln!(tmp, "TIRITH_WARN_ACK_MAX_SEVERITY={max_severity}")?;

    tmp.flush()?;

    let (_, path) = tmp.keep().map_err(|e| e.error)?;
    Ok(path)
}

/// Check if a finding's rule_id string matches an approval rule.
fn approval_rule_matches(rule_id_str: &str, approval_rule: &ApprovalRule) -> bool {
    approval_rule.rule_ids.iter().any(|r| r == rule_id_str)
}

/// Sanitize a description string per ADR-7.
///
/// Allowlist: `[A-Za-z0-9 .,_:/()\-']`. All other characters stripped.
/// Consecutive spaces collapsed. Max 200 bytes, truncated with `...`.
pub fn sanitize_description(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '.' | ',' | '_' | ':' | '/' | '(' | ')' | '-' | '\''
                )
        })
        .collect();

    // Collapse consecutive spaces
    let mut result = String::with_capacity(filtered.len());
    let mut prev_space = false;
    for c in filtered.chars() {
        if c == ' ' {
            if !prev_space {
                result.push(c);
            }
            prev_space = true;
        } else {
            result.push(c);
            prev_space = false;
        }
    }

    // Truncate to 200 bytes
    if result.len() > 200 {
        // Find a safe UTF-8 boundary
        let mut end = 197;
        while end > 0 && !result.is_char_boundary(end) {
            end -= 1;
        }
        result.truncate(end);
        result.push_str("...");
    }

    result
}

/// Sanitize the approval fallback value per ADR-7.
///
/// Only "block", "warn", and "allow" are valid. Any other value
/// (including values containing newlines, `=`, or shell metacharacters)
/// defaults to "block" for fail-closed safety.
fn sanitize_fallback(input: &str) -> &'static str {
    match input.trim().to_lowercase().as_str() {
        "block" => "block",
        "warn" => "warn",
        "allow" => "allow",
        _ => "block",
    }
}

/// Sanitize a rule_id to `[a-z_]+`, max 64 chars.
fn sanitize_rule_id(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| c.is_ascii_lowercase() || *c == '_')
        .take(64)
        .collect();
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ApprovalRule;
    use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings, Verdict};

    fn make_verdict(rule_id: RuleId, severity: Severity) -> Verdict {
        Verdict {
            action: Action::Block,
            findings: vec![Finding {
                rule_id,
                severity,
                title: "Test finding".to_string(),
                description: "A test finding description".to_string(),
                evidence: vec![Evidence::Text {
                    detail: "test".to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
        }
    }

    fn make_policy_with_approval(rule_ids: &[&str]) -> Policy {
        let mut policy = Policy::default();
        policy.approval_rules.push(ApprovalRule {
            rule_ids: rule_ids.iter().map(|s| s.to_string()).collect(),
            timeout_secs: 30,
            fallback: "block".to_string(),
        });
        policy
    }

    #[test]
    fn test_check_approval_matches() {
        let verdict = make_verdict(RuleId::CurlPipeShell, Severity::High);
        let policy = make_policy_with_approval(&["curl_pipe_shell"]);

        let meta = check_approval(&verdict, &policy);
        assert!(meta.is_some());
        let meta = meta.unwrap();
        assert!(meta.requires_approval);
        assert_eq!(meta.timeout_secs, 30);
        assert_eq!(meta.fallback, "block");
        assert_eq!(meta.rule_id, "curl_pipe_shell");
    }

    #[test]
    fn test_check_approval_no_match() {
        let verdict = make_verdict(RuleId::NonAsciiHostname, Severity::Medium);
        let policy = make_policy_with_approval(&["curl_pipe_shell"]);

        let meta = check_approval(&verdict, &policy);
        assert!(meta.is_none());
    }

    #[test]
    fn test_check_approval_empty_rules() {
        let verdict = make_verdict(RuleId::CurlPipeShell, Severity::High);
        let policy = Policy::default();

        let meta = check_approval(&verdict, &policy);
        assert!(meta.is_none());
    }

    #[test]
    fn test_sanitize_description_basic() {
        assert_eq!(
            sanitize_description("Normal text with (parens) and 123"),
            "Normal text with (parens) and 123"
        );
    }

    #[test]
    fn test_sanitize_description_strips_dangerous() {
        assert_eq!(
            sanitize_description("echo $HOME; rm -rf /; `whoami`"),
            "echo HOME rm -rf / whoami"
        );
    }

    #[test]
    fn test_sanitize_description_collapses_spaces() {
        assert_eq!(
            sanitize_description("too   many    spaces"),
            "too many spaces"
        );
    }

    #[test]
    fn test_sanitize_description_truncates() {
        let long = "a".repeat(300);
        let result = sanitize_description(&long);
        assert!(result.len() <= 200);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_sanitize_rule_id() {
        assert_eq!(sanitize_rule_id("curl_pipe_shell"), "curl_pipe_shell");
        // Uppercase letters are stripped (only [a-z_] allowed)
        assert_eq!(sanitize_rule_id("CurlPipeShell"), "urlipehell");
        assert_eq!(sanitize_rule_id(&"a".repeat(100)), "a".repeat(64));
    }

    #[test]
    fn test_sanitize_fallback() {
        assert_eq!(sanitize_fallback("block"), "block");
        assert_eq!(sanitize_fallback("warn"), "warn");
        assert_eq!(sanitize_fallback("allow"), "allow");
        assert_eq!(sanitize_fallback("BLOCK"), "block");
        assert_eq!(sanitize_fallback("  warn  "), "warn");
        // Malicious values default to "block" (fail-closed).
        assert_eq!(sanitize_fallback("block\nINJECTED=yes"), "block");
        assert_eq!(
            sanitize_fallback("allow\r\nTIRITH_REQUIRES_APPROVAL=no"),
            "block"
        );
        assert_eq!(sanitize_fallback(""), "block");
        assert_eq!(sanitize_fallback("invalid"), "block");
    }

    #[test]
    fn test_apply_approval() {
        let mut verdict = make_verdict(RuleId::CurlPipeShell, Severity::High);
        let meta = ApprovalMetadata {
            requires_approval: true,
            timeout_secs: 60,
            fallback: "warn".to_string(),
            rule_id: "curl_pipe_shell".to_string(),
            description: "Pipe to shell detected".to_string(),
        };
        apply_approval(&mut verdict, &meta);

        assert_eq!(verdict.requires_approval, Some(true));
        assert_eq!(verdict.approval_timeout_secs, Some(60));
        assert_eq!(verdict.approval_fallback.as_deref(), Some("warn"));
        assert_eq!(verdict.approval_rule.as_deref(), Some("curl_pipe_shell"));
    }

    #[test]
    fn test_write_approval_file() {
        let meta = ApprovalMetadata {
            requires_approval: true,
            timeout_secs: 30,
            fallback: "block".to_string(),
            rule_id: "curl_pipe_shell".to_string(),
            description: "Pipe to shell detected".to_string(),
        };

        let path = write_approval_file(&meta).expect("write should succeed");
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(content.contains("TIRITH_REQUIRES_APPROVAL=yes"));
        assert!(content.contains("TIRITH_APPROVAL_TIMEOUT=30"));
        assert!(content.contains("TIRITH_APPROVAL_FALLBACK=block"));
        assert!(content.contains("TIRITH_APPROVAL_RULE=curl_pipe_shell"));
        assert!(content.contains("TIRITH_APPROVAL_DESCRIPTION=Pipe to shell detected"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_no_approval_file() {
        let path = write_no_approval_file().expect("write should succeed");
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(content.contains("TIRITH_REQUIRES_APPROVAL=no"));
        assert!(!content.contains("TIRITH_APPROVAL_TIMEOUT"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_warn_ack_file() {
        let path = write_warn_ack_file(3, &Severity::Medium).expect("write should succeed");
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(content.contains("TIRITH_WARN_ACK_REQUIRED=yes"));
        assert!(content.contains("TIRITH_WARN_ACK_FINDINGS=3"));
        assert!(content.contains("TIRITH_WARN_ACK_MAX_SEVERITY=MEDIUM"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_approval_file_cleans_up_stale_leaks() {
        // Regression guard: a `tirith check --approval-check` invoked from a
        // terminal (or any caller that doesn't consume the temp file) used to
        // leak `tirith-approval-*.env` into $TEMP forever. The next write must
        // opportunistically remove leaked files older than the TTL — and must
        // NOT touch fresh files (a concurrent hook may still be reading them)
        // or unrelated files.
        use std::fs::File;
        use std::time::{Duration, SystemTime};

        let dir = std::env::temp_dir();

        // Unique-enough suffix so parallel runs of this suite don't interfere.
        let suffix = format!("{}-{}", std::process::id(), rand_token());
        let stale = dir.join(format!("tirith-approval-stale-{suffix}.env"));
        let fresh = dir.join(format!("tirith-approval-fresh-{suffix}.env"));
        let unrelated = dir.join(format!("tirith-other-{suffix}.env"));

        File::create(&stale).expect("stale create");
        File::create(&fresh).expect("fresh create");
        File::create(&unrelated).expect("unrelated create");

        // Backdate the stale file past the TTL.
        let two_hours_ago = SystemTime::now() - Duration::from_secs(7200);
        File::options()
            .write(true)
            .open(&stale)
            .and_then(|f| f.set_modified(two_hours_ago))
            .expect("backdate stale");

        let meta = ApprovalMetadata {
            requires_approval: true,
            timeout_secs: 0,
            fallback: "block".to_string(),
            rule_id: "test".to_string(),
            description: "test".to_string(),
        };
        let new_path = write_approval_file(&meta).expect("write should succeed");

        assert!(!stale.exists(), "stale leak should be cleaned up");
        assert!(fresh.exists(), "fresh file (within TTL) must be left alone");
        assert!(
            unrelated.exists(),
            "unrelated file (wrong prefix) must be left alone"
        );
        assert!(new_path.exists(), "new approval file must exist");

        let _ = std::fs::remove_file(&fresh);
        let _ = std::fs::remove_file(&unrelated);
        let _ = std::fs::remove_file(&new_path);
    }

    fn rand_token() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{nanos:x}")
    }
}

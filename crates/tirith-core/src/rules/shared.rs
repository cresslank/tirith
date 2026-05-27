//! Shared constants and helpers used by multiple rule modules.

/// Environment variable names that carry sensitive credentials.
/// Used by both `command.rs` (SensitiveEnvExport detection) and
/// `credential.rs` (dedup suppression).
pub const SENSITIVE_KEY_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
];

/// The canonical set of "critical" criticality labels recognised by the
/// M8 context / SSH / IaC / container rules. A label outside this set is
/// recorded for operator inventory but never causes the rule to fire.
///
/// Centralising this list avoids the drift hazard from having four
/// independent copies (PR-127 review #7) — adding `p1-staging` here
/// covers every consumer in one edit.
///
/// Matching is case-insensitive and ignores surrounding whitespace.
pub fn is_critical_label(label: &str) -> bool {
    let lower = label.trim().to_lowercase();
    matches!(
        lower.as_str(),
        "critical" | "production" | "prod" | "live" | "p0" | "p1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_critical_label_basic() {
        for s in &["critical", "production", "prod", "live", "p0", "p1"] {
            assert!(is_critical_label(s), "should be critical: {s:?}");
        }
        // Case-insensitive.
        assert!(is_critical_label("Critical"));
        assert!(is_critical_label("PRODUCTION"));
        // Whitespace tolerance.
        assert!(is_critical_label("  prod  "));
        // Non-critical recognised values.
        assert!(!is_critical_label("staging"));
        assert!(!is_critical_label("dev"));
        assert!(!is_critical_label("test"));
        assert!(!is_critical_label("p2"));
        assert!(!is_critical_label(""));
    }
}

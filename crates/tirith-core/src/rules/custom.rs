use regex::Regex;

use crate::custom_rule_dsl::{self, DslEvalContext, WhenClause};
use crate::extract::ScanContext;
use crate::policy::CustomRule;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// The matcher half of a compiled custom rule: a regex (the original path) or a
/// semantic-predicate `when:` clause (M13 ch4 DSL). A rule carries exactly one.
pub enum CompiledMatcher {
    Regex(Regex),
    When(Box<WhenClause>),
}

/// A compiled custom rule ready for matching.
pub struct CompiledCustomRule {
    pub id: String,
    pub matcher: CompiledMatcher,
    pub contexts: Vec<ScanContext>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
}

impl CompiledCustomRule {
    /// `true` when this rule's matcher is a `when:` clause (DSL rule).
    pub fn is_dsl(&self) -> bool {
        matches!(self.matcher, CompiledMatcher::When(_))
    }
}

/// Parse a rule's declared `context:` strings into [`ScanContext`]s, warning on
/// unknown tokens. Shared by both the regex and DSL compile paths.
fn parse_contexts(rule: &CustomRule) -> Vec<ScanContext> {
    rule.context
        .iter()
        .filter_map(|c| match c.as_str() {
            "exec" => Some(ScanContext::Exec),
            "paste" => Some(ScanContext::Paste),
            "file" => Some(ScanContext::FileScan),
            other => {
                eprintln!(
                    "tirith: warning: custom rule '{}' has unknown context: {other}",
                    rule.id
                );
                None
            }
        })
        .collect()
}

/// Compile custom rules from policy. Invalid rules (bad shape, invalid regex,
/// invalid `when:` regex, no valid contexts, or — for DSL rules — predicates
/// whose required trigger groups aren't covered by the declared `context:`) are
/// logged and skipped. This keeps the hot path fail-open: a malformed rule
/// never blocks the user. Strict validation with non-zero exit lives in
/// `tirith rule validate`.
pub fn compile_rules(rules: &[CustomRule]) -> Vec<CompiledCustomRule> {
    let mut compiled = Vec::new();
    for rule in rules {
        // Exactly-one-of pattern/when.
        if let Err(e) = rule.validate_shape() {
            eprintln!("tirith: warning: custom rule '{}' {e}, skipping", rule.id);
            continue;
        }

        let contexts = parse_contexts(rule);
        if contexts.is_empty() {
            eprintln!(
                "tirith: warning: custom rule '{}' has no valid contexts, skipping",
                rule.id
            );
            continue;
        }

        let matcher = if let Some(pattern) = &rule.pattern {
            if pattern.len() > 1024 {
                eprintln!(
                    "tirith: custom rule '{}' pattern too long ({} chars), skipping",
                    rule.id,
                    pattern.len()
                );
                continue;
            }
            match Regex::new(pattern) {
                Ok(r) => CompiledMatcher::Regex(r),
                Err(e) => {
                    eprintln!(
                        "tirith: warning: custom rule '{}' has invalid regex: {e}",
                        rule.id
                    );
                    continue;
                }
            }
        } else if let Some(when) = &rule.when {
            // Validate the clause's regexes up front so a bad inner regex is a
            // skip, not a per-input recompile failure.
            if let Err(e) = custom_rule_dsl::validate_regexes(when) {
                eprintln!(
                    "tirith: warning: custom rule '{}' has invalid when-clause: {e}",
                    rule.id
                );
                continue;
            }
            // Tier-1 invariant: the declared context must cover the clause's
            // required trigger groups, or the predicates can never see their
            // data. Skip (fail-open) on the hot path; `tirith rule validate`
            // reports this as a hard error.
            let required = custom_rule_dsl::required_triggers(when);
            if !required.is_satisfied_by(&contexts) {
                eprintln!(
                    "tirith: warning: custom rule '{}' when-clause needs context [{}] not covered by its declared context, skipping",
                    rule.id,
                    required.describe_unmet(&contexts)
                );
                continue;
            }
            CompiledMatcher::When(Box::new(when.clone()))
        } else {
            // validate_shape already guaranteed one of the two arms above.
            unreachable!("validate_shape guarantees exactly one of pattern/when");
        };

        compiled.push(CompiledCustomRule {
            id: rule.id.clone(),
            matcher,
            contexts,
            severity: rule.severity,
            title: rule.title.clone(),
            description: rule.description.clone(),
        });
    }
    compiled
}

/// Build a [`Finding`] for a matched custom rule (regex or DSL). The
/// `match_detail` is the rule-specific evidence line.
fn make_finding(rule: &CompiledCustomRule, match_detail: String) -> Finding {
    Finding {
        rule_id: RuleId::CustomRuleMatch,
        severity: rule.severity,
        title: rule.title.clone(),
        description: if rule.description.is_empty() {
            format!("Custom rule '{}' matched", rule.id)
        } else {
            rule.description.clone()
        },
        evidence: vec![Evidence::Text {
            detail: match_detail,
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: Some(rule.id.clone()),
    }
}

/// Check input against compiled REGEX custom rules for a given context.
///
/// DSL (`when:`) rules are evaluated separately by [`check_dsl`] (they need the
/// richer extracted data, not a `&str`). A `when:` rule never matches here.
pub fn check(input: &str, context: ScanContext, compiled: &[CompiledCustomRule]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in compiled {
        if !rule.contexts.contains(&context) {
            continue;
        }
        let CompiledMatcher::Regex(regex) = &rule.matcher else {
            continue;
        };

        if let Some(m) = regex.find(input) {
            let matched_text = m.as_str();
            let preview: String = matched_text.chars().take(100).collect();
            findings.push(make_finding(rule, format!("Matched: \"{preview}\"")));
        }
    }

    findings
}

/// Evaluate compiled DSL (`when:`) custom rules against the extracted analysis
/// data for a given context. Regex rules are skipped here (see [`check`]).
///
/// A finding fires (reusing [`RuleId::CustomRuleMatch`], like the regex path)
/// when the clause matches AND `context` is in the rule's declared contexts.
pub fn check_dsl(
    ctx: &DslEvalContext,
    context: ScanContext,
    compiled: &[CompiledCustomRule],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in compiled {
        if !rule.contexts.contains(&context) {
            continue;
        }
        let CompiledMatcher::When(clause) = &rule.matcher else {
            continue;
        };

        if custom_rule_dsl::evaluate(clause, ctx) {
            findings.push(make_finding(
                rule,
                format!("when-clause matched (rule '{}')", rule.id),
            ));
        }
    }

    findings
}

/// `true` when any compiled rule is a DSL (`when:`) rule. Lets the engine skip
/// building a [`DslEvalContext`] entirely on the common regex-only path.
pub fn any_dsl_rules(compiled: &[CompiledCustomRule]) -> bool {
    compiled.iter().any(|r| r.is_dsl())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, pattern: &str, contexts: &[&str]) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            pattern: Some(pattern.to_string()),
            when: None,
            context: contexts.iter().map(|s| s.to_string()).collect(),
            severity: Severity::High,
            title: format!("Test rule: {id}"),
            description: String::new(),
            action: None,
        }
    }

    fn make_dsl_rule(id: &str, when: WhenClause, contexts: &[&str]) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            pattern: None,
            when: Some(when),
            context: contexts.iter().map(|s| s.to_string()).collect(),
            severity: Severity::Critical,
            title: format!("DSL rule: {id}"),
            description: String::new(),
            action: None,
        }
    }

    #[test]
    fn test_compile_valid_rule() {
        let rules = vec![make_rule("test1", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].id, "test1");
        assert!(!compiled[0].is_dsl());
    }

    #[test]
    fn test_compile_invalid_regex_skipped() {
        let rules = vec![make_rule("bad", r"(unclosed", &["exec"])];
        let compiled = compile_rules(&rules);
        assert_eq!(compiled.len(), 0);
    }

    #[test]
    fn test_check_matches_in_context() {
        let rules = vec![make_rule(
            "corp",
            r"internal\.corp\.example\.com",
            &["exec"],
        )];
        let compiled = compile_rules(&rules);

        let findings = check(
            "curl https://internal.corp.example.com/api",
            ScanContext::Exec,
            &compiled,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CustomRuleMatch);
        assert_eq!(findings[0].custom_rule_id.as_deref(), Some("corp"));
    }

    #[test]
    fn test_check_no_match_wrong_context() {
        let rules = vec![make_rule("corp", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);

        let findings = check("internal.corp.example.com", ScanContext::Paste, &compiled);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_check_no_match_when_pattern_absent() {
        let rules = vec![make_rule("corp", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);

        let findings = check("curl https://example.com", ScanContext::Exec, &compiled);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_compile_skips_rule_with_both_pattern_and_when() {
        let mut rule = make_rule("both", r"x", &["exec"]);
        rule.when = Some(WhenClause::CommandUsesSudo(true));
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "rule with both pattern and when is skipped"
        );
    }

    #[test]
    fn test_compile_skips_rule_with_neither() {
        let mut rule = make_rule("neither", r"x", &["exec"]);
        rule.pattern = None;
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "rule with neither pattern nor when is skipped"
        );
    }

    #[test]
    fn test_compile_dsl_rule() {
        let rule = make_dsl_rule("dsl1", WhenClause::CommandUsesSudo(true), &["exec"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(compiled.len(), 1);
        assert!(compiled[0].is_dsl());
        assert!(any_dsl_rules(&compiled));
    }

    #[test]
    fn test_compile_dsl_rule_context_mismatch_skipped() {
        // command.* needs exec OR paste (round-3 R3-1), but the rule declares
        // only `file` — the FileScan path never extracts command facts, so the
        // predicate could never see its data and the rule is skipped.
        let rule = make_dsl_rule("mismatch", WhenClause::CommandUsesSudo(true), &["file"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "DSL rule needing exec/paste but declaring only file is skipped"
        );
    }

    #[test]
    fn test_compile_dsl_command_rule_paste_context_compiles() {
        // Regression (CodeRabbit M13 round-3 R3-1): a `command.*` rule declared
        // under `paste` must now COMPILE — `build_dsl_backing` fills command
        // facts for paste, so the predicate is live. The round-1/2 narrowing to
        // exec-only wrongly dropped it.
        let rule = make_dsl_rule("paste-cmd", WhenClause::CommandUsesSudo(true), &["paste"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            1,
            "DSL command rule under paste must compile (round-3 R3-1)"
        );
        assert!(compiled[0].is_dsl());
    }

    #[test]
    fn test_check_dsl_fires_in_context() {
        let rule = make_dsl_rule("sudo-rule", WhenClause::CommandUsesSudo(true), &["exec"]);
        let compiled = compile_rules(&[rule]);

        let ctx = DslEvalContext {
            uses_sudo: true,
            ..Default::default()
        };
        let findings = check_dsl(&ctx, ScanContext::Exec, &compiled);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CustomRuleMatch);
        assert_eq!(findings[0].custom_rule_id.as_deref(), Some("sudo-rule"));

        // Wrong context -> no fire.
        let none = check_dsl(&ctx, ScanContext::Paste, &compiled);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_regex_check_ignores_dsl_rules() {
        let rule = make_dsl_rule("dsl-only", WhenClause::CommandUsesSudo(true), &["exec"]);
        let compiled = compile_rules(&[rule]);
        // The regex `check` path must never match a DSL rule.
        let findings = check("sudo anything", ScanContext::Exec, &compiled);
        assert_eq!(findings.len(), 0);
    }
}

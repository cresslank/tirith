//! M13 ch4 — `tirith rule test|validate|explain` (the custom-rule DSL CLI).
//!
//! These commands operate on the custom rules declared in `.tirith/policy.yaml`
//! (`custom_rules:`), which carry EITHER a `pattern:` regex or a `when:`
//! semantic-predicate clause (the M13 ch4 DSL — [`tirith_core::custom_rule_dsl`]).
//!
//! * `test`    — evaluate one named rule against a `--input` and report FIRES /
//!   does-not-fire. The DSL eval context is built from the SAME extraction the
//!   engine runs ([`tirith_core::engine::dsl_backing_for_input`]), so a test
//!   matches production.
//! * `validate`— check every custom rule: exactly-one-of pattern/when,
//!   well-formed predicates/regexes, and the tier-1 invariant (the declared
//!   `context:` must cover the clause's required trigger groups). Exit 0 if all
//!   valid, 1 otherwise.
//! * `explain` — print one rule's predicate tree, severity, action and context.
//!
//! Scope vs `tirith policy validate`: that command validates the WHOLE policy
//! FILE structure (every key, allowlist/blocklist coherence, …). `tirith rule
//! validate` is the focused custom-rule-DSL checker — it reports the same
//! custom-rule errors but only those, with rule-id locations.

use tirith_core::custom_rule_dsl::{self, Reputation, WhenClause};
use tirith_core::extract::ScanContext;
use tirith_core::policy::{CustomRule, Policy};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

use super::write_json_stdout;

/// Resolve `--shell` to a [`ShellType`], defaulting to POSIX on an unknown
/// value (matching `tirith check`'s lenient shell handling).
fn resolve_shell(shell: &str) -> ShellType {
    shell.parse::<ShellType>().unwrap_or(ShellType::Posix)
}

/// Parse a rule's declared `context:` strings into [`ScanContext`]s.
fn declared_contexts(rule: &CustomRule) -> Vec<ScanContext> {
    rule.context
        .iter()
        .filter_map(|c| match c.as_str() {
            "exec" => Some(ScanContext::Exec),
            "paste" => Some(ScanContext::Paste),
            "file" => Some(ScanContext::FileScan),
            _ => None,
        })
        .collect()
}

fn scan_context_for_shell_input(rule: &CustomRule) -> ScanContext {
    // Prefer the rule's first declared exec/paste context for a command input;
    // a file-only rule tests in FileScan. This picks the context the engine
    // would actually evaluate the rule in for a typed command.
    let declared = declared_contexts(rule);
    if declared.contains(&ScanContext::Exec) {
        ScanContext::Exec
    } else if declared.contains(&ScanContext::Paste) {
        ScanContext::Paste
    } else if declared.contains(&ScanContext::FileScan) {
        ScanContext::FileScan
    } else {
        ScanContext::Exec
    }
}

/// `tirith rule test --rule <id> --input <s>` — evaluate one custom rule
/// against an input and report whether it FIRES.
pub fn test(rule_id: &str, input: &str, shell: &str, json: bool) -> i32 {
    let policy = Policy::discover(None);
    let rule = match policy.custom_rules.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_not_found("test", rule_id, &policy, json);
        }
    };

    let shell_type = resolve_shell(shell);
    let context = scan_context_for_shell_input(rule);

    let (fires, kind) = if let Some(when) = &rule.when {
        // DSL rule: build the eval context exactly as the engine does.
        let backing = tirith_core::engine::dsl_backing_for_input(input, shell_type, context);
        // `cwd_in` is evaluated against the process cwd (what the engine sees);
        // `file.path_matches` against `--input` treated as a path in FileScan.
        let cwd = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let file_path = if context == ScanContext::FileScan {
            Some(input.to_string())
        } else {
            None
        };
        let eval_ctx = backing.as_eval_context(cwd.as_deref(), file_path.as_deref());
        (custom_rule_dsl::evaluate(when, &eval_ctx), "when")
    } else if let Some(pattern) = &rule.pattern {
        // Regex rule: match the pattern against the input, mirroring the
        // engine's `rules::custom::check`.
        let fires = match regex::Regex::new(pattern) {
            Ok(re) => re.is_match(input),
            Err(e) => {
                return emit_error(
                    "test",
                    &format!("rule '{rule_id}' has invalid regex: {e}"),
                    json,
                );
            }
        };
        (fires, "pattern")
    } else {
        return emit_error(
            "test",
            &format!("rule '{rule_id}' has neither `pattern:` nor `when:`"),
            json,
        );
    };

    if json {
        let v = serde_json::json!({
            "rule": rule_id,
            "kind": kind,
            "context": scan_context_name(context),
            "fires": fires,
        });
        if !write_json_stdout(&v, "tirith rule test: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    if fires {
        println!(
            "FIRES: rule '{rule_id}' matches the input ({kind}, context {}).",
            scan_context_name(context)
        );
    } else {
        println!(
            "does not fire: rule '{rule_id}' does not match the input ({kind}, context {}).",
            scan_context_name(context)
        );
    }
    0
}

/// `tirith rule validate [--path <file>]` — validate every custom rule.
///
/// Exit 0 when all custom rules are valid; 1 when any is invalid (with the
/// offending rule id + reason). Cross-references `tirith policy validate` for
/// whole-file checks.
pub fn validate(path: Option<&str>, json: bool) -> i32 {
    let (policy, source) = match load_policy(path) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    let mut errors: Vec<RuleError> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for rule in &policy.custom_rules {
        if !seen.insert(rule.id.clone()) {
            errors.push(RuleError {
                rule: rule.id.clone(),
                message: "duplicate rule id".to_string(),
            });
        }

        // Exactly-one-of pattern/when.
        if let Err(e) = rule.validate_shape() {
            errors.push(RuleError {
                rule: rule.id.clone(),
                message: e.to_string(),
            });
            continue;
        }

        // Contexts must be known tokens.
        for c in &rule.context {
            if !matches!(c.as_str(), "exec" | "paste" | "file") {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: format!("unknown context '{c}' (valid: exec, paste, file)"),
                });
            }
        }

        if let Some(pattern) = &rule.pattern {
            if let Err(e) = regex::Regex::new(pattern) {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: format!("invalid regex: {e}"),
                });
            }
        }

        if let Some(when) = &rule.when {
            if let Err(e) = custom_rule_dsl::validate_regexes(when) {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: e,
                });
            }
            // Tier-1 invariant: the declared context must cover the clause's
            // required trigger groups — reject a DSL rule whose predicates map
            // to no declared trigger group.
            let declared = declared_contexts(rule);
            let required = custom_rule_dsl::required_triggers(when);
            if declared.is_empty() {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: "no valid context declared".to_string(),
                });
            } else if !required.is_satisfied_by(&declared) {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: format!(
                        "when-clause needs context [{}] not covered by declared context {:?}",
                        required.describe_unmet(&declared),
                        rule.context
                    ),
                });
            }
        }
    }

    let total = policy.custom_rules.len();
    if json {
        let v = serde_json::json!({
            "source": source,
            "valid": errors.is_empty(),
            "rule_count": total,
            "error_count": errors.len(),
            "errors": errors.iter().map(|e| serde_json::json!({
                "rule": e.rule,
                "message": e.message,
            })).collect::<Vec<_>>(),
        });
        if !write_json_stdout(&v, "tirith rule validate: failed to write JSON output") {
            return 2;
        }
        return if errors.is_empty() { 0 } else { 1 };
    }

    if errors.is_empty() {
        eprintln!("tirith rule validate: {source} — {total} custom rule(s), all valid");
        0
    } else {
        eprintln!(
            "tirith rule validate: {source} — {} error(s) in {total} custom rule(s):",
            errors.len()
        );
        for e in &errors {
            eprintln!("  custom_rules.{}: {}", e.rule, e.message);
        }
        eprintln!();
        eprintln!("(for whole-policy-file checks, run `tirith policy validate`)");
        1
    }
}

/// `tirith rule explain --rule <id>` — print a rule's predicate tree, severity,
/// action and context.
pub fn explain(rule_id: &str, json: bool) -> i32 {
    let policy = Policy::discover(None);
    let rule = match policy.custom_rules.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_not_found("explain", rule_id, &policy, json);
        }
    };

    // Effective action: a rule's declared `action:` is recorded metadata; the
    // engine derives the effective action from `severity` (a Critical finding
    // blocks, Medium warns, …). Report both so the operator sees what runs.
    let effective = action_for_severity(rule.severity);

    if json {
        let tree = rule.when.as_ref().map(clause_to_json);
        let v = serde_json::json!({
            "rule": rule.id,
            "kind": if rule.when.is_some() { "when" } else { "pattern" },
            "severity": rule.severity.to_string(),
            "declared_action": rule.action.map(action_name),
            "effective_action": action_name(effective),
            "context": rule.context,
            "title": rule.title,
            "description": rule.description,
            "pattern": rule.pattern,
            "when": tree,
        });
        if !write_json_stdout(&v, "tirith rule explain: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    println!("Custom rule: {}", rule.id);
    println!("  title:    {}", rule.title);
    if !rule.description.is_empty() {
        println!("  detail:   {}", rule.description);
    }
    println!("  severity: {}", rule.severity);
    match rule.action {
        Some(a) => println!(
            "  action:   {} (declared) — effective {} (derived from severity)",
            action_name(a),
            action_name(effective)
        ),
        None => println!(
            "  action:   {} (derived from severity)",
            action_name(effective)
        ),
    }
    println!("  context:  {}", rule.context.join(", "));
    println!();
    if let Some(pattern) = &rule.pattern {
        println!("  matcher:  regex");
        println!("    {pattern}");
    } else if let Some(when) = &rule.when {
        println!("  matcher:  when-clause (semantic predicates)");
        print_clause(when, 2);
    }
    0
}

// ---- shared helpers ----

struct RuleError {
    rule: String,
    message: String,
}

/// Load the policy for validation: from `--path` (read the file directly) or
/// the discovered local policy. Returns `(policy, source-label)`.
fn load_policy(path: Option<&str>) -> Result<(Policy, String), i32> {
    if let Some(p) = path {
        let yaml = match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tirith rule validate: cannot read {p}: {e}");
                return Err(1);
            }
        };
        // try_parse_yaml surfaces a parse error rather than warn-and-defaulting,
        // so a malformed `when:` is reported as exit 1 with the YAML location.
        match Policy::try_parse_yaml(&yaml) {
            Ok(policy) => Ok((policy, p.to_string())),
            Err(e) => {
                eprintln!("tirith rule validate: {p}: {e}");
                Err(1)
            }
        }
    } else {
        match tirith_core::policy::discover_local_policy_path(None) {
            Some(found) => {
                let yaml = match std::fs::read_to_string(&found) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("tirith rule validate: cannot read {}: {e}", found.display());
                        return Err(1);
                    }
                };
                match Policy::try_parse_yaml(&yaml) {
                    Ok(policy) => Ok((policy, found.display().to_string())),
                    Err(e) => {
                        eprintln!("tirith rule validate: {}: {e}", found.display());
                        Err(1)
                    }
                }
            }
            // No policy file at all — the default policy has zero custom rules,
            // which is trivially valid (matches the shipping/no-policy case).
            None => Ok((Policy::default(), "<no policy file>".to_string())),
        }
    }
}

fn emit_not_found(cmd: &str, rule_id: &str, policy: &Policy, json: bool) -> i32 {
    if json {
        let v = serde_json::json!({
            "error": format!("no custom rule named '{rule_id}'"),
            "available": policy.custom_rules.iter().map(|r| &r.id).collect::<Vec<_>>(),
        });
        let _ = write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        );
        return 1;
    }
    eprintln!("tirith rule {cmd}: no custom rule named '{rule_id}'");
    if policy.custom_rules.is_empty() {
        eprintln!("  (no custom_rules declared in policy; add one to .tirith/policy.yaml)");
    } else {
        eprintln!("  available rules:");
        for r in &policy.custom_rules {
            eprintln!("    {}", r.id);
        }
    }
    1
}

fn emit_error(cmd: &str, msg: &str, json: bool) -> i32 {
    if json {
        let v = serde_json::json!({ "error": msg });
        let _ = write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        );
    } else {
        eprintln!("tirith rule {cmd}: {msg}");
    }
    1
}

fn scan_context_name(c: ScanContext) -> &'static str {
    match c {
        ScanContext::Exec => "exec",
        ScanContext::Paste => "paste",
        ScanContext::FileScan => "file",
    }
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Warn => "warn",
        Action::Block => "block",
        Action::WarnAck => "warn_ack",
    }
}

/// Mirror [`tirith_core::verdict::action_from_findings`]'s severity→action map
/// for a single finding's severity (Critical/High → block, Medium → warn,
/// Low/Info → allow), so `explain` reports the action the rule actually drives.
fn action_for_severity(sev: tirith_core::verdict::Severity) -> Action {
    use tirith_core::verdict::Severity;
    match sev {
        Severity::Critical | Severity::High => Action::Block,
        Severity::Medium => Action::Warn,
        Severity::Low | Severity::Info => Action::Allow,
    }
}

/// Pretty-print a `when:` clause as an indented predicate tree.
fn print_clause(clause: &WhenClause, indent: usize) {
    let pad = "  ".repeat(indent);
    match clause {
        WhenClause::All(cs) => {
            println!("{pad}all:");
            for c in cs {
                print_clause(c, indent + 1);
            }
        }
        WhenClause::Any(cs) => {
            println!("{pad}any:");
            for c in cs {
                print_clause(c, indent + 1);
            }
        }
        WhenClause::Not(c) => {
            println!("{pad}not:");
            print_clause(c, indent + 1);
        }
        leaf => println!("{pad}{}", leaf_to_line(leaf)),
    }
}

/// One-line rendering of a leaf predicate.
fn leaf_to_line(leaf: &WhenClause) -> String {
    let key = leaf.key();
    match leaf {
        WhenClause::CommandHasPipelineTo(v)
        | WhenClause::CommandCwdIn(v)
        | WhenClause::UrlDomainNotIn(v) => format!("{key}: [{}]", v.join(", ")),
        WhenClause::CommandUsesSudo(b) => format!("{key}: {b}"),
        WhenClause::UrlHost(s)
        | WhenClause::UrlHostMatches(s)
        | WhenClause::UrlScheme(s)
        | WhenClause::PackageEcosystem(s)
        | WhenClause::PackageNameMatches(s)
        | WhenClause::FilePathMatches(s)
        | WhenClause::AgentKind(s)
        | WhenClause::McpTool(s) => format!("{key}: {s}"),
        WhenClause::UrlReputation(r) | WhenClause::PackageReputation(r) => {
            format!("{key}: {}", reputation_name(r))
        }
        // All/Any/Not are handled by print_clause; render compactly if reached.
        WhenClause::All(_) | WhenClause::Any(_) | WhenClause::Not(_) => key.to_string(),
    }
}

fn reputation_name(r: &Reputation) -> &'static str {
    match r {
        Reputation::Known => "known",
        Reputation::Unknown => "unknown",
        Reputation::Malicious => "malicious",
    }
}

/// Recursively render a `when:` clause as JSON for `--json` explain.
fn clause_to_json(clause: &WhenClause) -> serde_json::Value {
    match clause {
        WhenClause::All(cs) => {
            serde_json::json!({ "all": cs.iter().map(clause_to_json).collect::<Vec<_>>() })
        }
        WhenClause::Any(cs) => {
            serde_json::json!({ "any": cs.iter().map(clause_to_json).collect::<Vec<_>>() })
        }
        WhenClause::Not(c) => serde_json::json!({ "not": clause_to_json(c) }),
        leaf => serde_json::json!({ leaf.key(): leaf_value_json(leaf) }),
    }
}

fn leaf_value_json(leaf: &WhenClause) -> serde_json::Value {
    match leaf {
        WhenClause::CommandHasPipelineTo(v)
        | WhenClause::CommandCwdIn(v)
        | WhenClause::UrlDomainNotIn(v) => serde_json::json!(v),
        WhenClause::CommandUsesSudo(b) => serde_json::json!(b),
        WhenClause::UrlHost(s)
        | WhenClause::UrlHostMatches(s)
        | WhenClause::UrlScheme(s)
        | WhenClause::PackageEcosystem(s)
        | WhenClause::PackageNameMatches(s)
        | WhenClause::FilePathMatches(s)
        | WhenClause::AgentKind(s)
        | WhenClause::McpTool(s) => serde_json::json!(s),
        WhenClause::UrlReputation(r) | WhenClause::PackageReputation(r) => {
            serde_json::json!(reputation_name(r))
        }
        WhenClause::All(_) | WhenClause::Any(_) | WhenClause::Not(_) => serde_json::Value::Null,
    }
}

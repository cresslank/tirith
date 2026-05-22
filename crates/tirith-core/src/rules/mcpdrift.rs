//! MCP lockfile drift detection — file-content rule that fires when the
//! committed `.tirith/mcp.lock` no longer matches the repository's current
//! MCP-server inventory.
//!
//! This is the FileScan-path counterpart to `tirith mcp verify`. When
//! `tirith scan` walks the repository and reaches `.tirith/mcp.lock`, this
//! module parses the lockfile's recorded inventory, rebuilds the current
//! inventory from the repo's MCP config files, and emits
//! [`RuleId::McpServerDrift`] when the two differ. A pre-commit hook / CI
//! integration that runs `tirith scan` therefore catches MCP drift the same
//! way it catches an un-pinned action or a smuggled instruction.
//!
//! It runs only on the `tirith scan` FileScan path — never the exec hot
//! path — so a tier-1 PATTERN_TABLE entry is not required for reachability
//! (`tier1_scan` always returns `true` for FileScan, see `extract.rs`). The
//! module self-selects by path: only the `.tirith/mcp.lock` *target* of a
//! file scan ever triggers the inventory rebuild, so an arbitrary file with
//! the basename `mcp.lock` outside `.tirith/` is not misclassified.
//!
//! **Privacy.** The fired finding's description and evidence carry only
//! aggregate change counts and a server's *name* — never an env value, a URL
//! userinfo string, or a hash. The lockfile already strips those (see
//! `mcp_lock.rs`); this module observes the *hash* changed, never the
//! underlying secret.
//!
//! **Malformed input is never fatal.** A `.tirith/mcp.lock` that does not
//! parse, an unreadable repo root, or an inventory rebuild that fails (a
//! malformed config inside the repo) yields zero findings rather than a
//! panic — the same convention `configfile` / `cifile` / `aifile` follow.

use std::path::Path;

use crate::mcp_lock;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// `true` when `path` is the `.tirith/mcp.lock` file this rule scans.
///
/// Requires the path's basename to be `mcp.lock` AND its immediate parent
/// directory to be named `.tirith` — exactly the location
/// `tirith mcp lock` writes. A loose `mcp.lock` anywhere else in the repo is
/// not this lockfile.
pub fn is_mcp_lockfile(path: Option<&Path>) -> bool {
    let Some(path) = path else { return false };

    let Some(basename) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if basename != mcp_lock::MCP_LOCK_FILENAME {
        return false;
    }

    let Some(parent) = path.parent() else {
        return false;
    };
    parent
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == ".tirith")
        .unwrap_or(false)
}

/// Run the MCP-drift rule against a file's contents.
///
/// `file_path` must be the absolute or relative path the scan walked — the
/// repo root is derived from it (`<repo>/.tirith/mcp.lock` → `<repo>`).
/// A path that is not the lockfile, or for which the repo root cannot be
/// derived, yields no findings.
///
/// `content` is the file's textual contents as the scan read them; the
/// lockfile is JSON, so a non-UTF8 body simply fails to parse and yields
/// no findings.
pub fn check(content: &str, file_path: Option<&Path>) -> Vec<Finding> {
    if !is_mcp_lockfile(file_path) {
        return Vec::new();
    }

    // Parse the lockfile. A malformed lockfile is not this rule's concern —
    // the `tirith mcp verify` command and the `mcp lock` writer own that
    // surface; here we silently skip.
    let lockfile = match mcp_lock::parse_lockfile(content) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };

    // Derive the repo root: `<repo>/.tirith/mcp.lock` → `<repo>`.
    let Some(repo_root) = file_path.and_then(|p| p.parent()).and_then(|p| p.parent()) else {
        return Vec::new();
    };

    // Build the current inventory off of the repo root. `build_inventory` is
    // total (a malformed config contributes no entries) so this cannot panic
    // or error.
    let current = mcp_lock::build_inventory(repo_root);

    let drifts = mcp_lock::compute_drift(&current, &lockfile);
    if drifts.is_empty() {
        return Vec::new();
    }

    vec![finding_for_drift(&drifts)]
}

/// Build the single drift finding from the structured drift list.
///
/// Aggregates by drift kind so the description fits in one line: "N added,
/// M removed, K changed". The first few server names are listed for
/// orientation; the full structured drift is the domain of
/// `tirith mcp verify --format json`, not the scan finding.
fn finding_for_drift(drifts: &[mcp_lock::McpDrift]) -> Finding {
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    let mut names: Vec<String> = Vec::new();
    for d in drifts {
        match d {
            mcp_lock::McpDrift::Added { .. } => added += 1,
            mcp_lock::McpDrift::Removed { .. } => removed += 1,
            mcp_lock::McpDrift::Changed(_) => changed += 1,
        }
        if names.len() < 5 {
            names.push(d.name().to_string());
        }
    }

    let summary =
        format!("{added} added, {removed} removed, {changed} changed since the lockfile was taken");
    let mut detail = format!("MCP inventory drift: {summary}.");
    if !names.is_empty() {
        let listed: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
        let suffix = if drifts.len() > names.len() {
            format!(" first servers: {} …", listed.join(", "))
        } else {
            format!(" servers: {}", listed.join(", "))
        };
        detail.push_str(&suffix);
    }

    Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::Medium,
        title: "MCP server inventory has drifted from the committed lockfile".to_string(),
        description: format!(
            "The MCP servers declared in this repository's configuration files no longer \
             match `.tirith/mcp.lock` ({summary}). The change may be intentional — but it \
             is a security-relevant surface change (a server added, removed, or its \
             transport / env / declared tools / URL credentials altered) and should be \
             reviewed before commit. Run `tirith mcp diff` (informational) or \
             `tirith mcp verify` (gating) to see the exact drift, then re-run \
             `tirith mcp lock` to refresh the lockfile."
        ),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    use crate::mcp_lock::{McpEnvEntry, McpInventory, McpLockfile, McpServerEntry, McpTransport};

    fn write_lockfile_for(repo: &Path, inv: &McpInventory) {
        let lockdir = repo.join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(
            lockdir.join("mcp.lock"),
            McpLockfile::from_inventory(inv).render(),
        )
        .unwrap();
    }

    fn write_config(repo: &Path, name: &str, body: &str) {
        if let Some(parent) = Path::new(name).parent() {
            fs::create_dir_all(repo.join(parent)).unwrap();
        }
        fs::write(repo.join(name), body).unwrap();
    }

    #[test]
    fn is_mcp_lockfile_matches_exact_layout() {
        assert!(is_mcp_lockfile(Some(&PathBuf::from(".tirith/mcp.lock"))));
        assert!(is_mcp_lockfile(Some(&PathBuf::from(
            "/abs/repo/.tirith/mcp.lock"
        ))));
        // Wrong parent dir.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from("subdir/mcp.lock"))));
        // Wrong basename.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from(
            ".tirith/policy.yaml"
        ))));
        // No parent.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from("mcp.lock"))));
        // No path.
        assert!(!is_mcp_lockfile(None));
    }

    #[test]
    fn check_returns_empty_on_non_lockfile_path() {
        // A file with the right name elsewhere must not trigger.
        let v = check(
            r#"{"format_version":4,"inventory_hash":"x","configs":[],"servers":[]}"#,
            Some(&PathBuf::from("subdir/mcp.lock")),
        );
        assert!(v.is_empty());
    }

    #[test]
    fn check_returns_empty_when_inventory_matches_lockfile() {
        // A clean repo: the lockfile we wrote matches the inventory the
        // scan will compute. No drift, no finding.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path));
        assert!(findings.is_empty(), "no drift → no finding: {findings:?}");
    }

    #[test]
    fn check_fires_when_server_added_to_config_after_lockfile() {
        // Step 1: a repo with one MCP server, lockfile committed.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "a": { "command": "node" } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Step 2: the user adds a second MCP server to .mcp.json (so the
        // config drifted from the lockfile).
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "a": { "command": "node" },
                "b": { "command": "deno" }
            } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::McpServerDrift);
        assert_eq!(findings[0].severity, Severity::Medium);
        // The aggregated summary mentions the addition.
        assert!(findings[0].description.contains("1 added"));
    }

    #[test]
    fn check_fires_when_env_value_rotated() {
        // Headline integration of the env-value-hash drift signal: a
        // rotated credential surfaces as a finding when scanning the
        // (now-stale) lockfile.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "old-credential" } } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // The user rotates the token.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "new-credential" } } } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("1 changed"));

        // And no raw credential bytes appear in the finding.
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("old-credential"));
        assert!(!serialized.contains("new-credential"));
    }

    #[test]
    fn check_skips_unparseable_lockfile_quietly() {
        // A malformed lockfile is not this rule's concern.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(lockdir.join("mcp.lock"), "{not json").unwrap();

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path));
        assert!(findings.is_empty(), "malformed lockfile → no finding");
    }

    #[test]
    fn check_handles_lockfile_that_describes_url_userinfo_change() {
        // Lockfile records a URL with userinfo; the config changes to a
        // different userinfo. Drift fires, and the credential never appears
        // in the finding text.
        let repo = tempdir().unwrap();
        // Inventory in the lockfile: URL with userinfo "old:secretA".
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Url {
                    url: "https://host.example/sse".into(),
                    userinfo_hash: Some(
                        // Doesn't matter that this is a placeholder — the
                        // current side derives a different hash from the
                        // config and the two won't compare equal.
                        "0000000000000000000000000000000000000000000000000000000000000000".into(),
                    ),
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        write_lockfile_for(repo.path(), &inv);
        // Current config: URL with userinfo "rotated:newcredential" — a
        // distinctive value we can substring-scan for absence below.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "url": "https://rotated:newcredential@host.example/sse" } } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path));
        assert_eq!(findings.len(), 1);
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains("rotated:newcredential"),
            "raw URL userinfo leaked into the finding: {serialized}"
        );
    }

    #[test]
    fn check_returns_empty_when_no_lockfile_layout() {
        // Path has parent and grandparent but is not `<x>/.tirith/mcp.lock`.
        let path = PathBuf::from("some/other/mcp.lock");
        let findings = check(
            r#"{"format_version":4,"inventory_hash":"x","configs":[],"servers":[]}"#,
            Some(&path),
        );
        assert!(findings.is_empty());
    }

    // Keep an unused import quiet on the import block when compiling in
    // release mode. The constructor is referenced via build helpers above.
    #[allow(dead_code)]
    fn _ensure_imports_used() {
        let _e: McpEnvEntry = McpEnvEntry::from_raw("X", "y");
    }
}

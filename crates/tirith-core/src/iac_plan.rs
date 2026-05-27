//! IaC plan parsing and hashing — M8 ch3.
//!
//! Two responsibilities, deliberately separated from the hot path:
//!
//! 1. **Plan parsing.** `parse_plan_json` accepts a byte buffer holding the
//!    output of `terraform show -json tfplan` (also produced by
//!    `pulumi preview --json`, which uses the same `resource_changes`
//!    shape for the per-resource list, and by `tofu show -json`). Counts
//!    create / update / destroy and flags IAM / SG / public-bucket /
//!    DB / LB changes against a curated heuristic table. The heuristic
//!    is intentionally narrow — false positives here drive operator
//!    noise but missing categories are easy to add.
//!
//! 2. **Plan hashing + cache.** `record_plan_hash` writes
//!    `state_dir()/iac_plans/<sha256>.json` with a short metadata blob,
//!    `plan_hash_recorded` checks for membership, and `purge_old_plans`
//!    drops files older than the configured TTL (7d by default).
//!
//! Shell-out to `terraform show -json` happens ONLY from the
//! `tirith iac check-plan` CLI path via [`run_terraform_show_json`].
//! The engine hot path never calls these helpers — it consults
//! `plan_hash_recorded` directly with the byte content of the plan file.
//! `run_terraform_show_json` uses the same hard-timeout watchdog pattern
//! as `crate::context_detect::run_with_timeout` with a 5s budget (plans
//! can be large; the 1.5s context-detect cap is too tight here).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

/// Hard wall-clock cap for the `terraform show -json` / `tofu show -json`
/// shell-out. Plans can be large; we generously cap at 5s so a real plan
/// has time to render. The hot path NEVER calls this.
pub const TERRAFORM_SHOW_TIMEOUT: Duration = Duration::from_secs(5);

/// Stored plans older than this are dropped by [`purge_old_plans`].
pub const PLAN_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Maximum size we will read into memory for a plan file or its JSON
/// rendering. Terraform plan-JSON outputs can be several MiB for large
/// estates; 32 MiB is a safe upper bound for a CLI-driven flow.
pub const MAX_PLAN_SIZE_BYTES: u64 = 32 * 1024 * 1024;

/// Per-resource change counts plus the curated high-risk flags.
///
/// `total_changes` is the sum of `create + update + destroy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummary {
    /// Tool detected by the parser. `terraform` is the default for the
    /// shared JSON shape; `pulumi` is set when the input has the
    /// `steps` shape from `pulumi preview --json`.
    #[serde(default)]
    pub tool: PlanTool,
    /// Number of resources created.
    pub create: usize,
    /// Number of resources updated.
    pub update: usize,
    /// Number of resources destroyed.
    pub destroy: usize,
    /// `create + update + destroy`.
    pub total_changes: usize,
    /// Resource addresses that fall in the IAM category
    /// (`aws_iam_*`, `google_project_iam_*`, `azurerm_role_*`,
    /// `kubernetes_cluster_role*`, etc.).
    pub iam_changes: Vec<String>,
    /// Resource addresses that touch security groups
    /// (`aws_security_group*`, `google_compute_firewall*`, etc.).
    pub security_group_changes: Vec<String>,
    /// Resource addresses that grant public bucket access
    /// (`aws_s3_bucket_public_access_block`,
    /// `aws_s3_bucket_acl`, `google_storage_bucket_iam_member` with
    /// `allUsers`, etc.).
    pub public_bucket_changes: Vec<String>,
    /// Resource addresses that touch DB / cluster instances
    /// (`aws_db_instance`, `aws_rds_cluster`, `google_sql_database_instance`).
    pub db_changes: Vec<String>,
    /// Resource addresses that touch load balancers
    /// (`aws_lb`, `aws_alb`, `google_compute_forwarding_rule`).
    pub lb_changes: Vec<String>,
}

impl PlanSummary {
    /// `true` if any high-risk category is non-empty.
    pub fn has_high_risk_changes(&self) -> bool {
        !self.iam_changes.is_empty()
            || !self.security_group_changes.is_empty()
            || !self.public_bucket_changes.is_empty()
            || !self.db_changes.is_empty()
            || !self.lb_changes.is_empty()
    }
}

/// Which tool emitted the plan JSON. Used in evidence strings and the
/// recorded metadata blob.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTool {
    #[default]
    Terraform,
    Pulumi,
    Tofu,
}

impl PlanTool {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Pulumi => "pulumi",
            Self::Tofu => "tofu",
        }
    }
}

/// Parse a plan-JSON byte buffer into a [`PlanSummary`].
///
/// Supports two shapes:
///   1. Terraform / OpenTofu — `{ "resource_changes": [...] }`. Each entry
///      has a `change.actions: [create|update|delete|noop]` array and an
///      `address` / `type` string.
///   2. Pulumi — `{ "steps": [...] }`. Each step has `op` (`create`,
///      `update`, `delete`) and `urn` (`urn:pulumi:stack::project::type::name`).
///
/// Any other shape returns `Err`. The caller (`tirith iac check-plan`)
/// surfaces the error to the operator without panicking.
pub fn parse_plan_json(bytes: &[u8]) -> Result<PlanSummary, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("json parse error: {e}"))?;

    if value.get("resource_changes").is_some() {
        parse_terraform_plan(&value)
    } else if value.get("steps").is_some() {
        parse_pulumi_plan(&value)
    } else {
        Err(
            "unrecognized plan JSON shape: expected a `resource_changes` array (terraform / tofu) or a `steps` array (pulumi)"
                .into(),
        )
    }
}

fn parse_terraform_plan(value: &serde_json::Value) -> Result<PlanSummary, String> {
    let changes = value
        .get("resource_changes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing `resource_changes` array".to_string())?;

    // Heuristic — `terraform_version` ≠ pulumi; pulumi can also emit a
    // `resource_changes` extension; default to Terraform.
    let mut summary = PlanSummary {
        tool: PlanTool::Terraform,
        ..PlanSummary::default()
    };

    for change in changes {
        let address = change
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let resource_type = change.get("type").and_then(|v| v.as_str()).unwrap_or("");

        let actions: Vec<String> = change
            .get("change")
            .and_then(|c| c.get("actions"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        record_actions(&mut summary, &actions);
        record_high_risk(&mut summary, &address, resource_type);
    }

    summary.total_changes = summary.create + summary.update + summary.destroy;
    Ok(summary)
}

fn parse_pulumi_plan(value: &serde_json::Value) -> Result<PlanSummary, String> {
    let steps = value
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing `steps` array".to_string())?;

    let mut summary = PlanSummary {
        tool: PlanTool::Pulumi,
        ..PlanSummary::default()
    };

    for step in steps {
        let op = step.get("op").and_then(|v| v.as_str()).unwrap_or("");
        let urn = step.get("urn").and_then(|v| v.as_str()).unwrap_or("");

        record_actions(&mut summary, &[op.to_string()]);

        // Pulumi URN format: `urn:pulumi:stack::project::type::name`.
        // Type is the second-to-last `::` segment.
        let resource_type = pulumi_type_from_urn(urn);
        record_high_risk(&mut summary, urn, resource_type);
    }

    summary.total_changes = summary.create + summary.update + summary.destroy;
    Ok(summary)
}

fn pulumi_type_from_urn(urn: &str) -> &str {
    // urn:pulumi:<stack>::<project>::<type>::<name>
    let parts: Vec<&str> = urn.split("::").collect();
    if parts.len() >= 3 {
        parts[parts.len() - 2]
    } else {
        ""
    }
}

fn record_actions(summary: &mut PlanSummary, actions: &[String]) {
    // Terraform plan: actions is an array; a single change can be
    // `["create"]`, `["update"]`, `["delete"]`, `["delete", "create"]`
    // (replace), or `["no-op"]`. Pulumi: a single `op` string.
    for action in actions {
        match action.as_str() {
            "create" => summary.create += 1,
            "update" => summary.update += 1,
            "delete" => summary.destroy += 1,
            _ => {}
        }
    }
}

/// Resource-type / address heuristics for high-risk changes. The shipped
/// table is narrow — we surface the highest-signal categories and leave
/// the rest to operator review.
fn record_high_risk(summary: &mut PlanSummary, address: &str, resource_type: &str) {
    let lower = resource_type.to_lowercase();
    let address = if address.is_empty() {
        resource_type.to_string()
    } else {
        address.to_string()
    };

    // IAM mutations. Cover Terraform-style (`aws_iam_role`,
    // `google_project_iam_member`) plus Pulumi-style URN type names
    // (`aws:iam/role:Role`, `gcp:projects/iAMMember:IAMMember`,
    // `azure:authorization/roleAssignment:RoleAssignment`).
    let is_iam = lower.contains("iam_")
        || lower.contains("iam:")
        || lower.contains("iam/")
        || lower.contains(":iam")
        || lower.contains("_iam_")
        || lower.contains("role_")
        || lower.contains("clusterrole")
        || lower.contains("roleassignment")
        || lower.contains("roledefinition");
    if is_iam {
        summary.iam_changes.push(address.clone());
    }

    // Security-group / firewall.
    let is_sg = lower.contains("security_group") || lower.contains("compute_firewall");
    if is_sg {
        summary.security_group_changes.push(address.clone());
    }

    // Public bucket grants.
    let is_public_bucket = lower.contains("s3_bucket_public_access")
        || lower.contains("s3_bucket_acl")
        || lower.contains("storage_bucket_iam");
    if is_public_bucket {
        summary.public_bucket_changes.push(address.clone());
    }

    // DB / cluster.
    let is_db = lower.contains("db_instance")
        || lower.contains("rds_cluster")
        || lower.contains("sql_database_instance");
    if is_db {
        summary.db_changes.push(address.clone());
    }

    // Load balancers.
    let is_lb = lower == "aws_lb"
        || lower == "aws_alb"
        || lower.contains("_load_balancer")
        || lower.contains("forwarding_rule");
    if is_lb {
        summary.lb_changes.push(address);
    }
}

/// Compute the SHA-256 of a byte buffer as a lowercase hex string.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut s = String::with_capacity(result.len() * 2);
    for b in result {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Metadata stored alongside the recorded plan-hash. Kept small so the
/// store stays fast to walk; the actual plan body is NOT recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedPlan {
    pub sha256: String,
    pub recorded_at_unix: u64,
    pub plan_path: String,
    pub summary: PlanSummary,
}

/// Record a plan hash + its summary into the per-process plan store
/// (`state_dir()/iac_plans/<sha256>.json`).
///
/// Returns the hash that was recorded. Idempotent — re-recording the same
/// hash overwrites the previous entry's metadata (the `plan_path` may
/// change between runs even if the body is identical).
pub fn record_plan_hash(
    plan_bytes: &[u8],
    plan_path: &Path,
    summary: &PlanSummary,
) -> Result<String, String> {
    let sha = sha256_hex(plan_bytes);
    let dir = match crate::policy::iac_plans_dir() {
        Some(d) => d,
        None => return Err("could not resolve tirith state directory".into()),
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let entry = RecordedPlan {
        sha256: sha.clone(),
        recorded_at_unix: unix_now(),
        plan_path: plan_path.display().to_string(),
        summary: summary.clone(),
    };
    let body =
        serde_json::to_vec_pretty(&entry).map_err(|e| format!("serialize recorded plan: {e}"))?;
    let dest = dir.join(format!("{sha}.json"));
    write_file_0600(&dest, &body).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(sha)
}

/// `true` when a plan with the supplied hash has been recorded.
pub fn plan_hash_recorded(sha256: &str) -> bool {
    let dir = match crate::policy::iac_plans_dir() {
        Some(d) => d,
        None => return false,
    };
    let path = dir.join(format!("{sha256}.json"));
    path.is_file()
}

/// Human-readable form of the iac plan store path (for evidence
/// strings). Returns the literal `<unresolved>` when `state_dir()` is
/// not resolvable — we never panic in evidence formatting.
pub fn iac_plans_dir_display() -> String {
    match crate::policy::iac_plans_dir() {
        Some(p) => p.display().to_string(),
        None => "<unresolved>".to_string(),
    }
}

/// Load a recorded plan's metadata, if any.
pub fn load_recorded_plan(sha256: &str) -> Option<RecordedPlan> {
    let dir = crate::policy::iac_plans_dir()?;
    let path = dir.join(format!("{sha256}.json"));
    let content = std::fs::read(&path).ok()?;
    serde_json::from_slice(&content).ok()
}

/// Purge plans older than [`PLAN_CACHE_TTL`]. Returns the count of
/// removed files. Errors are swallowed silently — purge is best-effort.
pub fn purge_old_plans() -> usize {
    let dir = match crate::policy::iac_plans_dir() {
        Some(d) => d,
        None => return 0,
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let now = SystemTime::now();
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match metadata.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if let Ok(age) = now.duration_since(modified) {
            if age > PLAN_CACHE_TTL && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

fn write_file_0600(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(body)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shell out to `terraform show -json <plan_path>` (or `tofu show -json
/// <plan_path>`) with a hard timeout. Stdout buffer is read on a helper
/// thread to avoid pipe-buffer deadlocks.
///
/// **Hot-path warning.** This MUST NOT be called from `engine::analyze`.
/// The only legitimate caller is `tirith iac check-plan`, where the
/// operator is interactively requesting plan inspection.
pub fn run_terraform_show_json(plan_path: &Path, tool: PlanTool) -> Result<Vec<u8>, String> {
    let program = match tool {
        PlanTool::Terraform => "terraform",
        PlanTool::Tofu => "tofu",
        PlanTool::Pulumi => {
            return Err(
                "pulumi plans are JSON already — read the file directly rather than shelling out"
                    .into(),
            );
        }
    };

    let plan_path_string = plan_path.to_string_lossy().into_owned();
    let mut cmd = Command::new(program);
    cmd.args(["show", "-json", plan_path_string.as_str()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let mut child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;

    let stdout_handle = child.stdout.take().map(|mut s| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + TERRAFORM_SHOW_TIMEOUT;
    let poll = Duration::from_millis(50);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                if status.success() {
                    return Ok(stdout);
                } else {
                    return Err(format!(
                        "{program} show -json exited with status {}",
                        status.code().unwrap_or(-1)
                    ));
                }
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    return Err(format!(
                        "{program} show -json exceeded {}s timeout",
                        TERRAFORM_SHOW_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(poll);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                return Err(format!("try_wait {program}: {e}"));
            }
        }
    }
}

/// Detect the IaC tool from the plan file's parent directory's metadata
/// (e.g. `.terraform/`, `Pulumi.yaml`). Falls back to Terraform when no
/// hint is found — `terraform show -json` happens to handle OpenTofu's
/// plan files too because the wire format is identical for 1.x.
pub fn detect_plan_tool(plan_path: &Path) -> PlanTool {
    let parent = match plan_path.parent() {
        Some(p) => p,
        None => return PlanTool::Terraform,
    };

    let pulumi_marker = parent.join("Pulumi.yaml").is_file() || parent.join("Pulumi.yml").is_file();
    if pulumi_marker {
        return PlanTool::Pulumi;
    }

    // Distinguish tofu via the .terraform.lock.hcl path — both terraform
    // and tofu write this file, but tofu writes a `.tofu` lockfile too.
    let tofu_marker = parent.join(".tofu").is_dir() || parent.join("tofu.lock.hcl").is_file();
    if tofu_marker {
        return PlanTool::Tofu;
    }

    PlanTool::Terraform
}

/// Determine if a byte buffer is a JSON plan (for the Pulumi case where
/// the operator already has JSON in hand) vs a binary terraform plan.
/// Used by `iac check-plan` so the operator can pass either form.
pub fn looks_like_json(bytes: &[u8]) -> bool {
    let prefix: Vec<u8> = bytes
        .iter()
        .take(256)
        .filter(|b| !b.is_ascii_whitespace())
        .copied()
        .collect();
    prefix.first() == Some(&b'{') || prefix.first() == Some(&b'[')
}

#[cfg(test)]
mod tests {
    use super::*;

    const TF_PLAN_JSON: &str = r#"{
        "format_version": "1.2",
        "terraform_version": "1.5.7",
        "resource_changes": [
            {
                "address": "aws_s3_bucket.assets",
                "type": "aws_s3_bucket",
                "change": { "actions": ["create"] }
            },
            {
                "address": "aws_iam_role.app",
                "type": "aws_iam_role",
                "change": { "actions": ["create"] }
            },
            {
                "address": "aws_security_group.web",
                "type": "aws_security_group",
                "change": { "actions": ["update"] }
            },
            {
                "address": "aws_db_instance.primary",
                "type": "aws_db_instance",
                "change": { "actions": ["delete"] }
            },
            {
                "address": "aws_cloudwatch_metric_alarm.cpu",
                "type": "aws_cloudwatch_metric_alarm",
                "change": { "actions": ["no-op"] }
            }
        ]
    }"#;

    const PULUMI_PLAN_JSON: &str = r#"{
        "steps": [
            {
                "op": "create",
                "urn": "urn:pulumi:prod::myproj::aws:iam/role:Role::svc"
            },
            {
                "op": "delete",
                "urn": "urn:pulumi:prod::myproj::aws:s3/bucket:Bucket::assets"
            }
        ]
    }"#;

    #[test]
    fn parse_terraform_plan_counts_actions() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.create, 2);
        assert_eq!(summary.update, 1);
        assert_eq!(summary.destroy, 1);
        assert_eq!(summary.total_changes, 4);
        assert_eq!(summary.tool, PlanTool::Terraform);
    }

    #[test]
    fn parse_terraform_plan_flags_iam() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.iam_changes, vec!["aws_iam_role.app"]);
    }

    #[test]
    fn parse_terraform_plan_flags_security_group() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(
            summary.security_group_changes,
            vec!["aws_security_group.web"]
        );
    }

    #[test]
    fn parse_terraform_plan_flags_db_delete() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.db_changes, vec!["aws_db_instance.primary"]);
    }

    #[test]
    fn parse_terraform_plan_high_risk_true() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert!(summary.has_high_risk_changes());
    }

    #[test]
    fn parse_pulumi_plan_counts_actions() {
        let summary = parse_plan_json(PULUMI_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.create, 1);
        assert_eq!(summary.destroy, 1);
        assert_eq!(summary.tool, PlanTool::Pulumi);
    }

    #[test]
    fn parse_pulumi_plan_flags_iam_from_urn() {
        let summary = parse_plan_json(PULUMI_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.iam_changes.len(), 1);
        assert!(summary.iam_changes[0].contains("iam/role:Role"));
    }

    #[test]
    fn parse_plan_rejects_unknown_shape() {
        let bad = r#"{ "foo": [] }"#;
        let err = parse_plan_json(bad.as_bytes()).unwrap_err();
        assert!(err.contains("unrecognized plan JSON shape"));
    }

    #[test]
    fn parse_plan_rejects_invalid_json() {
        let bad = "not json at all";
        let err = parse_plan_json(bad.as_bytes()).unwrap_err();
        assert!(err.contains("json parse error"));
    }

    #[test]
    fn sha256_hex_stable() {
        let h1 = sha256_hex(b"hello");
        let h2 = sha256_hex(b"hello");
        let h3 = sha256_hex(b"world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn looks_like_json_detects_object() {
        assert!(looks_like_json(b"{\"foo\": 1}"));
        assert!(looks_like_json(b"   \n  [1,2,3]"));
    }

    #[test]
    fn looks_like_json_rejects_binary() {
        // Terraform binary plans have a specific magic header; any non-{
        // first non-whitespace byte should reject.
        assert!(!looks_like_json(&[0x50, 0x4b, 0x03, 0x04]));
    }

    #[test]
    fn detect_plan_tool_handles_missing_parent_dir() {
        let path = std::path::PathBuf::from("");
        let _ = detect_plan_tool(&path);
        // The function never panics on a path without a parent.
    }

    #[test]
    fn pulumi_type_from_urn_handles_short_urn() {
        assert_eq!(pulumi_type_from_urn(""), "");
        assert_eq!(pulumi_type_from_urn("urn:pulumi"), "");
        assert_eq!(
            pulumi_type_from_urn("urn:pulumi::proj::aws:iam/role:Role::svc"),
            "aws:iam/role:Role",
        );
    }
}

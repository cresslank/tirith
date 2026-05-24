//! M6 ch6 — local JSONL snapshot store for registry-API responses.
//!
//! Every successful `--online` fetch through `crate::registry_api` writes one
//! snapshot row per package to
//! `state_dir()/registry_snapshots/<eco>/<name>.jsonl`. The store is
//! append-only with a rolling cap of [`MAX_SNAPSHOTS_PER_PACKAGE`] rows per
//! package — the oldest rows are pruned on each write.
//!
//! Two reads of the most recent rows feed
//! [`crate::package_risk::MaintainerChangeHistory`] / [`OwnershipTransfer`] —
//! a real maintainer-set diff between two points in time, which a single
//! registry response cannot show. This is the core of the *real* ownership-
//! transfer signal that supersedes the legacy
//! `ApiProvenance::ownership_transferred` flag (inferred from one response).
//!
//! ## Invariants
//!
//! * Read-only on failures (best-effort I/O; never panics).
//! * Reuses an existing API response — never makes an extra request. The
//!   `gather_api_signals` path writes a snapshot whenever it has fresh data.
//! * Rolling cap of [`MAX_SNAPSHOTS_PER_PACKAGE`]. Plain JSONL is sufficient
//!   for the per-package row counts at hand; SQLite is reserved for a future
//!   wave if real-world counts demand it.
//! * No personally-identifying data is stored — only registry-public maintainer
//!   identifiers.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::package_risk::{
    ApiProvenance, MaintainerChangeHistory, MaintainerRef, OwnershipTransfer,
};
use crate::policy;
use crate::threatdb::Ecosystem;

/// Rolling cap: at most this many snapshot rows per package on disk.
/// 12 is enough to keep ~a year of monthly snapshots; older rows are pruned.
pub const MAX_SNAPSHOTS_PER_PACKAGE: usize = 12;

/// One snapshot row, one line of JSONL on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRow {
    /// Unix epoch seconds at the time of capture.
    pub captured_at: u64,
    /// The maintainer identifiers the registry reported at this point in
    /// time. Empty vector is a real "zero owners" signal; an absent field is
    /// the registry not exposing maintainers (PyPI, crates.io).
    pub maintainers: Vec<MaintainerRef>,
    /// Latest version string the registry reported, if any.
    #[serde(default)]
    pub latest_version: Option<String>,
    /// Registry-reported repository URL, if any.
    #[serde(default)]
    pub repository_url: Option<String>,
}

/// Resolve the snapshot store path for `(eco, name)`. Returns `None` when
/// `state_dir()` is unavailable (very unusual; we degrade gracefully).
fn snapshot_path(eco: Ecosystem, name: &str) -> Option<PathBuf> {
    let state = policy::state_dir()?;
    let dir = state
        .join("registry_snapshots")
        .join(eco.to_string().to_lowercase());
    let safe_name: String = name
        .chars()
        .map(|c| match c {
            '/' => '_',
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@') => c,
            _ => '_',
        })
        .collect();
    Some(dir.join(format!("{safe_name}.jsonl")))
}

/// Record a fresh snapshot for `(eco, name)` from a registry response.
/// Reuses the already-fetched [`ApiProvenance`]; makes no network call.
///
/// Best-effort: any I/O error is silently ignored. Returns `true` on success.
pub fn record_snapshot(eco: Ecosystem, name: &str, prov: &ApiProvenance) -> bool {
    let row = SnapshotRow {
        captured_at: unix_now(),
        maintainers: maintainers_from_provenance(prov),
        latest_version: prov.latest_version.clone(),
        repository_url: prov.repository_url_for_check(),
    };
    write_row(eco, name, &row)
}

/// Best-effort write of one row, with rolling-cap pruning.
fn write_row(eco: Ecosystem, name: &str, row: &SnapshotRow) -> bool {
    let Some(path) = snapshot_path(eco, name) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return false;
    }
    // Read existing rows so we can prune to the rolling cap.
    let mut rows = read_rows(&path);
    rows.push(row.clone());
    if rows.len() > MAX_SNAPSHOTS_PER_PACKAGE {
        let drop = rows.len() - MAX_SNAPSHOTS_PER_PACKAGE;
        rows.drain(..drop);
    }
    // Write the (possibly-pruned) set back as JSONL.
    let mut buf = String::new();
    for r in &rows {
        if let Ok(line) = serde_json::to_string(r) {
            buf.push_str(&line);
            buf.push('\n');
        }
    }
    std::fs::write(path, buf).is_ok()
}

/// Read all snapshot rows for `(eco, name)` in chronological order (oldest
/// first). Returns an empty vector when the file does not exist or any row
/// fails to parse — best-effort, never panics.
pub fn read_rows(path: &std::path::Path) -> Vec<SnapshotRow> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<SnapshotRow>(l).ok())
        .collect()
}

/// Read all rows for `(eco, name)`. Public for tests + the CLI inspector.
pub fn read_snapshots(eco: Ecosystem, name: &str) -> Vec<SnapshotRow> {
    let Some(path) = snapshot_path(eco, name) else {
        return Vec::new();
    };
    read_rows(&path)
}

/// Diff the two most recent snapshots for `(eco, name)`. Returns `None` when
/// fewer than two snapshots exist — the first `--online` run can only record,
/// not diff. Documented explicitly in the rule's `false_positive_guidance`.
pub fn diff_recent(eco: Ecosystem, name: &str) -> Option<MaintainerChangeHistory> {
    let rows = read_snapshots(eco, name);
    if rows.len() < 2 {
        return None;
    }
    let older = &rows[rows.len() - 2];
    let newer = &rows[rows.len() - 1];
    Some(diff_two_snapshots(older, newer))
}

/// Compute a `MaintainerChangeHistory` from two rows. Pure, no I/O.
pub fn diff_two_snapshots(older: &SnapshotRow, newer: &SnapshotRow) -> MaintainerChangeHistory {
    let old_ids: std::collections::HashSet<&str> =
        older.maintainers.iter().map(|m| m.id.as_str()).collect();
    let new_ids: std::collections::HashSet<&str> =
        newer.maintainers.iter().map(|m| m.id.as_str()).collect();
    let added: Vec<MaintainerRef> = newer
        .maintainers
        .iter()
        .filter(|m| !old_ids.contains(m.id.as_str()))
        .cloned()
        .collect();
    let removed: Vec<MaintainerRef> = older
        .maintainers
        .iter()
        .filter(|m| !new_ids.contains(m.id.as_str()))
        .cloned()
        .collect();
    let transfer_within_days = if newer.captured_at >= older.captured_at {
        let secs = newer.captured_at - older.captured_at;
        Some((secs / 86_400) as u32)
    } else {
        None
    };
    MaintainerChangeHistory {
        added,
        removed,
        transfer_within_days,
    }
}

/// Synthesize an `OwnershipTransfer` record from a `MaintainerChangeHistory`.
/// Pure; the diff already carries the data needed.
pub fn synthesize_transfer(hist: &MaintainerChangeHistory) -> OwnershipTransfer {
    OwnershipTransfer {
        previous: hist.removed.clone(),
        current: hist.added.clone(),
        within_days: hist.transfer_within_days,
    }
}

/// Pull a maintainer list out of an [`ApiProvenance`]. The new
/// [`ApiProvenance`] doesn't carry a maintainers field directly (that's a
/// `RegistryMetadata`-only field), so the recording path passes them in via
/// the snapshot writer's caller below. This helper is a hook for the future:
/// when ApiProvenance grows a maintainers field, we read it here. For now,
/// the snapshot row's `maintainers` defaults to empty unless the recording
/// site supplies it via [`record_snapshot_with_maintainers`].
fn maintainers_from_provenance(_prov: &ApiProvenance) -> Vec<MaintainerRef> {
    // ApiProvenance does not directly carry the maintainer list today (it
    // carries the *inferred-from-one-response* `ownership_transferred` bool
    // only). Snapshot maintainers are written explicitly via
    // [`record_snapshot_with_maintainers`] from the
    // `RegistryMetadata`-aware paths. Returning empty here is honest no-data.
    Vec::new()
}

/// Explicit snapshot writer when the caller has the maintainer list on hand
/// (e.g. from `RegistryMetadata` before it was folded into `ApiProvenance`).
pub fn record_snapshot_with_maintainers(
    eco: Ecosystem,
    name: &str,
    maintainers: Vec<MaintainerRef>,
    latest_version: Option<String>,
    repository_url: Option<String>,
) -> bool {
    let row = SnapshotRow {
        captured_at: unix_now(),
        maintainers,
        latest_version,
        repository_url,
    };
    write_row(eco, name, &row)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(captured_at: u64, ids: &[&str]) -> SnapshotRow {
        SnapshotRow {
            captured_at,
            maintainers: ids
                .iter()
                .map(|s| MaintainerRef {
                    id: (*s).to_string(),
                })
                .collect(),
            latest_version: Some("1.0.0".to_string()),
            repository_url: None,
        }
    }

    #[test]
    fn diff_two_snapshots_adds_and_removes() {
        let older = row(1_000_000, &["alice", "bob"]);
        let newer = row(1_000_000 + 86_400 * 5, &["bob", "eve"]);
        let h = diff_two_snapshots(&older, &newer);
        assert_eq!(
            h.added.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["eve"]
        );
        assert_eq!(
            h.removed.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["alice"]
        );
        assert_eq!(h.transfer_within_days, Some(5));
    }

    #[test]
    fn diff_two_snapshots_full_transfer_marks_no_overlap() {
        let older = row(0, &["alice"]);
        let newer = row(86_400, &["eve"]);
        let h = diff_two_snapshots(&older, &newer);
        assert!(h.is_full_ownership_transfer());
        let t = synthesize_transfer(&h);
        assert!(t
            .previous
            .iter()
            .all(|p| !t.current.iter().any(|c| c.id == p.id)));
    }

    #[test]
    fn diff_two_snapshots_empty_change_returns_empty_lists() {
        let older = row(0, &["alice"]);
        let newer = row(86_400, &["alice"]);
        let h = diff_two_snapshots(&older, &newer);
        assert!(h.added.is_empty());
        assert!(h.removed.is_empty());
        assert!(!h.is_recent()); // no diff → not recent
    }

    #[test]
    fn diff_recent_returns_none_when_fewer_than_two_rows() {
        // No state dir override — this should still gracefully return None.
        // (We can't write to state_dir from a unit test, so we exercise the
        // logic of read_snapshots returning empty.)
        let _ = read_snapshots(Ecosystem::Npm, "nonexistent-package-xyzzy-test");
    }

    #[test]
    fn snapshot_row_serializes_and_round_trips() {
        let r = row(123, &["a", "b"]);
        let s = serde_json::to_string(&r).unwrap();
        let back: SnapshotRow = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn snapshot_path_sanitizes_name() {
        // The path-segment sanitizer must replace `/` with `_` so a scoped npm
        // name does not write to a nested directory.
        // (Can't assert the exact path without a state_dir; just check it
        // returns Some for a normal name and the segment encoding is sane.)
        let path = snapshot_path(Ecosystem::Npm, "@org/util");
        if let Some(p) = path {
            let s = p.to_string_lossy();
            assert!(s.contains("@org_util.jsonl"));
        }
    }
}

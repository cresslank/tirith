//! M11 ch5 — incident mode (L2 #21).
//!
//! An *incident* is a manually-declared "we may be under attack right now"
//! posture. While an incident is active tirith stops being advisory and turns
//! the screws: the runtime policy is forced fail-closed, the `TIRITH=0` env
//! bypass (interactive AND non-interactive) is disabled, and a curated set of
//! already-shipping detection rules is elevated so the *next* suspicious thing
//! the operator runs is far more likely to block.
//!
//! # Zero new RuleIds
//!
//! Incident mode introduces **no** new [`crate::verdict::RuleId`]. It works
//! entirely by layering runtime overrides on top of the loaded
//! [`crate::policy::Policy`]:
//!
//! * `fail_mode` → [`crate::policy::FailMode::Closed`]
//! * `allow_bypass_env` → `false`
//! * `allow_bypass_env_noninteractive` → `false`
//! * a severity-override for each [`RuleId`] in [`INCIDENT_ELEVATED_RULES`],
//!   applied ONLY when the policy does not already pin that rule higher (we
//!   never *downgrade* an operator's explicit override).
//!
//! The override merge lives in [`crate::policy::Policy::apply_runtime_overrides`]
//! and runs on every analyze via the policy-discovery path, behind a 5-second
//! per-process stat cache so the common no-incident path is a near-noop.
//!
//! # The mode flag
//!
//! Active state is a single JSON file at `state_dir()/incident_active.json`
//! holding `{started_at, started_by, reason}`. Its mere existence means "an
//! incident is active"; deleting it ends the incident. This is deliberately
//! the simplest possible mechanism, for one load-bearing reason:
//!
//! # Lockout safety (CRITICAL)
//!
//! `tirith incident stop` is a **direct deletion of this state file** — it is
//! NOT routed through `tirith check` and is therefore NOT subject to the
//! incident's own fail-closed policy. If `stop` were gated by the policy it
//! flips on, a stuck incident on a machine with `allow_bypass_env: false`
//! would be unrecoverable. Stopping an incident must ALWAYS succeed regardless
//! of policy, so it is modeled as plain filesystem state, not a gated command.
//! The `tirith incident start --reason "…"` lockout test pins this.
//!
//! # Concurrent starts
//!
//! [`start`] uses `create_new` (O_EXCL) so a second `start` while one is
//! already active fails with [`StartError::AlreadyActive`] carrying the
//! existing `started_at` — it never silently overwrites the original reason or
//! timestamp.
//!
//! # Honest scope
//!
//! The flag file is user-writable. An attacker who already has the operator's
//! shell can delete it (ending the incident) exactly as they could touch any
//! other tirith state file. This is operator-trust — a footgun-and-response
//! aid, not an adversary-resistant control. Same model as the M8 sudo-session
//! and the M11 canary store.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::verdict::{RuleId, Severity};

/// The already-shipping rules incident mode elevates, with the severity each
/// is forced to while an incident is active.
///
/// **Grep-traceability invariant:** every entry here MUST be a real
/// [`RuleId`] variant. A new detection wave that warrants incident elevation
/// adds its rule to this list in the same chunk. The
/// `incident_elevated_rules_exist` test round-trips every entry through serde
/// so a renamed/removed variant is caught at test time, not in the field.
///
/// We only ever elevate (Medium → High, High → Critical, …). The merge in
/// [`crate::policy::Policy::apply_runtime_overrides`] never lowers a severity
/// the operator already pinned, and never lowers a rule's baseline.
pub const INCIDENT_ELEVATED_RULES: &[(RuleId, Severity)] = &[
    // A command sweeping multiple credential files at once — during an
    // incident this is "someone is collecting secrets to exfiltrate".
    (RuleId::CredentialFileSweep, Severity::Critical),
    // base64-decode-then-execute — the textbook obfuscated-payload shape.
    (RuleId::Base64DecodeExecute, Severity::Critical),
    // M9 ch5 — the leader binary was modified in the last few minutes. Benign
    // noise normally; during an incident a freshly-written binary is a prime
    // "the attacker just dropped this" signal.
    (RuleId::ExecRecentlyModified, Severity::High),
    // M9 ch5 — the leader binary is world-writable. Same reasoning: a
    // world-writable binary in the exec path is far more alarming mid-incident.
    (RuleId::ExecWorldWritable, Severity::High),
];

/// Default on-disk path of the incident-active flag: `state_dir()/incident_active.json`.
pub fn flag_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("incident_active.json"))
}

/// On-disk shape of the incident-active flag file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentState {
    /// Unix epoch seconds when the incident was declared.
    pub started_at: u64,
    /// Best-effort identity of who started it (`$USER` / `$LOGNAME`, else
    /// `"unknown"`). Advisory only — never load-bearing.
    #[serde(default)]
    pub started_by: String,
    /// Operator-supplied reason string. Stored verbatim, no parsing.
    #[serde(default)]
    pub reason: String,
}

impl IncidentState {
    /// Construct fresh incident state anchored at `SystemTime::now()`.
    pub fn now(reason: impl Into<String>) -> Self {
        Self {
            started_at: unix_now(),
            started_by: current_user(),
            reason: reason.into(),
        }
    }

    /// RFC-3339-ish display of `started_at` for human output. Falls back to the
    /// raw epoch seconds when the timestamp is outside chrono's range.
    pub fn started_at_display(&self) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp(self.started_at as i64, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| format!("{} (epoch seconds)", self.started_at))
    }
}

/// Why a [`start`] failed.
#[derive(Debug)]
pub enum StartError {
    /// An incident is already active. Carries the existing state so the CLI can
    /// print "already active since X" without re-reading the file.
    AlreadyActive(Box<IncidentState>),
    /// `state_dir()` could not be resolved (no `$HOME`, no `$XDG_STATE_HOME`).
    NoStateDir,
    /// A filesystem error while creating the flag file.
    Io(std::io::Error),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::AlreadyActive(s) => write!(
                f,
                "an incident is already active since {} (reason: {})",
                s.started_at_display(),
                if s.reason.is_empty() {
                    "<none>"
                } else {
                    &s.reason
                }
            ),
            StartError::NoStateDir => write!(f, "could not resolve tirith state dir"),
            StartError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Read the current incident state, if any. `None` when the flag file is
/// missing or unparseable (a corrupt flag is treated as "no incident" — but
/// see the safety note: deletion is the only intended way to end one, so a
/// corrupt-flag fall-through is a degraded best-effort, not a security
/// downgrade we rely on).
///
/// This is the un-cached read used by the CLI (`status`, `stop`, `report`).
/// The hot-path read used by the engine goes through [`active_cached`].
pub fn read_state() -> Option<IncidentState> {
    let path = flag_path()?;
    read_state_at(&path)
}

/// [`read_state`] against an explicit path (test seam).
pub fn read_state_at(path: &Path) -> Option<IncidentState> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Declare an incident: atomically create the flag file with `0o600`. Fails
/// with [`StartError::AlreadyActive`] if one already exists (O_EXCL) — never
/// overwrites an in-flight incident's `started_at`/`reason`.
pub fn start(reason: impl Into<String>) -> Result<IncidentState, StartError> {
    let path = flag_path().ok_or(StartError::NoStateDir)?;
    start_at(&path, reason)
}

/// [`start`] against an explicit path (test seam).
pub fn start_at(path: &Path, reason: impl Into<String>) -> Result<IncidentState, StartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StartError::Io)?;
    }
    let state = IncidentState::now(reason);
    let body =
        serde_json::to_vec_pretty(&state).map_err(|e| StartError::Io(std::io::Error::other(e)))?;

    let mut opts = std::fs::OpenOptions::new();
    // create_new => O_EXCL: fail rather than clobber a concurrent incident.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            use std::io::Write as _;
            f.write_all(&body).map_err(StartError::Io)?;
            invalidate_cache();
            Ok(state)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Someone beat us to it. Surface the *existing* state, not ours.
            let existing = read_state_at(path).unwrap_or_else(|| IncidentState {
                started_at: 0,
                started_by: String::new(),
                reason: String::new(),
            });
            Err(StartError::AlreadyActive(Box::new(existing)))
        }
        Err(e) => Err(StartError::Io(e)),
    }
}

/// End an incident: delete the flag file. **Always** succeeds when the file is
/// gone (idempotent — a missing flag is success). This is the lockout-safe
/// recovery path: it is a plain unlink, never gated by the incident's own
/// fail-closed policy.
///
/// Returns `Ok(true)` if a flag was removed, `Ok(false)` if none was present.
pub fn stop() -> Result<bool, String> {
    let path = match flag_path() {
        Some(p) => p,
        None => return Ok(false),
    };
    stop_at(&path)
}

/// [`stop`] against an explicit path (test seam).
pub fn stop_at(path: &Path) -> Result<bool, String> {
    let removed = match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(format!("remove {}: {e}", path.display())),
    };
    invalidate_cache();
    Ok(removed)
}

// ---- Hot-path cached active check -----------------------------------------

/// Per-process cache of the "is an incident active?" answer, keyed on the
/// resolved flag path. Mirrors [`crate::canary`]'s cache: load once, 5-second
/// TTL, re-stat on the flag's mtime. The common no-incident path costs one
/// `metadata()` stat (and not even that within the TTL window).
struct CacheState {
    path: PathBuf,
    state: Option<IncidentState>,
    loaded_at: Instant,
    mtime_nanos: u128,
    existed: bool,
}

static CACHE: Mutex<Option<CacheState>> = Mutex::new(None);

const CACHE_TTL: Duration = Duration::from_secs(5);

fn mtime_nanos(path: &Path) -> (bool, u128) {
    match std::fs::metadata(path) {
        Ok(m) => {
            let nanos = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            (true, nanos)
        }
        Err(_) => (false, 0),
    }
}

/// The hot-path read: returns the active incident state through the 5s cache.
/// `None` when no incident is active. Used by
/// [`crate::policy::Policy::apply_runtime_overrides`].
pub fn active_cached() -> Option<IncidentState> {
    let path = flag_path()?;
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let (existed, cur_mtime) = mtime_nanos(&path);

    if let Some(state) = guard.as_ref() {
        let fresh = state.path == path
            && now.duration_since(state.loaded_at) < CACHE_TTL
            && state.existed == existed
            && state.mtime_nanos == cur_mtime;
        if fresh {
            return state.state.clone();
        }
    }

    // Cache miss / stale: re-read. Absent file → None (the common path).
    let parsed = if existed { read_state_at(&path) } else { None };
    *guard = Some(CacheState {
        path: path.clone(),
        state: parsed.clone(),
        loaded_at: now,
        mtime_nanos: cur_mtime,
        existed,
    });
    parsed
}

/// `true` when an incident is currently active (cached). Convenience over
/// [`active_cached`] for call sites that only need the boolean.
pub fn is_active() -> bool {
    active_cached().is_some()
}

/// Drop the per-process cache. Tests that write/delete the flag directly then
/// assert via the cached API call this so a stale earlier load is not reused.
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort current-user label for `started_by`. Never fails — falls back to
/// `"unknown"`. Advisory metadata only.
fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME")) // Windows
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn flag_in(dir: &Path) -> PathBuf {
        dir.join("incident_active.json")
    }

    #[test]
    fn elevated_rules_are_real_ruleids() {
        // Grep-traceability invariant: every INCIDENT_ELEVATED_RULES entry must
        // round-trip through serde (i.e. be a live RuleId variant). A renamed
        // or removed variant fails to compile the const, but this also pins the
        // snake_case key the policy override map will use.
        for (rule, sev) in INCIDENT_ELEVATED_RULES {
            let key = serde_json::to_value(rule)
                .ok()
                .and_then(|v| v.as_str().map(String::from));
            assert!(
                key.is_some(),
                "RuleId {rule:?} does not serialize to a string"
            );
            // Severity must also serialize (UPPERCASE).
            assert!(serde_json::to_value(sev).is_ok());
        }
        // The four spec-mandated rules must be present.
        let keys: Vec<&RuleId> = INCIDENT_ELEVATED_RULES.iter().map(|(r, _)| r).collect();
        assert!(keys.contains(&&RuleId::CredentialFileSweep));
        assert!(keys.contains(&&RuleId::Base64DecodeExecute));
        assert!(keys.contains(&&RuleId::ExecRecentlyModified));
        assert!(keys.contains(&&RuleId::ExecWorldWritable));
    }

    #[test]
    fn start_creates_flag_and_status_reads_it() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        assert!(read_state_at(&flag).is_none(), "no incident before start");

        let state = start_at(&flag, "suspicious paste").unwrap();
        assert_eq!(state.reason, "suspicious paste");
        assert!(state.started_at > 0);

        let read = read_state_at(&flag).expect("flag present after start");
        assert_eq!(read.reason, "suspicious paste");
        assert_eq!(read.started_at, state.started_at);
    }

    #[test]
    fn second_start_errors_already_active_without_overwriting() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        let first = start_at(&flag, "first reason").unwrap();
        // A second start must fail and must NOT clobber the original.
        let err = start_at(&flag, "second reason").unwrap_err();
        match err {
            StartError::AlreadyActive(existing) => {
                assert_eq!(existing.reason, "first reason");
                assert_eq!(existing.started_at, first.started_at);
            }
            other => panic!("expected AlreadyActive, got {other:?}"),
        }
        // On disk, the original reason survives.
        assert_eq!(read_state_at(&flag).unwrap().reason, "first reason");
    }

    #[test]
    fn stop_removes_flag_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        start_at(&flag, "x").unwrap();
        assert!(stop_at(&flag).unwrap(), "first stop removes the flag");
        assert!(read_state_at(&flag).is_none(), "flag gone after stop");
        // Idempotent — stopping an already-stopped incident is success, not error.
        assert!(
            !stop_at(&flag).unwrap(),
            "second stop finds nothing, still Ok"
        );
    }

    #[test]
    fn stop_succeeds_even_with_fail_closed_policy_in_play() {
        // Lockout-safety unit: stop is a plain unlink with no policy in the
        // path. We can't easily fake fail-closed here (that lives in the CLI
        // integration test), but we CAN prove stop never consults policy: it
        // operates purely on the file and succeeds.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        start_at(&flag, "lockout drill").unwrap();
        // Even if the rest of the world is fail-closed, this returns Ok(true).
        assert!(stop_at(&flag).unwrap());
    }

    #[test]
    fn corrupt_flag_reads_as_none() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        std::fs::write(&flag, b"this is not json").unwrap();
        assert!(read_state_at(&flag).is_none());
    }

    #[test]
    fn started_at_display_is_rfc3339_for_sane_timestamps() {
        let s = IncidentState {
            started_at: 1_700_000_000,
            started_by: "tester".to_string(),
            reason: "demo".to_string(),
        };
        let disp = s.started_at_display();
        assert!(disp.contains("2023"), "got {disp}");
    }
}

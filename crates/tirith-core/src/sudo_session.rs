//! Sudo-session helpers (M8 ch4).
//!
//! The session-file lives at `state_dir()/sudo-session.json` and stores
//! `{started_at, ttl, reason}` for the operator's currently-claimed sudo
//! window. The M8 ch4 rule module consults this file when
//! `policy.sudo_require_reason` is on so a tagged session can suppress an
//! otherwise-blocking finding.
//!
//! ## Clock-skew tolerance
//!
//! TTL freshness checks compare against `SystemTime::now()` and the
//! recorded `started_at`. Two cases are tolerated:
//!
//! 1. Operator clock-skew (NTP drift, container time-warp) — if
//!    `now()` and the recorded `started_at` differ by ≤ 60 seconds we
//!    still treat the session as active.
//! 2. Stale-fail safety — when the system clock is wrong by hours, the
//!    `started_at` field can read as wildly in the future. We reject
//!    expired sessions but never panic on an unparseable timestamp.
//!
//! The on-disk `mtime` is **never** used to rewrite `started_at` —
//! `touch(1)`, `cp -p`, or a backup tool refreshing the timestamp must
//! not silently reactivate an expired session.
//!
//! ## Lifecycle
//!
//! `start` — creates the file with `0o600` and overwrites any prior
//! session. `end` — removes the file. `status` — reads the file and
//! computes `remaining_secs` from `now() - started_at`.
//!
//! Failures are deliberately non-fatal. A session file that can't be
//! read just means "no session active"; the rules treat that as a hard
//! Block (the rules ship the safer-default).
//!
//! ## Honest scope
//!
//! The session file is user-writable. An attacker who already has shell
//! access can simply touch the file. This is operator-trust, not
//! adversary-resistant — the goal is to catch operational footguns
//! ("I forgot I had a sudo window open"), not to stop a determined
//! attacker. The M8 ch1/ch2/ch3 labels-file model is the same shape.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum clock skew we tolerate when comparing the recorded
/// `started_at` against `SystemTime::now()`. Sixty seconds is wider
/// than typical NTP drift but tight enough that a clock that's
/// pathologically wrong still expires sessions.
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

/// Default TTL when the operator runs `tirith sudo session start`
/// without `--ttl`.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 30 * 60;

/// Path the session file lives at, when `state_dir()` is resolvable.
pub fn sudo_session_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|s| s.join("sudo-session.json"))
}

/// On-disk shape of the sudo-session file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoSession {
    /// Unix epoch seconds when the operator started the session.
    pub started_at: u64,
    /// Lifetime in seconds before the session expires.
    pub ttl_secs: u64,
    /// Operator-supplied reason string. Stored verbatim, no parsing.
    #[serde(default)]
    pub reason: String,
}

impl SudoSession {
    /// Construct a fresh session anchored at `SystemTime::now()`.
    pub fn now(ttl_secs: u64, reason: impl Into<String>) -> Self {
        Self {
            started_at: unix_now(),
            ttl_secs,
            reason: reason.into(),
        }
    }

    /// `true` when the session is still within its TTL window. The check
    /// is forgiving in two directions: clock-skew within
    /// [`CLOCK_SKEW_TOLERANCE_SECS`] is treated as "still valid", and a
    /// missing-but-recent file `mtime` is treated as a fallback anchor.
    pub fn is_active(&self) -> bool {
        let now = unix_now();
        let started = self.started_at;
        // Clock-skew tolerance: `started_at` may legitimately be slightly
        // in the future after a clock-correction. Don't reject those.
        let effective_now = if now >= started {
            now
        } else if started - now <= CLOCK_SKEW_TOLERANCE_SECS {
            started
        } else {
            // Clock is wildly off in the past direction. Treat as
            // expired — fail-closed for sessions is the safer default.
            return false;
        };
        let age = effective_now.saturating_sub(started);
        age <= self.ttl_secs
    }

    /// Seconds remaining in the session. `0` once expired.
    pub fn remaining_secs(&self) -> u64 {
        let now = unix_now();
        if now < self.started_at {
            // Negative age — treat as full TTL.
            return self.ttl_secs;
        }
        let age = now - self.started_at;
        self.ttl_secs.saturating_sub(age)
    }
}

/// Read the current session, if any. Returns `None` when the file is
/// missing OR the parsed session has expired. Caller never needs to
/// re-check the TTL.
///
/// We *never* overwrite a parsed `started_at` from disk mtime. A prior
/// implementation did so when the JSON timestamp drifted >1y from mtime,
/// intending to recover from on-disk schema changes; in practice
/// `touch(1)` or backup tools could refresh mtime on a long-expired
/// session and silently reactivate it for another TTL window.
pub fn read_active_session() -> Option<SudoSession> {
    let path = sudo_session_path()?;
    let bytes = std::fs::read(&path).ok()?;
    let session: SudoSession = serde_json::from_slice(&bytes).ok()?;

    if session.is_active() {
        Some(session)
    } else {
        None
    }
}

/// Write a new session file, overwriting any prior session. Returns the
/// final on-disk path.
pub fn write_session(session: &SudoSession) -> Result<PathBuf, String> {
    let path =
        sudo_session_path().ok_or_else(|| "could not resolve tirith state dir".to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let body =
        serde_json::to_vec_pretty(session).map_err(|e| format!("serialize sudo session: {e}"))?;
    write_file_0600(&path, &body).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

/// Remove the session file. Idempotent — missing-file is success.
pub fn remove_session() -> Result<(), String> {
    let path = match sudo_session_path() {
        Some(p) => p,
        None => return Ok(()),
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

fn write_file_0600(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
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
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a `--ttl` string like `30m` / `2h` / `90s` / bare seconds.
/// Returns the duration in seconds. Empty string → `None`.
///
/// The trailing suffix must be a single ASCII character. Multi-byte
/// suffixes (e.g. `5m€`) are rejected; previously the implementation
/// called `s.split_at(s.len() - 1)` which can panic mid-codepoint.
pub fn parse_ttl(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bare integer → seconds.
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    // The unit suffix must be a single ASCII byte. Reject anything else
    // (including multi-byte unicode) up-front so the boundary split below
    // is always safe.
    let last_byte = s.as_bytes().last().copied()?;
    if !last_byte.is_ascii() {
        return None;
    }
    let (num_part, suffix) = s.split_at(s.len() - 1);
    if num_part.is_empty() {
        return None;
    }
    let n: u64 = num_part.parse().ok()?;
    match suffix {
        "s" | "S" => Some(n),
        "m" | "M" => Some(n.saturating_mul(60)),
        "h" | "H" => Some(n.saturating_mul(60 * 60)),
        "d" | "D" => Some(n.saturating_mul(24 * 60 * 60)),
        _ => None,
    }
}

/// Format the duration as a short human string (`30m`, `2h`, `1d`).
pub fn format_ttl(secs: u64) -> String {
    if secs % (24 * 60 * 60) == 0 && secs >= 24 * 60 * 60 {
        return format!("{}d", secs / (24 * 60 * 60));
    }
    if secs % (60 * 60) == 0 && secs >= 60 * 60 {
        return format!("{}h", secs / (60 * 60));
    }
    if secs % 60 == 0 && secs >= 60 {
        return format!("{}m", secs / 60);
    }
    format!("{secs}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_handles_units() {
        assert_eq!(parse_ttl("30s"), Some(30));
        assert_eq!(parse_ttl("5m"), Some(300));
        assert_eq!(parse_ttl("2h"), Some(7200));
        assert_eq!(parse_ttl("1d"), Some(86400));
        assert_eq!(parse_ttl("90"), Some(90));
    }

    #[test]
    fn parse_ttl_rejects_garbage() {
        assert_eq!(parse_ttl(""), None);
        assert_eq!(parse_ttl("xyz"), None);
        assert_eq!(parse_ttl("3w"), None);
    }

    #[test]
    fn parse_ttl_does_not_panic_on_multibyte_suffix() {
        // Regression: parse_ttl previously called s.split_at(s.len() - 1)
        // which panics mid-codepoint when the last char is multi-byte
        // (e.g. €, 中, 😀). The CLI passes this string straight from the
        // operator's --ttl arg.
        assert_eq!(parse_ttl("5m€"), None);
        assert_eq!(parse_ttl("30s😀"), None);
        assert_eq!(parse_ttl("€"), None);
        assert_eq!(parse_ttl("m"), None); // unit only, no number
    }

    #[test]
    fn format_ttl_picks_largest_clean_unit() {
        assert_eq!(format_ttl(30), "30s");
        assert_eq!(format_ttl(300), "5m");
        assert_eq!(format_ttl(7200), "2h");
        assert_eq!(format_ttl(86400), "1d");
        assert_eq!(format_ttl(86461), "86461s");
    }

    #[test]
    fn fresh_session_is_active() {
        let s = SudoSession::now(60, "demo");
        assert!(s.is_active());
        assert!(s.remaining_secs() > 0);
    }

    #[test]
    fn expired_session_is_inactive() {
        let now = unix_now();
        let s = SudoSession {
            started_at: now.saturating_sub(120),
            ttl_secs: 30,
            reason: "stale".to_string(),
        };
        assert!(!s.is_active());
        assert_eq!(s.remaining_secs(), 0);
    }

    #[test]
    fn small_future_clock_skew_tolerated() {
        let now = unix_now();
        let s = SudoSession {
            started_at: now + 10, // 10s in the future — well under tolerance
            ttl_secs: 60,
            reason: "skew".to_string(),
        };
        assert!(s.is_active());
    }

    #[test]
    fn large_future_clock_skew_rejected() {
        let now = unix_now();
        let s = SudoSession {
            started_at: now + 10 * CLOCK_SKEW_TOLERANCE_SECS,
            ttl_secs: 60,
            reason: "wild_skew".to_string(),
        };
        assert!(!s.is_active());
    }
}

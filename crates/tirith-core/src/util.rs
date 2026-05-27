//! Utility helpers shared across the core crate.

use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Outcome of [`run_shell_with_timeout`]. Callers map this onto their own
/// error type (e.g. `ContextDetectFailure`, plain `String`).
#[derive(Debug)]
pub enum ShellTimeoutOutcome {
    /// Child ran to completion within the deadline. `stdout` is the
    /// captured bytes; `status` is the exit status (callers decide how to
    /// treat non-zero exits).
    Completed { status: ExitStatus, stdout: Vec<u8> },
    /// `spawn()` failed with `ErrorKind::NotFound` — the binary isn't on
    /// PATH. Callers typically translate this to "not configured".
    NotFound,
    /// `spawn()` failed for some other reason. The string carries a short
    /// formatted reason for audit/log surfaces.
    SpawnError(String),
    /// `try_wait()` returned an error after spawn succeeded.
    WaitError(String),
    /// Deadline elapsed; the child was sent `kill()` and reaped.
    Timeout,
}

/// Spawn a child process with stdout piped, drain stdout on a helper
/// thread (so the pipe buffer never blocks the child), and poll
/// `try_wait()` against a deadline. On timeout the child is killed and
/// reaped before returning.
///
/// Stderr behaviour is delegated to the caller via `stderr_stdio` —
/// passing `Stdio::null()` discards it cheaply, passing `Stdio::piped()`
/// requires the caller to drain stderr themselves (or accept the
/// pipe-fill deadlock risk). Most callers should pass `Stdio::null()`.
///
/// This consolidates two near-identical 70-line copies (PR-127 review #8)
/// in `context_detect.rs::run_with_timeout` and
/// `iac_plan.rs::run_terraform_show_json`.
pub fn run_shell_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
    poll_interval: Duration,
    stderr_stdio: Stdio,
) -> ShellTimeoutOutcome {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(stderr_stdio)
        .stdin(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ShellTimeoutOutcome::NotFound;
        }
        Err(e) => {
            return ShellTimeoutOutcome::SpawnError(format!("spawn {program}: {e}"));
        }
    };

    // Stream stdout on a helper thread so the pipe buffer never blocks
    // the child when output exceeds ~64KiB.
    let stdout_handle: Option<JoinHandle<Vec<u8>>> = child.stdout.take().map(|mut s| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                return ShellTimeoutOutcome::Completed { status, stdout };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    return ShellTimeoutOutcome::Timeout;
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                return ShellTimeoutOutcome::WaitError(format!("try_wait {program}: {e}"));
            }
        }
    }
}

/// Truncate a string to a maximum number of bytes without breaking UTF-8.
/// Returns the original string if it is already within the limit.
pub fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    if max_bytes == 0 {
        return String::new();
    }
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Simple Levenshtein distance for short strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, val) in dp[0].iter_mut().enumerate() {
        *val = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[m][n]
}

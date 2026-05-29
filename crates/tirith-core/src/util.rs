//! Utility helpers shared across the core crate.

use std::io::BufRead;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Read a line-oriented store, returning the TRIMMED, non-empty lines.
///
/// Shared by the JSONL stores (baseline / canary / taint). Two failure
/// behaviours are deliberately split so a corrupt file can never (a) silently
/// drop the rest of the file, nor (b) spin forever:
///
/// * A single [`std::io::ErrorKind::InvalidData`] line (the recoverable
///   invalid-UTF-8 case — `BufRead::lines()` decodes each line as UTF-8 and
///   yields `InvalidData` on a bad byte) is SKIPPED, so one corrupt byte does
///   not hide every later entry. A previous `map_while(Result::ok)` stopped at
///   the first such line, dropping the remainder of the store.
/// * Any OTHER error kind BREAKS the loop. A persistent I/O fault keeps
///   yielding the SAME `Err` from every `next()`, so an unconditional `continue`
///   would be an unbounded spin — we stop reading instead and return what we
///   have so far (fail-open, consistent with the corrupt-line-skip contract).
///
/// An absent / unopenable file yields an empty vec.
pub fn read_store_lines(path: &Path) -> Vec<String> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    collect_store_lines(std::io::BufReader::new(file))
}

/// Reader-generic core of [`read_store_lines`]. Split out so the
/// skip-`InvalidData` / break-on-other-error termination contract is unit-
/// testable against a custom `BufRead` (a real `File` cannot be made to yield a
/// deterministic non-`InvalidData` error across platforms).
pub fn collect_store_lines<R: BufRead>(reader: R) -> Vec<String> {
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    out
}

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

#[cfg(test)]
mod store_line_tests {
    use super::collect_store_lines;
    use std::io::{self, BufRead, Read};

    /// A `BufRead` whose `read_line` first yields some good lines, then returns
    /// a PERSISTENT non-`InvalidData` error on every subsequent call — modelling
    /// a hard I/O fault. If the loop `continue`d on this it would spin forever;
    /// the contract is to BREAK, so the call must return promptly with only the
    /// lines read before the fault.
    struct PersistentErrorReader {
        good: Vec<String>,
        idx: usize,
    }

    impl Read for PersistentErrorReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            // `lines()` uses `read_line`, not `read`; this is only here to
            // satisfy the `Read` supertrait bound on `BufRead`.
            Err(io::Error::other("unused"))
        }
    }

    impl BufRead for PersistentErrorReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Ok(&[])
        }
        fn consume(&mut self, _amt: usize) {}
        // `lines()` calls `read_line` under the hood; override it directly so we
        // control exactly what each iteration yields.
        fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
            if self.idx < self.good.len() {
                buf.push_str(&self.good[self.idx]);
                buf.push('\n');
                self.idx += 1;
                Ok(self.good[self.idx - 1].len() + 1)
            } else {
                // Persistent fault: returns the SAME error every call. A
                // `continue`-on-all-errors loop would never terminate.
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "persistent fault",
                ))
            }
        }
    }

    #[test]
    fn persistent_non_invaliddata_error_breaks_does_not_spin() {
        // CodeRabbit R6 #7: an unbounded `continue` on every read error spins
        // forever on a persistent fault. `collect_store_lines` must BREAK on a
        // non-`InvalidData` error and return the lines gathered so far. This
        // test would hang (not fail) on a regression — it is deliberately
        // cheap so the suite still time-boxes.
        let reader = PersistentErrorReader {
            good: vec!["one".to_string(), "two".to_string()],
            idx: 0,
        };
        let lines = collect_store_lines(reader);
        assert_eq!(lines, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn invalid_utf8_line_is_skipped_not_fatal() {
        // The recoverable case: a single invalid-UTF-8 line is skipped and the
        // reader keeps going. A real `BufReader` over bytes yields `InvalidData`
        // for the bad line, then continues.
        let bytes: Vec<u8> = [b"good1\n".as_ref(), &[0xff, 0xfe, b'\n'], b"good2\n"].concat();
        let lines = collect_store_lines(std::io::BufReader::new(&bytes[..]));
        assert_eq!(lines, vec!["good1".to_string(), "good2".to_string()]);
    }
}

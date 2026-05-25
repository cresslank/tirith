//! `tirith share <file>` and `tirith redact` — audience-aware output
//! redaction (M7 ch2).
//!
//! Both subcommands feed the input through
//! [`tirith_core::redact::redact_for_audience_with_custom`] (or
//! [`tirith_core::redact::redact_for_audience`] when no policy is
//! configured) and emit the redacted content to stdout. A summary of
//! per-label counts goes to stderr; `--json` swaps the human summary for
//! the documented JSON envelope.
//!
//! ## Audiences (CLI value → behavior)
//!
//! | `--target` / `--audience` | Strips |
//! |---|---|
//! | `github-issue` | secrets + internal hostnames; preserves repo paths |
//! | `slack`        | same as github-issue |
//! | `llm`          | secrets only; preserves stack traces + paths + line numbers |
//! | `public-paste` | most aggressive: also `/home/<u>`, `/Users/<u>`, RFC1918 IPs in hostname context |
//! | `generic`      | same as llm — the safe default |
//!
//! `share` reads from a file path (or `-` for stdin); `redact` always
//! reads stdin. Both exit 0 on success and 1 on I/O errors.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tirith_core::policy::Policy;
use tirith_core::redact::{
    redact_for_audience_with_custom, RedactReport, RedactionCount, ShareAudience,
};

/// Output of `tirith share` and `tirith redact` in `--json` mode.
///
/// Kept stable on purpose so wrappers can pipe `tirith share --json` into
/// jq filters without breaking. Matches the M7 ch2 spec:
/// `{ redacted_content, redactions: [{ label, count }, ...] }`.
#[derive(serde::Serialize)]
struct JsonOut<'a> {
    redacted_content: &'a str,
    redactions: &'a [RedactionCount],
}

/// `tirith share <path>` entry point.
///
/// Returns the process exit code: 0 on success, 1 on I/O failure.
/// Reads `path` (or stdin when `path == None` or `path == "-"`), runs the
/// audience-aware redactor, and writes the redacted content to
/// `out_path` (or stdout when `out_path == None`).
pub fn share(
    path: Option<&Path>,
    out_path: Option<&Path>,
    target: ShareAudience,
    json: bool,
) -> i32 {
    let input = match read_input(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith share: failed to read {}: {e}", display_label(path));
            return 1;
        }
    };

    let customer_patterns = load_customer_id_patterns();
    let report = redact_for_audience_with_custom(&input, target, &customer_patterns);

    if json {
        emit_json(&report, target)
    } else {
        if let Err(code) = write_output(out_path, &report.redacted_content) {
            return code;
        }
        print_human_summary(&report, target);
        0
    }
}

/// `tirith redact` entry point. Always stdin → stdout.
pub fn redact_stdin(audience: ShareAudience, json: bool) -> i32 {
    let input = match read_stdin() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith redact: failed to read stdin: {e}");
            return 1;
        }
    };

    let customer_patterns = load_customer_id_patterns();
    let report = redact_for_audience_with_custom(&input, audience, &customer_patterns);

    if json {
        emit_json(&report, audience)
    } else {
        if let Err(code) = write_output(None, &report.redacted_content) {
            return code;
        }
        print_human_summary(&report, audience);
        0
    }
}

/// Resolve `policy.share.customer_id_patterns` from the nearest discovered
/// policy. Failure to discover or load the policy is non-fatal: this is
/// off-hot-path utility code, and an empty list is the safe default.
///
/// We use [`Policy::discover_partial`] equivalent semantics by reading
/// only the local discovery path — the remote policy server is not in
/// scope for off-hot-path utility commands.
fn load_customer_id_patterns() -> Vec<String> {
    // `Policy::discover_local` is the private cousin of `discover`; the
    // public surface is `discover_partial`, which loads the same struct
    // shape (no remote fetch). For an empty `policy.share.customer_id_patterns`
    // section the default is the empty `Vec`.
    Policy::discover_partial(None).share.customer_id_patterns
}

fn read_input(path: Option<&Path>) -> std::io::Result<String> {
    match path {
        None => read_stdin(),
        Some(p) if p.as_os_str() == "-" => read_stdin(),
        Some(p) => fs::read_to_string(p),
    }
}

fn read_stdin() -> std::io::Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

fn display_label(path: Option<&Path>) -> String {
    match path {
        None => "<stdin>".to_string(),
        Some(p) if p.as_os_str() == "-" => "<stdin>".to_string(),
        Some(p) => p.display().to_string(),
    }
}

/// Write `content` to `out_path` if `Some`, else to stdout. Returns
/// `Err(exit_code)` on write failure.
fn write_output(out_path: Option<&Path>, content: &str) -> Result<(), i32> {
    match out_path {
        Some(p) => {
            if let Err(e) = fs::write(p, content) {
                eprintln!("tirith share: failed to write {}: {e}", p.display());
                return Err(1);
            }
            Ok(())
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            if stdout.write_all(content.as_bytes()).is_err() {
                eprintln!("tirith share: failed to write to stdout (broken pipe?)");
                return Err(1);
            }
            // Match `view`'s contract: append a newline when the content
            // didn't end in one. Avoids surprises in shells where the
            // prompt redraw would otherwise clobber the last line.
            if !content.ends_with('\n') {
                let _ = writeln!(stdout);
            }
            Ok(())
        }
    }
}

fn emit_json(report: &RedactReport, audience: ShareAudience) -> i32 {
    let _ = audience; // future: include in envelope when the schema rev needs it.
    let out = JsonOut {
        redacted_content: &report.redacted_content,
        redactions: &report.redactions,
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
        eprintln!("tirith share: failed to write JSON output");
        return 1;
    }
    0
}

/// Print the per-label summary to stderr.
///
/// Format: `tirith share: target=<aud>; removed N <label1>, M <label2>, ...`
///
/// When the report is empty we still print the target line so callers
/// piping `share` into `tee` get a confirmation that the run completed.
fn print_human_summary(report: &RedactReport, audience: ShareAudience) {
    let target = match audience {
        ShareAudience::GithubIssue => "github-issue",
        ShareAudience::Slack => "slack",
        ShareAudience::Llm => "llm",
        ShareAudience::PublicPaste => "public-paste",
        ShareAudience::Generic => "generic",
    };

    if report.redactions.is_empty() {
        eprintln!("tirith share: target={target}; no redactions applied");
        return;
    }

    let parts: Vec<String> = report
        .redactions
        .iter()
        .map(|r| format!("{} {}", r.count, r.label))
        .collect();
    eprintln!(
        "tirith share: target={target}; removed {}",
        parts.join(", ")
    );
}

/// Parse the CLI string into a [`ShareAudience`]. Returns a clap-style
/// error message listing valid values when the input is unrecognized.
pub fn parse_audience(s: &str) -> Result<ShareAudience, String> {
    ShareAudience::parse_cli(s).ok_or_else(|| {
        format!(
            "invalid audience '{s}' (expected one of: {})",
            ShareAudience::cli_values().join(", ")
        )
    })
}

/// Resolve an optional `--out <path>` argument. `None` means "stdout";
/// `Some("-")` is also treated as stdout for consistency with `share`'s
/// path input semantics.
pub fn resolve_out_path(s: Option<&str>) -> Option<PathBuf> {
    match s {
        None => None,
        Some("-") => None,
        Some(p) => Some(PathBuf::from(p)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn share_audience_parser_accepts_canonical_names() {
        assert!(parse_audience("github-issue").is_ok());
        assert!(parse_audience("slack").is_ok());
        assert!(parse_audience("llm").is_ok());
        assert!(parse_audience("public-paste").is_ok());
        assert!(parse_audience("generic").is_ok());
    }

    #[test]
    fn share_audience_parser_rejects_unknown_with_listing() {
        let err = parse_audience("zoom").unwrap_err();
        assert!(err.contains("expected one of"));
        assert!(err.contains("github-issue"));
    }

    #[test]
    fn share_writes_to_out_path_when_given() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("in.log");
        let out = dir.path().join("out.log");
        // Use a fake AWS key so a redaction happens.
        fs::write(&input, "key=AKIAIOSFODNN7EXAMPLE done\n").unwrap();
        let code = share(Some(&input), Some(&out), ShareAudience::Llm, false);
        assert_eq!(code, 0);
        let written = fs::read_to_string(&out).unwrap();
        assert!(!written.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn resolve_out_path_treats_dash_as_stdout() {
        assert!(resolve_out_path(None).is_none());
        assert!(resolve_out_path(Some("-")).is_none());
        assert_eq!(
            resolve_out_path(Some("/tmp/foo.txt")),
            Some(PathBuf::from("/tmp/foo.txt"))
        );
    }
}

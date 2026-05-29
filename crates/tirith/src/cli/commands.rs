//! M11 ch2 — `tirith commands init|list|run|check`.
//!
//! A thin CLI over the repo command manifest (`.tirith/commands.yaml`,
//! [`tirith_core::commands_manifest`]). The manifest is SUPPRESSION-BOUNDED: it
//! can suppress only the Info `repo_command_unknown` annotation for an exact
//! `allowed[]` match, and ELEVATE via a blocking `repo_command_dangerous_pattern`
//! on a `dangerous[]` glob match. It can NEVER weaken a real engine finding —
//! see the module doc on `commands_manifest`.
//!
//! - `init` — write the starter manifest to `<repo>/.tirith/commands.yaml`.
//! - `list` — print the catalogued `allowed[]` / `dangerous[]` entries.
//! - `run` — look up an `allowed[]` entry by name and execute its command, but
//!   ONLY after re-checking it through the engine (an allowed entry that the
//!   engine flags High/Critical is refused — the manifest cannot bypass
//!   detection here either).
//! - `check` — evaluate an arbitrary command against the manifest + engine
//!   (delegates to `tirith check`).

use std::process::Command;

use tirith_core::commands_manifest::{CommandsManifest, DangerousAction, ManifestError};

/// `tirith commands init` — write the starter `.tirith/commands.yaml`.
///
/// Refuses to overwrite an existing file unless `force` is set (so a hand-
/// edited manifest is never clobbered by accident).
pub fn init(force: bool, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let path = match tirith_core::commands_manifest::init_manifest_path(cwd.as_deref()) {
        Some(p) => p,
        None => {
            // A broken-pipe JSON write returns 2 (the JSON error never reached the
            // consumer); otherwise the semantic 1.
            if !emit_error(
                json,
                "tirith commands init",
                "could not resolve a target directory for .tirith/commands.yaml",
            ) {
                return 2;
            }
            return 1;
        }
    };

    if path.exists() && !force {
        if !emit_error(
            json,
            "tirith commands init",
            &format!(
                "{} already exists; pass --force to overwrite",
                path.display()
            ),
        ) {
            return 2;
        }
        return 1;
    }

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            if !emit_error(
                json,
                "tirith commands init",
                &format!("create {}: {e}", parent.display()),
            ) {
                return 2;
            }
            return 1;
        }
    }

    if let Err(e) = std::fs::write(&path, tirith_core::commands_manifest::STARTER_MANIFEST) {
        if !emit_error(
            json,
            "tirith commands init",
            &format!("write {}: {e}", path.display()),
        ) {
            return 2;
        }
        return 1;
    }

    if json {
        let v = serde_json::json!({
            "written": path.display().to_string(),
            "forced": force,
        });
        // A failed JSON write (e.g. broken pipe) must exit non-zero: the manifest
        // WAS written on disk, but a piped consumer that saw truncated JSON must
        // not also read a success code (mirrors command-card sign/verify).
        if !super::write_json_stdout(&v, "tirith commands init: failed to write JSON output") {
            return 2;
        }
    } else {
        println!("Wrote starter command manifest to {}", path.display());
        eprintln!("Edit it, then `tirith commands list` to review the catalogue.");
    }
    0
}

/// `tirith commands list` — print the manifest's catalogue.
pub fn list(json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let manifest = match CommandsManifest::discover(cwd.as_deref()) {
        Ok(Some(m)) => m,
        Ok(None) => {
            if json {
                let v = serde_json::json!({ "manifest": null, "allowed": [], "dangerous": [] });
                // A failed JSON write must surface non-zero so a piped consumer
                // never pairs truncated/absent JSON with a success exit.
                if !super::write_json_stdout(
                    &v,
                    "tirith commands list: failed to write JSON output",
                ) {
                    return 2;
                }
            } else {
                println!(
                    "No .tirith/commands.yaml found for this repo. Run `tirith commands init` to create one."
                );
            }
            return 0;
        }
        Err(e) => {
            if !emit_error(json, "tirith commands list", &manifest_err(&e)) {
                return 2;
            }
            return 1;
        }
    };

    if json {
        let allowed: Vec<_> = manifest
            .allowed
            .iter()
            .map(|e| serde_json::json!({ "name": e.name, "command": e.command }))
            .collect();
        let dangerous: Vec<_> = manifest
            .dangerous
            .iter()
            .map(|e| serde_json::json!({ "pattern": e.pattern, "action": dangerous_action_label(e.action) }))
            .collect();
        let v = serde_json::json!({ "allowed": allowed, "dangerous": dangerous });
        // A failed JSON write must surface non-zero so a piped consumer never
        // pairs a truncated catalogue with a success exit.
        if !super::write_json_stdout(&v, "tirith commands list: failed to write JSON output") {
            return 2;
        }
    } else {
        if manifest.allowed.is_empty() {
            println!("allowed: (none)");
        } else {
            println!("allowed:");
            for e in &manifest.allowed {
                println!("  {:<16} {}", e.name, e.command);
            }
        }
        if manifest.dangerous.is_empty() {
            println!("dangerous: (none)");
        } else {
            println!("dangerous:");
            for e in &manifest.dangerous {
                println!("  {:<7} {}", dangerous_action_label(e.action), e.pattern);
            }
        }
    }
    0
}

/// `tirith commands run <name>` — execute the `allowed[]` command named
/// `name`, after re-checking it through the engine.
///
/// SECURITY: being in `allowed[]` only suppresses the `repo_command_unknown`
/// annotation; it does NOT make a command safe to run blindly. We run the
/// resolved command back through `tirith check` first and REFUSE to execute if
/// the engine blocks it (a `dangerous[]` match or any real High/Critical
/// finding). This keeps the "manifest cannot bypass detection" invariant on the
/// execution path too.
pub fn run(name: &str, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let manifest = match CommandsManifest::discover(cwd.as_deref()) {
        Ok(Some(m)) => m,
        Ok(None) => {
            if !emit_error(
                json,
                "tirith commands run",
                "no .tirith/commands.yaml found for this repo (run `tirith commands init`)",
            ) {
                return 2;
            }
            return 1;
        }
        Err(e) => {
            if !emit_error(json, "tirith commands run", &manifest_err(&e)) {
                return 2;
            }
            return 1;
        }
    };

    let entry = match manifest.allowed.iter().find(|e| e.name == name) {
        Some(e) => e,
        None => {
            let names: Vec<&str> = manifest.allowed.iter().map(|e| e.name.as_str()).collect();
            if !emit_error(
                json,
                "tirith commands run",
                &format!(
                    "no allowed command named '{name}'. Available: {}",
                    if names.is_empty() {
                        "(none)".to_string()
                    } else {
                        names.join(", ")
                    }
                ),
            ) {
                return 2;
            }
            return 1;
        }
    };
    let command = entry.command.clone();

    // Discover the repo policy once so the audit log redacts the command text
    // with the operator's custom DLP patterns (same as `tirith check`), and the
    // findings render below sees the same policy-derived view.
    let policy = tirith_core::policy::Policy::discover(cwd.as_deref());

    // Re-check the resolved command through the engine. The manifest CANNOT
    // bypass detection: if the engine blocks (dangerous match, High/Critical
    // finding), we refuse to run it.
    let verdict = analyze_command(&command, cwd.as_deref());
    if verdict.action == tirith_core::verdict::Action::Block {
        // Audit the refusal so the blocked attempt is traceable.
        let _ = tirith_core::audit::log_verdict(
            &verdict,
            &command,
            None,
            None,
            &policy.dlp_custom_patterns,
        );
        let refusal = format!(
            "refusing to run '{name}' ({command}): tirith blocked it. \
             Inspect with `tirith commands check -- \"{command}\"`."
        );
        if json {
            // ONE combined JSON object: the verdict (action + findings) AND the
            // refusal, never two concatenated documents. (Previously
            // `render_findings` wrote a verdict JSON and `emit_error` wrote a
            // second `{"error":...}` JSON.)
            //
            // If the single-object write fails (e.g. broken pipe), the `--json`
            // contract that a machine consumer reads exactly one parseable object
            // is broken — returning the block exit code would falsely signal a
            // clean refusal even though nothing reached the caller. Report the
            // JSON-write failure instead (exit 2, the same code the
            // allow/warn-proceed write-failure path uses below).
            let wrote = emit_run_json(
                name,
                &command,
                &verdict,
                &policy.dlp_custom_patterns,
                /* running */ false,
                /* refused */ true,
                Some(&refusal),
            );
            return json_refusal_exit_code(wrote, verdict.action.exit_code());
        } else {
            // Human: surface WHY it was blocked (findings to stderr), then the
            // refusal line (also stderr) — mirroring `tirith check`.
            render_findings(&verdict, &policy.dlp_custom_patterns, json);
            emit_error(json, "tirith commands run", &refusal);
        }
        return verdict.action.exit_code();
    }

    // Audit the (allowed, non-blocked) run before executing it.
    let _ = tirith_core::audit::log_verdict(
        &verdict,
        &command,
        None,
        None,
        &policy.dlp_custom_patterns,
    );

    // A Warn/WarnAck verdict on an allowed command must NEVER be silently
    // swallowed: render its findings just like `tirith check` does. In an
    // interactive TTY, require explicit acknowledgement before running (mirrors
    // check.rs's strict-warn prompt); non-interactive callers see the findings
    // and proceed. (Block already returned above.)
    //
    // In JSON mode the findings are NOT rendered here (that would emit a
    // standalone verdict JSON); they are folded into the single combined object
    // emitted at the running/abort exit below.
    if verdict.action != tirith_core::verdict::Action::Allow {
        if !json {
            render_findings(&verdict, &policy.dlp_custom_patterns, json);
        }

        let interactive = if let Ok(val) = std::env::var("TIRITH_INTERACTIVE") {
            val == "1"
        } else {
            is_terminal::is_terminal(std::io::stderr())
        };
        if interactive {
            // Prompt always goes to stderr so stdout stays a single JSON object.
            eprint!(
                "tirith: proceed with {} warning(s) and run '{name}'? [y/N] ",
                verdict.findings.len()
            );
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            if !matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
                if json {
                    // Declined: ONE object recording the warn verdict + that we
                    // did not run it (refused by the user). A failed write breaks
                    // the single-object `--json` contract, so report the
                    // JSON-write failure (exit 2) rather than the abort code (1) —
                    // the caller never received the abort record.
                    let wrote = emit_run_json(
                        name,
                        &command,
                        &verdict,
                        &policy.dlp_custom_patterns,
                        /* running */ false,
                        /* refused */ true,
                        Some("aborted by user"),
                    );
                    return json_refusal_exit_code(wrote, 1);
                } else {
                    eprintln!("tirith commands run: aborted by user.");
                }
                return 1;
            }
        }
    }

    if json {
        // The single combined object for an allow / warn-proceed run. Emitted
        // BEFORE the spawn so a failed JSON write aborts BEFORE the command runs:
        // a piped consumer that asked for `--json` and saw a truncated record
        // must not have the command silently run anyway. Exit 2 (distinct from a
        // command's own exit code) signals the harness I/O failure.
        if !emit_run_json(
            name,
            &command,
            &verdict,
            &policy.dlp_custom_patterns,
            /* running */ true,
            /* refused */ false,
            None,
        ) {
            return 2;
        }
    } else {
        eprintln!("Running allowed command '{name}': {command}");
    }

    match run_shell_command(&command) {
        Ok(code) => code,
        Err(e) => {
            // The combined object (running:true) was already written to stdout;
            // a spawn failure now reports ONLY to stderr so stdout stays a single
            // JSON document. Human mode already routes through emit_error→stderr.
            if json {
                eprintln!("tirith commands run: failed to spawn command: {e}");
            } else {
                emit_error(
                    json,
                    "tirith commands run",
                    &format!("failed to spawn command: {e}"),
                );
            }
            1
        }
    }
}

/// Map a refusal-path JSON write result to the process exit code. On a clean
/// write the caller's refusal code (block action code, or 1 for a user abort) is
/// returned; on a write failure the single-object `--json` contract is broken
/// (the consumer never received the refusal record), so exit 2 — the same
/// JSON-write-failure code the allow/warn-proceed path returns — is reported
/// instead. Pure so the contract is unit-testable without a deterministically-
/// failing real stdout (mirrors the seam note on `cli::write_json_to`).
fn json_refusal_exit_code(wrote_ok: bool, refusal_code: i32) -> i32 {
    if wrote_ok {
        refusal_code
    } else {
        2
    }
}

/// Emit the single combined `commands run --json` object and return whether the
/// write succeeded. This is the ONLY JSON writer on the `commands run` stdout
/// path — every exit (block-refuse, warn-decline, allow/warn-proceed) routes
/// through it so a machine consumer always reads exactly one parseable object
/// per invocation, never two concatenated documents.
///
/// Shape: `{"name","command","action","findings":[...],"running":bool,
/// "refused":bool,"error":null|"..."}`. `findings` carries the same redacted
/// `Finding` records `tirith check` emits (DLP-redacted with the repo policy's
/// custom patterns).
fn emit_run_json(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    dlp_custom_patterns: &[String],
    running: bool,
    refused: bool,
    error: Option<&str>,
) -> bool {
    let v = build_run_json(
        name,
        command,
        verdict,
        dlp_custom_patterns,
        running,
        refused,
        error,
    );
    super::write_json_stdout(&v, "tirith commands run: failed to write JSON output")
}

/// Build the `commands run --json` object. Pure (no I/O) so the redaction
/// contract is unit-testable without a capturable stdout (mirrors the
/// `json_refusal_exit_code` seam). BOTH the `findings` AND the top-level
/// `command` are scrubbed with the same built-in + custom DLP patterns — leaving
/// the raw `command` would leak credentials / custom-DLP matches into JSON
/// stdout (and any log collector consuming it) even though `findings` is
/// redacted.
fn build_run_json(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    dlp_custom_patterns: &[String],
    running: bool,
    refused: bool,
    error: Option<&str>,
) -> serde_json::Value {
    let findings = tirith_core::redact::redacted_findings(&verdict.findings, dlp_custom_patterns);
    let redacted_command = tirith_core::redact::redact_command_text(command, dlp_custom_patterns);
    serde_json::json!({
        "name": name,
        "command": redacted_command,
        "action": verdict.action,
        "findings": findings,
        "running": running,
        "refused": refused,
        "error": error,
    })
}

/// Render a non-Allow verdict's findings the SAME way `tirith check` does so a
/// `commands run` Warn/Block surfaces its rules instead of being swallowed.
/// JSON goes to stdout (machine-readable), human output to stderr (so it does
/// not corrupt the executed command's stdout). No-op for an empty finding list.
fn render_findings(
    verdict: &tirith_core::verdict::Verdict,
    dlp_custom_patterns: &[String],
    json: bool,
) {
    if json {
        if tirith_core::output::write_json_with_suggestions(
            verdict,
            dlp_custom_patterns,
            None,
            std::io::stdout().lock(),
        )
        .is_err()
        {
            eprintln!("tirith commands run: failed to write JSON output");
        }
    } else if tirith_core::output::write_human(
        verdict,
        /* warn_only */ false,
        std::io::stderr().lock(),
    )
    .is_err()
    {
        eprintln!("tirith commands run: failed to write output");
    }
}

/// `tirith commands check -- "<cmd>"` — evaluate `cmd` against the manifest +
/// the full engine. Delegates to `tirith check`, which wires the manifest
/// (`repo_command_unknown` / `repo_command_dangerous_pattern`) into its normal
/// analysis. Exit code is the engine's action exit code.
pub fn check(cmd: &str, shell: &str, json: bool) -> i32 {
    // Reuse the exact `tirith check` path so manifest + engine semantics are
    // identical to a normal shell-hook check (no second, divergent code path).
    super::check::run(
        cmd, shell, json, /* non_interactive */ false, /* interactive_flag */ false,
        /* approval_check */ false, /* strict_warn */ false, /* no_daemon */ true,
        /* warn_only */ false, /* offline */ false,
        /* suggest_safe_command */ false, /* card */ None,
    )
}

/// The [`ShellType`](tirith_core::tokenize::ShellType) the safety re-check must
/// tokenize with: it MUST match the shell `run_shell_command` actually executes
/// (`cmd /C` on Windows, `$SHELL -c` → POSIX elsewhere). Analyzing a command
/// with the wrong shell can mis-tokenize pipes/operators and miss findings.
#[cfg(windows)]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Cmd;
#[cfg(not(windows))]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Posix;

/// Analyze `command` through the engine for `commands run`'s safety re-check.
fn analyze_command(command: &str, cwd: Option<&str>) -> tirith_core::verdict::Verdict {
    use tirith_core::engine::{self, AnalysisContext};
    use tirith_core::extract::ScanContext;

    let ctx = AnalysisContext {
        input: command.to_string(),
        // Match the shell that will actually run the command (see RUN_SHELL).
        shell: RUN_SHELL,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: cwd.map(str::to_string),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
    };
    engine::analyze(&ctx)
}

/// Run `command` through the platform shell, inheriting stdio. Returns the
/// child's exit code (128 if killed by a signal with no code).
///
/// The shell family here MUST match what [`analyze_command`] tokenized with
/// (see [`RUN_SHELL`]): the safety re-check is only sound if the engine parsed
/// the command the way the shell that runs it will. On non-Windows we therefore
/// execute via a POSIX `sh -c` (matching `ShellType::Posix`) rather than
/// `$SHELL -c` — `$SHELL` may be fish/csh, whose word-splitting and operator
/// semantics differ from POSIX, which would let the re-check parse a DIFFERENT
/// command than the one actually executed. Windows uses `cmd /C` (matching
/// `ShellType::Cmd`).
fn run_shell_command(command: &str) -> std::io::Result<i32> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        // Deterministically POSIX `sh`, NOT `$SHELL`, so execution matches the
        // Posix analysis in `analyze_command`.
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(command);
        c
    };
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(128))
}

/// Stable label for a `dangerous[]` entry's action, shared by the JSON and
/// human `list` renderers. The action is per-entry (`block` → Block, `warn` →
/// Warn); hardcoding "block" here would misreport a `DangerousAction::Warn`
/// entry.
fn dangerous_action_label(action: DangerousAction) -> &'static str {
    match action {
        DangerousAction::Block => "block",
        DangerousAction::Warn => "warn",
    }
}

/// Human-readable rendering of a manifest load error.
fn manifest_err(e: &ManifestError) -> String {
    format!("could not load .tirith/commands.yaml: {e}")
}

/// Emit an error to stderr (human) or as a JSON `{"error": ...}` object.
///
/// Returns `false` when the JSON write itself failed (broken pipe / truncated
/// output) so a `--json` caller can surface a write failure rather than pairing a
/// semantic exit code with no JSON delivered (CodeRabbit R8 #5). Human mode
/// always returns `true` — the stderr line is best-effort and not gated.
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        let v = serde_json::json!({ "error": msg });
        super::write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        eprintln!("{ctx}: {msg}");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::RUN_SHELL;
    use tirith_core::tokenize::ShellType;

    #[test]
    fn run_shell_matches_execution_platform() {
        // F7: the `commands run` safety re-check must tokenize with the SAME
        // shell family `run_shell_command` executes: `cmd /C` on Windows, and a
        // deterministic POSIX `/bin/sh -c` (NOT `$SHELL -c`, which could be
        // fish/csh) elsewhere. A mismatch (e.g. analyze-as-Posix but run-as-fish)
        // can mis-tokenize and miss findings.
        #[cfg(windows)]
        assert_eq!(RUN_SHELL, ShellType::Cmd);
        #[cfg(not(windows))]
        assert_eq!(RUN_SHELL, ShellType::Posix);
    }

    /// F7: the resolved execution shell must match `RUN_SHELL`'s family even when
    /// `$SHELL` points at a non-POSIX shell. We can't easily introspect the
    /// `Command` built by the private `run_shell_command`, so we pin the
    /// invariant: on non-Windows the analysis is Posix AND execution is hardwired
    /// to `/bin/sh` (a POSIX shell), independent of `$SHELL`. This is a
    /// compile-time/structural guarantee — the function no longer reads `$SHELL`.
    #[cfg(not(windows))]
    #[test]
    fn execution_shell_is_posix_independent_of_env_shell() {
        // The constant the analysis uses is Posix...
        assert_eq!(RUN_SHELL, ShellType::Posix);
        // ...and `/bin/sh` exists on the unix CI/runners we target, so the
        // hardwired execution path is a real POSIX shell rather than `$SHELL`.
        assert!(
            std::path::Path::new("/bin/sh").exists(),
            "the deterministic POSIX execution shell /bin/sh must exist"
        );
    }

    /// CodeRabbit/Greptile R4 #4: on the `commands run --json` REFUSAL paths
    /// (engine-block and user-abort), a FAILED single-object JSON write must
    /// override the refusal exit code with 2 (the JSON-write-failure code) —
    /// returning the block/abort code while nothing reached the caller would
    /// falsely signal a clean refusal over a broken `--json` contract. A clean
    /// write preserves the refusal code. (The real stdout cannot be made to fail
    /// deterministically across platforms — see the `cli::write_json_to` seam
    /// note — so the exit-code decision is factored into this pure helper.)
    #[test]
    fn json_refusal_exit_code_overrides_on_write_failure() {
        use super::json_refusal_exit_code;
        // Block-refuse path: clean write keeps the block exit code (1); a failed
        // write reports the JSON-write failure (2).
        assert_eq!(json_refusal_exit_code(true, 1), 1);
        assert_eq!(json_refusal_exit_code(false, 1), 2);
        // User-abort path passes refusal_code = 1: same contract.
        assert_eq!(json_refusal_exit_code(true, 1), 1);
        assert_eq!(json_refusal_exit_code(false, 1), 2);
        // A non-1 block action code (defensive) is likewise preserved on a clean
        // write and overridden to 2 on failure.
        assert_eq!(json_refusal_exit_code(true, 3), 3);
        assert_eq!(json_refusal_exit_code(false, 3), 2);
    }

    /// CodeRabbit R6 #1: `commands run --json` must DLP-redact the top-level
    /// `command` string with the same patterns the findings use. A raw command
    /// would leak credentials / custom-DLP matches into JSON stdout (and any log
    /// collector), even though `findings` is already scrubbed.
    #[test]
    fn run_json_redacts_top_level_command_with_custom_dlp() {
        use super::build_run_json;
        use tirith_core::verdict::{Timings, Verdict};

        // A custom DLP pattern that matches an internal token shape, plus a
        // built-in-matching GitHub PAT to prove built-in patterns apply too.
        let custom = vec![r"ACME-[A-Z0-9]{6}".to_string()];
        let secret_token = "ACME-AB12CD";
        // Build the GitHub PAT at runtime (CodeRabbit R7 #7): a contiguous
        // `ghp_<36+>` LITERAL in the source trips secret scanners. 40 body chars
        // (`[A-Za-z0-9]`) still satisfy the built-in `ghp_[A-Za-z0-9]{36,}`.
        let pat = format!("ghp_{}", "a1B2c3D4".repeat(5)); // 40 alphanumeric chars
        let command = format!("deploy --token {secret_token} --pat {pat}");

        let verdict = Verdict::allow_fast(1, Timings::default());
        let v = build_run_json(
            "deploy", &command, &verdict, &custom, /* running */ true,
            /* refused */ false, None,
        );

        let emitted = v
            .get("command")
            .and_then(|c| c.as_str())
            .expect("command field is a string");

        // The raw secret token MUST NOT appear; the redaction placeholder MUST.
        assert!(
            !emitted.contains(secret_token),
            "custom-DLP token leaked into the JSON command field: {emitted}"
        );
        assert!(
            emitted.contains("[REDACTED:custom]"),
            "custom-DLP match should be replaced with the redaction placeholder: {emitted}"
        );
        // The built-in GitHub-PAT pattern is also applied (the raw PAT is gone).
        assert!(
            !emitted.contains(pat.as_str()),
            "built-in DLP (GitHub PAT) leaked into the JSON command field: {emitted}"
        );
        // The non-secret parts of the command survive so the record stays useful.
        assert!(emitted.contains("deploy --token"), "got: {emitted}");
    }
}

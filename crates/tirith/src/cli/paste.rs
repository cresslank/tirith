use std::io::Read;

use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::tokenize::ShellType;

pub fn run(
    shell: &str,
    json: bool,
    non_interactive: bool,
    interactive_flag: bool,
    html_path: Option<&str>,
    with_source: bool,
) -> i32 {
    const MAX_PASTE: u64 = 1024 * 1024;

    let mut raw_bytes = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_PASTE + 1)
        .read_to_end(&mut raw_bytes)
    {
        eprintln!("tirith: failed to read stdin: {e}");
        return 1;
    }
    if raw_bytes.len() as u64 > MAX_PASTE {
        eprintln!("tirith: paste input exceeds 1 MiB limit");
        return 1;
    }

    if raw_bytes.is_empty() {
        return 0;
    }

    let shell_type = match shell.parse::<ShellType>() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("tirith: warning: unknown shell '{shell}', falling back to posix");
            ShellType::Posix
        }
    };

    // Lossy is fine here — raw bytes are preserved separately for byte-scan rules.
    let input = String::from_utf8_lossy(&raw_bytes).into_owned();

    let interactive = if interactive_flag {
        true
    } else if non_interactive {
        false
    } else if let Ok(val) = std::env::var("TIRITH_INTERACTIVE") {
        val == "1"
    } else {
        is_terminal::is_terminal(std::io::stderr())
    };

    let clipboard_html = html_path.and_then(|path| match std::fs::read_to_string(path) {
        Ok(html) => Some(html),
        Err(e) => {
            eprintln!("tirith: warning: failed to read clipboard HTML from '{path}': {e}");
            None
        }
    });

    // M12 ch1 — G1 TOCTOU fix, completed with the tri-state. ONLY `--with-source`
    // consults the companion `clipboard_source.json`, and it reads it EXACTLY
    // ONCE: the same in-memory record feeds BOTH the engine (which fires
    // `paste_source_mismatch`) and the `--with-source` display below. The result
    // is mapped to a `ClipboardSourceState` so the engine can tell "the CLI tried
    // and found nothing" (`AbsentOrInvalid`) apart from "the CLI never looked"
    // (`Unread`):
    //
    //   * `--with-source` + record found → `Loaded(rec)`; the engine uses this
    //     exact record, so the displayed `clipboard_source` and the finding can
    //     never disagree after a fast copy-paste-copy.
    //   * `--with-source` + nothing found → `AbsentOrInvalid`; the engine must NOT
    //     re-read disk. Previously this collapsed to `None`, and the engine then
    //     re-read the file — so a sidecar WRITTEN between the CLI's read and the
    //     engine's could fire `paste_source_mismatch` while the CLI showed "no
    //     source". The tri-state closes that window.
    //   * no `--with-source` → `Unread`; the CLI did not consult the sidecar and
    //     does not display it, so the engine reads it once itself (the historical
    //     plain-`tirith paste` behavior, unchanged).
    let display_record = if with_source {
        tirith_core::clipboard::read_source_record()
    } else {
        None
    };
    let clipboard_source_state = if with_source {
        match display_record.clone() {
            Some(rec) => tirith_core::clipboard::ClipboardSourceState::Loaded(rec),
            None => tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        }
    } else {
        tirith_core::clipboard::ClipboardSourceState::Unread
    };

    let ctx = AnalysisContext {
        input,
        shell: shell_type,
        scan_context: ScanContext::Paste,
        raw_bytes: Some(raw_bytes),
        interactive,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html,
        card_ref: None,
        clipboard_source: clipboard_source_state,
    };

    // PR #121 fix-list item 18 (mirrors `install.rs:760` / `check.rs`):
    // single policy snapshot for analysis + enforcement + audit. Pre-fix
    // `engine::analyze` discovered policy internally, then the surrounding
    // code re-ran `Policy::discover` for the `apply_agent_rules` /
    // `filter_findings_by_paranoia` / audit calls below. A change to
    // `.tirith/policy.yaml` between the two reads then routed detection
    // and enforcement against inconsistent policies — a TOCTOU window.
    // `analyze_returning_policy` returns the same snapshot the engine
    // used so the rest of this function works against ONE policy.
    let (mut verdict, policy) = engine::analyze_returning_policy(&ctx);

    // M4 item 8: best-effort origin attribution for the paste path. The CLI
    // is the only place that knows whether the caller looked like a human,
    // an agent (via TIRITH_INTEGRATION), or a CI runner. The audit entry
    // below picks the origin up automatically.
    verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 follow-up — enforce `agent_rules.deny` here. The
    // paste path does NOT route through `post_process_verdict` (the engine
    // is the only consumer of escalation/session bookkeeping). Without
    // this call, an operator who writes a `deny` matcher to block an
    // untrusted agent would see deny enforce on `tirith check` but
    // silently fail on `tirith paste` (a clipboard-poisoning hostile
    // surface). The helper is a no-op on `Allowed`/`Unspecified`.
    //
    // M4 PR #120 fix-6 (Greptile P1): mirror the bypass-skip branch the
    // hot paths in `check`/`gateway` use — under `TIRITH=0`, the raw
    // verdict already wins and `apply_agent_rules` must NOT silently
    // re-Block. The pin
    // `paste_agent_rules_deny_skipped_under_tirith_bypass_today`
    // covers this; the `check` mirror is
    // `agent_rules_deny_skipped_under_tirith_bypass_today`.
    if !verdict.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut verdict, &policy);
    }

    // Audit must capture full detection BEFORE paranoia filtering (ADR-13:
    // engine always detects everything; paranoia is an output-layer filter).
    // M4 item 8 chunk 3 — bypass-honored verdicts are now logged here too,
    // because the engine no longer audits its own bypass path (so the CLI
    // can stamp `agent_origin` on the verdict before the audit line
    // is written). Pre-chunk-3 this branch SKIPPED audit when bypass was
    // honored, trusting `analyze()` to have logged.
    let event_id = uuid::Uuid::new_v4().to_string();
    // Best-effort audit on the `paste` hot path — a write failure must not
    // change behavior, so the Result is intentionally dropped.
    let _ = tirith_core::audit::log_verdict(
        &verdict,
        &ctx.input,
        None,
        Some(event_id),
        &policy.dlp_custom_patterns,
    );

    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    if verdict.action != tirith_core::verdict::Action::Allow {
        last_trigger::write_last_trigger(&verdict, &ctx.input, &policy.dlp_custom_patterns);
    }

    if json {
        // M12 ch1 — `--with-source`: enrich the JSON envelope with the attributed
        // clipboard source (the page the paste was copied from), as EXTRA
        // top-level keys, NOT as a Finding. Attribution only happens when the
        // companion extension's recorded `content_sha256` matches this paste's
        // hash; otherwise (no extension / stale record / hash mismatch) we report
        // a `clipboard_source: null` so a scripted caller can tell "no source
        // recorded" apart from a missing flag.
        let source_attribution = if with_source {
            // Hash the ORIGINAL clipboard bytes, in lockstep with the engine's
            // `paste_source_mismatch` rule (see `resolve_source_attribution`), so
            // the displayed source and the finding never disagree for a non-UTF-8
            // paste.
            let raw = ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes());
            Some(resolve_source_attribution(raw, display_record.as_ref()))
        } else {
            None
        };
        if write_paste_json(&verdict, &policy.dlp_custom_patterns, source_attribution).is_err() {
            eprintln!("tirith: failed to write JSON output");
        }
    } else {
        if output::write_human_auto(&verdict, false).is_err() {
            eprintln!("tirith: failed to write output");
        }
        // M12 ch1 — `--with-source` in human mode: print a one-line attribution
        // note to stderr (the structured keys live in `--json`). Graceful when no
        // source was recorded for this paste.
        if with_source {
            let raw = ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes());
            match resolve_source_attribution(raw, display_record.as_ref()) {
                serde_json::Value::Null => {
                    eprintln!("tirith paste: no clipboard source recorded for this paste");
                }
                v => {
                    let url = v
                        .get("source_url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("(unknown)");
                    eprintln!("tirith paste: clipboard source: {url}");
                }
            }
        }
    }

    verdict.action.exit_code()
}

/// Resolve the attributed clipboard source for this paste, if the companion
/// extension recorded one whose `content_sha256` matches the pasted bytes.
/// Returns a JSON object (`{source_url, source_title}`) on a match, or `null`
/// when there is no recorded source / the hash does not match / the extension
/// isn't installed — so `--with-source` always emits a `clipboard_source` key and
/// a scripted caller can distinguish "matched source" from "no source recorded".
///
/// `raw` is the ORIGINAL clipboard bytes (the caller passes
/// `ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes())`). We hash THESE,
/// not the lossy `ctx.input` &str, so this display stays in LOCKSTEP with
/// the `paste_source_mismatch` rule (which also hashes the raw bytes): a non-UTF-8
/// paste must never make the displayed `clipboard_source` and the finding
/// disagree.
///
/// G1 TOCTOU fix: the `record` is the SAME one already read once at the top of
/// `run` and handed to the engine, so the displayed attribution and the
/// `paste_source_mismatch` finding can never disagree. We do NOT re-read
/// `clipboard_source.json` here.
fn resolve_source_attribution(
    raw: &[u8],
    record: Option<&tirith_core::clipboard::ClipboardSourceRecord>,
) -> serde_json::Value {
    let Some(record) = record else {
        return serde_json::Value::Null;
    };
    // Same shared comparison the engine's rule uses (`matches_bytes`), so the
    // displayed attribution and the PasteSourceMismatch finding can never disagree
    // (Greptile R1 #6). `raw` is the original pasted bytes, not a lossy String.
    if !record.matches_bytes(raw) {
        // A recorded source exists, but it does NOT describe this paste (stale
        // record / clipboard replaced). No attribution.
        return serde_json::Value::Null;
    }
    // The provenance fields originate from an arbitrary web page via the
    // (untrusted) browser extension, so they are sanitized before being
    // surfaced into `--json` or printed to the terminal: the URL's
    // query/fragment/userinfo (which can carry signed-URL tokens, session ids,
    // or email identifiers) are dropped, terminal control sequences are
    // stripped (tirith must not itself emit the injection it detects), and both
    // fields are length-capped. Both the human stderr path and the JSON path
    // read these sanitized values, so no raw `source_url`/`source_title` leaks.
    serde_json::json!({
        "source_url": sanitize_source_url(&record.source_url),
        "source_title": sanitize_provenance_text(&record.source_title),
    })
}

/// Max characters of provenance text surfaced into output. Bounds how much of a
/// (potentially sensitive) page title or path can leak into logs / JSON.
const PROVENANCE_MAX_CHARS: usize = 256;

/// Neutralize one untrusted provenance string before display/logging. The
/// `source_url` / `source_title` originate from an arbitrary web page (via the
/// browser extension), so they run through tirith's own output sanitizer — the
/// same `output_filter` the MCP gateway applies to error fields — which strips
/// ANSI/OSC/APC/DCS escape sequences, bare CR, other C0 controls, DEL, and
/// zero-width characters (tirith must never itself emit the terminal injection
/// it exists to detect). The tabs/newlines that sanitizer legitimately keeps
/// are then flattened to spaces for a tidy single line, and the result is
/// length-capped.
fn sanitize_provenance_text(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    tirith_core::mcp::output_filter::sanitize_text_into(s.as_bytes(), &mut out);
    let cleaned = String::from_utf8(out).unwrap_or_default();
    let flattened: String = cleaned
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    cap_chars(flattened.trim(), PROVENANCE_MAX_CHARS)
}

/// Redact the high-risk parts of a source URL — the query string, fragment, and
/// any embedded `user:pass@` userinfo can carry signed-URL tokens, session ids,
/// or email identifiers — while keeping the meaningful `scheme://host/path`
/// provenance, then sanitize + cap it like any other provenance text. A value
/// that does not parse as a URL is still sanitized verbatim (we never emit raw
/// untrusted bytes) but is not structurally redacted.
fn sanitize_source_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            parsed.set_query(None);
            parsed.set_fragment(None);
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            sanitize_provenance_text(parsed.as_str())
        }
        Err(_) => sanitize_provenance_text(url),
    }
}

/// Truncate to at most `max` characters (not bytes), appending `…` when cut.
fn cap_chars(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

/// Write the paste verdict as JSON, optionally splicing a top-level
/// `clipboard_source` key (`--with-source`). We render the verdict through the
/// shared `output::write_json` (so the envelope shape is identical to every
/// other JSON surface), then, only when source attribution was requested, parse
/// it back into a `serde_json::Value` to add the extra key. Without
/// `--with-source` this is byte-identical to `output::write_json`.
fn write_paste_json(
    verdict: &tirith_core::verdict::Verdict,
    custom_patterns: &[String],
    source_attribution: Option<serde_json::Value>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let Some(source) = source_attribution else {
        return output::write_json(verdict, custom_patterns, std::io::stdout().lock());
    };
    // Render the canonical envelope to a buffer, then add the extra key. A parse
    // failure here is impossible for our own serializer, but handle it by falling
    // back to the plain envelope rather than dropping output.
    let mut buf = Vec::new();
    output::write_json(verdict, custom_patterns, &mut buf)?;
    let mut value: serde_json::Value = match serde_json::from_slice(&buf) {
        Ok(v) => v,
        Err(_) => {
            // Unreachable in practice (our own serializer always emits valid
            // JSON), but if it ever happened we must still emit newline-
            // terminated output for line-oriented consumers. `write_json` already
            // appended a trailing newline to `buf`; flush it, then guarantee
            // termination explicitly rather than relying on that invariant.
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&buf)?;
            return writeln!(stdout);
        }
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert("clipboard_source".to_string(), source);
    }
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    writeln!(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::clipboard::{content_sha256_hex, ClipboardSourceRecord};

    fn record_for(payload: &[u8], source_url: &str, source_title: &str) -> ClipboardSourceRecord {
        ClipboardSourceRecord {
            updated_at: "2026-05-30T00:00:00Z".to_string(),
            // matching hash so attribution proceeds (matches_bytes == true)
            content_sha256: content_sha256_hex(payload),
            source_url: source_url.to_string(),
            source_title: source_title.to_string(),
            hidden_text_detected: false,
        }
    }

    // A recorded source whose hash does NOT match the paste yields no attribution
    // (the displayed source must stay in lockstep with the rule's verdict).
    #[test]
    fn no_attribution_when_hash_mismatches() {
        let rec = record_for(b"the-real-bytes", "https://docs.example.com/x", "X");
        let v = resolve_source_attribution(b"DIFFERENT-bytes", Some(&rec));
        assert_eq!(v, serde_json::Value::Null);
    }

    // Major (CodeRabbit): provenance comes from an untrusted page, so the URL's
    // token-bearing query/fragment/userinfo must be stripped and any terminal
    // control sequence in the title neutralized before either output path emits it.
    #[test]
    fn provenance_is_sanitized_before_emission() {
        let payload = b"install-me";
        let rec = record_for(
            payload,
            "https://user:pw@docs.example.com/install?token=SECRET123&sig=ABC#section",
            // ANSI color escape + BEL + an embedded newline, injected via the page title
            "Install\u{1b}[31mGuide\u{07}\nline2",
        );
        let v = resolve_source_attribution(payload, Some(&rec));
        let url = v.get("source_url").and_then(|u| u.as_str()).unwrap();
        let title = v.get("source_title").and_then(|t| t.as_str()).unwrap();

        // URL: query, fragment, and userinfo dropped; meaningful path kept.
        assert_eq!(url, "https://docs.example.com/install");
        assert!(
            !url.contains("SECRET123"),
            "signed token must not leak: {url:?}"
        );
        assert!(!url.contains("token=") && !url.contains("sig="));
        assert!(!url.contains('#') && !url.contains("user:pw"));

        // Title: ANSI/BEL control sequences stripped, newline flattened, text kept.
        assert!(
            !title.contains('\u{1b}'),
            "ANSI escape must be stripped: {title:?}"
        );
        assert!(!title.contains('\u{07}'), "BEL must be stripped: {title:?}");
        assert!(
            !title.contains('\n'),
            "newline must be flattened: {title:?}"
        );
        assert!(title.contains("Install") && title.contains("Guide"));
    }

    // Long titles are length-capped so a sensitive page title can't dump
    // unbounded text into logs/JSON.
    #[test]
    fn provenance_title_is_length_capped() {
        let payload = b"x";
        let rec = record_for(
            payload,
            "https://example.com/",
            &"A".repeat(PROVENANCE_MAX_CHARS + 50),
        );
        let v = resolve_source_attribution(payload, Some(&rec));
        let title = v.get("source_title").and_then(|t| t.as_str()).unwrap();
        // capped to PROVENANCE_MAX_CHARS plus the single ellipsis marker
        assert!(title.chars().count() <= PROVENANCE_MAX_CHARS + 1);
        assert!(
            title.ends_with('…'),
            "truncation marker expected: {title:?}"
        );
    }

    // A non-URL provenance value is still sanitized (never emitted raw) even
    // though it can't be structurally redacted.
    #[test]
    fn non_url_source_is_still_sanitized() {
        let got = sanitize_source_url("not a url\u{1b}[2J\u{07}");
        assert!(!got.contains('\u{1b}') && !got.contains('\u{07}'));
    }
}

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
    };

    let mut verdict = engine::analyze(&ctx);

    let policy = tirith_core::policy::Policy::discover(ctx.cwd.as_deref());

    // Audit must capture full detection BEFORE paranoia filtering (ADR-13:
    // engine always detects everything; paranoia is an output-layer filter).
    // Skip if bypass was honored — analyze() already logged it.
    if !verdict.bypass_honored {
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
    }

    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    if verdict.action != tirith_core::verdict::Action::Allow {
        last_trigger::write_last_trigger(&verdict, &ctx.input, &policy.dlp_custom_patterns);
    }

    if json {
        if output::write_json(
            &verdict,
            &policy.dlp_custom_patterns,
            std::io::stdout().lock(),
        )
        .is_err()
        {
            eprintln!("tirith: failed to write JSON output");
        }
    } else if output::write_human_auto(&verdict, false).is_err() {
        eprintln!("tirith: failed to write output");
    }

    verdict.action.exit_code()
}

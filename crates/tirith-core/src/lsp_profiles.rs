//! M14 (IDE Extensions) — per-file-type LSP analysis profiles.
//!
//! The LSP server (a separate binary) opens a document, decides what KIND of
//! file it is, analyzes the buffer through [`crate::engine::analyze`] in a
//! chosen [`ScanContext`], and then POST-FILTERS the resulting
//! [`crate::verdict::Verdict::findings`] down to the diagnostics that make sense
//! for that file type. There is NO engine-side rule-category toggle: every rule
//! that the chosen [`ScanContext`] can fire runs, and this module's job is to
//! describe two things per file type —
//!
//!   1. [`contexts_for`] — the ORDERED list of [`ScanContext`]s to analyze the
//!      buffer in (this selects WHICH rule families even run on the hot path).
//!      Most profiles use a single context ([`scan_context_for`] is the
//!      one-context convenience accessor over it); [`LspProfile::AiConfig`] uses
//!      TWO ([`ScanContext::FileScan`] **and** [`ScanContext::Paste`]) because
//!      its two signal families live in DIFFERENT branches of `engine::analyze`
//!      (see [`contexts_for`] for the empirical rationale). The LSP server runs
//!      `analyze` once per context and UNIONs the findings before filtering.
//!   2. [`retains`] — the per-profile allow-set of [`RuleId`]s to KEEP in the
//!      diagnostics (the post-filter applied to the unioned `verdict.findings`).
//!
//! This crate adds NO new [`RuleId`] for M14 — every id named below is a
//! shipping variant, reachable today via the documented context.
//!
//! ## Routing precedence ([`profile_for_path`])
//!
//! Routing is by FILENAME first, then by EXTENSION. The precedence, highest to
//! lowest, is:
//!
//!   1. **AI-config** — wins over everything else, so a `CLAUDE.md` routes to
//!      [`LspProfile::AiConfig`] (NOT [`LspProfile::MarkdownInstallDoc`]), and a
//!      file under `.claude/` / `.cursor/rules/` routes to `AiConfig` regardless
//!      of its extension. Detected by the crate's canonical
//!      [`crate::rules::aifile::is_ai_config_file`] (directory-aware: `.claude/*`,
//!      `.cursor/*`, MCP server configs, the agent-instruction basename set).
//!   2. **Markdown install doc** — a curated set of install-documentation
//!      markdown filenames (`README.md`, `INSTALL.md`, …). NOT every `.md`.
//!   3. **Source code** — a curated source-extension set.
//!   4. **Log file** — the `.log` extension.
//!   5. else `None` — the safe default: the LSP surfaces NO diagnostics for an
//!      unrecognised file type rather than guessing.

use std::path::Path;

// `ScanContext` is defined in `crate::extract` (the engine re-imports it
// privately). This is the canonical public path and the type the engine's own
// public `analyze` / `build_dsl_backing` signatures take.
use crate::extract::ScanContext;
use crate::verdict::RuleId;

/// The per-file-type LSP analysis profile.
///
/// Each variant maps to a [`ScanContext`] ([`scan_context_for`]) and a
/// [`RuleId`] allow-set ([`retains`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LspProfile {
    /// `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.claude/*`, `.cursor/rules/*`,
    /// MCP server configs, … — the instruction surface a coding agent reads.
    /// Surfaces the STATIC hidden-instruction / invisible-unicode config rules.
    AiConfig,
    /// `README.md` / `INSTALL.md` / `docs/install.md` and friends — install
    /// documentation whose fenced code blocks carry `curl | sh` install lines.
    /// Surfaces URL/transport/hostname + command-shape (pipe-to-shell) rules.
    MarkdownInstallDoc,
    /// A source file (`.rs`, `.py`, `.ts`, …). Surfaces Unicode-confusable /
    /// bidi / zero-width terminal rules plus credential leaks.
    SourceCode,
    /// A `.log` file. Targets the M7 output-direction rules — but note these
    /// fire only via [`crate::engine::analyze_output`], so they are NOT
    /// surfaced on the LSP's per-document `analyze` path (PARTIAL/best-effort in
    /// v1; see [`scan_context_for`]).
    LogFile,
}

/// Curated install-documentation markdown FILENAMES (lowercased, basename only).
///
/// Deliberately NOT "every `.md`": a project's `CHANGELOG.md` or design notes
/// should not be analyzed for `curl | sh` install lines. Only the files that
/// conventionally hold copy-paste install instructions are routed here.
const INSTALL_DOC_BASENAMES: &[&str] = &[
    "readme.md",
    "install.md",
    "installation.md",
    "installing.md",
    "getting-started.md",
    "getting_started.md",
];

/// Curated source-code EXTENSIONS (lowercased, no dot).
///
/// Source files are analyzed for invisible-unicode / confusable homoglyph
/// trojan-source attacks and hard-coded credentials. The set is intentionally
/// finite (no "treat anything that looks like code" heuristic) so routing is
/// predictable. Shell-script extensions are included because a homoglyph or a
/// hidden credential in a checked-in `*.sh` is the same threat.
const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "py", "ts", "tsx", "js", "jsx", "mjs", "cjs", "go", "rb", "java", "kt", "c", "cc", "cpp",
    "cxx", "h", "hpp", "hh", "cs", "php", "swift", "scala", "sh", "bash", "zsh", "fish", "ps1",
];

/// Route a path to its LSP analysis profile, or `None` when the file type is
/// not one the LSP analyzes.
///
/// Precedence (see the module doc): AI-config (filename + directory) wins over
/// markdown-install-doc, which wins over the extension-based source/log routing.
/// A `CLAUDE.md` is therefore `AiConfig`, not `MarkdownInstallDoc`.
pub fn profile_for_path(path: &Path) -> Option<LspProfile> {
    // 1. AI-config wins over everything. The canonical detector is
    //    directory-aware (`.claude/*`, `.cursor/*`) and basename-aware
    //    (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, MCP configs, …), so a
    //    `CLAUDE.md` (which is also Markdown) routes here, not to the install-doc
    //    profile.
    if crate::rules::aifile::is_ai_config_file(path) {
        return Some(LspProfile::AiConfig);
    }

    let basename_lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase());

    // 2. Markdown install docs — curated basename set (NOT every `.md`).
    if let Some(ref name) = basename_lower {
        if INSTALL_DOC_BASENAMES.contains(&name.as_str()) {
            return Some(LspProfile::MarkdownInstallDoc);
        }
    }

    // 3/4. Extension-based routing — source code, then log files.
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if SOURCE_EXTENSIONS.contains(&ext_lower.as_str()) {
            return Some(LspProfile::SourceCode);
        }
        // `.log` only — a `*.log.1` rotated file keeps its `.log.1` extension, so
        // it does not match here (kept narrow on purpose).
        if ext_lower == "log" {
            return Some(LspProfile::LogFile);
        }
    }

    // 5. Safe default: no diagnostics for an unrecognised file type.
    None
}

/// The [`ScanContext`] in which to analyze a buffer for a given profile.
///
/// The context is chosen so that the profile's desired rule families ACTUALLY
/// FIRE on the [`crate::engine::analyze`] hot path (verified against the
/// tier-1/2/3 dispatch in `engine.rs`):
///
/// * [`LspProfile::AiConfig`] → [`ScanContext::FileScan`] (its PRIMARY context;
///   see [`contexts_for`] for the SECOND context this profile also analyzes in).
///   The static AI-config rules — `AgentInstructionHidden` (hidden HTML-comment /
///   visually-hidden directives), `ConfigInvisibleUnicode` / `ConfigNonAscii`
///   (config-file invisible / non-ASCII content), and the terminal byte-scan
///   hidden / bidi / zero-width family — run ONLY in the `FileScan` branch of
///   `engine::analyze` (`configfile::check` + `aifile::check` +
///   `terminal::check_bytes`). Exec / Paste never invoke those file-content
///   scanners. (The AI-config DRIFT rules `AiConfigHiddenInstructionAdded` /
///   `AiConfigToolUseEscalation` are diff-triggered against a snapshot and so
///   CANNOT fire on a single buffer — see the limitation note on [`retains`].)
///   The catch (verified empirically — see [`contexts_for`]): a SUSPICIOUS URL
///   sitting in a `CLAUDE.md` body (e.g. a `curl http://punycode-host | sh`
///   install line an agent might fetch) fires NOTHING in `FileScan` — the
///   URL/transport/hostname rules live in the Exec/Paste branch only. So this
///   profile is the one case that analyzes in TWO contexts ([`contexts_for`]).
///
/// * [`LspProfile::MarkdownInstallDoc`] → [`ScanContext::Paste`]. URL /
///   transport / hostname rules (`extract_urls` → `hostname`/`transport`/
///   `path`/`ecosystem::check`) and command-shape rules (`command::check` →
///   `PipeToInterpreter` / `CurlPipeShell` / …) run only in the Exec / Paste
///   branch — NOT in `FileScan`, which is the key reason a doc cannot be
///   analyzed as a file here. `Paste` is chosen over `Exec` because a README is
///   pasted-like prose, not a typed command: `Exec` strips a leading
///   `# tirith-card:` prelude and runs hot-path guards (taint / command-card /
///   commands-manifest / blast-radius) that are meaningless for documentation,
///   while `Paste` runs the URL + command-shape rules cleanly. (`Paste`'s
///   tier-1 regex is a superset of `Exec`'s, so nothing is gated out.)
///
/// * [`LspProfile::SourceCode`] → [`ScanContext::Paste`]. The Unicode-confusable
///   / bidi / zero-width terminal family and the credential detector both fire
///   in Paste: `Paste` runs `terminal::check_bytes` over the FULL raw byte
///   buffer (every terminal rule), whereas `Exec` filters the byte-scan down to
///   the invisible-char subset and drops ANSI / control. `credential::check`
///   fires in both Exec and Paste (it only no-ops for `FileScan`).
///
/// * [`LspProfile::LogFile`] → [`ScanContext::Paste`]. DOCUMENTED LIMITATION
///   (see [`retains`]): the M7 `output_*` rules fire ONLY from
///   [`crate::engine::analyze_output`], never from `engine::analyze` in ANY
///   context. Since the LSP per-document path calls `analyze`, the `output_*`
///   family is not reachable on a single buffer through `analyze`. `Paste` is
///   the best-fit `analyze` context for a log (terminal byte-scan + prompt-
///   injection over the raw bytes); a LogFile-aware LSP server that wants the
///   true `output_*` diagnostics must route the buffer through `analyze_output`
///   instead and apply the same [`retains`] allow-set.
pub fn scan_context_for(profile: LspProfile) -> ScanContext {
    // The first (primary) element of `contexts_for` — single source of truth so
    // the one-context accessor can never drift from the multi-context list.
    contexts_for(profile)[0]
}

/// The ORDERED list of [`ScanContext`]s to analyze a buffer in for a given
/// profile. The LSP server runs [`crate::engine::analyze`] once PER context and
/// UNIONs the resulting findings, then applies [`retains`].
///
/// Every profile EXCEPT [`LspProfile::AiConfig`] returns exactly one context
/// (the same value [`scan_context_for`] yields). `AiConfig` returns TWO:
///
/// 1. [`ScanContext::FileScan`] — the static AI-config / hidden-instruction
///    scanners (`configfile::check`, `aifile::check`, `terminal::check_bytes`)
///    run ONLY in this branch of `engine::analyze`.
/// 2. [`ScanContext::Paste`] — the URL / transport / hostname rules
///    (`extract_urls` → `hostname`/`transport`/`path`/`ecosystem::check`) and
///    command-shape rules run ONLY in the Exec/Paste branch, NEVER in
///    `FileScan`.
///
/// Both are needed because a `CLAUDE.md` is at once an instruction surface (the
/// first signal) and a place where a poisoned `curl http://punycode-host | sh`
/// install URL can hide (the second signal). Verified empirically: a plain
/// suspicious URL in a `CLAUDE.md` body produces ZERO findings under `FileScan`
/// alone, and a hidden-HTML-comment directive produces ZERO findings under
/// `Paste` alone — so neither single context covers the AI-config threat model.
/// `Paste` rather than `Exec` covers the URL half, for the same reasons
/// documented on [`scan_context_for`] for the other Paste profiles: no
/// command-card prelude stripping, no taint or blast-radius hot-path guards, and
/// a tier-1 regex that is a superset of `Exec`'s.
///
/// The post-filter [`retains`] keeps only the AiConfig-relevant ids from the
/// union, so the extra Paste-only findings a config buffer can incidentally trip
/// (e.g. `hidden_multiline`, the bare `pipe_to_interpreter` on a prose line) are
/// dropped — only the genuine AI-config signals and the suspicious-URL families
/// survive.
pub fn contexts_for(profile: LspProfile) -> &'static [ScanContext] {
    match profile {
        // BOTH branches — the only multi-context profile (see fn doc).
        LspProfile::AiConfig => &[ScanContext::FileScan, ScanContext::Paste],
        LspProfile::MarkdownInstallDoc => &[ScanContext::Paste],
        LspProfile::SourceCode => &[ScanContext::Paste],
        LspProfile::LogFile => &[ScanContext::Paste],
    }
}

/// Whether a `rule_id` is RETAINED in the diagnostics for a given profile — the
/// post-filter the LSP server applies to `verdict.findings`.
///
/// Each list is curated (not "everything the context can fire") so the LSP shows
/// only the diagnostics that are meaningful for that file type. Every id named
/// here is a real, shipping [`RuleId`] variant — this function compile-checks
/// the allow-sets.
pub fn retains(profile: LspProfile, rule_id: RuleId) -> bool {
    match profile {
        // AI-config files: the STATIC hidden-instruction / invisible-content
        // rules reachable in `FileScan`, PLUS the suspicious-URL families that
        // only fire in the `Paste` half of this profile's two-context analysis
        // (see `contexts_for`). The union is filtered by this allow-set, so the
        // extra Paste-only noise (`hidden_multiline`, a bare prose-line
        // `pipe_to_interpreter`, …) is dropped while the genuine signals stay.
        LspProfile::AiConfig => matches!(
            rule_id,
            // Hidden directive in an agent-instruction file (HTML comment /
            // visually-hidden element). The primary AI-config signal.
            RuleId::AgentInstructionHidden
            // Config-file invisible / non-ASCII smuggling (`configfile::check`).
            | RuleId::ConfigInvisibleUnicode
            | RuleId::ConfigNonAscii
            // Visible prompt-injection / suspicious indicators in a config file.
            | RuleId::ConfigInjection
            | RuleId::ConfigSuspiciousIndicator
            // The terminal byte-scan invisible/deception family that
            // `terminal::check_bytes` fires in the FileScan branch — the same
            // smuggling channels, surfaced on the config buffer.
            | RuleId::BidiControls
            | RuleId::ZeroWidthChars
            | RuleId::UnicodeTags
            | RuleId::InvisibleMathOperator
            | RuleId::VariationSelector
            | RuleId::InvisibleWhitespace
            | RuleId::HangulFiller
            | RuleId::ConfusableText
            // Suspicious URL embedded in the config body — an agent that reads a
            // poisoned `CLAUDE.md` may FETCH the URL, so a homograph/punycode/
            // raw-IP host, a plain-HTTP or shortened install URL, or a
            // `curl … | sh` install line in the file IS an AI-config diagnostic.
            // These fire only in the `Paste` context (`contexts_for` runs it for
            // AiConfig); identical family to `MarkdownInstallDoc`'s allow-set.
            | RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
            | RuleId::PlainHttpToSink
            | RuleId::SchemelessToSink
            | RuleId::InsecureTlsFlags
            | RuleId::ShortenedUrl
            | RuleId::NonAsciiHostname
            | RuleId::PunycodeDomain
            | RuleId::MixedScriptInLabel
            | RuleId::UserinfoTrick
            | RuleId::ConfusableDomain
            | RuleId::RawIpUrl
            | RuleId::LookalikeTld
            // AI-config DRIFT rules — reachable only via `tirith ai diff`, NOT a
            // single-buffer `analyze` (see the limitation in the fn doc). Listed
            // so an `analyze_output`/diff-aware LSP keeps them if present.
            | RuleId::AiConfigHiddenInstructionAdded
            | RuleId::AiConfigToolUseEscalation
        ),

        // Markdown install docs: URL/transport + command-shape rules that fire on
        // the fenced install commands.
        LspProfile::MarkdownInstallDoc => matches!(
            rule_id,
            // Command-shape: pipe-to-shell install lines (`curl … | sh`).
            RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
            // Transport family: plain HTTP / insecure TLS / shortened URLs.
            | RuleId::PlainHttpToSink
            | RuleId::SchemelessToSink
            | RuleId::InsecureTlsFlags
            | RuleId::ShortenedUrl
            // Hostname family: homograph / punycode / mixed-script / confusable
            // / userinfo-trick / raw-IP domains in install URLs.
            | RuleId::NonAsciiHostname
            | RuleId::PunycodeDomain
            | RuleId::MixedScriptInLabel
            | RuleId::UserinfoTrick
            | RuleId::ConfusableDomain
            | RuleId::RawIpUrl
            | RuleId::LookalikeTld
        ),

        // Source code: Unicode-confusable / bidi / zero-width (trojan-source)
        // plus hard-coded credentials.
        LspProfile::SourceCode => matches!(
            rule_id,
            // Trojan-source / homoglyph terminal family.
            RuleId::ConfusableText
            | RuleId::BidiControls
            | RuleId::ZeroWidthChars
            | RuleId::UnicodeTags
            | RuleId::InvisibleMathOperator
            | RuleId::VariationSelector
            | RuleId::InvisibleWhitespace
            | RuleId::HangulFiller
            // Hard-coded secrets.
            | RuleId::CredentialInText
            | RuleId::HighEntropySecret
            | RuleId::PrivateKeyExposed
        ),

        // Log files: the M7 output-direction rules. NOTE: these are reachable
        // only via `analyze_output` (see the limitation in `scan_context_for`),
        // so on the `analyze`+`Paste` path the LSP surfaces nothing here unless
        // the server routes the buffer through `analyze_output`.
        LspProfile::LogFile => matches!(
            rule_id,
            RuleId::OutputOsc52ClipboardWrite
                | RuleId::OutputHiddenText
                | RuleId::OutputFakePrompt
                | RuleId::OutputTerminalHyperlinkMismatch
                | RuleId::OutputTitleManipulation
                | RuleId::OutputClearScreen
                | RuleId::OutputTruncatedEscapeSequence
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn profile_for_path_routes_ai_config() {
        assert_eq!(
            profile_for_path(Path::new("CLAUDE.md")),
            Some(LspProfile::AiConfig)
        );
        assert_eq!(
            profile_for_path(Path::new("AGENTS.md")),
            Some(LspProfile::AiConfig)
        );
        assert_eq!(
            profile_for_path(Path::new(".cursorrules")),
            Some(LspProfile::AiConfig)
        );
        // Directory-aware: a file under `.cursor/rules/` is AI-config regardless
        // of its `.md` extension.
        assert_eq!(
            profile_for_path(Path::new(".cursor/rules/style.md")),
            Some(LspProfile::AiConfig)
        );
        assert_eq!(
            profile_for_path(Path::new("repo/.claude/commands/foo.md")),
            Some(LspProfile::AiConfig)
        );
    }

    #[test]
    fn ai_config_wins_over_markdown_install_doc() {
        // A `CLAUDE.md` is both AI-config and Markdown; AI-config must win.
        assert_eq!(
            profile_for_path(Path::new("CLAUDE.md")),
            Some(LspProfile::AiConfig)
        );
    }

    #[test]
    fn profile_for_path_routes_markdown_install_doc() {
        assert_eq!(
            profile_for_path(Path::new("README.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        assert_eq!(
            profile_for_path(Path::new("INSTALL.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        assert_eq!(
            profile_for_path(Path::new("docs/install.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        assert_eq!(
            profile_for_path(Path::new("docs/installation.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        // A non-install `.md` is NOT routed (not every markdown file).
        assert_eq!(profile_for_path(Path::new("CHANGELOG.md")), None);
        assert_eq!(profile_for_path(Path::new("docs/architecture.md")), None);
    }

    #[test]
    fn profile_for_path_routes_source_code() {
        for name in ["foo.rs", "main.py", "app.ts", "lib.go", "x.sh", "h.hpp"] {
            assert_eq!(
                profile_for_path(Path::new(name)),
                Some(LspProfile::SourceCode),
                "{name} should route to SourceCode"
            );
        }
    }

    #[test]
    fn profile_for_path_routes_log_file() {
        assert_eq!(
            profile_for_path(Path::new("server.log")),
            Some(LspProfile::LogFile)
        );
        assert_eq!(
            profile_for_path(Path::new("var/log/app.log")),
            Some(LspProfile::LogFile)
        );
        // Rotated `*.log.1` keeps a `.1` extension → not matched (narrow on purpose).
        assert_eq!(profile_for_path(Path::new("app.log.1")), None);
    }

    #[test]
    fn profile_for_path_unknown_is_none() {
        assert_eq!(profile_for_path(Path::new("random.txt")), None);
        assert_eq!(profile_for_path(Path::new("data.json")), None);
        assert_eq!(profile_for_path(Path::new("image.png")), None);
        assert_eq!(profile_for_path(Path::new("noext")), None);
    }

    #[test]
    fn scan_context_for_returns_documented_context() {
        // The one-context accessor returns the PRIMARY context of each profile.
        assert_eq!(
            scan_context_for(LspProfile::AiConfig),
            ScanContext::FileScan
        );
        assert_eq!(
            scan_context_for(LspProfile::MarkdownInstallDoc),
            ScanContext::Paste
        );
        assert_eq!(scan_context_for(LspProfile::SourceCode), ScanContext::Paste);
        assert_eq!(scan_context_for(LspProfile::LogFile), ScanContext::Paste);
    }

    #[test]
    fn contexts_for_ai_config_is_filescan_then_paste() {
        // AiConfig is the ONLY multi-context profile: FileScan (static config /
        // hidden-instruction scanners) THEN Paste (URL/transport/hostname). The
        // order is load-bearing (`scan_context_for` returns element 0).
        assert_eq!(
            contexts_for(LspProfile::AiConfig),
            &[ScanContext::FileScan, ScanContext::Paste]
        );
        // The primary accessor must agree with element 0.
        assert_eq!(
            scan_context_for(LspProfile::AiConfig),
            contexts_for(LspProfile::AiConfig)[0]
        );
    }

    #[test]
    fn contexts_for_single_context_profiles() {
        // Every non-AiConfig profile analyzes in exactly ONE context, identical
        // to `scan_context_for`.
        for p in [
            LspProfile::MarkdownInstallDoc,
            LspProfile::SourceCode,
            LspProfile::LogFile,
        ] {
            assert_eq!(
                contexts_for(p),
                &[ScanContext::Paste],
                "{p:?} should be single-context Paste"
            );
            assert_eq!(scan_context_for(p), contexts_for(p)[0]);
        }
    }

    #[test]
    fn retains_ai_config_in_profile() {
        assert!(retains(
            LspProfile::AiConfig,
            RuleId::AgentInstructionHidden
        ));
        assert!(retains(
            LspProfile::AiConfig,
            RuleId::ConfigInvisibleUnicode
        ));
        assert!(retains(LspProfile::AiConfig, RuleId::BidiControls));
        // A suspicious-URL / command-shape rule IS retained for AI-config: an
        // agent reading a poisoned config may fetch a `curl … | sh` install URL,
        // so these (surfaced via the Paste half of `contexts_for`) are kept.
        assert!(retains(LspProfile::AiConfig, RuleId::CurlPipeShell));
        assert!(retains(LspProfile::AiConfig, RuleId::PunycodeDomain));
        assert!(retains(LspProfile::AiConfig, RuleId::PlainHttpToSink));
        // A credential rule is NOT an AI-config diagnostic (source-code only).
        assert!(!retains(LspProfile::AiConfig, RuleId::HighEntropySecret));
        assert!(!retains(LspProfile::AiConfig, RuleId::CredentialInText));
    }

    #[test]
    fn retains_markdown_install_doc_in_profile() {
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::PipeToInterpreter
        ));
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::CurlPipeShell
        ));
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::PlainHttpToSink
        ));
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::ConfusableDomain
        ));
        // A credential rule is not an install-doc diagnostic.
        assert!(!retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::HighEntropySecret
        ));
    }

    #[test]
    fn retains_source_code_in_profile() {
        assert!(retains(LspProfile::SourceCode, RuleId::ConfusableText));
        assert!(retains(LspProfile::SourceCode, RuleId::BidiControls));
        assert!(retains(LspProfile::SourceCode, RuleId::CredentialInText));
        assert!(retains(LspProfile::SourceCode, RuleId::PrivateKeyExposed));
        // A command-shape rule must NOT be retained for source code (the
        // load-bearing out-of-profile negative case).
        assert!(!retains(LspProfile::SourceCode, RuleId::CurlPipeShell));
        assert!(!retains(LspProfile::SourceCode, RuleId::PipeToInterpreter));
    }

    #[test]
    fn retains_log_file_in_profile() {
        assert!(retains(
            LspProfile::LogFile,
            RuleId::OutputOsc52ClipboardWrite
        ));
        assert!(retains(LspProfile::LogFile, RuleId::OutputHiddenText));
        assert!(retains(LspProfile::LogFile, RuleId::OutputFakePrompt));
        // An unrelated rule is not a log diagnostic.
        assert!(!retains(LspProfile::LogFile, RuleId::CredentialInText));
    }
}

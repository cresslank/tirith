//! Sudo-escalation rules (M8 ch4).
//!
//! These rules fire when the parsed command's leader resolves to `sudo`
//! (including `sudo -u user`, `sudo --user=user`, `sudo -E`, `env`-prefixed
//! sudo, etc.). The PATTERN_TABLE entry `sudo_cmd` (`\bsudo\b`) is the
//! tier-1 gate for the exec context.
//!
//! Five rule ids ship in this chunk:
//!
//! 1. **`SudoShellSpawn`** (High) — `sudo sh|bash|zsh|fish|dash|ksh|tcsh|
//!    pwsh|powershell|nu` opens an interactive root shell. Once inside,
//!    every subsequent command runs as root with zero tirith visibility
//!    (tirith intercepts the LOCAL shell, not a nested shell process).
//!
//! 2. **`SudoEnvPreserveSensitive`** (High) — `sudo -E` (or
//!    `--preserve-env`) with at least one sensitive env var from the
//!    `sensitive_env.toml` list currently exported. Passing
//!    `AWS_SECRET_ACCESS_KEY` to a privileged process is exactly the
//!    shape of an exfil-by-misconfiguration attack — the value lives in
//!    the elevated process's environment and is now visible to anything
//!    that reads `/proc/<pid>/environ`.
//!
//! 3. **`SudoTeeSystemFile`** (High) — `… | sudo tee <system-path>`
//!    pattern targeting `/etc/…`, `/usr/local/bin/…`, `/lib/systemd/…`,
//!    or `/etc/cron*`. Legitimate `sudo tee /tmp/foo` / `sudo tee
//!    ~/something` / repo-relative targets are NOT flagged — the rule
//!    is shape-specific.
//!
//! 4. **`SudoDownloadInstall`** (High) — `sudo curl|wget|fetch -o
//!    <system-path>` or equivalent download-and-install-as-root shape.
//!    Same target list as `SudoTeeSystemFile`.
//!
//! 5. **`SudoRecursivePermsBroadPath`** (High) — `sudo chmod|chown
//!    -R … /` (or `/home`, `/usr`, `/etc`). Recursively chmod'ing one of
//!    these wide trees rarely ends well — even when intentional it
//!    routinely strips `setuid` bits, locks operators out of their
//!    homedirs, or breaks distro packages.
//!
//! ## Detection guard
//!
//! Detection short-circuits when the parsed leader is not `sudo` (or a
//! `sudo` wrapped behind `env VAR=… sudo …`). The PATTERN_TABLE entry
//! `sudo_cmd` is the only tier-1 admission ticket.
//!
//! ## Policy integration
//!
//! When `policy.sudo_require_reason` is on AND the operator has an
//! active sudo-session (see `crate::sudo_session::read_active_session`),
//! we DOWNGRADE these findings from High to Medium so the operator
//! still sees the signal but doesn't trip the block. When
//! `sudo_require_reason` is OFF the session file is consulted purely
//! for the `tirith sudo session status` reporting surface and never
//! affects rule outcomes.

use crate::policy::Policy;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run the sudo-escalation rules. Returns at most a small handful of
/// findings — most invocations fire at most one of the five.
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    let segments = tokenize::tokenize(input, shell);
    let mut findings: Vec<Finding> = Vec::new();

    for seg in &segments {
        if let Some(parsed) = parse_sudo_invocation(seg, shell) {
            findings.extend(rules_for_segment(&parsed, input, seg, shell));
        } else if let Some(parsed) = parse_pipe_into_sudo_tee(seg, shell) {
            // `… | sudo tee /etc/foo` arrives as a segment whose leader
            // is `sudo` and arg-list starts with `tee`. We still need to
            // run the tee check on it.
            findings.extend(rules_for_segment(&parsed, input, seg, shell));
        }
    }

    if findings.is_empty() {
        return findings;
    }

    // Severity downgrade when a tagged sudo session is active AND the
    // operator has opted into `sudo_require_reason`. The session is
    // consulted lazily so the fast-path (no-finding case) doesn't touch
    // disk.
    if policy.sudo_require_reason {
        if let Some(_session) = crate::sudo_session::read_active_session() {
            for f in &mut findings {
                if f.severity == Severity::High {
                    f.severity = Severity::Medium;
                }
            }
        }
    }

    findings
}

/// Internal representation of a `sudo` invocation: the inner command
/// (after stripping sudo flags) and a snapshot of which sudo flags
/// were observed.
struct SudoParsed {
    /// Whether `-E` / `--preserve-env` (no value) appeared. Distinct
    /// from `--preserve-env=VAR_LIST` which is the targeted form.
    preserve_env_all: bool,
    /// Specific env vars preserved via `--preserve-env=A,B,C`.
    /// Stored lowercased / unchanged — the SENSITIVE list is matched
    /// case-insensitively.
    preserve_env_vars: Vec<String>,
    /// Inner command base name (post-sudo, post-flag-strip). Empty
    /// when sudo had no positional inner command.
    inner_cmd: String,
    /// Inner command's args (raw, quotes preserved).
    inner_args: Vec<String>,
}

/// Parse a single segment as a `sudo` invocation when its leader (after
/// `env`-wrapper resolution) is `sudo`. Returns `None` for non-sudo
/// segments.
fn parse_sudo_invocation(seg: &tokenize::Segment, shell: ShellType) -> Option<SudoParsed> {
    let cmd = seg.command.as_deref()?;
    let base = command_basename(cmd, shell);

    // Direct `sudo …`.
    if base == "sudo" {
        return Some(parse_sudo_args(&seg.args, shell));
    }

    // `env [VAR=val …] sudo …` — strip the env wrapper, then sudo.
    if base == "env" {
        let inner_start = skip_env_assignments(&seg.args);
        if inner_start < seg.args.len() {
            let inner_leader = command_basename(&seg.args[inner_start], shell);
            if inner_leader == "sudo" {
                return Some(parse_sudo_args(&seg.args[inner_start + 1..], shell));
            }
        }
    }

    None
}

/// Special-case parser for the trailing segment of a pipe (`… | sudo tee
/// /etc/foo`). The trailing segment's leader is `sudo` already, so the
/// regular `parse_sudo_invocation` already handles it — this helper is
/// kept for symmetry / future extension. Currently delegates.
fn parse_pipe_into_sudo_tee(seg: &tokenize::Segment, shell: ShellType) -> Option<SudoParsed> {
    let leader = seg.command.as_deref().map(|c| command_basename(c, shell))?;
    if leader != "sudo" {
        return None;
    }
    Some(parse_sudo_args(&seg.args, shell))
}

/// Skip `KEY=VAL` assignments and bare flags between the `env` leader
/// and the inner command. Returns the index of the first positional
/// argument that is NOT a `KEY=VAL` assignment or a flag.
fn skip_env_assignments(args: &[String]) -> usize {
    let mut idx = 0;
    while idx < args.len() {
        let a = strip_outer_quotes(&args[idx]);
        if a == "-S" || a == "--split-string" {
            idx += 1;
            continue;
        }
        if a.starts_with('-') && a.len() >= 2 {
            // env's `-i`, `-u VAR`, `--unset=VAR` etc. The plan-text
            // forms vary; we err on the side of skipping any leading
            // flag. We do NOT consume a value for `-u`, which would
            // mis-resolve `env -u SUDO_ASKPASS sudo` — instead we just
            // skip one slot and fall through.
            idx += 1;
            continue;
        }
        if a.contains('=') {
            idx += 1;
            continue;
        }
        return idx;
    }
    idx
}

/// Parse a slice of args BEYOND the `sudo` leader. Returns the parsed
/// view including the inner command + post-flag args.
fn parse_sudo_args(args: &[String], shell: ShellType) -> SudoParsed {
    let value_short = ["-u", "-g", "-C", "-D", "-R", "-T"];
    let value_long = [
        "--user",
        "--group",
        "--close-from",
        "--chdir",
        "--role",
        "--type",
        "--other-user",
        "--host",
        "--timeout",
    ];

    let mut idx = 0;
    let mut preserve_env_all = false;
    let mut preserve_env_vars: Vec<String> = Vec::new();
    let mut inner_start: Option<usize> = None;

    while idx < args.len() {
        let raw = &args[idx];
        let a = strip_outer_quotes(raw);
        if a == "--" {
            inner_start = Some(idx + 1);
            break;
        }
        // -E / --preserve-env (no value) — preserve ALL.
        if a == "-E" {
            preserve_env_all = true;
            idx += 1;
            continue;
        }
        if a == "--preserve-env" {
            preserve_env_all = true;
            idx += 1;
            continue;
        }
        // --preserve-env=VAR_LIST — preserve specific vars.
        if let Some(rest) = a.strip_prefix("--preserve-env=") {
            for v in rest.split(',') {
                let v = v.trim();
                if !v.is_empty() {
                    preserve_env_vars.push(v.to_string());
                }
            }
            idx += 1;
            continue;
        }
        // sudo's `-Eu user` form — `-E` is the only short flag that's
        // bundleable into a leading position. Be defensive: if we see
        // a multi-char short with `E`, mark preserve_env_all.
        if a.starts_with('-') && a.len() > 1 && !a.starts_with("--") && a.contains('E') {
            preserve_env_all = true;
            // Continue with the regular short-flag handling.
        }
        if a.starts_with("--") {
            if value_long.contains(&a) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            if value_short.contains(&a) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // First positional — this is the inner command.
        inner_start = Some(idx);
        break;
    }

    let inner_start = inner_start.unwrap_or(args.len());
    if inner_start >= args.len() {
        return SudoParsed {
            preserve_env_all,
            preserve_env_vars,
            inner_cmd: String::new(),
            inner_args: Vec::new(),
        };
    }

    let inner_cmd = command_basename(&args[inner_start], shell);
    let inner_args: Vec<String> = args[inner_start + 1..].to_vec();

    SudoParsed {
        preserve_env_all,
        preserve_env_vars,
        inner_cmd,
        inner_args,
    }
}

/// Apply the five rule checks against a parsed sudo invocation.
fn rules_for_segment(
    parsed: &SudoParsed,
    input: &str,
    seg: &tokenize::Segment,
    shell: ShellType,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let inner = parsed.inner_cmd.as_str();
    let inner_args = &parsed.inner_args;

    // 1) sudo <interactive-shell>
    if is_interactive_shell(inner) {
        findings.push(make_finding(
            RuleId::SudoShellSpawn,
            Severity::High,
            format!("sudo {inner}: interactive root shell"),
            format!(
                "`sudo {inner}` opens an interactive root shell. Subsequent commands typed \
                 into that shell run with full privileges and are NOT seen by tirith \
                 (we intercept the local shell, not nested shells). Run the specific \
                 command that needs elevation with sudo, not a shell."
            ),
            input,
            seg,
        ));
    }

    // 2) sudo -E with sensitive env set
    if parsed.preserve_env_all {
        let active = sensitive_env_active();
        if !active.is_empty() {
            let preview = active
                .iter()
                .take(3)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(make_finding(
                RuleId::SudoEnvPreserveSensitive,
                Severity::High,
                "sudo -E preserves sensitive env vars into the privileged process".to_string(),
                format!(
                    "`sudo -E` (or `--preserve-env`) forwards sensitive credentials \
                     ({preview}{extra}) into the privileged process. Those values \
                     become readable via `/proc/<pid>/environ` to anything that can \
                     enumerate processes. Use `sudo --preserve-env=ONLY,VARS,YOU,NEED` \
                     to limit the surface.",
                    extra = if active.len() > 3 {
                        format!(", … {} more", active.len() - 3)
                    } else {
                        String::new()
                    }
                ),
                input,
                seg,
            ));
        }
    } else if !parsed.preserve_env_vars.is_empty() {
        // --preserve-env=VAR_LIST — fire only if any of the listed
        // vars is in the sensitive set (presence-only, no value read).
        let intersecting: Vec<&str> = parsed
            .preserve_env_vars
            .iter()
            .filter(|v| is_sensitive_env_name(v))
            .map(|s| s.as_str())
            .collect();
        if !intersecting.is_empty() {
            findings.push(make_finding(
                RuleId::SudoEnvPreserveSensitive,
                Severity::High,
                "sudo --preserve-env names sensitive env vars".to_string(),
                format!(
                    "`sudo --preserve-env={list}` explicitly forwards sensitive \
                     credentials into the privileged process. If those vars are set, \
                     they become readable via `/proc/<pid>/environ`. Drop them from \
                     the preserve-env list, or unset them before running sudo.",
                    list = intersecting.join(",")
                ),
                input,
                seg,
            ));
        }
    }

    // 3) sudo tee <system-path>
    if inner == "tee" {
        if let Some(target) = first_tee_target(inner_args) {
            if is_protected_system_path(&target) {
                findings.push(make_finding(
                    RuleId::SudoTeeSystemFile,
                    Severity::High,
                    format!("sudo tee writes to protected system path '{target}'"),
                    format!(
                        "`… | sudo tee {target}` writes attacker-controllable input \
                         to a privileged system path. If the upstream content is \
                         untrusted (a fetched script, an LLM-generated config, …) \
                         this overwrites a file the OS trusts. Confirm the input \
                         source before re-running."
                    ),
                    input,
                    seg,
                ));
            }
        }
    }

    // 4) sudo curl|wget|fetch -o <system-path>
    if is_download_tool(inner) {
        if let Some(target) = first_download_output_path(inner_args) {
            if is_protected_system_path(&target) {
                findings.push(make_finding(
                    RuleId::SudoDownloadInstall,
                    Severity::High,
                    format!("sudo {inner} writes downloaded content to '{target}'"),
                    format!(
                        "`sudo {inner} -o {target}` downloads remote content and \
                         writes it to a privileged system path as root. The standard \
                         attack shape is `sudo curl -o /usr/local/bin/<tool> <url>` — \
                         it bypasses package signing entirely. Download to a \
                         user-writable path, review, then `sudo install` if needed."
                    ),
                    input,
                    seg,
                ));
            }
        }
    }

    // 5) sudo chmod|chown -R … <broad-path>
    if (inner == "chmod" || inner == "chown") && has_recursive_flag(inner_args) {
        if let Some(target) = first_broad_path_arg(inner_args, shell) {
            findings.push(make_finding(
                RuleId::SudoRecursivePermsBroadPath,
                Severity::High,
                format!("sudo {inner} -R against broad system path '{target}'"),
                format!(
                    "`sudo {inner} -R … {target}` recursively rewrites permissions on \
                     a broad system tree. This routinely strips setuid bits, locks \
                     operators out of their homedirs, and breaks distro packages. \
                     Narrow the path to the specific subdirectory you intended."
                ),
                input,
                seg,
            ));
        }
    }

    findings
}

/// Interactive shells we refuse to spawn under sudo. This list mirrors
/// `safe_command::is_interactive_shell` — keep them in sync.
fn is_interactive_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "ksh"
            | "tcsh"
            | "csh"
            | "ash"
            | "mksh"
            | "pwsh"
            | "powershell"
            | "nu"
    )
}

fn is_download_tool(name: &str) -> bool {
    matches!(name, "curl" | "wget" | "fetch")
}

fn has_recursive_flag(args: &[String]) -> bool {
    args.iter().any(|a| {
        let a = strip_outer_quotes(a);
        a == "-R" || a == "-r" || a == "--recursive"
    })
}

/// Pull the first positional that looks like a path (not a flag, not a
/// numeric mode) from the args. Handles the `-R 777 /home` shape.
fn first_broad_path_arg(args: &[String], _shell: ShellType) -> Option<String> {
    let mut after_double_dash = false;
    for arg in args.iter() {
        let a = strip_outer_quotes(arg);
        if after_double_dash {
            if is_broad_path(a) {
                return Some(a.to_string());
            }
            continue;
        }
        if a == "--" {
            after_double_dash = true;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            continue;
        }
        // skip numeric chmod mode (777, 0755, ...) and user:group spec
        if is_chmod_mode_or_owner(a) {
            continue;
        }
        if is_broad_path(a) {
            return Some(a.to_string());
        }
    }
    None
}

/// Heuristic: a "broad path" is `/`, `/home`, `/usr`, `/etc`, or a
/// direct subpath that does NOT narrow into a per-user / per-package
/// subdirectory. We deliberately keep this narrow — false-positives on
/// `/etc/myapp/config.d` are noisy.
fn is_broad_path(p: &str) -> bool {
    matches!(
        p,
        "/" | "/home" | "/usr" | "/etc" | "/var" | "/opt" | "/srv" | "/lib" | "/bin"
    )
        // Trailing slash variants.
        || matches!(
            p,
            "/home/" | "/usr/" | "/etc/" | "/var/" | "/opt/" | "/srv/" | "/lib/" | "/bin/"
        )
}

fn is_chmod_mode_or_owner(a: &str) -> bool {
    // 777, 0755, 1777 — purely numeric.
    if a.chars().all(|c| c.is_ascii_digit()) && !a.is_empty() {
        return true;
    }
    // u+x, g-r, a=rw — symbolic mode shape.
    if a.contains(['+', '-', '='])
        && a.chars().all(|c| {
            matches!(
                c,
                'a' | 'u' | 'g' | 'o' | 'r' | 'w' | 'x' | 's' | 't' | 'X' | '+' | '-' | '='
            )
        })
    {
        return true;
    }
    // user:group — chown spec.
    if a.contains(':') && !a.starts_with('/') {
        return true;
    }
    false
}

/// Find the `tee` target — first positional arg that is not a flag.
fn first_tee_target(args: &[String]) -> Option<String> {
    for arg in args.iter() {
        let a = strip_outer_quotes(arg);
        if a == "--" {
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            continue;
        }
        return Some(a.to_string());
    }
    None
}

/// Find the `curl/wget -o <path>` output path. Handles glued forms
/// (`-o=file`, `--output=file`) and split forms (`-o file`).
fn first_download_output_path(args: &[String]) -> Option<String> {
    let mut iter = args.iter().enumerate();
    while let Some((_i, arg)) = iter.next() {
        let a = strip_outer_quotes(arg);
        if let Some(rest) = a.strip_prefix("--output=") {
            return Some(rest.to_string());
        }
        if let Some(rest) = a.strip_prefix("-o=") {
            return Some(rest.to_string());
        }
        if a == "-o" || a == "--output" || a == "-O" {
            // Next arg is the path. Some tools (wget) also use `-O`.
            if let Some((_, next)) = iter.next() {
                let v = strip_outer_quotes(next);
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Returns `true` when the target file path is under a protected system
/// directory or a well-known shell-init dotfile in the user's home.
/// Deliberately narrow to keep false-positives low — the
/// `tee /tmp/foo` / `tee ~/notes.md` / `tee ./relative` shapes never fire.
///
/// Home-dotfile protection covers `~/.bashrc` / `~/.zshrc` / `~/.profile`
/// / `~/.bash_profile` / `~/.zshenv` / `~/.bash_login` / `~/.zprofile` —
/// the textbook persistence-vector files. The dotfile-overwrite rule
/// (`check_dotfile_overwrite` in `rules/command.rs`) catches the redirect
/// shape but not the pipe-into-`sudo tee` shape, so the carveout here
/// must close that gap.
fn is_protected_system_path(p: &str) -> bool {
    // Repo-relative / current-dir — never protected.
    if !p.starts_with('/')
        && !p.starts_with('~')
        && !p.starts_with("$HOME")
        && !p.starts_with("${HOME")
    {
        return false;
    }

    // Shell-init dotfiles in the user's home are protected. We match the
    // bare dotfile name; subdirectories like `~/.config/zsh/...` are not
    // covered here because the user almost always owns them and they're
    // not the textbook persistence vector.
    if is_home_shell_init_dotfile(p) {
        return true;
    }

    // Other paths under ~/ and $HOME/ are user-writable and not
    // protected.
    if p.starts_with('~') || p.starts_with("$HOME") || p.starts_with("${HOME") {
        return false;
    }

    // /tmp is shared but not OS-system.
    if p == "/tmp" || p.starts_with("/tmp/") {
        return false;
    }
    // /var/tmp same.
    if p == "/var/tmp" || p.starts_with("/var/tmp/") {
        return false;
    }
    // Documented system trees.
    p.starts_with("/etc/")
        || p == "/etc"
        || p.starts_with("/usr/local/bin/")
        || p == "/usr/local/bin"
        || p.starts_with("/usr/bin/")
        || p == "/usr/bin"
        || p.starts_with("/usr/sbin/")
        || p == "/usr/sbin"
        || p.starts_with("/lib/systemd/")
        || p.starts_with("/lib/")
        || p.starts_with("/usr/lib/systemd/")
        || p.starts_with("/etc/cron")
        || p.starts_with("/etc/systemd/")
        // Webroot / persistent system dirs added per PR-127 review.
        || p == "/var/www"
        || p.starts_with("/var/www/")
        || p == "/srv"
        || p.starts_with("/srv/")
        || p == "/root"
        || p.starts_with("/root/")
        || p == "/boot"
        || p.starts_with("/boot/")
        || p == "/var/lib"
        || p.starts_with("/var/lib/")
}

/// Returns `true` when the path points at a well-known shell-init
/// dotfile in the user's home directory. Matches `~/.bashrc`,
/// `~/.zshrc`, `~/.profile`, `~/.bash_profile`, `~/.zshenv`,
/// `~/.bash_login`, `~/.zprofile`. Both `~/` and `$HOME/` prefixes are
/// recognised. Suffixes like `~/.bashrc.bak` are NOT matched — only the
/// exact basenames listed.
fn is_home_shell_init_dotfile(p: &str) -> bool {
    const PREFIXES: &[&str] = &["~/", "$HOME/", "${HOME}/", "${HOME:-/root}/"];
    const FILES: &[&str] = &[
        ".bashrc",
        ".zshrc",
        ".profile",
        ".bash_profile",
        ".zshenv",
        ".bash_login",
        ".zprofile",
    ];
    for prefix in PREFIXES {
        if let Some(tail) = p.strip_prefix(prefix) {
            return FILES.contains(&tail);
        }
    }
    false
}

/// Return the list of sensitive env-var names that are currently set in
/// `std::env`. Order follows `sensitive_env.toml` for determinism.
fn sensitive_env_active() -> Vec<String> {
    crate::safe_command::sensitive_env_vars()
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .map(|s| s.to_string())
        .collect()
}

fn is_sensitive_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    crate::safe_command::sensitive_env_vars()
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&upper))
}

fn make_finding(
    rule_id: RuleId,
    severity: Severity,
    title: String,
    description: String,
    input: &str,
    seg: &tokenize::Segment,
) -> Finding {
    Finding {
        rule_id,
        severity,
        title,
        description,
        evidence: vec![
            Evidence::CommandPattern {
                pattern: "sudo <escalation-gate>".to_string(),
                matched: seg.raw.chars().take(200).collect(),
            },
            Evidence::Text {
                detail: format!("input: {}", input.chars().take(200).collect::<String>()),
            },
        ],
        human_view: Some(
            "Sudo guard — confirm with `tirith sudo --help` before re-running.".to_string(),
        ),
        agent_view: Some(format!("tirith refused: sudo gate. rule={rule_id:?}",)),
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn strip_outer_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn command_basename(cmd: &str, shell: ShellType) -> String {
    let unq = strip_outer_quotes(cmd);
    let basename = match shell {
        ShellType::PowerShell | ShellType::Cmd => unq.rsplit(['/', '\\']).next().unwrap_or(unq),
        _ => unq.rsplit('/').next().unwrap_or(unq),
    };
    let lower = basename.to_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn sudo_sh_fires_shell_spawn() {
        let policy = Policy::default();
        let findings = check("sudo sh", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)),
            "sudo sh must fire SudoShellSpawn: {findings:?}"
        );
    }

    #[test]
    fn sudo_bash_fires_shell_spawn() {
        let policy = Policy::default();
        let findings = check("sudo bash", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)));
    }

    #[test]
    fn sudo_with_user_flag_then_shell_fires() {
        let policy = Policy::default();
        let findings = check("sudo -u root bash", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)));
    }

    #[test]
    fn sudo_apt_update_does_not_fire_shell_spawn() {
        let policy = Policy::default();
        let findings = check("sudo apt update", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn sudo_tee_etc_cron_fires() {
        let policy = Policy::default();
        let findings = check("sudo tee /etc/cron.d/foo", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)),
            "{findings:?}"
        );
    }

    #[test]
    fn sudo_tee_usr_local_bin_fires() {
        let policy = Policy::default();
        let findings = check("sudo tee /usr/local/bin/tool", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)));
    }

    #[test]
    fn sudo_tee_tmp_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo tee /tmp/foo", ShellType::Posix, &policy);
        assert!(
            findings.is_empty(),
            "sudo tee /tmp/foo must NOT fire: {findings:?}"
        );
    }

    #[test]
    fn sudo_tee_home_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo tee ~/foo", ShellType::Posix, &policy);
        assert!(
            findings.is_empty(),
            "sudo tee ~/foo must NOT fire: {findings:?}"
        );
    }

    #[test]
    fn sudo_tee_home_dotfile_fires() {
        // Regression: PR-127 review #3. `sudo tee ~/.bashrc` is a
        // textbook persistence vector that previously bypassed every
        // sudo rule (carveout) AND the dotfile_overwrite rule (which
        // only matches the redirect shape, not pipe-into-`sudo tee`).
        let policy = Policy::default();
        for path in [
            "~/.bashrc",
            "~/.zshrc",
            "~/.profile",
            "~/.bash_profile",
            "~/.zshenv",
            "$HOME/.bashrc",
            "${HOME}/.zshrc",
        ] {
            let cmd = format!("sudo tee {path}");
            let findings = check(&cmd, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)),
                "expected SudoTeeSystemFile for `{cmd}`; got: {findings:?}"
            );
        }
    }

    #[test]
    fn sudo_tee_webroot_and_persistent_dirs_fire() {
        // Regression: PR-127 review #16. /var/www, /srv, /root, /boot,
        // /var/lib were missing from the protected-paths list.
        let policy = Policy::default();
        for path in [
            "/var/www/html/x.php",
            "/srv/http/index.html",
            "/root/.ssh/authorized_keys",
            "/boot/grub.cfg",
            "/var/lib/dpkg/status",
        ] {
            let cmd = format!("sudo tee {path}");
            let findings = check(&cmd, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)),
                "expected SudoTeeSystemFile for `{cmd}`; got: {findings:?}"
            );
        }
    }

    #[test]
    fn sudo_curl_o_usr_local_bin_fires() {
        let policy = Policy::default();
        let findings = check(
            "sudo curl -o /usr/local/bin/foo https://example.com/foo",
            ShellType::Posix,
            &policy,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoDownloadInstall)),
            "{findings:?}"
        );
    }

    #[test]
    fn sudo_curl_to_home_does_not_fire() {
        let policy = Policy::default();
        let findings = check(
            "sudo curl -o ~/foo https://example.com/foo",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn sudo_wget_glued_output_etc_fires() {
        let policy = Policy::default();
        let findings = check(
            "sudo wget --output=/etc/foo https://example.com/foo",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoDownloadInstall)));
    }

    #[test]
    fn sudo_chmod_r_777_home_fires() {
        let policy = Policy::default();
        let findings = check("sudo chmod -R 777 /home", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoRecursivePermsBroadPath)),
            "{findings:?}"
        );
    }

    #[test]
    fn sudo_chmod_r_777_narrow_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo chmod -R 777 /home/me/proj", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn sudo_chown_r_root_etc_fires() {
        let policy = Policy::default();
        let findings = check("sudo chown -R root:root /etc", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoRecursivePermsBroadPath)));
    }

    #[test]
    fn sudo_chmod_without_recursive_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo chmod 777 /home", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn non_sudo_does_not_fire() {
        let policy = Policy::default();
        let findings = check("ls /etc", ShellType::Posix, &policy);
        assert!(findings.is_empty());
    }

    #[test]
    fn env_wrapped_sudo_sh_fires() {
        let policy = Policy::default();
        let findings = check("env FOO=bar sudo bash", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)));
    }

    #[test]
    fn preserve_env_named_aws_secret_fires() {
        // We don't mutate the env in this test; we exercise the
        // explicit `--preserve-env=AWS_SECRET_ACCESS_KEY` form so the
        // libc-environ race is irrelevant.
        let policy = Policy::default();
        let findings = check(
            "sudo --preserve-env=AWS_SECRET_ACCESS_KEY pip install foo",
            ShellType::Posix,
            &policy,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoEnvPreserveSensitive)),
            "expected SudoEnvPreserveSensitive: {findings:?}"
        );
    }

    #[test]
    fn preserve_env_named_non_sensitive_does_not_fire() {
        let policy = Policy::default();
        let findings = check(
            "sudo --preserve-env=PATH,LANG pip install foo",
            ShellType::Posix,
            &policy,
        );
        // Neither PATH nor LANG is in sensitive_env.toml.
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoEnvPreserveSensitive)),
            "PATH/LANG must NOT fire SudoEnvPreserveSensitive: {findings:?}"
        );
    }

    #[test]
    fn is_protected_system_path_recognises_etc_cron_d() {
        assert!(is_protected_system_path("/etc/cron.d/foo"));
        assert!(is_protected_system_path("/etc/cron.daily/foo"));
        assert!(is_protected_system_path("/etc/systemd/system/x.service"));
        assert!(is_protected_system_path("/lib/systemd/system/x.service"));
        assert!(is_protected_system_path("/usr/local/bin/tool"));
        assert!(!is_protected_system_path("/tmp/foo"));
        assert!(!is_protected_system_path("/home/me/foo"));
        assert!(!is_protected_system_path("relative/path"));
        // ~/foo (non-dotfile, non-shell-init) is still allowed.
        assert!(!is_protected_system_path("~/foo"));
    }

    #[test]
    fn is_protected_system_path_covers_home_shell_init_dotfiles() {
        // Regression: PR-127 review #3 — `sudo tee ~/.bashrc` was a
        // textbook persistence vector silently allowed.
        assert!(is_protected_system_path("~/.bashrc"));
        assert!(is_protected_system_path("~/.zshrc"));
        assert!(is_protected_system_path("~/.profile"));
        assert!(is_protected_system_path("~/.bash_profile"));
        assert!(is_protected_system_path("~/.zshenv"));
        assert!(is_protected_system_path("~/.bash_login"));
        assert!(is_protected_system_path("~/.zprofile"));
        assert!(is_protected_system_path("$HOME/.bashrc"));
        assert!(is_protected_system_path("${HOME}/.zshrc"));
        // Suffixes / non-shell-init dotfiles remain allowed.
        assert!(!is_protected_system_path("~/.bashrc.bak"));
        assert!(!is_protected_system_path("~/.config/some.toml"));
        assert!(!is_protected_system_path("~/.vimrc"));
    }

    #[test]
    fn is_protected_system_path_covers_webroot_and_persistent_dirs() {
        // Regression: PR-127 review #16 — /var/www, /srv, /root, /boot,
        // /var/lib were missing.
        assert!(is_protected_system_path("/var/www"));
        assert!(is_protected_system_path("/var/www/html/x.php"));
        assert!(is_protected_system_path("/srv/http/index.html"));
        assert!(is_protected_system_path("/root"));
        assert!(is_protected_system_path("/root/.ssh/authorized_keys"));
        assert!(is_protected_system_path("/boot/grub.cfg"));
        assert!(is_protected_system_path("/var/lib/dpkg/status"));
    }

    #[test]
    fn is_broad_path_strict_set() {
        assert!(is_broad_path("/"));
        assert!(is_broad_path("/home"));
        assert!(is_broad_path("/etc"));
        assert!(is_broad_path("/usr"));
        // PR-127 review #13 expansion.
        assert!(is_broad_path("/var"));
        assert!(is_broad_path("/opt"));
        assert!(is_broad_path("/srv"));
        assert!(is_broad_path("/lib"));
        assert!(is_broad_path("/bin"));
        assert!(!is_broad_path("/etc/cron.d"));
        assert!(!is_broad_path("/home/me"));
    }

    #[test]
    fn first_download_output_path_split_and_glued() {
        assert_eq!(
            first_download_output_path(&[
                "-o".to_string(),
                "/usr/local/bin/foo".to_string(),
                "https://example.com/foo".to_string(),
            ])
            .as_deref(),
            Some("/usr/local/bin/foo"),
        );
        assert_eq!(
            first_download_output_path(&[
                "--output=/etc/x".to_string(),
                "https://example.com/x".to_string(),
            ])
            .as_deref(),
            Some("/etc/x"),
        );
        assert_eq!(
            first_download_output_path(&["-O".to_string(), "/usr/local/bin/foo".to_string(),])
                .as_deref(),
            Some("/usr/local/bin/foo"),
        );
    }
}

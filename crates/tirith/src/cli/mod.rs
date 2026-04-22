use std::io::Write;

/// Output format for commands that support human and JSON output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HumanJsonFormat {
    #[default]
    Human,
    Json,
}

impl HumanJsonFormat {
    /// Resolve the effective format from an optional `--format` value and a
    /// `--json` boolean alias.  Returns `(format, is_json)` so callers can
    /// destructure both in one step.
    pub fn resolve(format: Option<Self>, json_flag: bool) -> (Self, bool) {
        let resolved = if json_flag {
            Self::Json
        } else {
            format.unwrap_or(Self::Human)
        };
        (resolved, resolved == Self::Json)
    }
}

/// Output format for scan, which additionally supports SARIF.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HumanJsonSarifFormat {
    #[default]
    Human,
    Json,
    Sarif,
}

impl HumanJsonSarifFormat {
    /// Resolve the effective format from optional `--format`, `--json`, and
    /// `--sarif` boolean aliases.  Returns `(format, is_json, is_sarif)`.
    pub fn resolve(format: Option<Self>, json_flag: bool, sarif_flag: bool) -> (Self, bool, bool) {
        let resolved = if json_flag {
            Self::Json
        } else if sarif_flag {
            Self::Sarif
        } else {
            format.unwrap_or(Self::Human)
        };
        (resolved, resolved == Self::Json, resolved == Self::Sarif)
    }
}

/// Suggest the closest match from a list of candidates using Levenshtein distance.
/// Returns `None` if no candidate is within `max_distance`.
pub fn suggest_closest<'a>(
    query: &str,
    candidates: &[&'a str],
    max_distance: usize,
) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (*c, tirith_core::util::levenshtein(query, c)))
        .filter(|(_, d)| *d <= max_distance)
        .min_by_key(|(_, d)| *d)
        .map(|(c, _)| c)
}

/// Prompt user for confirmation. Returns true only if:
/// - `yes` is true (`--yes` was passed), OR
/// - stderr is a TTY AND user types y/yes
///
/// Returns **false** in non-interactive contexts without `--yes`,
/// preventing silent approval of destructive operations.
pub fn confirm(prompt: &str, yes: bool) -> bool {
    if yes {
        return true;
    }
    if !is_terminal::is_terminal(std::io::stderr()) {
        eprintln!("tirith: skipping prompt (not a TTY — use --yes to auto-approve)");
        return false;
    }
    eprint!("{prompt} [y/N] ");
    // Flush is best-effort; if it fails the prompt may not be visible but read_line still works.
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(_) => matches!(input.trim(), "y" | "Y" | "yes" | "Yes"),
        Err(e) => {
            eprintln!("tirith: could not read confirmation input: {e}");
            false
        }
    }
}

pub mod audit;
pub mod check;
pub mod checkpoint;
pub mod completions;
pub mod daemon;
pub mod diff;
pub mod doctor;
pub mod explain;
pub mod gateway;
pub mod hook_event;
pub mod init;
pub mod last_trigger;
pub mod license_cmd;
pub mod manpage;
pub mod mcp_server;
pub mod paste;
pub mod policy;
pub mod receipt;
pub mod scan;
pub mod score;
pub mod threatdb_cmd;
pub mod trust;
pub mod warnings;
pub mod why;

#[cfg(unix)]
pub mod fetch;
#[cfg(unix)]
pub mod run;
pub mod setup;

#[cfg(test)]
pub(crate) mod test_harness;

#[cfg(any(test, windows))]
fn trim_wrapping_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(any(test, windows))]
fn parse_shim_target(contents: &str) -> Option<std::path::PathBuf> {
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("path") {
            return None;
        }
        let value = trim_wrapping_quotes(value.trim());
        if value.is_empty() {
            return None;
        }
        Some(std::path::PathBuf::from(value))
    })
}

#[cfg(any(test, windows))]
fn resolve_shim_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut sidecar = path.to_path_buf();
    sidecar.set_extension("shim");

    let contents = std::fs::read_to_string(&sidecar).ok()?;
    let target = parse_shim_target(&contents)?;
    let target = if target.is_relative() {
        sidecar.parent()?.join(target)
    } else {
        target
    };

    target.canonicalize().ok().or(Some(target))
}

fn resolve_effective_tirith_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    if let Some(target) = resolve_shim_target(path) {
        return Some(target);
    }

    path.canonicalize().ok()
}

pub fn tirith_path_lookup_command() -> &'static str {
    #[cfg(unix)]
    {
        "which -a tirith"
    }
    #[cfg(not(unix))]
    {
        "where.exe tirith"
    }
}

/// Resolve all `tirith` executables on PATH using the shell's own command resolution.
/// Returns paths that the shell would actually execute, not just filesystem entries.
pub fn resolve_tirith_on_path() -> Vec<std::path::PathBuf> {
    let output = {
        #[cfg(unix)]
        {
            std::process::Command::new("sh")
                .args(["-c", "which -a tirith 2>/dev/null"])
                .output()
        }
        #[cfg(not(unix))]
        {
            std::process::Command::new("where.exe")
                .arg("tirith")
                .output()
        }
    };

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(std::path::PathBuf::from)
        .collect()
}

/// Find `tirith` executables on PATH that are not the current binary.
/// Deduplicates by logical target path so duplicate PATH entries and shim aliases
/// don't produce repeated warnings.
pub fn find_shadow_binaries() -> Vec<String> {
    let our_canonical = std::env::current_exe()
        .ok()
        .and_then(|p| resolve_effective_tirith_target(&p));

    let mut seen = std::collections::HashSet::new();
    let mut shadows = Vec::new();

    for path in resolve_tirith_on_path() {
        let canonical = resolve_effective_tirith_target(&path);
        // Skip if it resolves to our own binary
        if let (Some(ours), Some(ref theirs)) = (&our_canonical, &canonical) {
            if ours == theirs {
                continue;
            }
        }
        // Dedup by canonical path (fall back to display path for unresolvable entries)
        let key = canonical
            .map(|c| c.display().to_string())
            .unwrap_or_else(|| path.display().to_string());
        if seen.insert(key) {
            shadows.push(path.display().to_string());
        }
    }
    shadows
}

#[cfg(test)]
mod tests {
    use super::{parse_shim_target, resolve_shim_target};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn parse_shim_target_accepts_unquoted_values() {
        let parsed =
            parse_shim_target("path = C:\\Users\\alice\\scoop\\apps\\tirith\\current\\tirith.exe");
        assert_eq!(
            parsed,
            Some(PathBuf::from(
                "C:\\Users\\alice\\scoop\\apps\\tirith\\current\\tirith.exe"
            ))
        );
    }

    #[test]
    fn parse_shim_target_accepts_case_insensitive_quoted_values() {
        let parsed = parse_shim_target("ARGS = --help\r\nPATH = \"/tmp/tirith.exe\"\r\n");
        assert_eq!(parsed, Some(PathBuf::from("/tmp/tirith.exe")));
    }

    #[test]
    fn resolve_shim_target_uses_absolute_target_from_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("apps/tirith/current/tirith.exe");
        let shim = dir.path().join("shims/tirith.exe");

        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&real, b"real").unwrap();
        fs::write(&shim, b"shim").unwrap();
        fs::write(
            shim.with_extension("shim"),
            format!("path = \"{}\"\n", real.display()),
        )
        .unwrap();

        assert_eq!(
            resolve_shim_target(&shim).unwrap().canonicalize().unwrap(),
            real.canonicalize().unwrap()
        );
    }

    #[test]
    fn resolve_shim_target_uses_relative_target_from_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("apps/tirith/current/tirith.exe");
        let shim = dir.path().join("shims/tirith.exe");

        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&real, b"real").unwrap();
        fs::write(&shim, b"shim").unwrap();
        fs::write(
            shim.with_extension("shim"),
            "path = ../apps/tirith/current/tirith.exe\n",
        )
        .unwrap();

        assert_eq!(
            resolve_shim_target(&shim).unwrap().canonicalize().unwrap(),
            real.canonicalize().unwrap()
        );
    }
}

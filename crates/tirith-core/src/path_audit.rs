//! `$PATH` shadowing + leader-path provenance (M9 ch5).
//!
//! Two surfaces live here:
//!
//! 1. **Hot-path leader checks** ([`classify_leader_path`]) — the THREE cheap,
//!    stat-free string compares the engine runs (Exec context, behind
//!    `policy.exec_guard_enabled`). Given the resolved leader's path, the
//!    current repo root, and the `$PATH` string, decide whether the leader is
//!    in `/tmp`, in the repo, or in a user-writable repo-local/`/tmp` `$PATH`
//!    dir that precedes a system dir. The only syscall is a `libc::access`
//!    `W_OK` probe (cheaper than a `stat`, and only on the dir that resolved
//!    the leader). No `codesign`, no `file`, no mtime read.
//!
//! 2. **`tirith path audit`** ([`audit_path_str`]) — the cold, full-PATH
//!    enumeration: duplicate command names across dirs, repo-local `$PATH`
//!    dirs, `/tmp` `$PATH` dirs, and writable-before-system dirs. Takes the
//!    `$PATH` value as a STRING parameter so tests never mutate the process
//!    `PATH` (the libc `setenv` race, PR #125).
//!
//! ## Why `PathWritableDirBeforeSystem` is repo-local / `/tmp` focused
//!
//! On Intel macOS, `/usr/local/bin` is world-writable by default, and almost
//! every developer has `~/.local/bin`, `~/.cargo/bin`, Homebrew dirs, etc.
//! ahead of `/usr/bin`. Flagging "any writable dir before a system dir" would
//! fire on essentially every shell. The HOT-path rule therefore fires only
//! when the writable, precedes-system dir is *also* repo-local or under
//! `/tmp` — the genuinely suspicious shapes an attacker controls via a PR or a
//! scratch drop. The broader "any writable dir before system" inventory is
//! surfaced by `tirith path audit` (cold) as informational context, not as a
//! blocking hot-path finding.
//!
//! ## Known limitation — resolution-vs-execution race (TOCTOU)
//!
//! Everything here resolves the leader / enumerates `$PATH` at ANALYSIS time.
//! The shell may resolve a *different* binary at EXECUTION time (PATH hash
//! cache, a file written between the two, a symlink swap). tirith reports what
//! it observed at analysis time; it cannot guarantee the byte-identical file
//! runs. This is inherent to a pre-exec advisory and is documented rather than
//! papered over.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// System directories whose precedence the writable-before-system rule cares
/// about. A user-writable, repo-local/`/tmp` dir that appears BEFORE any of
/// these in `$PATH` can shadow the system command of the same name.
///
/// Unix uses the FHS bin dirs; Windows uses the well-known `System32` /
/// `Windows` roots so a writable dir ahead of them on `%PATH%` is still flagged
/// rather than the audit silently treating every Windows PATH as clean (the
/// writability probe is still Unix-only, so on Windows this only powers
/// `is_system_path` / `--secure`, not the writable-before-system rule).
#[cfg(not(windows))]
pub const SYSTEM_PATH_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Windows system directories (see [`SYSTEM_PATH_DIRS`] doc). Backslash form
/// matches how `%PATH%` entries are written; `split_path` keeps them verbatim.
#[cfg(windows)]
pub const SYSTEM_PATH_DIRS: &[&str] = &[
    r"C:\Windows\System32",
    r"C:\Windows",
    r"C:\Windows\System32\Wbem",
    r"C:\Windows\System32\WindowsPowerShell\v1.0",
];

/// One cheap classification of the resolved leader's path (hot path). A leader
/// can match more than one (e.g. a repo dir that is also on `$PATH` ahead of a
/// system dir), so [`classify_leader_path`] returns a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderLocation {
    /// Leader path is under `/tmp` (or `$TMPDIR`). → [`RuleId::ExecInTmp`].
    InTmp,
    /// Leader path is inside the current repo working tree.
    /// → [`RuleId::ExecInRepoBin`].
    InRepo,
    /// Leader resolved from a user-writable, repo-local/`/tmp` `$PATH` dir that
    /// precedes a system dir. → [`RuleId::PathWritableDirBeforeSystem`].
    WritableDirBeforeSystem,
}

/// Inputs to the hot-path leader classification. Kept as borrowed strings so
/// the engine can pass slices it already holds.
pub struct LeaderContext<'a> {
    /// The resolved leader path. Either an explicit path the user typed
    /// (`./x`, `/tmp/x`, `~/x` already expanded) or the dir+name the `$PATH`
    /// search resolved to. `None` short-circuits to no findings.
    pub resolved_path: Option<PathBuf>,
    /// The current repo root (`policy::find_repo_root(cwd)`), if any.
    pub repo_root: Option<&'a Path>,
    /// The directory the leader resolved FROM (the `$PATH` entry, or the
    /// parent of an explicit path). Used for the writable-before-system check.
    pub resolved_dir: Option<&'a Path>,
    /// The ordered `$PATH` dirs (already split), used to decide whether
    /// `resolved_dir` precedes a system dir.
    pub path_dirs: &'a [PathBuf],
    /// Temp-dir roots to treat as `/tmp` (production: `["/tmp", $TMPDIR]`).
    pub tmp_roots: &'a [PathBuf],
}

/// Classify the resolved leader path against the three cheap hot-path signals.
/// Pure except for one `libc::access(W_OK)` probe on `resolved_dir` (only when
/// the precedence check already matched). Returns the set of matched locations
/// in a stable order.
pub fn classify_leader_path(ctx: &LeaderContext<'_>) -> Vec<LeaderLocation> {
    let mut out = Vec::new();
    let Some(resolved) = ctx.resolved_path.as_deref() else {
        return out;
    };

    // (i) /tmp — string prefix against each tmp root.
    if path_under_any(resolved, ctx.tmp_roots) {
        out.push(LeaderLocation::InTmp);
    }

    // (ii) repo — string prefix against the repo root.
    if let Some(repo) = ctx.repo_root {
        if path_under(resolved, repo) {
            out.push(LeaderLocation::InRepo);
        }
    }

    // (iii) writable dir before system: the dir the leader resolved from must
    // (a) appear in $PATH before a system dir, (b) be repo-local or under /tmp,
    // and (c) be writable by the current user. (b) keeps ~/.local/bin and the
    // world-writable Intel-macOS /usr/local/bin out of the HOT finding.
    if let Some(dir) = ctx.resolved_dir {
        let repo_local = ctx.repo_root.map(|r| path_under(dir, r)).unwrap_or(false);
        let tmp_local = path_under_any(dir, ctx.tmp_roots);
        if (repo_local || tmp_local)
            && dir_precedes_system(dir, ctx.path_dirs)
            && dir_is_user_writable(dir)
        {
            out.push(LeaderLocation::WritableDirBeforeSystem);
        }
    }

    out
}

/// Build the hot-path [`Finding`]s for the matched leader locations. The
/// resolved leader path is included as evidence (it is not a secret).
pub fn leader_findings(locations: &[LeaderLocation], resolved_display: &str) -> Vec<Finding> {
    locations
        .iter()
        .map(|loc| match loc {
            LeaderLocation::InTmp => Finding {
                rule_id: RuleId::ExecInTmp,
                severity: Severity::Medium,
                title: "Command resolves to a binary under /tmp".to_string(),
                description: format!(
                    "The command leader resolves to `{resolved_display}`, which lives in a \
                     world-writable scratch directory. Binaries dropped in /tmp are a classic \
                     staging location for run-once payloads."
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("resolved_path={resolved_display}"),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            LeaderLocation::InRepo => Finding {
                rule_id: RuleId::ExecInRepoBin,
                severity: Severity::Medium,
                title: "Command resolves to a binary inside the repository".to_string(),
                description: format!(
                    "The command leader resolves to `{resolved_display}`, which lives inside the \
                     current repository's working tree. Running a checked-in binary executes \
                     code that an attacker can land through a pull request. Run \
                     `tirith exec check` for full provenance."
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("resolved_path={resolved_display}"),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            LeaderLocation::WritableDirBeforeSystem => Finding {
                rule_id: RuleId::PathWritableDirBeforeSystem,
                severity: Severity::High,
                title: "Command resolved from a user-writable PATH dir ahead of the system path"
                    .to_string(),
                description: format!(
                    "The command leader resolves to `{resolved_display}`, from a directory the \
                     current user can write that precedes /usr/bin (and is repo-local or under \
                     /tmp). A writable directory ahead of the system path lets any local process \
                     shadow system commands. Reorder $PATH so system dirs come first."
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("resolved_path={resolved_display}"),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
        })
        .collect()
}

// ─── cold: `tirith path audit` ───────────────────────────────────────────────

/// How a `$PATH` directory is classified by the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathDirRisk {
    /// Inside the current repo working tree.
    InRepo,
    /// Under `/tmp` (or `$TMPDIR`).
    InTmp,
    /// User-writable AND precedes a system dir (informational in the audit;
    /// the HOT rule is narrower).
    WritableBeforeSystem,
    /// Resolves a command name that also resolves in another dir (duplicate).
    DuplicateCommand,
}

/// One reported entry from [`audit_path_str`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAuditEntry {
    /// The `$PATH` directory.
    pub dir: String,
    /// Why it was flagged.
    pub risk: PathDirRisk,
    /// For `DuplicateCommand`: the command name that collides. Empty otherwise.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub command: String,
}

/// Full result of [`audit_path_str`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathAuditReport {
    /// The ordered `$PATH` dirs as parsed (display form).
    pub path_dirs: Vec<String>,
    /// Flagged entries (one per (dir, risk) — duplicates carry the command).
    pub findings: Vec<PathAuditEntry>,
}

impl PathAuditReport {
    /// `true` when at least one High-severity-class finding is present
    /// (`InTmp` or `WritableBeforeSystem`). Used by the CLI for exit code.
    pub fn has_high(&self) -> bool {
        self.findings.iter().any(|e| {
            matches!(
                e.risk,
                PathDirRisk::InTmp | PathDirRisk::WritableBeforeSystem
            )
        })
    }
}

/// Audit a `$PATH` string. `path_value` is the raw `$PATH` (colon-separated on
/// Unix; the caller passes `std::env::var("PATH")` in production, a synthetic
/// string in tests). `repo_root` and `tmp_roots` are injected so the function
/// is hermetic. Directory existence + writability are probed on the real FS,
/// so tests that want those signals create real temp dirs.
pub fn audit_path_str(
    path_value: &str,
    repo_root: Option<&Path>,
    tmp_roots: &[PathBuf],
) -> PathAuditReport {
    let dirs = split_path(path_value);
    let mut report = PathAuditReport {
        path_dirs: dirs.iter().map(|d| d.display().to_string()).collect(),
        findings: Vec::new(),
    };

    // Per-dir location/writability classification.
    for dir in &dirs {
        let repo_local = repo_root.map(|r| path_under(dir, r)).unwrap_or(false);
        let tmp_local = path_under_any(dir, tmp_roots);
        if repo_local {
            report.findings.push(PathAuditEntry {
                dir: dir.display().to_string(),
                risk: PathDirRisk::InRepo,
                command: String::new(),
            });
        }
        if tmp_local {
            report.findings.push(PathAuditEntry {
                dir: dir.display().to_string(),
                risk: PathDirRisk::InTmp,
                command: String::new(),
            });
        }
        // Writable-before-system is SCOPED to repo-local / /tmp dirs (risk #2):
        // flagging every writable dir ahead of the system path would fire on
        // ~/.local/bin, Homebrew, and the world-writable Intel-macOS
        // /usr/local/bin on essentially every dev machine. The narrow scope
        // matches the hot-path `PathWritableDirBeforeSystem` rule.
        if (repo_local || tmp_local) && dir_precedes_system(dir, &dirs) && dir_is_user_writable(dir)
        {
            report.findings.push(PathAuditEntry {
                dir: dir.display().to_string(),
                risk: PathDirRisk::WritableBeforeSystem,
                command: String::new(),
            });
        }
    }

    // Duplicate command names: enumerate executables per dir and report names
    // that resolve in more than one dir. We report the SHADOWED dir (the later
    // one) so the entry points at the copy the shell would NOT run.
    //
    // SCOPED to security-relevant duplicates: a duplicate is reported only when
    // one of the two colliding directories is repo-local or under /tmp. On a
    // normal dev machine hundreds of commands legitimately appear in both
    // Homebrew and a system dir (`node`, `git`, …); flagging all of them would
    // bury the genuine "a repo/ /tmp copy shadows (or is shadowed by) the real
    // tool" signal. The narrow scope keeps the audit actionable.
    let suspicious_dir = |dir: &Path| -> bool {
        repo_root.map(|r| path_under(dir, r)).unwrap_or(false) || path_under_any(dir, tmp_roots)
    };
    let mut first_seen: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, dir) in dirs.iter().enumerate() {
        for name in executables_in_dir(dir) {
            match first_seen.get(&name).copied() {
                None => {
                    first_seen.insert(name, idx);
                }
                Some(first_idx) => {
                    // Report only when the first OR the shadowed dir is
                    // repo-local / /tmp.
                    if suspicious_dir(dir) || suspicious_dir(&dirs[first_idx]) {
                        report.findings.push(PathAuditEntry {
                            dir: dir.display().to_string(),
                            risk: PathDirRisk::DuplicateCommand,
                            command: name,
                        });
                    }
                }
            }
        }
    }

    report
}

/// Resolve a bare command NAME against the `$PATH` string, returning every dir
/// (in order) whose entry is an executable file of that name. Used by
/// `tirith path which`. Does NOT mutate the process environment.
pub fn which_all(command: &str, path_value: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in split_path(path_value) {
        let candidate = dir.join(command);
        if is_executable_file(&candidate) {
            out.push(candidate);
        }
    }
    out
}

/// `true` when `path` resolves to a SYSTEM location (under one of
/// [`SYSTEM_PATH_DIRS`]). Used by `tirith path which --secure` to decide
/// whether the first-resolved binary is the trusted system copy.
pub fn is_system_path(path: &Path) -> bool {
    SYSTEM_PATH_DIRS
        .iter()
        .any(|sys| path_under(path, Path::new(sys)))
}

// ─── hot-path leader resolution ──────────────────────────────────────────────

/// The resolved leader of a command, ready for [`classify_leader_path`].
pub struct ResolvedLeader {
    /// Absolute (best-effort) path to the leader binary.
    pub path: PathBuf,
    /// The directory it resolved from (parent of `path`).
    pub dir: PathBuf,
}

/// Resolve a command leader token to a path for the hot-path provenance check.
///
/// If `leader` has a path component (`/`, or `\` on Windows): `~/...` expands
/// against `home`, a relative path resolves against `cwd`, and an absolute path
/// is used as-is. The path is NOT required to exist (a typed `./build/x` is
/// still classifiable as repo-local).
///
/// Otherwise `leader` is a bare command name, resolved against `path_value` via
/// [`which_all`], taking the FIRST executable hit (what the shell runs). A bare
/// name with no PATH hit yields `None` (nothing to classify).
///
/// Pure w.r.t. the process environment: `cwd`, `home`, and `path_value` are all
/// passed in, so the engine controls them and tests stay hermetic.
pub fn resolve_leader(
    leader: &str,
    cwd: Option<&Path>,
    home: Option<&Path>,
    path_value: &str,
) -> Option<ResolvedLeader> {
    let leader = leader.trim();
    if leader.is_empty() {
        return None;
    }

    let has_path_component = leader.contains('/') || (cfg!(windows) && leader.contains('\\'));

    let path = if has_path_component {
        if let Some(rest) = leader.strip_prefix("~/") {
            home?.join(rest)
        } else if leader == "~" {
            home?.to_path_buf()
        } else {
            let p = PathBuf::from(leader);
            if p.is_absolute() {
                p
            } else {
                cwd?.join(p)
            }
        }
    } else {
        // Bare command name → first PATH hit.
        which_all(leader, path_value).into_iter().next()?
    };

    let dir = path.parent().map(|p| p.to_path_buf())?;
    Some(ResolvedLeader { path, dir })
}

// ─── shared helpers ──────────────────────────────────────────────────────────

/// Split a `$PATH` value into directories. Empty entries (a literal `::` or a
/// leading/trailing `:`) mean "current directory" in POSIX, which is itself a
/// shadowing risk — we map them to `.` so they're audited rather than dropped.
pub fn split_path(path_value: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    let sep = ';';
    #[cfg(not(windows))]
    let sep = ':';
    path_value
        .split(sep)
        .map(|e| {
            if e.is_empty() {
                PathBuf::from(".")
            } else {
                PathBuf::from(e)
            }
        })
        .collect()
}

/// `true` when `child` is `ancestor` or lives beneath it. Both sides are
/// canonicalized so a symlinked ancestor (macOS `/tmp` -> `/private/tmp`,
/// `$TMPDIR` under `/var/folders`) still matches a child resolved through it.
/// A non-existent child cannot be canonicalized directly, so we canonicalize
/// its nearest EXISTING ancestor and re-append the trailing components — this
/// keeps a typed `./build/x` (which may not exist yet) classifiable while
/// still resolving the symlinked dir prefix.
fn path_under(child: &Path, ancestor: &Path) -> bool {
    let c = canonicalize_lenient(child);
    let a = canonicalize_lenient(ancestor);
    c == a || c.starts_with(&a)
}

/// Canonicalize `path` if it exists; otherwise canonicalize the longest
/// existing ancestor and re-append the remaining (non-existent) components.
/// Falls back to the literal path if even the root cannot be canonicalized.
fn canonicalize_lenient(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let mut remainder: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            remainder.push(name.to_os_string());
        }
        if let Ok(base) = parent.canonicalize() {
            let mut out = base;
            for name in remainder.iter().rev() {
                out.push(name);
            }
            return out;
        }
        cur = parent;
    }
    path.to_path_buf()
}

fn path_under_any(child: &Path, ancestors: &[PathBuf]) -> bool {
    ancestors.iter().any(|a| path_under(child, a))
}

/// `true` when `dir` appears in `path_dirs` strictly before the first system
/// dir. If no system dir is present, there is nothing to "precede" → false.
fn dir_precedes_system(dir: &Path, path_dirs: &[PathBuf]) -> bool {
    let dir_idx = path_dirs.iter().position(|d| d == dir);
    let Some(dir_idx) = dir_idx else {
        return false;
    };
    let sys_idx = path_dirs
        .iter()
        .position(|d| SYSTEM_PATH_DIRS.iter().any(|s| d == Path::new(s)));
    match sys_idx {
        Some(s) => dir_idx < s,
        None => false,
    }
}

/// `true` when the current user can write to `dir`. Uses `access(2)` `W_OK`
/// (cheaper than a metadata stat, and matches the kernel's own check). On
/// non-Unix this conservatively returns `false` (the writable-before-system
/// rule is a Unix-PATH concern).
#[cfg(unix)]
fn dir_is_user_writable(dir: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: cpath is a valid NUL-terminated C string for the duration of the
    // call; access() only reads it and returns an int.
    unsafe { libc::access(cpath.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(unix))]
fn dir_is_user_writable(_dir: &Path) -> bool {
    false
}

/// `true` when `path` is a regular file with an execute bit set (Unix) / a
/// likely-executable extension (non-Unix). Symlinks are followed (metadata,
/// not symlink_metadata).
pub fn is_executable_file(path: &Path) -> bool {
    let Ok(md) = std::fs::metadata(path) else {
        return false;
    };
    if !md.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("exe") | Some("bat") | Some("cmd") | Some("com")
        )
    }
}

/// Enumerate the executable file names directly inside `dir` (non-recursive).
/// Unreadable / missing dirs yield an empty list. Names only (no path).
fn executables_in_dir(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if is_executable_file(&p) {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mkexec(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn pb(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    // ── hot-path classify_leader_path ─────────────────────────────────────

    #[test]
    fn leader_in_tmp_classifies_in_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let leader = tmp.path().join("payload");
        let tmp_roots = vec![tmp.path().to_path_buf()];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: None,
            resolved_dir: Some(tmp.path()),
            path_dirs: &[],
            tmp_roots: &tmp_roots,
        };
        let locs = classify_leader_path(&ctx);
        assert!(locs.contains(&LeaderLocation::InTmp), "{locs:?}");
    }

    #[test]
    fn leader_in_repo_classifies_in_repo() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let bindir = repo.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let leader = bindir.join("eslint");
        std::fs::write(&leader, b"x").unwrap();
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: Some(repo.path()),
            resolved_dir: Some(&bindir),
            path_dirs: &[],
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(locs.contains(&LeaderLocation::InRepo), "{locs:?}");
    }

    #[test]
    fn leader_outside_repo_and_tmp_classifies_nothing() {
        let other = tempfile::tempdir().unwrap();
        let leader = other.path().join("git");
        std::fs::write(&leader, b"x").unwrap();
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: None,
            resolved_dir: Some(other.path()),
            path_dirs: &[],
            tmp_roots: &[],
        };
        assert!(classify_leader_path(&ctx).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn writable_repo_dir_before_system_fires() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let bindir = repo.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let leader = bindir.join("ls");
        mkexec(&leader);
        // $PATH: repo bin FIRST, then /usr/bin.
        let path_dirs = vec![bindir.clone(), pb("/usr/bin")];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: Some(repo.path()),
            resolved_dir: Some(&bindir),
            path_dirs: &path_dirs,
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(
            locs.contains(&LeaderLocation::WritableDirBeforeSystem),
            "{locs:?}"
        );
        assert!(locs.contains(&LeaderLocation::InRepo), "{locs:?}");
    }

    #[cfg(unix)]
    #[test]
    fn writable_dir_after_system_does_not_fire() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let bindir = repo.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let leader = bindir.join("ls");
        mkexec(&leader);
        // /usr/bin FIRST, repo bin AFTER → not "before system".
        let path_dirs = vec![pb("/usr/bin"), bindir.clone()];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: Some(repo.path()),
            resolved_dir: Some(&bindir),
            path_dirs: &path_dirs,
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(
            !locs.contains(&LeaderLocation::WritableDirBeforeSystem),
            "must not fire when writable dir is AFTER the system dir: {locs:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_repo_writable_dir_before_system_does_not_fire_on_hot_path() {
        // A writable dir before /usr/bin that is NOT repo-local and NOT /tmp
        // (the ~/.local/bin shape) must NOT fire the HOT rule.
        let home_local = tempfile::tempdir().unwrap();
        let leader = home_local.path().join("ls");
        mkexec(&leader);
        let path_dirs = vec![home_local.path().to_path_buf(), pb("/usr/bin")];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: None,
            resolved_dir: Some(home_local.path()),
            path_dirs: &path_dirs,
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(
            locs.is_empty(),
            "a generic writable ~/.local/bin shape must not fire the HOT rule: {locs:?}"
        );
    }

    #[test]
    fn leader_findings_carry_path_evidence() {
        let f = leader_findings(&[LeaderLocation::InTmp], "/tmp/payload");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, RuleId::ExecInTmp);
        assert_eq!(f[0].severity, Severity::Medium);
        let blob = format!("{:?}", f[0].evidence);
        assert!(blob.contains("/tmp/payload"), "{blob}");
    }

    // ── cold: audit_path_str ──────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn audit_flags_repo_local_dir_before_system() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let nm = repo.path().join("node_modules/.bin");
        std::fs::create_dir_all(&nm).unwrap();
        mkexec(&nm.join("eslint"));
        let path_value = format!("{}:/usr/bin", nm.display());
        let report = audit_path_str(&path_value, Some(repo.path()), &[]);
        let risks: Vec<PathDirRisk> = report.findings.iter().map(|e| e.risk).collect();
        assert!(risks.contains(&PathDirRisk::InRepo), "{risks:?}");
        assert!(
            risks.contains(&PathDirRisk::WritableBeforeSystem),
            "{risks:?}"
        );
        assert!(report.has_high());
    }

    #[cfg(unix)]
    #[test]
    fn audit_flags_tmp_dir_and_duplicate_command() {
        let tmp = tempfile::tempdir().unwrap();
        let d1 = tmp.path().join("d1");
        let d2 = tmp.path().join("d2");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        // Same command name in both dirs → duplicate; both under tmp root.
        mkexec(&d1.join("kubectl"));
        mkexec(&d2.join("kubectl"));
        let path_value = format!("{}:{}", d1.display(), d2.display());
        let tmp_roots = vec![tmp.path().to_path_buf()];
        let report = audit_path_str(&path_value, None, &tmp_roots);
        let risks: Vec<PathDirRisk> = report.findings.iter().map(|e| e.risk).collect();
        assert!(risks.contains(&PathDirRisk::InTmp), "{risks:?}");
        assert!(risks.contains(&PathDirRisk::DuplicateCommand), "{risks:?}");
        // The duplicate entry names the colliding command and points at d2
        // (the shadowed, later copy).
        let dup = report
            .findings
            .iter()
            .find(|e| e.risk == PathDirRisk::DuplicateCommand)
            .unwrap();
        assert_eq!(dup.command, "kubectl");
        assert!(dup.dir.contains("d2"), "{}", dup.dir);
    }

    #[test]
    fn audit_clean_path_has_no_findings() {
        // Two non-existent, non-system, non-repo dirs → nothing to flag.
        let report = audit_path_str("/opt/clean/bin:/usr/bin", None, &[]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(!report.has_high());
    }

    // ── which_all + is_system_path ────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn which_all_resolves_in_path_order() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        mkexec(&d1.path().join("git"));
        mkexec(&d2.path().join("git"));
        let path_value = format!("{}:{}", d1.path().display(), d2.path().display());
        let hits = which_all("git", &path_value);
        assert_eq!(hits.len(), 2);
        assert!(hits[0].starts_with(d1.path()));
        assert!(hits[1].starts_with(d2.path()));
    }

    #[cfg(unix)]
    #[test]
    fn which_all_skips_non_executable() {
        let d1 = tempfile::tempdir().unwrap();
        // A non-executable file named git → not resolved.
        std::fs::write(d1.path().join("git"), b"text").unwrap();
        let hits = which_all("git", &d1.path().display().to_string());
        assert!(hits.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn is_system_path_recognizes_usr_bin() {
        assert!(is_system_path(Path::new("/usr/bin/git")));
        assert!(is_system_path(Path::new("/bin/sh")));
        assert!(!is_system_path(Path::new("/opt/homebrew/bin/git")));
        assert!(!is_system_path(Path::new("/tmp/git")));
    }

    #[cfg(windows)]
    #[test]
    fn is_system_path_recognizes_system32() {
        // SYSTEM_PATH_DIRS on Windows holds the System32 / Windows dirs.
        assert!(is_system_path(Path::new(r"C:\Windows\System32\cmd.exe")));
        assert!(!is_system_path(Path::new(r"C:\Users\me\bin\git.exe")));
    }

    // `split_path` uses the platform separator (`:` on Unix, `;` on Windows),
    // so each separator case is gated to the platform whose separator it uses.
    #[cfg(not(windows))]
    #[test]
    fn split_path_maps_empty_to_dot() {
        let dirs = split_path("/usr/bin::/bin");
        assert_eq!(dirs, vec![pb("/usr/bin"), pb("."), pb("/bin")]);
    }

    #[cfg(windows)]
    #[test]
    fn split_path_maps_empty_to_dot_windows() {
        // On Windows the separator is `;`; an empty entry (a literal `;;` or a
        // trailing `;`) still maps to `.` so it is audited, not dropped.
        let dirs = split_path(r"C:\bin;;C:\sys");
        assert_eq!(dirs, vec![pb(r"C:\bin"), pb("."), pb(r"C:\sys")]);
        // A colon inside a drive-letter path must NOT be treated as a separator.
        let drive = split_path(r"C:\Windows\System32");
        assert_eq!(drive, vec![pb(r"C:\Windows\System32")]);
    }

    // ── resolve_leader ────────────────────────────────────────────────────

    #[test]
    fn resolve_leader_relative_path_against_cwd() {
        let cwd = tempfile::tempdir().unwrap();
        let r = resolve_leader("./build/tool", Some(cwd.path()), None, "").unwrap();
        assert_eq!(r.path, cwd.path().join("build/tool"));
        assert_eq!(r.dir, cwd.path().join("build"));
    }

    #[test]
    fn resolve_leader_tilde_expands_against_home() {
        let home = tempfile::tempdir().unwrap();
        let r = resolve_leader("~/bin/x", None, Some(home.path()), "").unwrap();
        assert_eq!(r.path, home.path().join("bin/x"));
    }

    // `/usr/local/bin/foo` is only `is_absolute()` on Unix (no drive letter on
    // Windows), so the Unix and Windows absolute-path cases are gated apart.
    #[cfg(not(windows))]
    #[test]
    fn resolve_leader_absolute_path_used_directly() {
        let r = resolve_leader("/usr/local/bin/foo", None, None, "").unwrap();
        assert_eq!(r.path, pb("/usr/local/bin/foo"));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_leader_absolute_path_used_directly_windows() {
        // A drive-rooted Windows path with backslashes is absolute and used
        // as-is (no cwd needed) — and a `\`-bearing leader counts as having a
        // path component on Windows.
        let r = resolve_leader(r"C:\tools\foo.exe", None, None, "").unwrap();
        assert_eq!(r.path, pb(r"C:\tools\foo.exe"));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_leader_relative_no_cwd_is_none_not_panic() {
        // A relative leader with no cwd must return None gracefully, never
        // panic (the bug the Windows CI surfaced: a non-drive path is relative
        // on Windows, so `cwd?` short-circuits to None instead of unwrapping).
        assert!(resolve_leader(r"build\tool", None, None, "").is_none());
        assert!(resolve_leader("/usr/local/bin/foo", None, None, "").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_leader_bare_name_uses_first_path_hit() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        mkexec(&d1.path().join("mytool"));
        mkexec(&d2.path().join("mytool"));
        let path_value = format!("{}:{}", d1.path().display(), d2.path().display());
        let r = resolve_leader("mytool", None, None, &path_value).unwrap();
        assert!(
            r.path.starts_with(d1.path()),
            "first hit wins: {:?}",
            r.path
        );
    }

    #[test]
    fn resolve_leader_bare_name_no_hit_is_none() {
        assert!(resolve_leader("definitely-not-on-path-xyz", None, None, "/usr/bin").is_none());
    }
}

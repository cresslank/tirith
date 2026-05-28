//! `tirith temp-run` — run a command in a throwaway temp directory and diff
//! its filesystem impact (M10 ch6, design-decision D1).
//!
//! HONESTY-OF-CLAIM (the dominant requirement for this command):
//! `temp-run` is **file isolation only — NOT a sandbox and NOT a security
//! boundary**. The command runs with the user's FULL privileges. It can read
//! the keychain, ssh keys, AWS / cloud credentials, and reach the network
//! exactly as if you had run it directly. The ONLY thing `temp-run` changes is
//! the *working directory*: the command starts in a fresh `mkdtemp` dir (empty
//! by default, or a `.git`-stripped copy of the repo with `--copy-repo`) so
//! files it WRITES land there instead of polluting your tree, and you get a
//! diff of what it touched. Use it for filesystem-impact PREVIEW only.
//!
//! Runtime sandboxing is an explicit tirith non-goal (see
//! `docs/threat-model.md`). This command does not contradict that non-goal — it
//! is a file-isolation workflow, not a containment boundary.
//!
//! Portability notes (why this is pure Rust, no shell-out):
//!   * `--copy-repo` walks the tree with `walkdir` + `fs::copy`, filtering any
//!     path with a `.git/` component. We do NOT use `cp -R --exclude=.git`:
//!     `--exclude` is a GNU coreutils extension and is absent on BSD/macOS `cp`.
//!   * `--strip-env` uses `Command::env_clear()` then re-adds an explicit
//!     allowlist (HOME, PATH, USER, LANG, TERM). We do NOT use `env -i HOME
//!     PATH …`: the bare-name passthrough form of `env -i` is inconsistent
//!     across coreutils and BSD `env` (BSD treats the names as commands).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::cli::{confirm, write_json_stdout};

/// The single honesty banner reused across help text and every human output
/// surface. Pinned by `help_snapshots.rs::help_temp_run` and the
/// `docs/threat-model.md` wording so the three never drift apart.
pub const NOT_A_SANDBOX_BANNER: &str = "\
file isolation only; not a sandbox. The command runs with full user privileges \
and can read your keychain, ssh keys, AWS creds, and the network. Use this for \
filesystem-impact preview ONLY.";

/// Stable machine-readable marker carried by every JSON envelope so a
/// downstream consumer can never mistake `temp-run` for a security boundary.
pub const ISOLATION_KIND: &str = "file_only_not_a_sandbox";

/// Environment variables preserved under `--strip-env`. Deliberately tiny:
/// enough for most commands to find a home, a PATH, and render text, but not
/// the broad surface (tokens, cloud creds) a real run would inherit. This is a
/// convenience knob, NOT a secret-scrubbing security control.
const STRIP_ENV_ALLOWLIST: [&str; 5] = ["HOME", "PATH", "USER", "LANG", "TERM"];

/// Cap on files copied / inventoried so a giant tree can't hang the command.
const MAX_FILES: usize = 100_000;

/// `tirith temp-run -- <cmd>` — mkdtemp, optionally seed it, run the command
/// there with the user's full privileges, diff the temp dir, then prompt to
/// delete or keep it.
///
/// This is NOT a sandbox (see the module docs and [`NOT_A_SANDBOX_BANNER`]).
/// The exit code is the CHILD command's exit code, except a usage error (2) or
/// a setup/spawn failure (2). The filesystem diff is reported but never
/// overrides the child's exit code.
pub fn run(command: &[String], copy_repo: bool, strip_env: bool, json: bool) -> i32 {
    let command_str = command.join(" ");
    if command_str.trim().is_empty() {
        eprintln!(
            "tirith temp-run: no command given \
             (usage: tirith temp-run -- ./script.sh)"
        );
        return 2;
    }

    // mkdtemp. The TempDir handle stays alive for the whole function so its
    // Drop never fires mid-run or mid-diff (cleanup-race guard). We only delete
    // at the very end, and only on explicit confirmation.
    let temp = match tempfile::Builder::new()
        .prefix("tirith-temp-run-")
        .tempdir()
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tirith temp-run: failed to create temp directory: {e}");
            return 2;
        }
    };
    let temp_path = temp.path().to_path_buf();

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Optionally seed the temp dir with a .git-stripped copy of the repo.
    let copied = if copy_repo {
        match copy_repo_into(&cwd, &temp_path) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("tirith temp-run: failed to copy repo: {e}");
                return 2;
            }
        }
    } else {
        None
    };

    if !json {
        print_preamble(&command_str, &temp_path, copy_repo, strip_env, copied);
    }

    // Baseline inventory AFTER seeding — so `--copy-repo` files aren't reported
    // as "new". An empty temp dir yields an empty baseline.
    let before = inventory(&temp_path);

    // Run the command IN the temp dir, with the user's full privileges. The
    // working directory is the only thing we constrain.
    let exit_code = match run_in_dir(&command_str, &temp_path, strip_env) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tirith temp-run: failed to run command: {e}");
            return 2;
        }
    };

    let after = inventory(&temp_path);
    let (new_files, modified_files) = diff_inventories(&before, &after, &temp_path);

    // Decide keep-vs-delete BEFORE moving the TempDir handle. Non-interactive
    // (or an explicit "no") keeps the dir and prints its path; interactive "yes"
    // deletes it. We never delete out from under the diff above.
    let delete = confirm(
        &format!("tirith temp-run: delete temp dir {}?", temp_path.display()),
        false,
    );

    let kept_path = if delete {
        // Dropping the handle removes the directory.
        drop(temp);
        None
    } else {
        // Persist the directory past Drop and surface the path for review.
        let persisted = temp.keep();
        Some(persisted)
    };

    if json {
        emit_json(
            &command_str,
            exit_code,
            copy_repo,
            strip_env,
            copied,
            &new_files,
            &modified_files,
            kept_path.as_deref(),
        );
    } else {
        print_result(exit_code, &new_files, &modified_files, kept_path.as_deref());
    }

    exit_code
}

/// Print the up-front honesty banner and run plan (human mode).
fn print_preamble(
    command_str: &str,
    temp_path: &Path,
    copy_repo: bool,
    strip_env: bool,
    copied: Option<usize>,
) {
    let s = tirith_core::style::Stream::Stdout;
    println!(
        "{} {}",
        tirith_core::style::bold("temp-run:", s),
        command_str
    );
    // The honesty banner, loud and unmissable, on every invocation.
    println!("  {}", tirith_core::style::red(NOT_A_SANDBOX_BANNER, s));
    println!("  temp dir: {}", temp_path.display());
    if copy_repo {
        match copied {
            Some(n) => println!("  seeded:   copied {n} file(s) from the repo (.git excluded)"),
            None => println!("  seeded:   repo copy"),
        }
    } else {
        println!("  seeded:   empty (pass --copy-repo to copy the repo, .git excluded)");
    }
    if strip_env {
        println!(
            "  env:      stripped to allowlist [{}] (convenience, NOT secret scrubbing)",
            STRIP_ENV_ALLOWLIST.join(", ")
        );
    } else {
        println!("  env:      inherited in full (pass --strip-env to trim to an allowlist)");
    }
    println!();
}

/// Print the post-run filesystem diff and the keep/delete outcome (human mode).
fn print_result(
    exit_code: i32,
    new_files: &[String],
    modified_files: &[String],
    kept_path: Option<&Path>,
) {
    println!("  exit code: {exit_code}");
    print_list_section("new files", new_files);
    print_list_section("modified files", modified_files);
    match kept_path {
        Some(p) => println!("\n  kept temp dir: {}", p.display()),
        None => println!("\n  temp dir deleted"),
    }
}

fn print_list_section(label: &str, items: &[String]) {
    if items.is_empty() {
        println!("\n  {label}: none");
    } else {
        println!("\n  {label} ({}):", items.len());
        for i in items {
            println!("    {i}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_json(
    command_str: &str,
    exit_code: i32,
    copy_repo: bool,
    strip_env: bool,
    copied: Option<usize>,
    new_files: &[String],
    modified_files: &[String],
    kept_path: Option<&Path>,
) {
    let json_val = serde_json::json!({
        // The load-bearing honesty field: a consumer reading this can never
        // mistake temp-run for a security boundary.
        "isolation_kind": ISOLATION_KIND,
        "not_a_sandbox": true,
        "disclaimer": NOT_A_SANDBOX_BANNER,
        "command": command_str,
        "exit_code": exit_code,
        "copy_repo": copy_repo,
        "files_copied": copied,
        "strip_env": strip_env,
        "env_allowlist": if strip_env { STRIP_ENV_ALLOWLIST.to_vec() } else { Vec::new() },
        "new_files": new_files,
        "modified_files": modified_files,
        "temp_dir_kept": kept_path.is_some(),
        "temp_dir": kept_path.map(|p| p.display().to_string()),
    });
    write_json_stdout(&json_val, "tirith temp-run: failed to write JSON output");
}

/// Run `command_str` through the platform shell with its working directory set
/// to `dir`. With `strip_env`, the child's environment is cleared and rebuilt
/// from the explicit allowlist. Returns the child's exit code (128 if killed by
/// a signal with no code). The command runs with the user's full privileges —
/// this is NOT isolation.
fn run_in_dir(command_str: &str, dir: &Path, strip_env: bool) -> std::io::Result<i32> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command_str);
        c
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut c = Command::new(shell);
        c.arg("-c").arg(command_str);
        c
    };
    cmd.current_dir(dir);

    if strip_env {
        // Portable env trimming: clear everything, then re-add only the
        // allowlist values that are actually set in the current environment.
        // (NOT `env -i NAME …` — the bare-name form is non-portable.)
        cmd.env_clear();
        for key in STRIP_ENV_ALLOWLIST {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
    }

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(128))
}

/// Copy the repo rooted at `src` into `dst`, excluding any path with a `.git`
/// component. Pure `walkdir` + `fs::copy` — portable, no `cp --exclude`.
/// Returns the number of regular files copied. Symlinks are skipped (we copy
/// file contents only; a copied tree is for impact preview, not a faithful
/// mirror).
fn copy_repo_into(src: &Path, dst: &Path) -> std::io::Result<usize> {
    use walkdir::WalkDir;

    let mut copied = 0usize;
    for entry in WalkDir::new(src)
        .follow_links(false)
        .into_iter()
        // Prune `.git` directories wholesale so we never descend into them.
        .filter_entry(|e| !(e.file_type().is_dir() && e.file_name().to_str() == Some(".git")))
    {
        if copied >= MAX_FILES {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        // Belt-and-suspenders: skip anything that still has a `.git` component
        // (e.g. a nested submodule `.git` file) that slipped past the prune.
        if path
            .components()
            .any(|c| c.as_os_str().to_str() == Some(".git"))
        {
            continue;
        }
        let rel = match path.strip_prefix(src) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() {
            continue; // the root itself
        }
        let target = dst.join(rel);
        let ft = entry.file_type();
        if ft.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if ft.is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(path, &target)?;
            copied += 1;
        }
        // Symlinks and other special files are intentionally skipped.
    }
    Ok(copied)
}

/// Inventory regular files under `root` as a `path -> mtime` map, capped at
/// [`MAX_FILES`]. Symlinks are recorded by their own metadata (not followed).
fn inventory(root: &Path) -> BTreeMap<String, SystemTime> {
    use walkdir::WalkDir;

    let mut out = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
        if out.len() >= MAX_FILES {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Record files and symlinks (anything that isn't a directory) so a
        // newly-created symlink shows up in the diff.
        if !meta.is_dir() {
            if let Ok(mtime) = meta.modified() {
                out.insert(entry.path().to_string_lossy().into_owned(), mtime);
            }
        }
    }
    out
}

/// Diff two inventories into `(new_files, modified_files)`, with both lists
/// sorted and paths rendered relative to `root` for readable output.
fn diff_inventories(
    before: &BTreeMap<String, SystemTime>,
    after: &BTreeMap<String, SystemTime>,
    root: &Path,
) -> (Vec<String>, Vec<String>) {
    let rel = |p: &str| -> String {
        Path::new(p)
            .strip_prefix(root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string())
    };

    let mut new_files: Vec<String> = after
        .keys()
        .filter(|p| !before.contains_key(*p))
        .map(|p| rel(p))
        .collect();
    new_files.sort();

    let mut modified_files: Vec<String> = after
        .iter()
        .filter_map(|(p, mtime_after)| {
            before
                .get(p)
                .filter(|mtime_before| *mtime_before != mtime_after)
                .map(|_| rel(p))
        })
        .collect();
    modified_files.sort();

    (new_files, modified_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn banner_states_not_a_sandbox_and_full_privileges() {
        assert!(NOT_A_SANDBOX_BANNER.contains("not a sandbox"));
        assert!(NOT_A_SANDBOX_BANNER.contains("full user privileges"));
        assert!(NOT_A_SANDBOX_BANNER.contains("keychain"));
        assert_eq!(ISOLATION_KIND, "file_only_not_a_sandbox");
    }

    #[test]
    fn copy_repo_excludes_git_directory() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::create_dir_all(src.path().join(".git/objects")).unwrap();
        fs::write(src.path().join(".git/config"), b"[core]").unwrap();
        fs::write(src.path().join(".git/objects/abc"), b"obj").unwrap();
        fs::create_dir_all(src.path().join("src")).unwrap();
        fs::write(src.path().join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(src.path().join("README.md"), b"# hi").unwrap();

        let copied = copy_repo_into(src.path(), dst.path()).unwrap();
        assert_eq!(copied, 2, "should copy main.rs and README.md only");
        assert!(dst.path().join("src/main.rs").is_file());
        assert!(dst.path().join("README.md").is_file());
        assert!(
            !dst.path().join(".git").exists(),
            ".git must be excluded from the copy"
        );
    }

    #[test]
    fn diff_reports_new_and_modified_files() {
        let root = tempfile::tempdir().unwrap();
        let before = inventory(root.path());
        assert!(before.is_empty());

        fs::write(root.path().join("created.txt"), b"new").unwrap();
        let after = inventory(root.path());

        let (new_files, modified_files) = diff_inventories(&before, &after, root.path());
        assert_eq!(new_files, vec!["created.txt".to_string()]);
        assert!(modified_files.is_empty());
    }
}

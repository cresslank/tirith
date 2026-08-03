//! Shared set of built-in build-artifact directory names.
//!
//! These are directories that contain generated or vendored output rather than
//! authored source. The scanner skips them during directory walks, and a later
//! correlation pass reuses the same set so the two stay in agreement.

/// Directory basenames treated as build artifacts / generated output.
///
/// Skipping these avoids scanning machine-generated files and keeps walks fast.
pub const BUILT_IN_SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".next",
    "vendor",
    ".cache",
    "out",
    ".turbo",
    "coverage",
    ".expo",
];

/// Returns true if `name` (a directory basename) is a built-in build-artifact
/// directory that should be skipped during scanning.
pub fn should_skip_dir(name: &str) -> bool {
    BUILT_IN_SKIP_DIRS.contains(&name)
}

/// Returns true if any component of `path` is a built-in build-artifact
/// directory. Components are split on both `/` and `\` so the check works for
/// POSIX and Windows-style paths.
pub fn is_build_artifact_path(path: &str) -> bool {
    if path.split(['/', '\\']).any(should_skip_dir) {
        return true;
    }

    // Hermes Agent creates these generated runtime artifacts under the operating
    // system's temporary roots. Scope the exemption to those roots so authored
    // files with similar names remain part of deletion correlation.
    let normalized = path.replace('\\', "/");
    let lowercase = normalized.to_ascii_lowercase();
    let in_temp_root = normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/tmp/")
        || normalized.starts_with("/var/folders/")
        || lowercase
            .get(1..)
            .is_some_and(|suffix| suffix.starts_with(":/temp/"));
    if !in_temp_root {
        return false;
    }

    let mut components = normalized.split('/');
    let basename = components.next_back().unwrap_or(path);
    if components.any(|component| {
        component
            .strip_prefix("hermes_sandbox_")
            .is_some_and(|suffix| !suffix.is_empty())
    }) {
        return true;
    }

    basename.starts_with("hermes-snap-") && basename.contains(".sh.tmp.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_dirs_are_members() {
        for name in ["out", ".turbo", "coverage", ".expo"] {
            assert!(should_skip_dir(name), "{name} should be a skip dir");
        }
    }

    #[test]
    fn original_dirs_still_members() {
        for name in [
            ".git",
            "node_modules",
            "target",
            "__pycache__",
            ".tox",
            "dist",
            "build",
            ".next",
            "vendor",
            ".cache",
        ] {
            assert!(should_skip_dir(name), "{name} should be a skip dir");
        }
    }

    #[test]
    fn non_build_dirs_are_not_members() {
        assert!(!should_skip_dir("src"));
        assert!(!should_skip_dir(".vscode"));
    }

    #[test]
    fn build_artifact_path_detection() {
        assert!(is_build_artifact_path("a/dist/b.js"));
        assert!(is_build_artifact_path(
            "/tmp/hermes-snap-deadbeef.sh.tmp.$BASHPID"
        ));
        assert!(is_build_artifact_path(
            r"C:\Temp\hermes-snap-deadbeef.sh.tmp.1234"
        ));
        assert!(is_build_artifact_path(
            "/var/folders/ab/cd/T/hermes_sandbox_deadbeef/script.py"
        ));
        assert!(is_build_artifact_path(
            "/tmp/hermes_sandbox_1234567890abcdef/script.py"
        ));
        assert!(is_build_artifact_path(
            r"C:\Temp\hermes_sandbox_deadbeef\script.py"
        ));
        assert!(!is_build_artifact_path(
            "/workspace/hermes_sandbox_deadbeef/script.py"
        ));
        assert!(!is_build_artifact_path(
            "/workspace/hermes-snap-deadbeef.sh.tmp.1234"
        ));
        assert!(!is_build_artifact_path("src/hermes-snap-not-a-temp.sh"));
        assert!(!is_build_artifact_path("src/hermes_sandbox_rules.rs"));
        assert!(!is_build_artifact_path("/tmp/hermes_sandbox_/script.py"));
        assert!(!is_build_artifact_path("src/main.rs"));
    }

    #[test]
    fn build_artifact_path_handles_backslashes() {
        assert!(is_build_artifact_path("a\\node_modules\\b.js"));
    }
}

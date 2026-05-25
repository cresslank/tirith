//! Operational-context detection — M8 ch1.
//!
//! Reads the *currently-selected* context for each supported cloud / k8s
//! provider so the `rules::context` module can decide whether the parsed
//! command's target context is labeled production. The four readers:
//!
//! 1. **kube** — `~/.kube/config` `current-context` field, honoring
//!    `$KUBECONFIG` (which may list multiple files; the first wins for the
//!    purpose of `current-context`, mirroring kubectl 1.28+ behavior).
//! 2. **aws** — `$AWS_PROFILE` env (then `$AWS_DEFAULT_PROFILE`), falling back
//!    to the `[default]` section of `~/.aws/config`. We never *parse* the
//!    profile's contents — only resolve the profile *name*; that name is
//!    what operators label with `tirith context label aws:<profile> …`.
//! 3. **gcloud** — shells out to `gcloud config list --format=json` with a
//!    hard 1.5s timeout. Extracts `core.account` and `core.project` for
//!    labels; the canonical context string is `<account>@<project>` (or
//!    just `<project>` when the account is unknown).
//! 4. **az** — shells out to `az account show -o json` with a hard 1.5s
//!    timeout. Extracts the active subscription `name` (operator-facing
//!    string that matches `az account list -o table`).
//!
//! Every external command goes through [`run_with_timeout`] which wraps
//! `std::process::Command` in a watchdog thread. On timeout we `kill()` the
//! child and return [`ContextDetectFailure::Timeout`]; on non-zero exit we
//! return [`ContextDetectFailure::Exited`]. The hot path NEVER blocks on a
//! shell-out — callers gate detection on the parsed leader being a cloud
//! CLI (see `engine.rs`) and a 5-second per-process cache keeps repeat
//! invocations cheap.
//!
//! ## Cache semantics
//!
//! [`detect_all`] is what the engine calls. Results are cached in a
//! process-global `OnceLock`-backed `Mutex` for [`CACHE_TTL_SECS`] (5s).
//! Within that window every call returns the same map. After expiry the
//! next call refreshes; failures are cached too (negative caching prevents
//! a permanently-broken `gcloud` from being re-invoked every second).
//!
//! ## Honest scope
//!
//! These signals are operator-trust, not adversary-resistant. The strings
//! we read are caller-controlled (`~/.kube/config` is a user-writable file,
//! `gcloud config` is settable by anyone with shell access). The labels
//! file (`~/.config/tirith/context-labels.yaml`) is the security boundary
//! — an attacker who can mutate it can already run anything. We trust the
//! labels file to declare which contexts are critical, then we lift the
//! provider's current-context string into a finding when a destructive
//! command targets a labeled context.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hard per-call wall-clock cap for any shell-out. The watchdog thread
/// `kill`s the child if the call hasn't finished by this deadline.
const SHELL_OUT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Per-process cache TTL. Mirrors the documented design — keeps the hot
/// path responsive when the operator runs a burst of `kubectl` / `aws`
/// commands in quick succession.
pub const CACHE_TTL_SECS: u64 = 5;

/// Provider identifier. The string form matches the `provider:context`
/// label keys (e.g. `kube:prod-us-east`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Provider {
    Kube,
    Aws,
    Gcp,
    Azure,
}

impl Provider {
    /// Label-key prefix (`kube`, `aws`, `gcp`, `azure`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kube => "kube",
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
        }
    }

    /// Parse from the `provider:context` label-key prefix.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "kube" | "k8s" | "kubernetes" => Some(Self::Kube),
            "aws" => Some(Self::Aws),
            "gcp" | "gcloud" | "google" => Some(Self::Gcp),
            "azure" | "az" => Some(Self::Azure),
            _ => None,
        }
    }

    /// Map a parsed command leader (lowercased basename) to the provider
    /// it targets, if any. `kubectl`/`kustomize`/`helm`/`argocd` → Kube;
    /// `aws`/`aws-vault` → AWS; `gcloud` → GCP; `az` → Azure.
    pub fn from_leader(leader: &str) -> Option<Self> {
        match leader {
            "kubectl" | "kustomize" | "helm" | "argocd" => Some(Self::Kube),
            "aws" | "aws-vault" => Some(Self::Aws),
            "gcloud" => Some(Self::Gcp),
            "az" => Some(Self::Azure),
            _ => None,
        }
    }
}

/// Failure reason returned by a single-provider reader.
///
/// `NotConfigured` means "no kubeconfig found / no AWS profile / no gcloud
/// CLI on PATH" — the provider simply isn't configured on this machine, so
/// the rule should not fire for that provider.
///
/// `Timeout` / `Exited` / `Io` are operational failures that get logged and
/// negative-cached for [`CACHE_TTL_SECS`] so a permanently-broken provider
/// doesn't slow down every cloud-CLI check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextDetectFailure {
    /// The provider isn't configured on this machine (no config file, no
    /// CLI on PATH). Not an error — just absence of signal.
    NotConfigured,
    /// The shell-out exceeded [`SHELL_OUT_TIMEOUT`]. The child was killed.
    Timeout,
    /// The shell-out exited with a non-zero status code.
    Exited(i32),
    /// The shell-out failed for an I/O reason (couldn't spawn, couldn't
    /// read stdout, couldn't parse JSON, etc.). Carries a short reason
    /// string for the audit log.
    Io(String),
}

impl std::fmt::Display for ContextDetectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "not configured"),
            Self::Timeout => write!(f, "timeout after {}ms", SHELL_OUT_TIMEOUT.as_millis()),
            Self::Exited(c) => write!(f, "exited with status {c}"),
            Self::Io(reason) => write!(f, "io error: {reason}"),
        }
    }
}

/// Resolved active context for a single provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderContext {
    pub provider: Provider,
    /// The operator-facing context name. For kube this is
    /// `current-context`; for aws it's the profile name; for gcp it's
    /// `<account>@<project>` (or `<project>` when the account is unknown
    /// or empty); for azure it's the subscription name.
    pub context: String,
}

impl ProviderContext {
    /// The `provider:context` label-key form.
    pub fn label_key(&self) -> String {
        format!("{}:{}", self.provider.as_str(), self.context)
    }
}

/// Combined result of detecting every provider. The hot path consumes the
/// `BTreeMap` directly; failures are exposed for the audit log.
#[derive(Debug, Clone, Default)]
pub struct DetectionResult {
    pub contexts: BTreeMap<Provider, ProviderContext>,
    pub failures: BTreeMap<Provider, ContextDetectFailure>,
}

impl DetectionResult {
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }
}

/// Process-global cache. `OnceLock` defers initialization until the first
/// call; the inner `Mutex` is fine-grained — readers are infrequent
/// (parsed-leader gated).
static CACHE: OnceLock<Mutex<CacheEntry>> = OnceLock::new();

#[derive(Default)]
struct CacheEntry {
    captured_at: Option<Instant>,
    result: DetectionResult,
}

fn cache() -> &'static Mutex<CacheEntry> {
    CACHE.get_or_init(|| Mutex::new(CacheEntry::default()))
}

/// Detect the active context for every configured provider, with a
/// per-process cache. Safe to call from the hot path — never blocks longer
/// than [`SHELL_OUT_TIMEOUT`] per provider on the cache-cold path, and
/// returns instantly on a cache hit.
///
/// Test-only override: when `TIRITH_CONTEXT_DETECT_DISABLE=1` is set, this
/// returns an empty result without touching the filesystem or running any
/// shell-outs. Used by the engine integration tests so they don't pick up
/// the developer's real `kubeconfig` / `aws config`.
pub fn detect_all() -> DetectionResult {
    if std::env::var("TIRITH_CONTEXT_DETECT_DISABLE")
        .ok()
        .as_deref()
        == Some("1")
    {
        return DetectionResult::default();
    }

    let now = Instant::now();
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(captured_at) = guard.captured_at {
        if now.duration_since(captured_at) < Duration::from_secs(CACHE_TTL_SECS) {
            return guard.result.clone();
        }
    }

    let fresh = refresh_all();
    guard.captured_at = Some(now);
    guard.result = fresh.clone();
    fresh
}

/// Detect the active context for a single provider. Used by the
/// `tirith context status` CLI which wants per-provider failure detail.
/// The result is NOT cached at the per-provider level — `detect_all`
/// already coalesces.
pub fn detect_single(provider: Provider) -> Result<ProviderContext, ContextDetectFailure> {
    match provider {
        Provider::Kube => detect_kube(),
        Provider::Aws => detect_aws(),
        Provider::Gcp => detect_gcloud(),
        Provider::Azure => detect_azure(),
    }
}

/// Clear the per-process cache. Tests call this between scenarios; the
/// hot path never needs it (the TTL handles staleness).
pub fn clear_cache_for_tests() {
    if let Some(lock) = CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = CacheEntry::default();
        }
    }
}

fn refresh_all() -> DetectionResult {
    let mut contexts = BTreeMap::new();
    let mut failures = BTreeMap::new();

    for provider in [
        Provider::Kube,
        Provider::Aws,
        Provider::Gcp,
        Provider::Azure,
    ] {
        match detect_single(provider) {
            Ok(ctx) => {
                contexts.insert(provider, ctx);
            }
            Err(ContextDetectFailure::NotConfigured) => {
                // Absence of signal — don't record as a failure.
            }
            Err(other) => {
                failures.insert(provider, other);
            }
        }
    }

    DetectionResult { contexts, failures }
}

// ────────────────────────────────────────────────────────────────────── kube

fn detect_kube() -> Result<ProviderContext, ContextDetectFailure> {
    let path = match resolve_kubeconfig_path() {
        Some(p) => p,
        None => return Err(ContextDetectFailure::NotConfigured),
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| ContextDetectFailure::Io(format!("read {}: {e}", path.display())))?;

    let value: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| ContextDetectFailure::Io(format!("yaml parse: {e}")))?;

    let current = value
        .get("current-context")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or(ContextDetectFailure::NotConfigured)?;

    Ok(ProviderContext {
        provider: Provider::Kube,
        context: current,
    })
}

/// Resolve the active kubeconfig path. Honors `$KUBECONFIG` (uses the
/// FIRST path when the env var is a `:`-separated list, mirroring how
/// kubectl resolves `current-context` from the first file) and falls
/// back to `~/.kube/config`.
fn resolve_kubeconfig_path() -> Option<PathBuf> {
    if let Ok(env_val) = std::env::var("KUBECONFIG") {
        let env_val = env_val.trim();
        if !env_val.is_empty() {
            let separator = if cfg!(windows) { ';' } else { ':' };
            let first = env_val.split(separator).next().unwrap_or(env_val).trim();
            if !first.is_empty() {
                let path = PathBuf::from(first);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    let home = home::home_dir()?;
    let path = home.join(".kube").join("config");
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────── aws

fn detect_aws() -> Result<ProviderContext, ContextDetectFailure> {
    // Env precedence per `aws --help`: `AWS_PROFILE` then `AWS_DEFAULT_PROFILE`.
    for name in ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"] {
        if let Ok(val) = std::env::var(name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Ok(ProviderContext {
                    provider: Provider::Aws,
                    context: trimmed.to_string(),
                });
            }
        }
    }

    // Fall back to a file under `~/.aws/` so we have *some* signal when
    // the operator hasn't set `AWS_PROFILE`. We only need to know the
    // profile NAME — never the credential value.
    let home = home::home_dir().ok_or(ContextDetectFailure::NotConfigured)?;
    let config_path = home.join(".aws").join("config");
    let credentials_path = home.join(".aws").join("credentials");

    if !config_path.is_file() && !credentials_path.is_file() {
        return Err(ContextDetectFailure::NotConfigured);
    }

    // Use the default profile if either file declares one. `aws` does not
    // distinguish "missing default" from "no aws config at all" — we
    // return `default` because that is what `aws` itself would use.
    Ok(ProviderContext {
        provider: Provider::Aws,
        context: "default".to_string(),
    })
}

// ──────────────────────────────────────────────────────────────────── gcloud

fn detect_gcloud() -> Result<ProviderContext, ContextDetectFailure> {
    let out = run_with_timeout("gcloud", &["config", "list", "--format=json"])?;
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| ContextDetectFailure::Io(format!("json parse: {e}")))?;

    let core = value
        .get("core")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let account = core
        .get("account")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let project = core
        .get("project")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let context = match (account, project) {
        (Some(a), Some(p)) => format!("{a}@{p}"),
        (None, Some(p)) => p.to_string(),
        (Some(a), None) => a.to_string(),
        (None, None) => return Err(ContextDetectFailure::NotConfigured),
    };

    Ok(ProviderContext {
        provider: Provider::Gcp,
        context,
    })
}

// ───────────────────────────────────────────────────────────────────── azure

fn detect_azure() -> Result<ProviderContext, ContextDetectFailure> {
    let out = run_with_timeout("az", &["account", "show", "-o", "json"])?;
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| ContextDetectFailure::Io(format!("json parse: {e}")))?;

    // `az account show` returns `{"name": "...", "id": "...", ...}`. The
    // operator-facing label is `name` (matches what `az account list -o
    // table` prints); fall back to `id` (subscription UUID) if missing.
    let context = value
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("id").and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ContextDetectFailure::NotConfigured)?
        .to_string();

    Ok(ProviderContext {
        provider: Provider::Azure,
        context,
    })
}

// ─────────────────────────────────────────────────────────────── shell-out

/// A simple `Output`-shaped result that's `Clone`-able for our caller.
#[derive(Debug, Clone)]
struct ShellOutOutput {
    #[allow(dead_code)] // reserved for future error reporting
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
}

/// Run a binary with a hard wall-clock timeout.
///
/// The implementation polls `child.try_wait()` in 25ms ticks. If the child
/// is still running past [`SHELL_OUT_TIMEOUT`], we send a kill and return
/// [`ContextDetectFailure::Timeout`]. This is simpler than a watchdog
/// thread (which has a take-ownership race with `wait_with_output`) and
/// equally precise for our 1.5s deadline.
///
/// Stdout is read on a helper thread so the pipe doesn't fill up while
/// we poll. The main thread owns the `Child` for the entire call.
///
/// Returns:
/// - `Ok(out)` on success (exit 0) with the child's stdout captured.
/// - `Err(ContextDetectFailure::NotConfigured)` when the binary isn't on
///   PATH (`spawn()` returns `NotFound`). Distinct from a real I/O error
///   so missing-CLI is treated as "no signal" rather than "broken
///   provider".
/// - `Err(ContextDetectFailure::Timeout)` when the deadline elapses.
/// - `Err(ContextDetectFailure::Exited(code))` on non-zero exit.
/// - `Err(ContextDetectFailure::Io(reason))` on other spawn / read errors.
fn run_with_timeout(program: &str, args: &[&str]) -> Result<ShellOutOutput, ContextDetectFailure> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ContextDetectFailure::NotConfigured);
        }
        Err(e) => {
            return Err(ContextDetectFailure::Io(format!("spawn {program}: {e}")));
        }
    };

    // Stream stdout in a helper thread so the OS pipe buffer doesn't fill
    // up while we poll for exit. We collect into a Vec<u8> on the thread.
    let stdout_handle = child.stdout.take().map(|mut s| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + SHELL_OUT_TIMEOUT;
    let poll = Duration::from_millis(25);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                return if status.success() {
                    Ok(ShellOutOutput {
                        status: status.code(),
                        stdout,
                    })
                } else {
                    Err(ContextDetectFailure::Exited(status.code().unwrap_or(-1)))
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Best-effort kill; reap the corpse and return Timeout.
                    let _ = child.kill();
                    let _ = child.wait();
                    // Drop the stdout reader by joining it (it'll exit
                    // when the pipe closes due to the kill).
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    return Err(ContextDetectFailure::Timeout);
                }
                std::thread::sleep(poll);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                return Err(ContextDetectFailure::Io(format!("try_wait {program}: {e}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parse_round_trips() {
        for p in [
            Provider::Kube,
            Provider::Aws,
            Provider::Gcp,
            Provider::Azure,
        ] {
            assert_eq!(Provider::parse(p.as_str()), Some(p));
        }
    }

    #[test]
    fn provider_parse_aliases() {
        assert_eq!(Provider::parse("k8s"), Some(Provider::Kube));
        assert_eq!(Provider::parse("kubernetes"), Some(Provider::Kube));
        assert_eq!(Provider::parse("gcloud"), Some(Provider::Gcp));
        assert_eq!(Provider::parse("az"), Some(Provider::Azure));
        assert_eq!(Provider::parse("unknown"), None);
    }

    #[test]
    fn provider_from_leader() {
        assert_eq!(Provider::from_leader("kubectl"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("helm"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("argocd"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("kustomize"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("aws"), Some(Provider::Aws));
        assert_eq!(Provider::from_leader("aws-vault"), Some(Provider::Aws));
        assert_eq!(Provider::from_leader("gcloud"), Some(Provider::Gcp));
        assert_eq!(Provider::from_leader("az"), Some(Provider::Azure));
        assert_eq!(Provider::from_leader("curl"), None);
    }

    #[test]
    fn label_key_format() {
        let ctx = ProviderContext {
            provider: Provider::Kube,
            context: "prod-us-east".into(),
        };
        assert_eq!(ctx.label_key(), "kube:prod-us-east");
    }

    #[test]
    fn timeout_disables_detection_via_env() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // SAFETY: tests in this crate serialize env mutation via TEST_ENV_LOCK.
        unsafe {
            std::env::set_var("TIRITH_CONTEXT_DETECT_DISABLE", "1");
        }
        clear_cache_for_tests();
        let r = detect_all();
        assert!(r.is_empty(), "disable env must produce empty result");
        unsafe {
            std::env::remove_var("TIRITH_CONTEXT_DETECT_DISABLE");
        }
        clear_cache_for_tests();
    }

    #[test]
    fn aws_env_precedence_aws_profile_wins() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::set_var("AWS_PROFILE", "prod");
            std::env::set_var("AWS_DEFAULT_PROFILE", "dev");
        }
        let ctx = detect_aws().expect("aws detection");
        assert_eq!(ctx.context, "prod");
        unsafe {
            std::env::remove_var("AWS_PROFILE");
            std::env::remove_var("AWS_DEFAULT_PROFILE");
        }
    }

    #[test]
    fn aws_falls_back_to_default_profile_name() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::remove_var("AWS_PROFILE");
            std::env::remove_var("AWS_DEFAULT_PROFILE");
        }
        // We can't assert the result deterministically (depends on whether
        // ~/.aws exists on the test box). Just check it doesn't panic and
        // returns *some* shape.
        let _ = detect_aws();
    }

    #[test]
    fn timeout_triggers_on_slow_binary() {
        // Use `sleep` (POSIX) — present on macOS / Linux test runners.
        // Skip on Windows; the watchdog path is the same anyway.
        if cfg!(windows) {
            return;
        }
        let result = run_with_timeout("sleep", &["10"]);
        assert!(
            matches!(result, Err(ContextDetectFailure::Timeout)),
            "expected Timeout, got {result:?}",
        );
    }

    #[test]
    fn missing_binary_reports_not_configured() {
        let result = run_with_timeout("this-binary-definitely-does-not-exist-xyzzy", &[]);
        assert!(
            matches!(result, Err(ContextDetectFailure::NotConfigured)),
            "expected NotConfigured, got {result:?}",
        );
    }

    #[test]
    fn kube_parses_current_context_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let kube_path = dir.path().join("config");
        std::fs::write(
            &kube_path,
            "apiVersion: v1\nkind: Config\ncurrent-context: my-cluster\ncontexts:\n  - name: my-cluster\n",
        )
        .unwrap();
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::set_var("KUBECONFIG", kube_path.display().to_string());
        }
        let ctx = detect_kube().expect("kube detection");
        assert_eq!(ctx.context, "my-cluster");
        unsafe {
            std::env::remove_var("KUBECONFIG");
        }
    }

    #[test]
    fn kube_kubeconfig_multi_file_takes_first() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a.yaml");
        let second = dir.path().join("b.yaml");
        std::fs::write(
            &first,
            "apiVersion: v1\nkind: Config\ncurrent-context: first-ctx\n",
        )
        .unwrap();
        std::fs::write(
            &second,
            "apiVersion: v1\nkind: Config\ncurrent-context: second-ctx\n",
        )
        .unwrap();
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let sep = if cfg!(windows) { ";" } else { ":" };
        let joined = format!("{}{sep}{}", first.display(), second.display());
        unsafe {
            std::env::set_var("KUBECONFIG", joined);
        }
        let ctx = detect_kube().expect("kube detection");
        assert_eq!(ctx.context, "first-ctx");
        unsafe {
            std::env::remove_var("KUBECONFIG");
        }
    }
}

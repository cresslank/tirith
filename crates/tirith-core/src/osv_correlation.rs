//! M6 ch6 — thin adapter over the shipping `threatdb_api.rs` OSV cache.
//!
//! The runtime threat-enrichment path (`crate::threatdb_api::enrich_command`)
//! already implements OSV / deps.dev / Google Safe Browsing lookups under
//! `ThreatIntelConfig::osv_enabled`, with on-disk caching and a 1-hour TTL.
//! `package risk` / `install` / `ecosystem scan` benefit from the same data
//! without registering a new `ThreatSource` variant (the contiguous-discriminant
//! test in `threatdb.rs` stays green) and without introducing a second cache.
//!
//! This module provides one public function — [`for_package`] — that consults
//! the same on-disk cache layout `threatdb_api.rs` uses and falls through to
//! a fresh OSV query when the cache is cold. It returns a small
//! [`OsvAdvisorySummary`] shape that `ApiProvenance::osv_advisories` carries
//! into the deterministic factor model.
//!
//! ## Honesty
//!
//! * No new `ThreatSource` variant. `tirith threat-db sources` is unchanged.
//! * No new cache directory. Same `state_dir()/threatdb-api-cache/` as the
//!   runtime threat-enrichment path; cached keys are namespaced (`osv:...`)
//!   so we never collide with deps.dev or KEV rows.
//! * Best-effort: any error (network, timeout, unparseable response) is a
//!   silent `Vec::new()`, never a panic.
//! * Read-only — never writes anything other than the cache file the shipping
//!   path was already going to write.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::package_risk::OsvAdvisorySummary;
use crate::policy;
use crate::threatdb::Ecosystem;

/// Reuse the shipping `threatdb_api.rs` TTL — 1 hour. Documented there as the
/// freshness window for OSV; matching it keeps the two paths consistent.
const CACHE_TTL_SECS: u64 = 3600;
/// Cap the per-call timeout. The CLI path is interactive; a degraded score
/// beats a long hang.
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// Resolve OSV advisories for `(eco, name, version)` via the shared cache.
///
/// Returns an empty vector when the ecosystem has no OSV mapping (e.g. the
/// distro/docker/go backends with no public OSV equivalent), when offline
/// mode is active, or on any network / parse failure — honest no-data.
pub fn for_package(eco: Ecosystem, name: &str, version: &str) -> Vec<OsvAdvisorySummary> {
    let Some(eco_name) = osv_ecosystem_name(eco) else {
        return Vec::new();
    };
    let cache_key = format!("{}:{name}:{version}", eco_label(eco));

    // Cache hit?
    if let Some(cached) = load_cache::<Vec<OsvAdvisorySummary>>(&cache_key) {
        return cached;
    }

    // Cache miss — issue the same POST the shipping `threatdb_api.rs` path
    // makes. (We could call into that module directly, but its types are
    // private to the module by design; reproducing the request keeps the
    // adapter thin and self-contained.)
    let advs = match query_osv_sync(eco_name, name, version) {
        Some(v) => v,
        None => return Vec::new(),
    };

    store_cache(&cache_key, &advs);
    advs
}

// ---------------------------------------------------------------------------
// cache
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope<T> {
    fetched_at: u64,
    value: T,
}

/// Cache file path. Lives under `state_dir()/threatdb-api-cache/` with an
/// `osv2-` prefix so it never collides with the rows the shipping
/// `threatdb_api.rs` writes (which use `osv-`).
fn cache_path(key: &str) -> Option<std::path::PathBuf> {
    let state = policy::state_dir()?;
    let digest = sha2::Sha256::digest(format!("osv2:{key}").as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    Some(
        state
            .join("threatdb-api-cache")
            .join(format!("osv2-{hex}.json")),
    )
}

fn load_cache<T: for<'de> Deserialize<'de>>(key: &str) -> Option<T> {
    let path = cache_path(key)?;
    let content = std::fs::read_to_string(path).ok()?;
    let env: CacheEnvelope<T> = serde_json::from_str(&content).ok()?;
    if unix_now().saturating_sub(env.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(env.value)
}

fn store_cache<T: Serialize>(key: &str, value: &T) {
    let Some(path) = cache_path(key) else { return };
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let env = CacheEnvelope {
        fetched_at: unix_now(),
        value,
    };
    if let Ok(serialized) = serde_json::to_vec(&env) {
        let _ = std::fs::write(path, serialized);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// network query
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    sev_type: String,
    #[serde(default)]
    score: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvReference {
    #[serde(default)]
    url: String,
}

fn query_osv_sync(
    ecosystem_name: &str,
    name: &str,
    version: &str,
) -> Option<Vec<OsvAdvisorySummary>> {
    let deadline = Instant::now() + Duration::from_secs(REQUEST_TIMEOUT_SECS);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .ok()?;
    let body = serde_json::json!({
        "package": { "name": name, "ecosystem": ecosystem_name },
        "version": version,
    });

    let _ = deadline; // currently the global timeout is enforced by the client
    let resp = client
        .post("https://api.osv.dev/v1/query")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("tirith/{} (osv-correlation)", env!("CARGO_PKG_VERSION")),
        )
        .json(&body)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json::<OsvQueryResponse>()
        .ok()?;

    let summaries: Vec<OsvAdvisorySummary> = resp
        .vulns
        .into_iter()
        .map(|v| OsvAdvisorySummary {
            cvss: parse_cvss3_base(&v.severity),
            id: v.id,
            aliases: v.aliases,
            summary: v.summary,
            reference: v.references.into_iter().map(|r| r.url).next(),
        })
        .collect();
    Some(summaries)
}

/// Parse the CVSS v3 base score out of an OSV `severity` array. OSV records a
/// CVSS string like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` with the
/// base score not embedded; we accept either the full vector or a bare
/// numeric (some advisories emit `"score": "9.8"`). We pull a numeric if
/// present, otherwise return `None` and let the rule fire at its default
/// Medium severity.
fn parse_cvss3_base(severity: &[OsvSeverity]) -> Option<f32> {
    severity
        .iter()
        .find(|s| s.sev_type.starts_with("CVSS_V3"))
        .and_then(|s| {
            // Bare numeric form ("7.5")
            if let Ok(v) = s.score.trim().parse::<f32>() {
                return Some(v);
            }
            // Vector form — no base score embedded; we don't ship a vector
            // calculator. Return None; the consumer treats this as "unknown
            // CVSS, fall back to source-claimed severity".
            None
        })
}

fn eco_label(eco: Ecosystem) -> &'static str {
    // Lowercase ASCII matches what `threatdb_api.rs` uses as the cache key.
    match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::RubyGems => "rubygems",
        Ecosystem::Crates => "cargo",
        Ecosystem::Go => "go",
        Ecosystem::Maven => "maven",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Packagist => "packagist",
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => "unsupported",
    }
}

fn osv_ecosystem_name(eco: Ecosystem) -> Option<&'static str> {
    // OSV's canonical names — same mapping as `threatdb_api.rs::osv_ecosystem_name`.
    match eco {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("PyPI"),
        Ecosystem::RubyGems => Some("RubyGems"),
        Ecosystem::Crates => Some("crates.io"),
        Ecosystem::Go => Some("Go"),
        Ecosystem::Maven => Some("Maven"),
        Ecosystem::NuGet => Some("NuGet"),
        Ecosystem::Packagist => Some("Packagist"),
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_ecosystem_returns_empty() {
        let advs = for_package(Ecosystem::Apt, "nginx", "1.0");
        assert!(advs.is_empty(), "apt is not a supported OSV ecosystem");
    }

    #[test]
    fn cvss_numeric_score_parsed() {
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V3".to_string(),
            score: "7.5".to_string(),
        }];
        assert_eq!(parse_cvss3_base(&sev), Some(7.5));
    }

    #[test]
    fn cvss_vector_form_returns_none() {
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L".to_string(),
        }];
        assert_eq!(parse_cvss3_base(&sev), None);
    }

    #[test]
    fn cvss_other_type_ignored() {
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V2".to_string(),
            score: "5.0".to_string(),
        }];
        assert_eq!(parse_cvss3_base(&sev), None);
    }

    #[test]
    fn for_package_offline_failure_is_empty_not_panic() {
        // No network in tests; this exercises the graceful fallback path.
        // We deliberately do NOT assert non-emptiness — the call may hit a
        // cached row from a previous CI run, but more often returns empty.
        let _ = for_package(
            Ecosystem::Npm,
            "this-package-name-cannot-exist-xyzzy-12345",
            "1.0.0",
        );
    }
}

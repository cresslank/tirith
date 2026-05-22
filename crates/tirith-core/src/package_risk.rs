//! Deterministic, fully explainable package provenance / maintainer-risk
//! scoring — **offline-signals phase**.
//!
//! `tirith package risk <ecosystem> <name>` produces a risk score for a
//! package the same way [`crate::scoring`] scores a URL: as a fixed sum of
//! named, inspectable factors. There is **no model, no learned weight, no
//! statistical classifier** — every score is reproducible by hand from the
//! signals below.
//!
//! ## Offline only
//!
//! This module computes risk from signals available **without any network or
//! registry-API call**:
//!
//! 1. **Name-vs-popular** — is the name a known-popular package, an unknown
//!    name, or a one-edit near-miss of a popular one? Sourced from the local
//!    threat-DB `popular` section ([`ThreatDb::is_popular_package`] and
//!    [`ThreatDb::check_popular_distance`]).
//! 2. **Known-malicious typosquat** — is the name in the threat-DB's
//!    `typosquat` index, i.e. a *confirmed* malicious typosquat
//!    ([`ThreatDb::check_typosquat`])? This is a stronger signal than a mere
//!    name resemblance.
//! 3. **Install-script / lifecycle-hook presence** — only when the package
//!    content is locally available (a `node_modules` / `site-packages`
//!    directory, or a path the caller supplies). tirith never downloads the
//!    package to obtain this.
//! 4. **Binary-blob presence** — compiled / native artifacts bundled inside
//!    the locally-available package content.
//!
//! Registry-API-backed signals (download counts, package age, maintainer
//! history, 2FA status, …) are the **next** chunk. They are represented here
//! by [`ApiSignals::NotComputed`] — a clean seam — and this module never
//! reaches the network.
//!
//! ## The factor model
//!
//! The score is the sum of:
//!
//! - **Name vs. popular packages** — the dominant term. A name one edit from a
//!   known-popular package is the classic typosquat/slopsquat shape and scores
//!   high; a name that *is* a known-popular package scores 0; an unknown name
//!   gets a small baseline (unknown is not the same as malicious).
//! - **Known-malicious typosquat** — additive: the threat-DB independently
//!   lists this exact name as a malicious typosquat.
//! - **Install / lifecycle scripts** — additive, only when local content was
//!   inspected: an `install` / `postinstall` / `preinstall` hook (npm) or a
//!   `setup.py` with executable install logic (PyPI) is a common malware
//!   delivery vector.
//! - **Bundled binary blobs** — additive, only when local content was
//!   inspected.
//!
//! The final score is `min(100, sum)`. The clamp is reported as an explicit
//! factor when it bites, so the breakdown always sums exactly to the score.
//!
//! ## Relationship to the verdict
//!
//! This score is **advisory and standalone**. It is not a detection rule, it
//! does not produce a [`Verdict`](crate::verdict::Verdict), and it changes no
//! `Action`, exit code, or audit log. `tirith package risk` is an inspection
//! command.

use serde::Serialize;

use crate::threatdb::{Ecosystem, ThreatDb};

/// The maximum possible score. Scores are clamped here.
pub const MAX_SCORE: u32 = 100;

// --- factor weights (all fixed, all inspectable) ---------------------------

/// A name one Levenshtein edit from a known-popular package — the classic
/// typosquat / slopsquat shape.
const NAME_NEAR_POPULAR_WEIGHT: u32 = 60;
/// A name that does not resemble any known-popular package and is not itself
/// known-popular. Unknown is not malicious — this baseline is deliberately
/// small.
const NAME_UNKNOWN_WEIGHT: u32 = 10;
/// The name is in the threat-DB's malicious-typosquat index — a confirmed bad
/// name, not a mere resemblance. Additive on top of the near-popular term.
const KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT: u32 = 30;
/// An install / lifecycle hook is present in locally-inspected package content.
const INSTALL_SCRIPT_WEIGHT: u32 = 15;
/// Compiled / native binary blobs are bundled in locally-inspected content.
const BINARY_BLOB_WEIGHT: u32 = 10;

/// Risk-level buckets, fixed thresholds (same shape as `crate::scoring`).
pub fn risk_level(score: u32) -> &'static str {
    match score {
        0..=20 => "low",
        21..=50 => "medium",
        51..=75 => "high",
        _ => "critical",
    }
}

/// One named, inspectable contributor to a package-risk score.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RiskFactor {
    /// Stable machine identifier (e.g. `"name_vs_popular"`).
    pub id: &'static str,
    /// Human-readable label.
    pub label: String,
    /// Points this factor contributes. Always >= 0 except the `clamp` factor.
    pub points: i32,
    /// Plain-language explanation, written so a reader can verify it by hand.
    pub detail: String,
}

/// How the package name relates to the local threat-DB `popular` set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NameVsPopular {
    /// The name *is* a known-popular package in this ecosystem.
    KnownPopular,
    /// The name is one Levenshtein edit from a known-popular package.
    NearPopular {
        /// The popular package the name resembles.
        popular_name: String,
        /// Levenshtein edit distance (1 — `check_popular_distance` caps at 1).
        distance: usize,
    },
    /// The name neither is, nor resembles, any known-popular package.
    Unknown,
}

/// Whether locally-available package content was inspected, and what it held.
///
/// `package risk` only inspects content the caller already has on disk — it
/// never downloads a package. When no local content is available, content
/// signals are simply absent from the score (not a network fetch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ContentSignals {
    /// No local package directory was supplied or found — content signals were
    /// not evaluated. This is not a fetch and not a failure.
    NotInspected,
    /// A local package directory was inspected.
    Inspected {
        /// The inspected directory (for transparency in the explanation).
        path: String,
        /// An install / lifecycle hook was found (e.g. an npm `postinstall`
        /// script, or a PyPI `setup.py`).
        has_install_script: bool,
        /// Plain-language note on what install indicator matched, if any.
        install_script_detail: Option<String>,
        /// Compiled / native binary artifacts were found bundled in the
        /// package directory.
        has_binary_blob: bool,
        /// Plain-language note on what binary indicator matched, if any.
        binary_blob_detail: Option<String>,
    },
}

/// State of the registry-API-backed signals.
///
/// The API-backed phase (download counts, package age, maintainer history,
/// 2FA, …) is a separate chunk. This enum is the seam: the offline phase
/// always reports [`ApiSignals::NotComputed`], and a future chunk can add an
/// `Available { … }` variant without disturbing the offline factor model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ApiSignals {
    /// Registry-API signals were not computed — this is the offline phase.
    NotComputed {
        /// Why they were not computed (always the same in this phase).
        reason: &'static str,
    },
}

impl ApiSignals {
    /// The offline phase's fixed value: API signals are intentionally not
    /// computed here.
    pub fn offline() -> Self {
        ApiSignals::NotComputed {
            reason: "registry-API signals are computed in a later phase; \
                     this score uses offline signals only",
        }
    }
}

/// A complete, reproducible explanation of a package-risk score.
///
/// Invariant: `factors.iter().map(|f| f.points).sum() == score as i32`.
#[derive(Debug, Clone, Serialize)]
pub struct RiskBreakdown {
    /// Ecosystem the lookup used (lowercase string, e.g. `"npm"`).
    pub ecosystem: String,
    /// The package name that was scored.
    pub name: String,
    /// Final risk score, 0..=100.
    pub score: u32,
    /// Risk level bucket derived from `score`.
    pub risk_level: &'static str,
    /// `true` when the local threat DB could not be loaded — name signals fall
    /// back to "unknown" and the caller should be told the DB is missing.
    pub threat_db_missing: bool,
    /// The name-vs-popular classification (always present).
    pub name_vs_popular: NameVsPopular,
    /// The exact malicious-typosquat name match, if the DB lists one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malicious_typosquat_of: Option<String>,
    /// What local package content (if any) was inspected.
    pub content_signals: ContentSignals,
    /// Registry-API signals — always [`ApiSignals::NotComputed`] in this phase.
    pub api_signals: ApiSignals,
    /// The factors that sum to `score`, in display order.
    pub factors: Vec<RiskFactor>,
}

impl RiskBreakdown {
    /// Sum of all factor contributions.
    pub fn factor_sum(&self) -> i32 {
        self.factors.iter().map(|f| f.points).sum()
    }

    /// `true` iff the factors sum exactly to the final score — the
    /// reproducible-by-hand contract. Used by tests and a debug assert.
    pub fn verify(&self) -> bool {
        self.factor_sum() == self.score as i32
    }
}

/// Inputs to [`score_package`] — the raw offline signals, already gathered.
///
/// Keeping signal gathering (which touches the threat DB and the filesystem)
/// out of the scoring function lets `score_package` be a pure, total function
/// of its inputs, so tests can drive every factor combination directly.
#[derive(Debug, Clone)]
pub struct PackageSignals {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub threat_db_missing: bool,
    pub name_vs_popular: NameVsPopular,
    /// `Some(popular_target)` when the threat DB lists this exact name as a
    /// known malicious typosquat.
    pub malicious_typosquat_of: Option<String>,
    pub content_signals: ContentSignals,
}

/// Compute the deterministic risk score and full factor breakdown from
/// already-gathered offline signals.
///
/// This is a pure, total function — the single source of truth for the
/// `package risk` number. The breakdown it returns always satisfies
/// `breakdown.verify()`.
pub fn score_package(signals: &PackageSignals) -> RiskBreakdown {
    let mut factors: Vec<RiskFactor> = Vec::new();

    // Factor 1 — name vs. popular packages. The dominant term.
    let (name_points, name_label, name_detail) = match &signals.name_vs_popular {
        NameVsPopular::KnownPopular => (
            0,
            "Name vs. popular packages",
            format!(
                "'{}' is itself a known-popular {} package — the name is recognized, \
                 contributing 0 points.",
                signals.name, signals.ecosystem
            ),
        ),
        NameVsPopular::NearPopular {
            popular_name,
            distance,
        } => (
            NAME_NEAR_POPULAR_WEIGHT as i32,
            "Name vs. popular packages",
            format!(
                "'{}' is edit-distance {} from the known-popular {} package '{}' — \
                 the classic typosquat/slopsquat shape, contributing {} points.",
                signals.name, distance, signals.ecosystem, popular_name, NAME_NEAR_POPULAR_WEIGHT
            ),
        ),
        NameVsPopular::Unknown => {
            let db_note = if signals.threat_db_missing {
                " (the local threat DB is not installed, so the popular-package \
                 comparison could not run — install it for a sharper signal)"
            } else {
                ""
            };
            (
                NAME_UNKNOWN_WEIGHT as i32,
                "Name vs. popular packages",
                format!(
                    "'{}' neither is, nor closely resembles, any known-popular {} package{}. \
                     Unknown is not malicious — a small {}-point baseline only.",
                    signals.name, signals.ecosystem, db_note, NAME_UNKNOWN_WEIGHT
                ),
            )
        }
    };
    factors.push(RiskFactor {
        id: "name_vs_popular",
        label: name_label.to_string(),
        points: name_points,
        detail: name_detail,
    });

    // Factor 2 — known malicious typosquat (additive). The threat DB lists this
    // exact name as a malicious typosquat — a confirmed bad name.
    if let Some(target) = &signals.malicious_typosquat_of {
        factors.push(RiskFactor {
            id: "known_malicious_typosquat",
            label: "Known malicious typosquat".to_string(),
            points: KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT as i32,
            detail: format!(
                "The local threat database lists '{}' as a known malicious typosquat of \
                 '{}' — an independent, confirmed bad-name match, contributing {} points.",
                signals.name, target, KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT
            ),
        });
    }

    // Factors 3 & 4 — content signals, only when local content was inspected.
    match &signals.content_signals {
        ContentSignals::NotInspected => {
            // No local content — no content factors. Recorded in the breakdown
            // via `content_signals`, not as a zero factor, to keep the factor
            // list to the signals that actually applied.
        }
        ContentSignals::Inspected {
            has_install_script,
            install_script_detail,
            has_binary_blob,
            binary_blob_detail,
            ..
        } => {
            if *has_install_script {
                let what = install_script_detail
                    .as_deref()
                    .unwrap_or("an install / lifecycle hook");
                factors.push(RiskFactor {
                    id: "install_script_present",
                    label: "Install / lifecycle script".to_string(),
                    points: INSTALL_SCRIPT_WEIGHT as i32,
                    detail: format!(
                        "The inspected package content contains {what} — a common \
                         malware-delivery vector, contributing {INSTALL_SCRIPT_WEIGHT} points."
                    ),
                });
            }
            if *has_binary_blob {
                let what = binary_blob_detail
                    .as_deref()
                    .unwrap_or("bundled binary artifacts");
                factors.push(RiskFactor {
                    id: "binary_blob_present",
                    label: "Bundled binary blob".to_string(),
                    points: BINARY_BLOB_WEIGHT as i32,
                    detail: format!(
                        "The inspected package content contains {what} — opaque compiled \
                         code that cannot be reviewed as source, contributing \
                         {BINARY_BLOB_WEIGHT} points."
                    ),
                });
            }
        }
    }

    // Sum and clamp. An over-100 sum is reported as an explicit negative
    // `clamp` factor so the breakdown still sums exactly to the score.
    let raw_sum: i32 = factors.iter().map(|f| f.points).sum();
    let score = raw_sum.clamp(0, MAX_SCORE as i32) as u32;
    if raw_sum > MAX_SCORE as i32 {
        let clamp = MAX_SCORE as i32 - raw_sum;
        factors.push(RiskFactor {
            id: "clamp",
            label: "Score cap".to_string(),
            points: clamp,
            detail: format!(
                "Factors summed to {raw_sum}; the score is capped at {MAX_SCORE}, \
                 so {clamp} points are removed."
            ),
        });
    }

    RiskBreakdown {
        ecosystem: signals.ecosystem.to_string(),
        name: signals.name.clone(),
        score,
        risk_level: risk_level(score),
        threat_db_missing: signals.threat_db_missing,
        name_vs_popular: signals.name_vs_popular.clone(),
        malicious_typosquat_of: signals.malicious_typosquat_of.clone(),
        content_signals: signals.content_signals.clone(),
        api_signals: ApiSignals::offline(),
        factors,
    }
}

/// Classify a package name against the threat-DB `popular` set.
///
/// Exact-match wins (`KnownPopular`); otherwise a one-edit near-miss
/// (`NearPopular`); otherwise `Unknown`. When `db` is `None` the threat DB is
/// not installed and every name is `Unknown`.
pub fn classify_name(db: Option<&ThreatDb>, eco: Ecosystem, name: &str) -> NameVsPopular {
    let Some(db) = db else {
        return NameVsPopular::Unknown;
    };
    if db.is_popular_package(eco, name) {
        return NameVsPopular::KnownPopular;
    }
    match db.check_popular_distance(eco, name) {
        Some((popular_name, distance)) => NameVsPopular::NearPopular {
            popular_name,
            distance,
        },
        None => NameVsPopular::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(name_vs_popular: NameVsPopular) -> PackageSignals {
        PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "test-pkg".to_string(),
            threat_db_missing: false,
            name_vs_popular,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
        }
    }

    #[test]
    fn known_popular_scores_zero() {
        let b = score_package(&signals(NameVsPopular::KnownPopular));
        assert_eq!(b.score, 0);
        assert_eq!(b.risk_level, "low");
        assert!(b.verify());
        // Exactly one factor: name_vs_popular at 0.
        assert_eq!(b.factors.len(), 1);
        assert_eq!(b.factors[0].id, "name_vs_popular");
        assert_eq!(b.factors[0].points, 0);
    }

    #[test]
    fn unknown_name_scores_small_baseline() {
        let b = score_package(&signals(NameVsPopular::Unknown));
        assert_eq!(b.score, NAME_UNKNOWN_WEIGHT);
        assert_eq!(b.risk_level, "low");
        assert!(b.verify());
    }

    #[test]
    fn near_popular_scores_high() {
        let b = score_package(&signals(NameVsPopular::NearPopular {
            popular_name: "react".to_string(),
            distance: 1,
        }));
        assert_eq!(b.score, NAME_NEAR_POPULAR_WEIGHT);
        assert_eq!(b.risk_level, "high");
        assert!(b.verify());
    }

    #[test]
    fn malicious_typosquat_adds_on_top_of_near_popular() {
        let mut s = signals(NameVsPopular::NearPopular {
            popular_name: "react".to_string(),
            distance: 1,
        });
        s.malicious_typosquat_of = Some("react".to_string());
        let b = score_package(&s);
        // 60 near-popular + 30 known-malicious-typosquat = 90.
        assert_eq!(
            b.score,
            NAME_NEAR_POPULAR_WEIGHT + KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT
        );
        assert_eq!(b.risk_level, "critical");
        assert!(b.verify());
        assert!(b
            .factors
            .iter()
            .any(|f| f.id == "known_malicious_typosquat"));
    }

    #[test]
    fn install_script_and_binary_blob_are_additive() {
        let mut s = signals(NameVsPopular::Unknown);
        s.content_signals = ContentSignals::Inspected {
            path: "/tmp/node_modules/test-pkg".to_string(),
            has_install_script: true,
            install_script_detail: Some("a postinstall lifecycle script".to_string()),
            has_binary_blob: true,
            binary_blob_detail: Some("a bundled .node native addon".to_string()),
        };
        let b = score_package(&s);
        // 10 unknown + 15 install-script + 10 binary-blob = 35.
        assert_eq!(
            b.score,
            NAME_UNKNOWN_WEIGHT + INSTALL_SCRIPT_WEIGHT + BINARY_BLOB_WEIGHT
        );
        assert_eq!(b.risk_level, "medium");
        assert!(b.verify());
        assert!(b.factors.iter().any(|f| f.id == "install_script_present"));
        assert!(b.factors.iter().any(|f| f.id == "binary_blob_present"));
    }

    #[test]
    fn not_inspected_content_adds_no_factor() {
        let b = score_package(&signals(NameVsPopular::Unknown));
        assert!(!b
            .factors
            .iter()
            .any(|f| f.id == "install_script_present" || f.id == "binary_blob_present"));
        assert!(matches!(b.content_signals, ContentSignals::NotInspected));
    }

    #[test]
    fn score_is_clamped_with_explicit_clamp_factor() {
        // Worst case: near-popular (60) + malicious typosquat (30) +
        // install-script (15) + binary-blob (10) = 115 raw → clamps to 100.
        let mut s = signals(NameVsPopular::NearPopular {
            popular_name: "react".to_string(),
            distance: 1,
        });
        s.malicious_typosquat_of = Some("react".to_string());
        s.content_signals = ContentSignals::Inspected {
            path: "/tmp/p".to_string(),
            has_install_script: true,
            install_script_detail: None,
            has_binary_blob: true,
            binary_blob_detail: None,
        };
        let b = score_package(&s);
        assert_eq!(b.score, 100);
        assert_eq!(b.risk_level, "critical");
        let clamp = b
            .factors
            .iter()
            .find(|f| f.id == "clamp")
            .expect("clamp factor must be present when the raw sum exceeds 100");
        assert_eq!(clamp.points, -15);
        assert!(b.verify(), "even clamped, factors must sum to score");
    }

    #[test]
    fn api_signals_are_always_not_computed_in_offline_phase() {
        let b = score_package(&signals(NameVsPopular::Unknown));
        assert!(matches!(b.api_signals, ApiSignals::NotComputed { .. }));
    }

    #[test]
    fn every_breakdown_verifies_across_signal_combinations() {
        let name_options = [
            NameVsPopular::KnownPopular,
            NameVsPopular::Unknown,
            NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
        ];
        for nvp in &name_options {
            for typo in [None, Some("react".to_string())] {
                for install in [false, true] {
                    for blob in [false, true] {
                        for inspected in [false, true] {
                            let content = if inspected {
                                ContentSignals::Inspected {
                                    path: "/tmp/p".to_string(),
                                    has_install_script: install,
                                    install_script_detail: None,
                                    has_binary_blob: blob,
                                    binary_blob_detail: None,
                                }
                            } else {
                                ContentSignals::NotInspected
                            };
                            let s = PackageSignals {
                                ecosystem: Ecosystem::Npm,
                                name: "p".to_string(),
                                threat_db_missing: false,
                                name_vs_popular: nvp.clone(),
                                malicious_typosquat_of: typo.clone(),
                                content_signals: content,
                            };
                            let b = score_package(&s);
                            assert!(
                                b.verify(),
                                "breakdown must sum to score: nvp={nvp:?} typo={typo:?} \
                                 install={install} blob={blob} inspected={inspected} \
                                 (score={}, factor_sum={})",
                                b.score,
                                b.factor_sum()
                            );
                            assert!(b.score <= MAX_SCORE);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn classify_name_returns_unknown_when_db_missing() {
        assert_eq!(
            classify_name(None, Ecosystem::Npm, "anything"),
            NameVsPopular::Unknown
        );
    }
}

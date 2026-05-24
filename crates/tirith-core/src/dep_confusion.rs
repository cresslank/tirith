//! M6 ch6 — dependency-confusion heuristic.
//!
//! Returns a [`DepConfusionVerdict`] for a given `(eco, name, policy)` triple.
//! Two heuristics are layered:
//!
//!  1. **Operator-supplied internal-name patterns.** When the policy carries
//!     `internal_package_names` and the public-registry resolution matches
//!     one of those patterns, this is the textbook dep-confusion shape (the
//!     2021 `@<org>/<util>` attack). For M6 ch6 the field is a temporary
//!     top-level field on `Policy`; ch7 moves it under
//!     `package_policy.internal_package_names`. Glob-style wildcard at the
//!     end of an `@<org>/*` pattern is supported.
//!  2. **Registry-namespace shape.** Without the operator list, the heuristic
//!     falls back to obvious `@<reserved-org>/<name>` patterns — npm scope
//!     names whose `@<org>` portion is a known internal-org indicator
//!     (`@my-company`, `@internal`, `@private`, etc.). Conservative on
//!     purpose: false positives on legitimate scoped public packages are a
//!     bigger UX harm than a missed signal here.
//!
//! Read-only; no I/O. The heuristic runs offline.

use crate::package_risk::DepConfusionVerdict;
use crate::policy::Policy;
use crate::threatdb::Ecosystem;

/// Evaluate the dependency-confusion heuristic for `(eco, name)`.
///
/// `risk == false` is the default; only a positive match flips it.
pub fn evaluate(eco: Ecosystem, name: &str, policy: &Policy) -> DepConfusionVerdict {
    // Trim defensively. A name with leading/trailing whitespace would not
    // resolve at the registry, so we treat it as a no-match.
    let name = name.trim();
    if name.is_empty() {
        return DepConfusionVerdict {
            risk: false,
            reason: String::new(),
        };
    }

    // (1) Operator-supplied internal-name patterns. The field lives at the
    // top level of `Policy` for M6 ch6 (temporary; ch7 moves it under
    // `package_policy`). Patterns support a single trailing `*` wildcard.
    for pattern in &policy.internal_package_names {
        if matches_pattern(pattern, name) {
            return DepConfusionVerdict {
                risk: true,
                reason: format!(
                    "name '{name}' matches the operator-declared internal pattern \
                     '{pattern}'; resolving it on the public registry shadows the \
                     internal package."
                ),
            };
        }
    }

    // (2) Registry-namespace shape — npm scoped names whose `@<org>` portion
    // looks like an internal-only scope. The fallback list is conservative.
    if matches!(eco, Ecosystem::Npm) {
        if let Some(scope) = npm_scope(name) {
            if is_reserved_internal_scope(scope) {
                return DepConfusionVerdict {
                    risk: true,
                    reason: format!(
                        "the scope '{scope}' has a reserved/internal shape; resolving \
                         '{name}' on the public registry can shadow an internal package."
                    ),
                };
            }
        }
    }

    DepConfusionVerdict {
        risk: false,
        reason: String::new(),
    }
}

/// `true` when `pattern` matches `name`. The only supported wildcard is a
/// single trailing `*`: `@org/*` matches every `@org/<anything>` name.
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        pattern == name
    }
}

/// Return the `@<scope>` portion of an npm scoped name (`@org`), or `None`.
fn npm_scope(name: &str) -> Option<&str> {
    if !name.starts_with('@') {
        return None;
    }
    let slash = name.find('/')?;
    Some(&name[..slash])
}

/// Scopes whose name shape is a strong "this is private" signal. Conservative
/// list; ch7's `internal_package_names` is the real surface for this.
const RESERVED_INTERNAL_SCOPES: &[&str] = &[
    "@internal",
    "@private",
    "@corp",
    "@company",
    "@inhouse",
    "@enterprise",
    "@local",
];

fn is_reserved_internal_scope(scope: &str) -> bool {
    let lower = scope.to_lowercase();
    RESERVED_INTERNAL_SCOPES.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(internal: &[&str]) -> Policy {
        Policy {
            internal_package_names: internal.iter().map(|s| (*s).to_string()).collect(),
            ..Policy::default()
        }
    }

    #[test]
    fn no_internal_names_does_not_flag_normal_packages() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "react", &p);
        assert!(!v.risk);
        assert!(v.reason.is_empty());
    }

    #[test]
    fn exact_internal_name_flags() {
        let p = policy_with(&["@my-co/util"]);
        let v = evaluate(Ecosystem::Npm, "@my-co/util", &p);
        assert!(v.risk);
        assert!(v.reason.contains("@my-co/util"));
    }

    #[test]
    fn wildcard_internal_pattern_flags_subnames() {
        let p = policy_with(&["@my-co/*"]);
        let v = evaluate(Ecosystem::Npm, "@my-co/util", &p);
        assert!(v.risk);
        let v2 = evaluate(Ecosystem::Npm, "@my-co/another", &p);
        assert!(v2.risk);
        let v3 = evaluate(Ecosystem::Npm, "@other/util", &p);
        assert!(!v3.risk);
    }

    #[test]
    fn reserved_internal_scope_flags_without_policy() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "@internal/helper", &p);
        assert!(v.risk);
        let v2 = evaluate(Ecosystem::Npm, "@private/util", &p);
        assert!(v2.risk);
    }

    #[test]
    fn non_reserved_scope_does_not_flag_without_policy() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "@org/lib", &p);
        assert!(!v.risk);
    }

    #[test]
    fn non_npm_ecosystem_does_not_use_scope_heuristic() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::PyPI, "@internal/helper", &p);
        assert!(!v.risk, "PyPI does not use npm scopes");
    }

    #[test]
    fn empty_name_returns_no_risk() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "   ", &p);
        assert!(!v.risk);
    }

    #[test]
    fn pattern_matcher_handles_trailing_star() {
        assert!(matches_pattern("@foo/*", "@foo/bar"));
        assert!(!matches_pattern("@foo/*", "@bar/baz"));
        assert!(matches_pattern("exact", "exact"));
        assert!(!matches_pattern("exact", "exact-different"));
    }
}

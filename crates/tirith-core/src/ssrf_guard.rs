//! Connect-time DNS guard — SSRF backstop for DNS rebinding.
//!
//! The URL validators in [`crate::url_validate`] resolve a host and reject
//! non-public destinations *before* a request is dispatched. That check and the
//! socket connect are two separate DNS lookups, so a hostile resolver can
//! answer "public" at validation time and "127.0.0.1" at connect time (classic
//! DNS rebinding), and it does not cover the addresses reqwest picks for each
//! redirect hop.
//!
//! [`SsrfGuardResolver`] closes that gap: installed via
//! `ClientBuilder::dns_resolver`, it is the resolver reqwest actually connects
//! through, so every address that reaches `connect()` — initial request and
//! every redirect hop — is filtered through the same public/non-public
//! classifier the validators use ([`crate::url_validate::is_public_addr`]).
//!
//! Note: tirith-core does not depend on `tokio` directly, so the blocking
//! `to_socket_addrs` lookup runs inline inside the returned future rather than
//! on a `spawn_blocking` worker. reqwest's blocking client drives this resolver
//! on its dedicated internal runtime, where a short synchronous DNS lookup is
//! acceptable (it is the same call the validators already make on the blocking
//! path).

use std::net::ToSocketAddrs;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// reqwest DNS resolver that drops any resolved address which is not a routable
/// public destination, failing the lookup if nothing public remains.
///
/// `allow_private` relaxes the filter for user fetch paths that have opted in via
/// `TIRITH_ALLOW_PRIVATE_FETCH=1` (see [`fetch_resolver`]); server paths use the
/// strict [`ssrf_guard_resolver`] and never relax.
pub struct SsrfGuardResolver {
    allow_private: bool,
}

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let allow_private = self.allow_private;
        Box::pin(async move {
            // Port 0 is fine: the connector overrides it with the real port; we
            // only care about the IPs the host resolves to.
            let lookup = (host.as_str(), 0u16).to_socket_addrs();
            let resolved =
                lookup.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            // Cloud-metadata IPs (IMDS — instance credentials) are dropped
            // UNCONDITIONALLY, even under the `allow_private` carve-out: the
            // `TIRITH_ALLOW_PRIVATE_FETCH` opt-in relaxes private/loopback/
            // link-local destinations but must never reach a metadata endpoint,
            // so a redirect or DNS-rebind can't land on IMDS once the env is set.
            // Outside the carve-out the strict public-only filter already
            // excludes them; this is the backstop for the relaxed path.
            let filtered: Vec<std::net::SocketAddr> = if allow_private {
                resolved
                    .filter(|addr| !crate::url_validate::is_cloud_metadata_addr(addr))
                    .collect()
            } else {
                resolved
                    .filter(crate::url_validate::is_public_addr)
                    .collect()
            };

            if filtered.is_empty() {
                return Err(
                    "ssrf_guard: host resolves to a non-public or empty address set".into(),
                );
            }

            Ok(Box::new(filtered.into_iter()) as Addrs)
        })
    }
}

/// Strict [`SsrfGuardResolver`] (public destinations only) for server clients,
/// installed via `ClientBuilder::dns_resolver`.
pub fn ssrf_guard_resolver() -> Arc<SsrfGuardResolver> {
    Arc::new(SsrfGuardResolver {
        allow_private: false,
    })
}

/// Resolver for user fetch paths. Strict by default, but honors the explicit
/// `TIRITH_ALLOW_PRIVATE_FETCH=1` opt-in (see
/// [`crate::url_validate::allow_private_fetch`]) so a user can fetch a command
/// card or script from an internal/localhost host. An attacker controls the URL,
/// not the user's environment, so this cannot be enabled adversarially.
pub fn fetch_resolver() -> Arc<SsrfGuardResolver> {
    Arc::new(SsrfGuardResolver {
        allow_private: crate::url_validate::allow_private_fetch(),
    })
}

/// Maximum redirect hops the server clients will follow before giving up.
/// reqwest's implicit default would silently follow up to 10 hops into
/// anywhere; the server paths cap at 5 and re-validate every hop.
const SERVER_MAX_REDIRECTS: usize = 5;

/// Decide whether a server client should follow one redirect hop.
///
/// This is the testable core of [`server_redirect_policy`], shared by every
/// server client (policy fetch, audit upload, license refresh, webhook
/// delivery). It enforces two things on every hop:
///
/// 1. The hop count stays under [`SERVER_MAX_REDIRECTS`] — `prior_hops` is the
///    number of redirects already followed (reqwest's `attempt.previous().len()`).
/// 2. The redirect target re-passes [`crate::url_validate::validate_server_url`],
///    so an open redirect cannot bounce a request from a public host into a
///    private/loopback/metadata destination.
///
/// Returns `Ok(())` to follow the hop, or `Err(reason)` to abort the request.
pub fn server_redirect_decision(target_url: &str, prior_hops: usize) -> Result<(), String> {
    if prior_hops >= SERVER_MAX_REDIRECTS {
        return Err("too many redirects".to_string());
    }
    crate::url_validate::validate_server_url(target_url)
}

/// Shared redirect policy for the server clients: re-validate every redirect
/// target and cap the hop count. The decision lives in
/// [`server_redirect_decision`] so it can be unit-tested without driving a real
/// HTTP redirect; this just adapts that decision onto reqwest's `Attempt` API.
pub fn server_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match server_redirect_decision(attempt.url().as_str(), attempt.previous().len()) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::url_validate::{is_cloud_metadata_addr, is_public_addr};
    use std::net::SocketAddr;

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 0)
    }

    // The resolver's decision is `is_public_addr` applied to each resolved
    // address. We can't drive real DNS hermetically, so assert the filter the
    // resolver uses behaves correctly on representative addresses.

    #[test]
    fn test_guard_filter_rejects_loopback() {
        assert!(!is_public_addr(&sock("127.0.0.1")));
        assert!(!is_public_addr(&sock("::1")));
    }

    #[test]
    fn test_guard_filter_rejects_private() {
        assert!(!is_public_addr(&sock("10.0.0.1")));
        assert!(!is_public_addr(&sock("192.168.0.1")));
        assert!(!is_public_addr(&sock("172.16.0.1")));
    }

    #[test]
    fn test_guard_filter_rejects_link_local_and_metadata() {
        assert!(!is_public_addr(&sock("169.254.1.1")));
        assert!(!is_public_addr(&sock("169.254.169.254")));
        assert!(!is_public_addr(&sock("fe80::1")));
    }

    #[test]
    fn test_guard_filter_accepts_public() {
        assert!(is_public_addr(&sock("93.184.216.34")));
        assert!(is_public_addr(&sock("2607:f8b0:4004:800::200e")));
    }

    #[test]
    fn test_resolver_constructs() {
        let _r = super::ssrf_guard_resolver();
    }

    // Under the `TIRITH_ALLOW_PRIVATE_FETCH` relaxation the resolver keeps
    // private/loopback/link-local addresses (it skips `is_public_addr`) but must
    // STILL drop cloud-metadata IPs via `is_cloud_metadata_addr`. We can't drive
    // real DNS hermetically, so we pin the predicate the relaxed path filters on
    // and replicate the relaxed filter over a representative resolved set.

    #[test]
    fn test_metadata_filter_flags_imds_addresses() {
        assert!(is_cloud_metadata_addr(&sock("169.254.169.254")));
        assert!(is_cloud_metadata_addr(&sock("100.100.100.200")));
        assert!(is_cloud_metadata_addr(&sock("fd00:ec2::254")));
        assert!(is_cloud_metadata_addr(&sock("::ffff:169.254.169.254")));
        // Non-metadata private/link-local addresses are NOT flagged — the
        // carve-out may legitimately reach these.
        assert!(!is_cloud_metadata_addr(&sock("169.254.1.1")));
        assert!(!is_cloud_metadata_addr(&sock("127.0.0.1")));
        assert!(!is_cloud_metadata_addr(&sock("10.0.0.1")));
    }

    #[test]
    fn test_relaxed_filter_drops_metadata_keeps_private() {
        // Mirror the `allow_private` branch of `SsrfGuardResolver::resolve`: it
        // collects everything EXCEPT metadata IPs. The private 10.x address is
        // kept under the carve-out; all three metadata IPs (AWS/GCP/Azure,
        // Alibaba, and the AWS IPv6 IMDS) are dropped.
        let resolved = [
            sock("10.0.0.1"),
            sock("169.254.169.254"),
            sock("100.100.100.200"),
            sock("fd00:ec2::254"),
        ];
        let kept: Vec<SocketAddr> = resolved
            .into_iter()
            .filter(|addr| !is_cloud_metadata_addr(addr))
            .collect();
        assert_eq!(
            kept,
            vec![sock("10.0.0.1")],
            "relaxed resolver must drop every metadata IP but keep the private one"
        );
    }

    #[test]
    fn test_relaxed_filter_metadata_only_yields_empty() {
        // If a host resolves ONLY to metadata IPs, the relaxed filter empties the
        // set, which the resolver turns into a hard lookup failure.
        let resolved = [sock("169.254.169.254"), sock("fd00:ec2::254")];
        let kept: Vec<SocketAddr> = resolved
            .into_iter()
            .filter(|addr| !is_cloud_metadata_addr(addr))
            .collect();
        assert!(
            kept.is_empty(),
            "a metadata-only resolution must leave nothing to connect to"
        );
    }

    // server_redirect_decision: the testable core of the shared server redirect
    // policy. Pins both the per-hop SSRF re-validation and the hop cap — neither
    // is reachable from the existing tests, which never drive a real redirect.

    #[test]
    fn test_server_redirect_rejects_private_target() {
        // An open redirect bouncing a public request into loopback must be
        // refused even on the first hop (prior_hops = 0).
        let result = super::server_redirect_decision("http://127.0.0.1/x", 0);
        assert!(result.is_err(), "redirect to loopback must be rejected");
    }

    #[test]
    fn test_server_redirect_rejects_over_hop_cap() {
        // A public target is fine on its own, but 5 prior hops trips the cap.
        let result = super::server_redirect_decision("https://8.8.8.8/api", 5);
        assert!(result.is_err(), "hop count at the cap must be rejected");
        assert!(result.unwrap_err().contains("too many redirects"));
    }

    #[test]
    fn test_server_redirect_allows_public_under_cap() {
        // HTTPS public target, hop count under the cap → follow.
        let result = super::server_redirect_decision("https://8.8.8.8/api", 4);
        assert!(
            result.is_ok(),
            "public target under the cap must be followed"
        );
    }
}

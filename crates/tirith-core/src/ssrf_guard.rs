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

            let filtered: Vec<std::net::SocketAddr> = if allow_private {
                resolved.collect()
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

#[cfg(test)]
mod tests {
    use crate::url_validate::is_public_addr;
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
}

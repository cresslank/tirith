//! Shared constants and helpers used by multiple rule modules.

/// Minimum length of a base64 run worth treating as an embedded payload (a short
/// run, like a hash or an id, is not interesting). Shared by `aifile.rs` and
/// `configfile.rs`.
pub const MIN_BASE64_BLOB_LEN: usize = 96;

/// Whether `content` contains a long base64 run that actually decodes (standard
/// or URL-safe, padded or not): the shape of an encoded payload smuggled into a
/// text field. Returns the matched run passed through `truncate` when found.
///
/// The `truncate` parameter is the only thing that differs between call sites:
/// `aifile` truncates with a non-ASCII ellipsis, `configfile` truncates ASCII-
/// only so its evidence string never introduces non-ASCII bytes.
pub fn find_base64_blob_with(
    content: &str,
    truncate: impl Fn(&str, usize) -> String,
) -> Option<String> {
    use base64::Engine as _;
    let bytes = content.as_bytes();
    let is_b64 =
        |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_';
    let mut i = 0;
    while i < bytes.len() {
        if !is_b64(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_b64(bytes[i]) {
            i += 1;
        }
        // Tolerate trailing `=` padding.
        let mut end = i;
        while end < bytes.len() && bytes[end] == b'=' {
            end += 1;
        }
        let run = &content[start..end];
        if run.len() >= MIN_BASE64_BLOB_LEN {
            let decodes = base64::engine::general_purpose::STANDARD
                .decode(run)
                .is_ok()
                || base64::engine::general_purpose::URL_SAFE
                    .decode(run)
                    .is_ok()
                || base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(run)
                    .is_ok()
                || base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(run)
                    .is_ok();
            if decodes {
                return Some(truncate(run, 64));
            }
        }
        i = end.max(i);
    }
    None
}

/// Sensitive-credential env var names. Used by `command.rs` (SensitiveEnvExport)
/// and `credential.rs` (dedup suppression).
pub const SENSITIVE_KEY_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
];

/// Known URL-shortener hosts. Centralised so `transport.rs` (`ShortenedUrl`) and
/// `paste_provenance.rs` (host-mismatch escalation) can't drift (M12 ch1).
/// Matching is exact, case-insensitive at the call site.
pub const URL_SHORTENER_HOSTS: &[&str] = &[
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "is.gd",
    "v.gd",
    "goo.gl",
    "ow.ly",
];

/// `true` when `host` (any case) is a known URL shortener from
/// [`URL_SHORTENER_HOSTS`].
pub fn is_url_shortener(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    URL_SHORTENER_HOSTS.iter().any(|s| lower == *s)
}

/// `true` when `host` is a loopback / local target that never leaves the
/// machine: `localhost`, the `127.0.0.0/8` loopback block (a real IPv4 loopback
/// address), IPv6 `::1` (bracketed or bare), the unspecified address `0.0.0.0`,
/// or any `*.localhost` name. Centralised so `transport.rs` (PlainHttpToSink) and
/// `escalation.rs` (W7 Network-event derivation) share one definition and cannot
/// drift. Matching is exact and case-sensitive on the already-lowercased host the
/// callers pass.
///
/// The 127.0.0.0/8 case is gated on actually parsing as an IPv4 address: a bare
/// `host.starts_with("127.")` would also match hostnames like `127.evil.example`,
/// marking a real REMOTE host as local and excluding it from network detection.
/// `Ipv4Addr::is_loopback` is true for the whole 127.0.0.0/8 block and false for
/// any non-address string.
pub fn is_loopback_host(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0.0.0.0"
    ) || host
        .parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
        || host.ends_with(".localhost")
}

/// Canonical "critical" criticality labels for the M8 context/SSH/IaC/container
/// rules; a label outside this set never fires. Centralised to avoid the
/// four-copy drift hazard (PR-127 review #7). Case-insensitive, whitespace-trimmed.
pub fn is_critical_label(label: &str) -> bool {
    let lower = label.trim().to_lowercase();
    matches!(
        lower.as_str(),
        "critical" | "production" | "prod" | "live" | "p0" | "p1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_url_shortener_basic() {
        assert!(is_url_shortener("bit.ly"));
        assert!(is_url_shortener("T.CO"), "case-insensitive");
        assert!(is_url_shortener("tinyurl.com"));
        assert!(!is_url_shortener("github.com"));
        assert!(!is_url_shortener("bit.ly.evil.com"));
    }

    #[test]
    fn is_critical_label_basic() {
        for s in &["critical", "production", "prod", "live", "p0", "p1"] {
            assert!(is_critical_label(s), "should be critical: {s:?}");
        }
        // Case-insensitive.
        assert!(is_critical_label("Critical"));
        assert!(is_critical_label("PRODUCTION"));
        // Whitespace tolerance.
        assert!(is_critical_label("  prod  "));
        // Non-critical recognised values.
        assert!(!is_critical_label("staging"));
        assert!(!is_critical_label("dev"));
        assert!(!is_critical_label("test"));
        assert!(!is_critical_label("p2"));
        assert!(!is_critical_label(""));
    }

    #[test]
    fn is_loopback_host_only_matches_real_loopback() {
        // Named and IPv6 local targets.
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("app.localhost"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("0.0.0.0"));
        // The whole 127.0.0.0/8 block parses as an IPv4 loopback address.
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.1.2.3"));
        assert!(is_loopback_host("127.255.255.254"));
        // A hostname that merely STARTS WITH "127." is NOT loopback: it is a real
        // remote host and must stay in network detection (no evasion via prefix).
        assert!(!is_loopback_host("127.evil.example"));
        assert!(!is_loopback_host("127.0.0.1.evil.example"));
        // A non-loopback IPv4 address is not local.
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("128.0.0.1"));
    }
}

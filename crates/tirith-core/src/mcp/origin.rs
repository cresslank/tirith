//! Per-MCP-session origin state.
//!
//! M4 item 8 chunk 1, observation-only side. The MCP server (`tirith
//! mcp-server`) is a stdio process: one client connects, runs through
//! `initialize` once, then issues `tools/call` requests for the rest of the
//! session. The [`AgentOrigin::Mcp`] payload — derived from
//! `initialize.clientInfo` — is therefore process-scoped: stable for the
//! lifetime of the MCP server process.
//!
//! [`AgentOrigin::Mcp`]: crate::agent_origin::AgentOrigin::Mcp
//!
//! The dispatcher writes the origin once when it handles `initialize`; the
//! tools layer reads it when constructing each verdict.

use std::sync::RwLock;

use crate::agent_origin::AgentOrigin;
use crate::mcp::types::ClientInfo;

/// Process-scoped store of the current MCP session's origin.
///
/// `RwLock<Option<...>>` rather than `OnceLock` because the dispatcher accepts
/// a *new* `initialize` from the Initialized / Ready states (the MCP spec
/// allows clients to renegotiate); the second initialize replaces the first.
static MCP_ORIGIN: RwLock<Option<AgentOrigin>> = RwLock::new(None);

/// Record the MCP client identity from an `initialize` payload. Called by the
/// dispatcher exactly when it handles the `initialize` request.
///
/// If `client_info` is `None` (some implementations omit it), records a
/// default-shaped [`AgentOrigin::Mcp`] with `client_name = "unknown-mcp-client"`
/// so the audit entry still says "this came from an MCP client" rather than
/// silently falling back to the CLI default.
pub fn set_from_initialize(client_info: Option<&ClientInfo>) {
    let origin = match client_info {
        Some(ci) => {
            AgentOrigin::mcp(&ci.name, ci.version.as_deref()).unwrap_or_else(|| AgentOrigin::Mcp {
                client_name: "unknown-mcp-client".to_string(),
                client_version: None,
            })
        }
        None => AgentOrigin::Mcp {
            client_name: "unknown-mcp-client".to_string(),
            client_version: None,
        },
    };

    // RwLock::write can only fail if the lock is poisoned (a thread holding
    // it panicked). MCP dispatcher is single-threaded today but defend
    // anyway — recovering the inner value lets us still update the origin.
    let mut guard = MCP_ORIGIN
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(origin);
}

/// Return the current MCP session's origin, if `initialize` has been seen.
///
/// Returns `None` before `initialize` (no tool call should reach the tools
/// layer in that state — the dispatcher refuses) or if the origin store is
/// somehow unreadable.
pub fn current() -> Option<AgentOrigin> {
    MCP_ORIGIN
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}

/// Test-only reset hook. Lets unit tests stage a fresh state between cases
/// without leaking origin state across them.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    if let Ok(mut guard) = MCP_ORIGIN.write() {
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_from_initialize_with_client_info_records_mcp_origin() {
        reset_for_test();
        let ci = ClientInfo {
            name: "Claude Code".to_string(),
            version: Some("1.2.3".to_string()),
        };
        set_from_initialize(Some(&ci));
        let origin = current().expect("origin should be set");
        match origin {
            AgentOrigin::Mcp {
                client_name,
                client_version,
            } => {
                assert_eq!(client_name, "Claude Code");
                assert_eq!(client_version.as_deref(), Some("1.2.3"));
            }
            other => panic!("expected Mcp variant, got {other:?}"),
        }
    }

    #[test]
    fn set_from_initialize_with_no_client_info_records_unknown() {
        reset_for_test();
        set_from_initialize(None);
        let origin = current().expect("origin should be set");
        match origin {
            AgentOrigin::Mcp {
                client_name,
                client_version,
            } => {
                assert_eq!(client_name, "unknown-mcp-client");
                assert_eq!(client_version, None);
            }
            other => panic!("expected Mcp variant, got {other:?}"),
        }
    }

    #[test]
    fn hostile_client_info_is_sanitized() {
        reset_for_test();
        // A million-byte name with embedded ANSI / newline / NUL bytes must
        // (a) not crash, (b) cap at MAX_LABEL_LEN, (c) leave no control
        // bytes in the stored value.
        let hostile = format!("{}\n\x1b[31m\x00", "x".repeat(1_000_000));
        let ci = ClientInfo {
            name: hostile,
            version: None,
        };
        set_from_initialize(Some(&ci));
        let origin = current().expect("origin should be set");
        if let AgentOrigin::Mcp { client_name, .. } = origin {
            assert!(client_name.len() <= crate::agent_origin::MAX_LABEL_LEN);
            assert!(!client_name.contains('\n'));
            assert!(!client_name.contains('\x1b'));
            assert!(!client_name.contains('\x00'));
        } else {
            panic!("expected Mcp variant");
        }
    }

    #[test]
    fn blank_client_name_falls_back_to_unknown() {
        reset_for_test();
        let ci = ClientInfo {
            name: "   ".to_string(),
            version: None,
        };
        set_from_initialize(Some(&ci));
        let origin = current().expect("origin should be set");
        if let AgentOrigin::Mcp { client_name, .. } = origin {
            assert_eq!(client_name, "unknown-mcp-client");
        } else {
            panic!("expected Mcp variant");
        }
    }
}

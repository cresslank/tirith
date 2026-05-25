//! Cross-platform clipboard helpers (M7 ch3).
//!
//! Thin wrapper around [`arboard`](https://crates.io/crates/arboard) that:
//!
//! 1. Translates `arboard::Error` into a tirith-friendly [`ClipboardError`]
//!    so callers don't have to depend on `arboard` directly.
//! 2. Maps "no clipboard backend" (Linux without X/Wayland, headless CI)
//!    onto [`ClipboardError::NoBackend`] so the CLI can degrade to a
//!    documented JSON envelope instead of panicking.
//!
//! The clipboard helpers are intentionally tiny — text-only, no images,
//! no clear-on-exit hooks. The full feature surface (debounced polling,
//! audit-log on secret detect) lives in `crates/tirith/src/cli/clipboard.rs`
//! where the polling lifecycle is owned by the daemon command.
//!
//! ## Headless behavior
//!
//! On Linux without `$DISPLAY` or `$WAYLAND_DISPLAY` and on Windows session
//! 0 ("non-interactive" services), `arboard::Clipboard::new()` returns an
//! error. We classify any such failure as `NoBackend` — the CLI surfaces
//! this as a soft "no clipboard backend" envelope so headless CI runners
//! and SSH sessions don't see a hard panic.
//!
//! ## Examples
//!
//! ```no_run
//! use tirith_core::clipboard;
//!
//! match clipboard::read_clipboard_text() {
//!     Ok(Some(text)) => println!("clipboard has {} bytes", text.len()),
//!     Ok(None) => println!("clipboard is empty"),
//!     Err(clipboard::ClipboardError::NoBackend) => {
//!         println!("no clipboard backend (likely headless)");
//!     }
//!     Err(e) => eprintln!("clipboard error: {e}"),
//! }
//! ```

use thiserror::Error;

/// Failure modes for clipboard access.
///
/// `NoBackend` is the soft-fail path: callers should report it as a
/// degraded state (empty envelope, exit 0 in JSON mode) rather than a
/// hard error so headless CI runners and SSH sessions don't trip alerts.
#[derive(Debug, Error)]
pub enum ClipboardError {
    /// No clipboard backend is available (e.g. Linux without X or
    /// Wayland, or a non-interactive Windows session). Caller should
    /// degrade gracefully, not panic.
    #[error("no clipboard backend available (headless display server?)")]
    NoBackend,

    /// `arboard` rejected the request for an unrelated reason — e.g.
    /// content type mismatch, an actively-held selection elsewhere, or
    /// an OS-level permissions denial.
    #[error("clipboard error: {0}")]
    Other(String),
}

/// Read the clipboard's text payload. Returns `Ok(None)` when the
/// clipboard is empty or carries non-text content (an image, a file
/// list, etc.). Returns `Err(NoBackend)` when no clipboard backend is
/// available.
///
/// Underlying calls are routed through `arboard::Clipboard::new()` +
/// `get_text()`. `arboard` documents `ContentNotAvailable` for
/// non-text payloads, which we collapse into `Ok(None)`.
pub fn read_clipboard_text() -> Result<Option<String>, ClipboardError> {
    let mut cb = open_clipboard()?;
    match cb.get_text() {
        Ok(s) => Ok(Some(s)),
        // Non-text payload (e.g. image, file list) is normal — surface
        // as `Ok(None)` rather than an error.
        Err(arboard::Error::ContentNotAvailable) => Ok(None),
        Err(e) => Err(classify_arboard_error(e)),
    }
}

/// Replace the clipboard's text payload with `s`. Returns
/// `Err(NoBackend)` when no clipboard backend is available.
pub fn write_clipboard_text(s: &str) -> Result<(), ClipboardError> {
    let mut cb = open_clipboard()?;
    cb.set_text(s.to_string()).map_err(classify_arboard_error)
}

/// Opens an arboard handle, classifying the new()-side failure into a
/// `NoBackend` when the OS reports no display server.
fn open_clipboard() -> Result<arboard::Clipboard, ClipboardError> {
    arboard::Clipboard::new().map_err(classify_arboard_error)
}

/// Classify an `arboard::Error` into the right `ClipboardError` variant.
///
/// `arboard` doesn't expose a stable typed "headless" discriminator —
/// the symptom shows up either as `ClipboardOccupied` or, more often,
/// as `Unknown { description: "No X/Wayland display..." }`. We pattern-
/// match on the rendered description so the CLI sees the same
/// `NoBackend` regardless of which underlying init path failed.
fn classify_arboard_error(e: arboard::Error) -> ClipboardError {
    let rendered = e.to_string();
    let lc = rendered.to_ascii_lowercase();

    // Linux X11/Wayland init failure paths surface as "no display server",
    // "wayland display not found", "x11 display not found", "could not
    // open display", etc. Windows non-interactive session-0 returns
    // "OpenClipboard failed". Match a small set of keywords rather than
    // exact strings so we don't get brittle on minor arboard rev bumps.
    if lc.contains("no display server")
        || lc.contains("display not found")
        || lc.contains("could not open display")
        || lc.contains("wayland_display")
        || lc.contains("openclipboard failed")
        || lc.contains("no x11 display")
        || lc.contains("could not connect to display")
    {
        return ClipboardError::NoBackend;
    }

    ClipboardError::Other(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ClipboardError::NoBackend` renders a stable human message — the
    /// CLI's JSON envelope quotes it back, so the wording is part of the
    /// public contract.
    #[test]
    fn no_backend_renders_stable_message() {
        let msg = ClipboardError::NoBackend.to_string();
        assert!(msg.contains("no clipboard backend"));
    }

    /// `ClipboardError::Other` carries the upstream message through
    /// unchanged so debugging an arboard failure doesn't require
    /// repro'ing the headless case.
    #[test]
    fn other_passes_through_upstream_message() {
        let e = ClipboardError::Other("permissions denied".into());
        assert!(e.to_string().contains("permissions denied"));
    }
}

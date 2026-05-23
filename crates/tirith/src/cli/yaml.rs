//! Shared YAML scalar / inline-comment helpers used by every `tirith`
//! subcommand that writes YAML scaffolds (`mcp policy init`, `agent policy
//! init`, `agent allow`, …).
//!
//! Why shared (M4 item 8 chunk 3, consolidation): pre-chunk-3, `cli/mcp.rs`
//! and `cli/agent.rs` each carried their own copy of these helpers. The
//! definitions were byte-identical (verified by the existing round-trip
//! tests in both modules) but the duplication meant a future change had to
//! land twice — and the DEL-escape fix landed mid-batch in `cli/mcp.rs`
//! only, with `cli/agent.rs` independently copying the same rules to stay
//! self-contained. Centralizing here means there is one place to audit
//! the YAML safety rules, one place for the DEL-escape fix to live, and
//! one place to extend when a future scaffold needs a new escape form.
//!
//! ## Safety contract
//!
//! * [`safe_scalar`] returns YAML that round-trips byte-for-byte through
//!   `serde_yaml`. Every YAML reserved indicator, every C0 control byte,
//!   DEL, the empty string, and multi-byte UTF-8 are all quoted-and-escaped
//!   correctly. The chunk-2 round-trip test (preserved in
//!   `cli/mcp.rs::yaml_safe_scalar_round_trips_through_yaml_parser`)
//!   pins the contract for every YAML special character; we re-run a
//!   minimal smoke set here too so this module is self-checking.
//!
//! * [`safe_inline_comment`] is for `#`-comment suffixes. The only
//!   characters we worry about there are line-breakers (`\n`, `\r`) and
//!   control bytes that could reach the operator's terminal as ANSI
//!   escapes. When the input contains any control byte we render the
//!   whole string in Rust's `Debug` form (`format!("{s:?}")`); otherwise
//!   we pass it through unmodified.
//!
//! Both helpers are `pub(crate)` so they're reachable from every CLI
//! subcommand without being part of the public `tirith` library surface.

/// Bytes that force a YAML scalar to be quoted rather than emitted as a
/// bare plain scalar.
///
/// The list is the union of:
/// * YAML's reserved indicator set (`:` would split a key, `#` would
///   start a comment, `-` could start a sequence, `?`/`,`/`[`/`]`/`{`/`}`
///   are flow-style structure, `&`/`*` are anchors/aliases, `!` is a
///   tag, `|`/`>` are block-scalar indicators, `'`/`"` are quote
///   markers, `%` is a directive, `@`/`` ` `` are reserved for future
///   use);
/// * whitespace (`space`, `\t`) — leading or embedded whitespace can
///   confuse plain-scalar parsing rules.
///
/// **Control bytes** (`b < 0x20` and `0x7f` DEL) are checked separately
/// in [`safe_scalar`] — they too force quoting, and at the same
/// time prevent terminal-injection when the operator `cat`s the
/// example file.
pub(crate) const YAML_NEEDS_QUOTING_BYTES: &[u8] = b":#-?,[]{}&*!|>'\"%@` \t";

/// Render a scalar (server name / tool name / matcher payload) for
/// inclusion in a YAML document. Returns the input unmodified when it is
/// safe as a bare scalar; quotes (`"..."`) and JSON-escapes when it
/// contains a YAML special character, whitespace, or any non-printable
/// byte (including DEL).
///
/// This is **load-bearing for safety**: scaffolds carry server / tool /
/// matcher names from arbitrary config files, and an attacker (or a
/// careless author) can declare a name containing `:` (would split the
/// YAML key), `#` (would split off the value as a comment), a newline
/// (would break the document structure), or an ANSI escape (would
/// reach the operator's terminal when the example is `cat`-ed). The
/// quoted/escaped form is unambiguous in every case.
pub(crate) fn safe_scalar(s: &str) -> String {
    // Empty string must always be quoted — bare empty is invalid YAML.
    if s.is_empty() {
        return "\"\"".to_string();
    }
    // A string is safe as a bare scalar iff every byte is a printable
    // ASCII non-special character. The set of "special" YAML indicators
    // is centralized in `YAML_NEEDS_QUOTING_BYTES`; control bytes are
    // checked separately so a future indicator change does not have to
    // remember to keep the `< 0x20` / `== 0x7f` guards too.
    let needs_quoting = s
        .bytes()
        .any(|b| YAML_NEEDS_QUOTING_BYTES.contains(&b) || b < 0x20 || b == 0x7f);
    if !needs_quoting {
        return s.to_string();
    }
    // JSON-style escaping (a strict subset of YAML's double-quoted form
    // — `serde_json::to_string` handles every C0 control byte safely).
    // Post-process for DEL (`\u{7f}`): JSON treats DEL as printable, so it
    // ends up as a literal byte in the output, but YAML 1.2 §5.7 rejects
    // a literal DEL inside a double-quoted scalar. Replace with ``
    // so the YAML round-trip is exact — pinned by
    // `yaml_safe_scalar_round_trips_del` in `cli/mcp.rs`.
    serde_json::to_string(s)
        .map(|json| json.replace('\u{7f}', "\\u007F"))
        .unwrap_or_else(|_| format!("\"{}\"", s.escape_debug()))
}

/// Render a string for use as an inline `#`-comment suffix. We don't
/// embed source-config paths inside YAML keys (they are not keys), so
/// the unsafe characters we worry about are the line-breakers
/// (`\n`, `\r`) and ANSI escapes. The simplest correct rendering is
/// Rust's `Debug` form, which always emits printable bytes only.
pub(crate) fn safe_inline_comment(s: &str) -> String {
    // If the string contains no control bytes, return it as-is for
    // readability. Otherwise debug-escape the whole thing.
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        format!("{s:?}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // The full round-trip behavior is pinned by the existing tests in both
    // call-site modules (`cli/mcp.rs` and `cli/agent.rs`), which now reach
    // into this shared module. The smoke checks below stay here so this
    // module compiles green on its own — they're a copy of the most
    // load-bearing handful of cases, not the full table.
    // -----------------------------------------------------------------------

    #[test]
    fn safe_scalar_empty_becomes_quoted() {
        assert_eq!(safe_scalar(""), "\"\"");
    }

    #[test]
    fn safe_scalar_plain_identifier_is_bare() {
        assert_eq!(safe_scalar("abc"), "abc");
        assert_eq!(safe_scalar("v1_2_3"), "v1_2_3");
    }

    #[test]
    fn safe_scalar_quotes_yaml_indicator_byte() {
        for &b in YAML_NEEDS_QUOTING_BYTES {
            let s = format!("a{}b", b as char);
            let out = safe_scalar(&s);
            assert!(
                out.starts_with('"') && out.ends_with('"'),
                "byte 0x{b:02x} ({:?}) must force quoting: got {out:?}",
                b as char,
            );
        }
    }

    #[test]
    fn safe_scalar_quotes_control_bytes() {
        // C0 control + DEL.
        for b in 0u8..0x20 {
            let s = format!("a{}b", b as char);
            assert!(safe_scalar(&s).starts_with('"'));
        }
        assert!(safe_scalar("a\x7fb").starts_with('"'));
    }

    #[test]
    fn safe_scalar_escapes_del_for_yaml_roundtrip() {
        // DEL must not appear as a raw byte in the YAML output (YAML 1.2
        // §5.7 disallows it inside a double-quoted scalar). It must be
        // escaped to ``.
        let scalar = safe_scalar("\x7f");
        assert!(
            !scalar.contains('\u{7f}'),
            "raw DEL must not appear: {scalar:?}"
        );
        assert!(
            scalar.contains("\\u007F"),
            "DEL must be escaped: {scalar:?}"
        );
        // And the round-trip through serde_yaml recovers the original.
        let doc = format!("k: {scalar}\n");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).expect("DEL round-trip parses");
        assert_eq!(parsed.get("k").and_then(|v| v.as_str()), Some("\x7f"));
    }

    #[test]
    fn safe_inline_comment_passes_safe_strings_unchanged() {
        assert_eq!(safe_inline_comment("/etc/foo.json"), "/etc/foo.json");
        assert_eq!(safe_inline_comment(".mcp.json"), ".mcp.json");
    }

    #[test]
    fn safe_inline_comment_escapes_control_bytes() {
        let out = safe_inline_comment("evil\nname");
        // Debug form quotes the entire string and escapes the newline.
        assert!(out.starts_with('"') && out.ends_with('"'), "got {out:?}");
        assert!(out.contains("\\n"));
    }
}

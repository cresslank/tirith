//! MCP server inventory and `.tirith/mcp.lock` lockfile generation.
//!
//! This module is the data layer behind `tirith mcp lock` (Milestone 4, Agent
//! & MCP governance). It does two things, both **local file operations off the
//! tier-1/2/3 detection hot path**:
//!
//! 1. **Inventory** ([`build_inventory`]) — given a repository root, discover
//!    the **repo-local** MCP configuration files (`mcp.json`, `.mcp.json`,
//!    `mcp_settings.json`, and the IDE variants under `.vscode/`, `.cursor/`,
//!    `.windsurf/`, `.cline/`, `.amazonq/`, `.continue/`, `.kiro/`) and parse
//!    each into a structured [`McpInventory`]: one [`McpServerEntry`] per
//!    declared MCP server, recording its name, transport descriptor, and the
//!    tool list it declares.
//!
//! 2. **Lockfile** ([`McpLockfile::from_inventory`] / [`McpLockfile::render`])
//!    — serialize that inventory into a deterministic JSON lockfile
//!    (`<repo_root>/.tirith/mcp.lock`): per server a canonical transport
//!    descriptor, the tool list, and a content hash; plus a format version and
//!    a hash over the whole inventory. [`McpLockfile::from_inventory`] sorts
//!    servers by `(name, source_config)` **before** hashing, so the lockfile
//!    and its `inventory_hash` are stable regardless of config-discovery
//!    order — a future `mcp verify` / `mcp diff` (chunk 2) can diff two
//!    lockfiles cleanly.
//!
//! **Repo-local only.** Discovery never walks into `~/.claude/` or any other
//! user-level configuration directory — only files inside the given repo root
//! are inventoried. This is the same scoping decision the policy system makes
//! with org-level lists. The guarantee is enforced, not merely structural: a
//! config path that is a symlink (or sits under a symlinked directory), or
//! whose canonicalized path escapes the repo root, is **rejected** — a
//! symlinked `.mcp.json` pointing at a user-level config is not read.
//!
//! **Malformed input is never fatal.** A configuration file that is not valid
//! JSON, or that does not carry an MCP-server object, contributes **no
//! entries** and never panics — the same "malformed → empty, no panic"
//! convention the rest of the codebase follows (see `configfile::check_mcp_*`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Lockfile format version. Bump only on a breaking schema change so a future
/// `mcp verify` can refuse — or migrate — an older lockfile deliberately.
///
/// Version history:
/// * `1` — initial schema: per-server name, transport (`url`, or stdio
///   `command` + `args`), tools, source config, and content hash.
/// * `2` — a stdio transport now also captures the server's `env` (the
///   environment variables the config injects into the subprocess); `env` is
///   part of the per-server content hash, so an `env` change registers as
///   drift. A v1 lockfile is therefore not byte-comparable to a v2 one.
/// * `3` — env entries no longer serialize a raw value: each entry is
///   `{ name, value_hash }`, where `value_hash` is the lowercase-hex SHA-256
///   of `name || ':' || value`. An env value is commonly a credential
///   (`API_TOKEN`, `GITHUB_PERSONAL_ACCESS_TOKEN`, `OPENAI_API_KEY`, …), and
///   the lockfile is designed to be committed — persisting the value would
///   leak it. Hashing with the name as a salt still makes any value change
///   register as drift (the hash flips), so drift detection is unchanged in
///   spirit; only the *value* leaves the process, the hash does, and even a
///   low-entropy value (`1`, `true`) is not brute-forceable across servers
///   because the per-key salt makes the digest unique to (name, value). A v2
///   lockfile is therefore not byte-comparable to a v3 one.
/// * `4` — the same `name`+salted-SHA-256 redaction scheme is applied to the
///   `url` transport's userinfo. A URL declared as `https://user:token@host/`
///   is now stored as `https://host/` and the captured userinfo (the literal
///   `user[:password]` substring) is hashed into a `userinfo_hash` of
///   `sha256(server_name || ':' || userinfo)`, salted by the MCP server's
///   name. The hash is folded into the per-server content hash, so a userinfo
///   change registers as drift exactly like an env-value change does; a URL
///   that carried no userinfo serializes with `userinfo_hash` **omitted** (not
///   set to a sentinel value), so "no credential present" is structurally
///   distinct on the wire from "credential present". HTTP Basic Auth tokens
///   in a URL are credentials in exactly the same threat model that motivated
///   v3, and `.tirith/mcp.lock` is designed to be committed — so the raw
///   userinfo never lands in the file. A v3 lockfile is not byte-comparable
///   to a v4 one.
pub const MCP_LOCK_FORMAT_VERSION: u32 = 4;

/// Basename of the lockfile, written under `<repo_root>/.tirith/`.
pub const MCP_LOCK_FILENAME: &str = "mcp.lock";

/// One environment variable a stdio MCP server is launched with, as captured
/// in the lockfile.
///
/// **The raw value is never stored.** An env value is commonly a credential
/// (`API_TOKEN`, `GITHUB_PERSONAL_ACCESS_TOKEN`, `OPENAI_API_KEY`, …) and the
/// lockfile is designed to be committed — persisting plaintext values would
/// leak secrets into version control. Instead, we record a fixed-output hash:
/// `value_hash = sha256(name || ':' || value)`. The name is the per-entry salt
/// — a low-entropy value (`1`, `true`, `production`) hashes differently under
/// each name, so a digest cannot be brute-forced once and reused across
/// servers / configs. Drift detection is unchanged in spirit: a swapped value
/// still flips `value_hash`, which still flips the per-server content hash.
///
/// Computed exactly once in [`parse_env`]; the raw value never leaves that
/// function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpEnvEntry {
    /// The environment variable's name (the key in the config's `env` object).
    pub name: String,
    /// Lowercase-hex SHA-256 of `name || ':' || value`. The colon is a fixed
    /// delimiter so an attacker cannot manufacture two `(name, value)` pairs
    /// whose concatenations collide: e.g. `("AB", "c")` hashes `"AB:c"`, not
    /// `"ABc"`, so it cannot collide with `("A", "Bc")` which hashes `"A:Bc"`.
    pub value_hash: String,
}

impl McpEnvEntry {
    /// Build an entry from a `(name, raw_value)` pair, hashing the value
    /// immediately. This is the **only** legitimate way to construct an entry
    /// from a real value, and the raw value is consumed and dropped before the
    /// function returns — it never reaches a struct field, the serializer, or
    /// the rest of the process.
    pub fn from_raw(name: &str, raw_value: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        // A fixed `:` delimiter — never legal inside an env variable name on
        // POSIX or Windows — so `(name, value)` cannot be ambiguously framed.
        hasher.update(b":");
        hasher.update(raw_value.as_bytes());
        let value_hash = hex_lower(&hasher.finalize());
        McpEnvEntry {
            name: name.to_string(),
            value_hash,
        }
    }
}

/// How an MCP server is reached. A server declares **either** a remote URL
/// (`url` transport) **or** a local subprocess (`command` + `args`); the two
/// are mutually exclusive in every known config shape, so this is an enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransport {
    /// A network-reachable MCP server (HTTP / SSE / streamable-HTTP).
    ///
    /// **The URL is stored with any userinfo stripped.** A URL declared as
    /// `https://user:token@host:port/path` is recorded here as
    /// `https://host:port/path`; the `user:token` substring is HTTP Basic
    /// Auth and is a credential. `.tirith/mcp.lock` is designed to be
    /// committed, so persisting the raw userinfo would leak the credential
    /// into version control — the same threat model that motivated the v3
    /// env-value redaction.
    ///
    /// When the source URL carried a userinfo component, `userinfo_hash` is
    /// `Some(sha256(server_name || ':' || userinfo))` — the same name-salted
    /// SHA-256 scheme `McpEnvEntry` uses, with the **MCP server's name** as
    /// the per-entry salt. Folded into the per-server content hash, so a
    /// userinfo change registers as drift exactly like an env-value change
    /// does. When the source URL had no userinfo, `userinfo_hash` is `None`
    /// and is **omitted** from the serialized lockfile (not written as
    /// `null`), so "no credential" is structurally distinct on the wire from
    /// "credential present".
    ///
    /// **The stored `url` is the canonical `url::Url::as_str()` form**
    /// regardless of whether userinfo was present in the source — both
    /// branches round-trip through the parser, so removing or adding a
    /// credential from the source config does not surface as a spurious
    /// `UrlChanged` drift alongside `UserinfoAdded` / `UserinfoRemoved`
    /// (`url::Url` defaults a missing path to `/`, so a bare-host URL has
    /// two textual shapes — only the canonical one ends up in the lockfile).
    ///
    /// A URL that does not parse cleanly (so userinfo cannot be safely
    /// identified) is stored verbatim with `userinfo_hash = None`. This is
    /// the correct conservative behavior: stripping bytes from a string we
    /// cannot parse could itself mangle the input.
    Url {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        userinfo_hash: Option<String>,
    },
    /// A local MCP server spawned as a subprocess.
    Stdio {
        /// The executable to run.
        command: String,
        /// Arguments passed to the executable, in declared order.
        #[serde(default)]
        args: Vec<String>,
        /// Environment variables the config injects into the subprocess, as
        /// `(name, value_hash)` entries sorted by name. Security-relevant: a
        /// change to a server's `env` (a swapped credential, an added variable
        /// that alters what the server does) must register as drift, so it is
        /// part of the inventory, the lockfile schema, and the per-server
        /// hash. **Raw values are never stored** — each entry carries only a
        /// salted hash; see [`McpEnvEntry`]. An empty vec means the config
        /// declared no `env` object.
        #[serde(default)]
        env: Vec<McpEnvEntry>,
    },
    /// The server object declared neither a `url` nor a `command`. Captured
    /// rather than dropped: an MCP entry with no transport is itself a
    /// finding-worthy oddity that a later `mcp verify` should be able to see.
    Unknown,
}

/// One MCP server as declared in a repository's MCP configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerEntry {
    /// The server's declared name (the key in the `mcpServers` / `servers`
    /// object).
    pub name: String,
    /// How the server is reached.
    pub transport: McpTransport,
    /// The tools the server declares, sorted and de-duplicated for a stable
    /// hash. An empty vec means the config declared no explicit tool list
    /// (which an MCP client treats as "all tools").
    pub tools: Vec<String>,
    /// Repo-relative path of the config file this entry was parsed from.
    pub source_config: String,
}

impl McpServerEntry {
    /// A stable per-server content hash over name + transport (including a
    /// stdio server's `env`) + tools. Two entries hash identically iff they
    /// declare the same server the same way, so a future `mcp diff` can detect
    /// a changed server by hash alone.
    ///
    /// `source_config` is deliberately **excluded**: moving an unchanged server
    /// definition between two config files must not register as drift.
    ///
    /// **Collision-free framing.** Every variable-length component (each arg,
    /// each tool, each `env` name/value) is *length-prefixed* — its byte length
    /// is written before its bytes via [`hash_field`] — rather than joined by a
    /// `\0` separator. A separator-only scheme is ambiguous: `["a", "b"]` and
    /// `["ab"]` would feed the hasher the same bytes, and a value that itself
    /// contains a `\0` could forge a boundary. Length-prefixing makes the byte
    /// stream an unambiguous encoding of the structure.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"mcp-server-v2\0");
        hash_field(&mut hasher, self.name.as_bytes());
        match &self.transport {
            McpTransport::Url { url, userinfo_hash } => {
                hasher.update(b"url\0");
                hash_field(&mut hasher, url.as_bytes());
                // Fold `userinfo_hash` in so a userinfo change registers as
                // drift (just like an env-value change does for stdio). The
                // presence/absence of the hash is itself framed: a leading
                // 0/1 byte distinguishes `None` from `Some("")`, so a future
                // empty-hash sentinel cannot collide with a no-userinfo URL.
                // The hash itself is already deterministically derived from
                // (server_name, raw userinfo), so any userinfo change flips
                // the per-server content hash even though no raw value is
                // stored or hashed at this layer.
                match userinfo_hash {
                    Some(h) => {
                        hasher.update(b"\x01");
                        hash_field(&mut hasher, h.as_bytes());
                    }
                    None => {
                        hasher.update(b"\x00");
                    }
                }
            }
            McpTransport::Stdio { command, args, env } => {
                hasher.update(b"stdio\0");
                hash_field(&mut hasher, command.as_bytes());
                hash_field(&mut hasher, &(args.len() as u64).to_le_bytes());
                for arg in args {
                    hash_field(&mut hasher, arg.as_bytes());
                }
                hash_field(&mut hasher, &(env.len() as u64).to_le_bytes());
                for entry in env {
                    // Each env entry feeds its name AND its value_hash into the
                    // per-server hash. The `value_hash` already deterministically
                    // depends on the raw value (via `name + ':' + value`), so any
                    // value change still flips the per-server content hash —
                    // drift detection is unchanged even though no raw value is
                    // stored or hashed here.
                    hash_field(&mut hasher, entry.name.as_bytes());
                    hash_field(&mut hasher, entry.value_hash.as_bytes());
                }
            }
            McpTransport::Unknown => {
                hasher.update(b"unknown\0");
            }
        }
        hash_field(&mut hasher, &(self.tools.len() as u64).to_le_bytes());
        for tool in &self.tools {
            hash_field(&mut hasher, tool.as_bytes());
        }
        hex_lower(&hasher.finalize())
    }
}

/// Feed one length-prefixed field into a hasher: the value's byte length as a
/// little-endian `u64`, then the value's bytes. Length-prefixing every
/// variable-length component makes the hash input an unambiguous encoding —
/// no list of values can collide with a different list, and a `\0` (or any
/// byte) inside a value can never be mistaken for a field boundary.
fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// The structured inventory of every MCP server declared in a repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpInventory {
    /// Every discovered server entry, sorted by `(name, source_config)`.
    pub servers: Vec<McpServerEntry>,
    /// Repo-relative paths of the MCP config files that were discovered (every
    /// file checked, including ones that yielded no server — so the caller can
    /// honestly report "N configs, M servers").
    pub configs: Vec<String>,
    /// Repo-relative paths of config files that were discovered but could not
    /// be parsed (not valid JSON, or no MCP-server object). Informational —
    /// these are NOT an error; they simply contribute no entries.
    pub malformed_configs: Vec<String>,
}

impl McpInventory {
    /// `true` when no MCP configuration was found at all. Distinct from "found
    /// configs but they declared zero servers" — the caller words its honest
    /// output differently for the two.
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }
}

/// A single server record as it appears in the on-disk lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpLockServer {
    /// Server name.
    pub name: String,
    /// Canonical transport descriptor.
    pub transport: McpTransport,
    /// Declared tool list (sorted, de-duplicated).
    pub tools: Vec<String>,
    /// Repo-relative path of the config file the server was declared in.
    pub source_config: String,
    /// Per-server content hash (see [`McpServerEntry::content_hash`]).
    pub hash: String,
}

/// The `.tirith/mcp.lock` document.
///
/// JSON, deterministically ordered (servers sorted by `(name, source_config)`),
/// so re-running `tirith mcp lock` on an unchanged repository produces a
/// byte-identical file and a `git diff` of the lockfile shows exactly what
/// changed in the MCP surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpLockfile {
    /// Lockfile schema version.
    pub format_version: u32,
    /// Hash over the whole inventory — the ordered concatenation of every
    /// server's content hash. Changes iff any server is added, removed, or
    /// altered. The cheap top-level "did anything change?" check for `mcp
    /// verify`.
    pub inventory_hash: String,
    /// Repo-relative paths of the MCP config files captured, sorted.
    pub configs: Vec<String>,
    /// Every locked MCP server, sorted by `(name, source_config)`.
    pub servers: Vec<McpLockServer>,
}

impl McpLockfile {
    /// Build a lockfile from an inventory. Pure and deterministic: the same
    /// inventory always yields the same lockfile — **regardless of the order
    /// the inventory's servers happen to be in**.
    ///
    /// `build_inventory` already sorts, but `from_inventory` is a public entry
    /// point that may be handed an inventory assembled by any means (a test, a
    /// future caller, a different discovery order), so the sort is repeated
    /// here and is the load-bearing one: servers are sorted by
    /// `(name, source_config)` **before** the inventory hash is computed, so
    /// both the lockfile and its `inventory_hash` are stable.
    pub fn from_inventory(inventory: &McpInventory) -> Self {
        let mut servers: Vec<McpLockServer> = inventory
            .servers
            .iter()
            .map(|entry| McpLockServer {
                name: entry.name.clone(),
                transport: entry.transport.clone(),
                tools: entry.tools.clone(),
                source_config: entry.source_config.clone(),
                hash: entry.content_hash(),
            })
            .collect();

        // Deterministic ordering — independent of config-discovery order — so
        // the lockfile and the inventory hash below are both stable. Must
        // happen before `compute_inventory_hash`, which hashes server order.
        servers.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.source_config.cmp(&b.source_config))
        });

        let inventory_hash = compute_inventory_hash(&servers);

        let mut configs = inventory.configs.clone();
        configs.sort();
        configs.dedup();

        McpLockfile {
            format_version: MCP_LOCK_FORMAT_VERSION,
            inventory_hash,
            configs,
            servers,
        }
    }

    /// Render the lockfile to its on-disk string form: pretty JSON with a
    /// trailing newline. Deterministic — the input ordering is already fixed
    /// by [`from_inventory`].
    pub fn render(&self) -> String {
        // serde_json::to_string_pretty cannot fail for this fully-owned,
        // string-keyed structure, but handle the Result rather than unwrap so
        // a future schema change can never panic the `mcp lock` command.
        match serde_json::to_string_pretty(self) {
            Ok(mut s) => {
                s.push('\n');
                s
            }
            Err(_) => "{}\n".to_string(),
        }
    }
}

/// Hash the ordered list of per-server content hashes into one inventory hash.
fn compute_inventory_hash(servers: &[McpLockServer]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-inventory-v1\0");
    for server in servers {
        hasher.update(server.hash.as_bytes());
        hasher.update(b"\0");
    }
    hex_lower(&hasher.finalize())
}

/// Lowercase hex encoding of a byte slice. Local helper — avoids pulling in the
/// `hex` crate for one call site.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String never fails.
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Repo-root-relative MCP config locations to probe.
///
/// Mirrors `configfile::is_mcp_config_file` exactly — the bare-root JSON files
/// plus the IDE host-directory variants. Kept as an explicit list (rather than
/// a filesystem walk) so discovery is bounded, fast, and never strays outside
/// the known MCP config surface.
const MCP_CONFIG_RELATIVE_PATHS: &[&str] = &[
    // Bare repo-root MCP configs.
    "mcp.json",
    ".mcp.json",
    "mcp_settings.json",
    // IDE host-directory variants.
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".windsurf/mcp.json",
    ".cline/mcp_settings.json",
    ".amazonq/mcp.json",
    ".continue/mcp.json",
    ".kiro/settings/mcp.json",
];

/// Discover the repo-local MCP config files that exist under `repo_root`.
///
/// Returns `(absolute_path, repo_relative_path)` pairs, sorted by the relative
/// path for determinism. Only **regular files reachable without crossing a
/// symlink, and resolving to a location inside `repo_root`**, are returned.
///
/// Discovery is strictly repo-local. Every probed path is a fixed relative
/// path joined onto `repo_root`, so the *probed* path can never escape the
/// repository — but a probed path could itself **be** a symlink (or sit under
/// a symlinked parent directory) pointing outside the repo. Following that
/// would break the "repo-local only" guarantee — a malicious or careless
/// `.mcp.json -> ~/.claude/mcp.json` symlink would pull a user-level config
/// into the inventory. So a config path is rejected when:
///
/// * it (or any ancestor up to `repo_root`) is itself a symlink — checked with
///   `symlink_metadata`, which does **not** follow the final component, so the
///   check is not subject to the TOCTOU window an `is_file()` probe has; or
/// * its canonicalized (fully symlink-resolved) path does not stay inside the
///   canonicalized `repo_root` — a defense-in-depth backstop.
pub fn discover_mcp_configs(repo_root: &Path) -> Vec<(PathBuf, String)> {
    // Canonicalize the repo root once for the containment check. If the root
    // itself cannot be canonicalized (it does not exist), no config under it
    // can be discovered anyway — return empty rather than guess.
    let canonical_root = match repo_root.canonicalize() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut found: Vec<(PathBuf, String)> = Vec::new();
    for rel in MCP_CONFIG_RELATIVE_PATHS {
        let abs = repo_root.join(rel);

        // Reject if the final component, or any directory component between
        // `repo_root` and it, is a symlink. `symlink_metadata` does not follow
        // the path it is given, so each component is inspected as-is.
        if path_crosses_symlink(repo_root, rel) {
            continue;
        }

        // The file must be a regular file (not a directory, FIFO, …). Use
        // `symlink_metadata` so a symlink that slipped past the component walk
        // is still not silently followed.
        match std::fs::symlink_metadata(&abs) {
            Ok(meta) if meta.file_type().is_file() => {}
            _ => continue,
        }

        // Defense in depth: the fully-resolved path must stay inside the
        // resolved repo root. (With the symlink-component check above this is
        // belt-and-braces, but it also catches an exotic mount/junction case.)
        match abs.canonicalize() {
            Ok(canonical) if canonical.starts_with(&canonical_root) => {}
            _ => continue,
        }

        found.push((abs, (*rel).to_string()));
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

/// `true` if any component of `rel` — joined onto `repo_root` — is a symlink.
///
/// Walks from `repo_root` outward one component at a time, calling
/// `symlink_metadata` (which never follows the inspected path's last
/// component) on each prefix. `repo_root` itself is intentionally **not**
/// inspected: the caller chose it, and a repo legitimately reached through a
/// symlinked checkout directory must still be scannable — only symlinks
/// *inside* the repo, on the way to a config file, are rejected.
fn path_crosses_symlink(repo_root: &Path, rel: &str) -> bool {
    let mut current = repo_root.to_path_buf();
    for component in Path::new(rel).components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return true;
                }
            }
            // A component that does not exist cannot be a symlink; let the
            // caller's `symlink_metadata` on the full path handle "missing".
            Err(_) => return false,
        }
    }
    false
}

/// Build the MCP inventory for a repository.
///
/// Discovers every repo-local MCP config under `repo_root`, parses each, and
/// returns the structured [`McpInventory`]. A config that cannot be parsed is
/// recorded in [`McpInventory::malformed_configs`] and contributes no servers —
/// it is never an error and never a panic.
pub fn build_inventory(repo_root: &Path) -> McpInventory {
    let configs = discover_mcp_configs(repo_root);

    let mut inventory = McpInventory::default();

    for (abs_path, rel_path) in configs {
        inventory.configs.push(rel_path.clone());

        let content = match std::fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(_) => {
                // Unreadable (permissions, vanished mid-walk): treat like a
                // malformed config — recorded, no entries, no panic.
                inventory.malformed_configs.push(rel_path);
                continue;
            }
        };

        match parse_mcp_config(&content, &rel_path) {
            Some(mut servers) => {
                if servers.is_empty() {
                    // Valid JSON, valid MCP shape, but zero servers declared.
                    // Not malformed — just an empty config; it still counts as
                    // a discovered config.
                } else {
                    inventory.servers.append(&mut servers);
                }
            }
            None => {
                // Not valid JSON, or no MCP-server object at all.
                inventory.malformed_configs.push(rel_path);
            }
        }
    }

    // Deterministic ordering: sort the merged server list by (name, source).
    inventory.servers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.source_config.cmp(&b.source_config))
    });
    inventory.configs.sort();
    inventory.configs.dedup();
    inventory.malformed_configs.sort();
    inventory.malformed_configs.dedup();

    inventory
}

/// Parse one MCP config file's contents into a list of server entries.
///
/// Returns:
/// * `Some(vec)` — the file is valid JSON **and** carries a recognized
///   MCP-server object (`mcpServers` or its `servers` alias). The vec may be
///   empty if that object declared no servers.
/// * `None` — the file is not valid JSON, or has no MCP-server object at all.
///   The caller records this as a malformed/non-MCP config.
///
/// Every malformed individual server object (a server whose value is not a
/// JSON object) is skipped silently rather than failing the whole file — one
/// bad entry must not discard the others.
pub fn parse_mcp_config(content: &str, source_config: &str) -> Option<Vec<McpServerEntry>> {
    let json: serde_json::Value = serde_json::from_str(content).ok()?;

    // Both shape variants: the canonical `mcpServers` and the `servers` alias.
    // `configfile::check_mcp_config` accepts exactly this pair.
    let servers_obj = json
        .get("mcpServers")
        .or_else(|| json.get("servers"))
        .and_then(|v| v.as_object())?;

    let mut entries = Vec::with_capacity(servers_obj.len());
    for (name, config) in servers_obj {
        // A server whose value is not a JSON object is malformed — skip it,
        // keep the rest.
        let obj = match config.as_object() {
            Some(o) => o,
            None => continue,
        };

        let transport = parse_transport(name, obj);
        let tools = parse_tools(obj);

        entries.push(McpServerEntry {
            name: name.clone(),
            transport,
            tools,
            source_config: source_config.to_string(),
        });
    }

    Some(entries)
}

/// Derive the transport descriptor from a single server object.
///
/// `url` wins over `command` if a (malformed) config declares both — a remote
/// URL is the higher-risk surface, so it is the one recorded.
///
/// `server_name` is the MCP server's declared name (the key in the config's
/// `mcpServers` / `servers` object). It is used as the per-entry salt for the
/// URL transport's `userinfo_hash` (see [`redact_url_userinfo`]).
fn parse_transport(
    server_name: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> McpTransport {
    if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
        let (redacted_url, userinfo_hash) = redact_url_userinfo(server_name, url);
        return McpTransport::Url {
            url: redacted_url,
            userinfo_hash,
        };
    }

    if let Some(command) = obj.get("command").and_then(|v| v.as_str()) {
        let args = obj
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let env = parse_env(obj);
        return McpTransport::Stdio {
            command: command.to_string(),
            args,
            env,
        };
    }

    McpTransport::Unknown
}

/// Strip any HTTP Basic Auth userinfo (`user[:password]`) from a URL declared
/// in an MCP config, returning the redacted URL and a salted hash of the
/// captured userinfo.
///
/// **Security invariant.** A URL declared as `https://user:token@host:port/`
/// in `.mcp.json` is recorded as `https://host:port/` in the lockfile, and
/// the captured `user:token` substring is hashed with the MCP server's name
/// as the salt (`sha256(server_name || ':' || userinfo)`) — exactly the
/// scheme [`McpEnvEntry::from_raw`] uses for env values. The raw userinfo is
/// consumed inside this function and dropped before the function returns;
/// it never reaches a struct field, the serializer, or the rest of the
/// process. This is the load-bearing security invariant of the v4 lockfile
/// format for the URL transport: a committed `.tirith/mcp.lock` never
/// contains a Basic Auth credential that was in the source `.mcp.json`.
///
/// **Behavior.**
/// * The URL parses cleanly with a non-empty userinfo → return the URL with
///   `set_username("")` and `set_password(None)`, then re-serialize via
///   `url::Url::as_str()`, plus `Some(sha256(server_name || ':' || userinfo))`.
///   `userinfo` is the exact `username[:password]` substring as parsed —
///   percent-encoded bytes are hashed as-is, because that is what the
///   original config declared and any byte-level difference must register
///   as drift.
/// * The URL parses cleanly with no userinfo (the common case) → return the
///   **canonical** `url::Url::as_str()` form and `None`. The URL is
///   round-tripped through the parser even though there is nothing to
///   redact, so the stored bytes have the same shape whether the source URL
///   carried userinfo or not. Without this symmetry, removing a credential
///   from the source config would surface as a spurious `UrlChanged` drift
///   alongside `UserinfoRemoved` (e.g. `https://host` locks as
///   `https://host/` when userinfo was present, then a later verify against
///   a stripped `https://host` source would diff `https://host/` vs
///   `https://host` and flag two changes when semantically only one
///   happened). An "all-zero userinfo" form like `https://:@host/` or
///   `https://@host/` is normalized by `url::Url` to the no-userinfo form
///   during parsing, so it is treated as the no-userinfo case — the user
///   supplied nothing.
/// * The URL does not parse → return the URL verbatim and `None`. Without a
///   safe parser we cannot identify the userinfo boundary, so we refuse to
///   modify the string. (A malformed URL is captured anyway: it is itself a
///   finding-worthy oddity a later `mcp verify` should see.)
///
/// Returns `(redacted_url, userinfo_hash)`. The raw userinfo lives only as
/// the local `userinfo` String for the duration of the hash computation and
/// is dropped on function exit; it is never returned.
fn redact_url_userinfo(server_name: &str, url: &str) -> (String, Option<String>) {
    let parsed = match url::Url::parse(url) {
        Ok(p) => p,
        // Unparseable URL: store verbatim, no userinfo to hash. This is the
        // conservative choice — stripping bytes from a string we cannot
        // structurally parse could mangle the input.
        Err(_) => return (url.to_string(), None),
    };

    let username = parsed.username();
    let password = parsed.password();

    // Reconstruct the literal userinfo substring as it appears between the
    // scheme separator and the host: `user`, `user:password`, or `:password`.
    // The `url` crate normalizes the all-empty `:@` and `@` forms (no user,
    // no password) away during parsing, so `None`/`""` here genuinely means
    // the source URL declared no userinfo and there is nothing to redact.
    let userinfo: Option<String> = match (username, password) {
        ("", None) => None,
        (u, None) => Some(u.to_string()),
        (u, Some(p)) => Some(format!("{u}:{p}")),
    };

    // No userinfo: round-trip through `url::Url::as_str()` anyway, so the
    // stored URL has the same canonical shape whether the source URL declared
    // a userinfo or not. The userinfo-strip path below also emits
    // `parsed.as_str()`, so going through the same canonicalization here is
    // what keeps `compute_drift` from reporting a spurious `UrlChanged`
    // alongside `UserinfoRemoved`. Concretely: `https://user:token@host`
    // would lock as `https://host/` (url::Url appends a missing path
    // default), and if we kept the no-userinfo case byte-verbatim, a later
    // verify against a stripped `https://host` source would diff
    // `https://host/` vs `https://host` and flag two changes when the
    // endpoint did not actually change.
    let Some(raw_userinfo) = userinfo else {
        return (parsed.as_str().to_string(), None);
    };

    // Same name-salted SHA-256 scheme as `McpEnvEntry::from_raw`: the server
    // name is the per-entry salt so the same Basic Auth token under two
    // different servers hashes to two different digests, and a literal `:`
    // delimiter prevents server/userinfo boundary forgery (`("AB", "c")`
    // hashes `"AB:c"`, never the bytes of `("A", "Bc")`).
    let userinfo_hash = {
        let mut hasher = Sha256::new();
        hasher.update(server_name.as_bytes());
        hasher.update(b":");
        hasher.update(raw_userinfo.as_bytes());
        Some(hex_lower(&hasher.finalize()))
    };

    // Strip userinfo from the URL we will store. `set_username("")` /
    // `set_password(None)` only fail for URLs that cannot have an authority
    // (e.g. `data:`, `mailto:`), and a URL of that shape cannot carry
    // userinfo in the first place — so since we just observed a userinfo
    // present, both `set_*` calls must succeed.
    let mut parsed = parsed;
    let strip_ok = parsed.set_password(None).is_ok() && parsed.set_username("").is_ok();

    // Hard safety net: if the strip silently failed, refuse to return a URL
    // whose bytes still contain the userinfo. This is paranoid (the `set_*`
    // calls cannot fail for a URL we just parsed successfully *with* a
    // userinfo), but the cost is one branch and the consequence of being
    // wrong is a credential in the committed lockfile. Build a host-only
    // string from the parsed components so the lockfile is never
    // credential-bearing even in this defensive branch.
    if !strip_ok {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or("");
        let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
        let path = parsed.path();
        let redacted = format!("{scheme}://{host}{port}{path}");
        return (redacted, userinfo_hash);
    }

    (parsed.as_str().to_string(), userinfo_hash)
}

/// Extract a stdio server's `env` object as `(name, value_hash)` entries,
/// sorted by name so the hash is stable regardless of JSON key order. A
/// non-string env value is hashed by its compact JSON rendering (so a numeric
/// or boolean env value — unusual but seen in real configs — is not silently
/// dropped); a missing or non-object `env` field yields an empty vec.
///
/// `env` is **security-relevant**: it is what a config injects into the MCP
/// subprocess. Capturing it means a swapped credential or an added variable
/// shows up as drift in `mcp verify` / `mcp diff` rather than passing silently.
///
/// **The raw value never leaves this function.** It is read out of the JSON
/// map into a local `String`, immediately consumed by [`McpEnvEntry::from_raw`]
/// to compute `sha256(name || ':' || value)`, and then dropped at the end of
/// the iteration step. No struct field, log line, return value, or serialized
/// output ever carries the plaintext value. This is the load-bearing security
/// invariant of the v3 lockfile format: a committed `.tirith/mcp.lock` never
/// contains a secret that was in the source `.mcp.json`.
fn parse_env(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<McpEnvEntry> {
    let mut env: Vec<McpEnvEntry> = obj
        .get("env")
        .and_then(|v| v.as_object())
        .map(|map| {
            map.iter()
                .map(|(k, v)| {
                    // A string value is hashed verbatim; any other JSON value
                    // is hashed by its compact JSON form so it still contributes
                    // a deterministic per-value digest. The raw value sits in a
                    // local `String` only long enough for `from_raw` to consume
                    // it — it never reaches a struct, the serializer, the
                    // hasher's transport-level frame, or stdout.
                    let raw_value: String = match v.as_str() {
                        Some(s) => s.to_string(),
                        None => v.to_string(),
                    };
                    McpEnvEntry::from_raw(k, &raw_value)
                })
                .collect()
        })
        .unwrap_or_default();
    // Sort by name for a stable hash regardless of JSON key order.
    env.sort_by(|a, b| a.name.cmp(&b.name));
    env
}

/// Extract the declared tool list from a server object, sorted and
/// de-duplicated for a stable hash. Non-string entries in the `tools` array are
/// dropped. A missing or non-array `tools` field yields an empty vec.
fn parse_tools(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut tools: Vec<String> = obj
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    tools.sort();
    tools.dedup();
    tools
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

/// How a stdio server's `env` differs from what the lockfile recorded.
///
/// Each variant carries only the variable's **name** — the lockfile carries
/// only a salted hash of the value (see [`McpEnvEntry`]), and a drift report is
/// printed to a human and to `--format json`, so a raw value (which could be a
/// credential) must never leave drift detection. The hash is folded into the
/// per-server content hash, so a value swap surfaces as `ValueHashChanged` here
/// without ever being decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpEnvChange {
    /// The server now declares an env variable that the lockfile did not.
    Added { name: String },
    /// The lockfile declared an env variable that the server no longer does.
    Removed { name: String },
    /// The variable is present on both sides but its `value_hash` differs —
    /// the underlying value changed (a rotated credential, a swapped flag).
    ValueHashChanged { name: String },
}

/// How a server's transport differs from what the lockfile recorded.
///
/// The transport descriptor is the most security-relevant part of a server's
/// definition: a swapped URL is a redirection, a swapped command is a rebound
/// subprocess. Each variant captures *only* what is needed for a readable
/// drift report — `KindChanged` records the two kinds plainly, the more
/// specific variants record the structural shape of the change without
/// repeating the raw URL / command (those flow through the higher-level
/// server-changed entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransportChange {
    /// The transport's *kind* changed (e.g. `stdio` → `url`).
    KindChanged {
        /// The previous kind, lowercase: `"url"` / `"stdio"` / `"unknown"`.
        previous: String,
        /// The current kind.
        current: String,
    },
    /// Both sides are `url` and the stored URL bytes differ — the redacted
    /// (userinfo-stripped) URL bytes the lockfile carries are not equal to
    /// the current redacted URL.
    UrlChanged,
    /// Both sides are `url` and the `userinfo_hash` differs: a credential was
    /// added, removed, or swapped. `added` / `removed` carry the literal
    /// transition; a swap surfaces as both `Removed` and `Added` would mask
    /// the diff, so the swap case is `Swapped`.
    UserinfoAdded,
    UserinfoRemoved,
    UserinfoSwapped,
    /// Both sides are `stdio` and the command bytes differ.
    CommandChanged,
    /// Both sides are `stdio` and the arg list differs (added / removed /
    /// reordered).
    ArgsChanged,
    /// Both sides are `stdio` and one or more env variables added / removed /
    /// changed value-hash. The per-variable detail rides in
    /// [`McpServerDrift::env_changes`] for readability.
    EnvChanged,
}

/// What kind of change a tool list saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolsChangeKind {
    /// The set of tool names is the same but the recorded order differs.
    /// (Tool lists are sorted on parse, so this fires only when two sides
    /// were sorted differently — a defensive variant; in practice `Set` is
    /// what fires when the *declared* tools change.)
    Reordered,
    /// One or more tools were added.
    Added,
    /// One or more tools were removed.
    Removed,
    /// Both sides have tools but the set itself differs (additions and
    /// removals together).
    Set,
}

/// One server's drift entry — the headline change plus per-field detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerDriftEntry {
    /// The server's name (the key in the config's `mcpServers` / `servers`
    /// object). Same on both sides for a `Changed` entry.
    pub name: String,
    /// Repo-relative path of the config the *current* inventory pulled the
    /// server from; for a `Removed` server, the lockfile's `source_config`.
    pub source_config: String,
    /// The transport changes detected, sorted for determinism.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport_changes: Vec<McpTransportChange>,
    /// Per-variable env changes (stdio transport only), sorted by `name`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_changes: Vec<McpEnvChange>,
    /// What kind of tool change, if any. `None` when the tool list is byte-equal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_change: Option<McpToolsChangeKind>,
    /// Tool names added by the current inventory, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_added: Vec<String>,
    /// Tool names removed since the lockfile was taken, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_removed: Vec<String>,
}

impl McpServerDriftEntry {
    /// `true` when the entry records no per-field changes — used internally to
    /// reject an empty `Changed` drift (a defensive check; in normal use a
    /// `Changed` drift only exists when at least one field actually changed).
    fn is_empty(&self) -> bool {
        self.transport_changes.is_empty()
            && self.env_changes.is_empty()
            && self.tools_change.is_none()
            && self.tools_added.is_empty()
            && self.tools_removed.is_empty()
    }
}

/// One drift between the current inventory and the loaded lockfile.
///
/// A `Vec<McpDrift>` is the structured shape both `tirith mcp verify` and
/// `tirith mcp diff` consume. Sort order: `Removed` first (by name), then
/// `Added` (by name), then `Changed` (by name) — `Removed` first because it
/// is the most surprising / security-relevant case (a server that the
/// lockfile expected is gone), and grouping `Added` and `Changed` by name
/// makes the human output read top-to-bottom by server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpDrift {
    /// A server in the lockfile is no longer in the current inventory.
    Removed {
        /// The server's name as the lockfile recorded it.
        name: String,
        /// Repo-relative source config the lockfile recorded.
        source_config: String,
    },
    /// A server in the current inventory is not in the lockfile.
    Added {
        /// The server's name.
        name: String,
        /// Repo-relative source config the current inventory found.
        source_config: String,
        /// The tools the new server declares, sorted and de-duplicated (the
        /// same canonical form `McpServerEntry::tools` carries). Surfaced so
        /// a policy gate — for example `scan.mcp_allowed_tools` — can
        /// inspect the brand-new server's tool surface, mirroring the
        /// `tools_added` field on `Changed`. An empty vec means the
        /// newly-added server declared no tools (an MCP client treats that
        /// as "all tools"); a non-empty vec lists each declared tool.
        ///
        /// **Privacy.** Like `tools_added` on `Changed`, this carries only
        /// tool *names* — no values, no hashes — so a drift report can be
        /// printed and serialized safely.
        ///
        /// **Wire shape.** Skipped on serialization when empty so an older
        /// drift document (without the field) round-trips into a current
        /// `Added` with `tools: vec![]`. This is a structural extension,
        /// **not** a lockfile schema change — `.tirith/mcp.lock`'s
        /// `format_version` is unchanged (still 4).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tools: Vec<String>,
    },
    /// A server present on both sides has changed — its per-server `hash`
    /// differs. The entry holds the per-field detail.
    Changed(McpServerDriftEntry),
}

impl McpDrift {
    /// Sort key for deterministic ordering: kind-bucket first (Removed = 0,
    /// Added = 1, Changed = 2), then by `(name, source_config)` inside each
    /// bucket. This is what makes a `Vec<McpDrift>` byte-stable.
    fn sort_key(&self) -> (u8, String, String) {
        match self {
            McpDrift::Removed {
                name,
                source_config,
            } => (0, name.clone(), source_config.clone()),
            McpDrift::Added {
                name,
                source_config,
                ..
            } => (1, name.clone(), source_config.clone()),
            McpDrift::Changed(entry) => (2, entry.name.clone(), entry.source_config.clone()),
        }
    }

    /// The server name this drift refers to.
    pub fn name(&self) -> &str {
        match self {
            McpDrift::Removed { name, .. } => name,
            McpDrift::Added { name, .. } => name,
            McpDrift::Changed(entry) => &entry.name,
        }
    }
}

/// Compute the structured drift between the current inventory and the
/// lockfile that was previously written.
///
/// **Fast path.** The lockfile carries an `inventory_hash` computed over the
/// ordered concatenation of every server's content hash; the current
/// inventory's *would-be* lockfile carries the same kind of hash. If those
/// two hashes are byte-equal, the inventory is unchanged at every level — no
/// server added, removed, or altered — so the drift is empty without doing
/// any per-server work.
///
/// **Slow path.** When the two inventory hashes differ, every server is
/// compared by `(name, source_config)` (deterministic, since both sides are
/// sorted by that pair in `from_inventory`). A server on one side and not
/// the other is `Added` / `Removed`; a server on both sides whose per-server
/// `content_hash` differs is `Changed`, with `compute_changed_entry` filling
/// in the per-field detail.
///
/// **A note on the `source_config` interaction.** `content_hash`
/// deliberately excludes `source_config` — moving an unchanged server
/// definition from `.mcp.json` to `.vscode/mcp.json` is a *non-event* in
/// the chunk-1 schema. Since `inventory_hash` aggregates `content_hash`es,
/// such a move leaves the inventory hash unchanged and the fast path
/// returns empty drift. A repo that legitimately declares **two** distinct
/// servers with the same name in different configs still works: each is a
/// separate `(name, source_config)` entry in the lockfile, and changes are
/// attributed to the entry that actually changed.
///
/// The returned `Vec<McpDrift>` is sorted deterministically — see
/// [`McpDrift::sort_key`].
///
/// **Privacy.** Drift entries carry only **names**: server names, env
/// variable names, tool names. The lockfile already strips env raw values
/// and URL userinfos (replacing each with a salted hash); drift detection
/// observes that the *hash* changed, never the underlying secret. A drift
/// report is therefore safe to print to a terminal and to serialize as JSON.
pub fn compute_drift(current: &McpInventory, lock: &McpLockfile) -> Vec<McpDrift> {
    // Compute the current inventory's would-be inventory hash. If it equals
    // the lockfile's recorded one, nothing changed; skip the per-server
    // comparison entirely.
    let current_lock = McpLockfile::from_inventory(current);
    if current_lock.inventory_hash == lock.inventory_hash {
        return Vec::new();
    }

    // Walk both sides by sorted name. Both `current_lock.servers` and
    // `lock.servers` are sorted by `(name, source_config)` — that is the
    // invariant `from_inventory` establishes — so a merge walk yields the
    // diff in O(n + m).
    let mut drifts: Vec<McpDrift> = Vec::new();
    let mut i = 0usize; // index into current_lock.servers
    let mut j = 0usize; // index into lock.servers

    while i < current_lock.servers.len() && j < lock.servers.len() {
        let cur = &current_lock.servers[i];
        let prev = &lock.servers[j];

        let key_cur = (&cur.name, &cur.source_config);
        let key_prev = (&prev.name, &prev.source_config);

        match key_cur.cmp(&key_prev) {
            std::cmp::Ordering::Less => {
                // Current side has a server before the lockfile's next one —
                // the lockfile doesn't have it. Added. The new server's
                // tool list rides along so a policy gate
                // (`scan.mcp_allowed_tools`) can see what the brand-new
                // server is exposing — mirroring `tools_added` on Changed.
                drifts.push(McpDrift::Added {
                    name: cur.name.clone(),
                    source_config: cur.source_config.clone(),
                    tools: cur.tools.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                // Lockfile has a server before the current side's next one —
                // current side doesn't have it. Removed.
                drifts.push(McpDrift::Removed {
                    name: prev.name.clone(),
                    source_config: prev.source_config.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                // Same (name, source_config). If the per-server content hash
                // matches, the server is byte-identical — no drift. If the
                // hashes differ, classify the per-field change.
                if cur.hash != prev.hash {
                    if let Some(entry) = compute_changed_entry(cur, prev) {
                        drifts.push(McpDrift::Changed(entry));
                    }
                }
                i += 1;
                j += 1;
            }
        }
    }
    while i < current_lock.servers.len() {
        let cur = &current_lock.servers[i];
        drifts.push(McpDrift::Added {
            name: cur.name.clone(),
            source_config: cur.source_config.clone(),
            tools: cur.tools.clone(),
        });
        i += 1;
    }
    while j < lock.servers.len() {
        let prev = &lock.servers[j];
        drifts.push(McpDrift::Removed {
            name: prev.name.clone(),
            source_config: prev.source_config.clone(),
        });
        j += 1;
    }

    drifts.sort_by_key(McpDrift::sort_key);
    drifts
}

/// Classify the field-level change between two servers that share a
/// `(name, source_config)` but have different per-server `hash` values.
///
/// Returns `Some(entry)` when at least one field-level change is detected.
/// Returns `None` only in the defensive case where the hashes differ but no
/// field-level cause is identified — that should not happen for well-formed
/// inputs (`content_hash` is total over every field), and an empty `Changed`
/// entry would be noise.
fn compute_changed_entry(
    current: &McpLockServer,
    previous: &McpLockServer,
) -> Option<McpServerDriftEntry> {
    let mut transport_changes: Vec<McpTransportChange> = Vec::new();
    let mut env_changes: Vec<McpEnvChange> = Vec::new();

    match (&current.transport, &previous.transport) {
        (
            McpTransport::Url {
                url: cur_url,
                userinfo_hash: cur_userinfo,
            },
            McpTransport::Url {
                url: prev_url,
                userinfo_hash: prev_userinfo,
            },
        ) => {
            if cur_url != prev_url {
                transport_changes.push(McpTransportChange::UrlChanged);
            }
            match (cur_userinfo.as_deref(), prev_userinfo.as_deref()) {
                (None, None) => {}
                (Some(_), None) => {
                    transport_changes.push(McpTransportChange::UserinfoAdded);
                }
                (None, Some(_)) => {
                    transport_changes.push(McpTransportChange::UserinfoRemoved);
                }
                (Some(a), Some(b)) if a != b => {
                    transport_changes.push(McpTransportChange::UserinfoSwapped);
                }
                _ => {}
            }
        }
        (
            McpTransport::Stdio {
                command: cur_cmd,
                args: cur_args,
                env: cur_env,
            },
            McpTransport::Stdio {
                command: prev_cmd,
                args: prev_args,
                env: prev_env,
            },
        ) => {
            if cur_cmd != prev_cmd {
                transport_changes.push(McpTransportChange::CommandChanged);
            }
            if cur_args != prev_args {
                transport_changes.push(McpTransportChange::ArgsChanged);
            }
            env_changes = diff_env(cur_env, prev_env);
            if !env_changes.is_empty() {
                transport_changes.push(McpTransportChange::EnvChanged);
            }
        }
        (cur, prev) => {
            // Kind changed (stdio ↔ url, or either ↔ unknown). Encode the
            // before/after kind directly so the human and JSON forms can
            // render "stdio → url".
            transport_changes.push(McpTransportChange::KindChanged {
                previous: transport_kind_name(prev).to_string(),
                current: transport_kind_name(cur).to_string(),
            });
        }
    }

    let (tools_change, tools_added, tools_removed) = diff_tools(&current.tools, &previous.tools);

    // Transport changes are sorted so equal drifts compare equal regardless of
    // detection order. The sort discriminates by serialized form so it is
    // stable across enum variant additions.
    transport_changes
        .sort_by_key(|c| serde_json::to_string(c).unwrap_or_else(|_| format!("{c:?}")));

    let entry = McpServerDriftEntry {
        name: current.name.clone(),
        source_config: current.source_config.clone(),
        transport_changes,
        env_changes,
        tools_change,
        tools_added,
        tools_removed,
    };

    if entry.is_empty() {
        None
    } else {
        Some(entry)
    }
}

/// Lowercase short name of a transport kind, used in drift reports.
fn transport_kind_name(t: &McpTransport) -> &'static str {
    match t {
        McpTransport::Url { .. } => "url",
        McpTransport::Stdio { .. } => "stdio",
        McpTransport::Unknown => "unknown",
    }
}

/// Diff two env lists. Both are sorted by name (the invariant `parse_env`
/// establishes), so a merge walk yields per-variable changes in O(n + m).
/// Returned entries are themselves sorted by `name` for determinism.
fn diff_env(current: &[McpEnvEntry], previous: &[McpEnvEntry]) -> Vec<McpEnvChange> {
    let mut out: Vec<McpEnvChange> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < current.len() && j < previous.len() {
        let cur = &current[i];
        let prev = &previous[j];
        match cur.name.cmp(&prev.name) {
            std::cmp::Ordering::Less => {
                out.push(McpEnvChange::Added {
                    name: cur.name.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(McpEnvChange::Removed {
                    name: prev.name.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if cur.value_hash != prev.value_hash {
                    out.push(McpEnvChange::ValueHashChanged {
                        name: cur.name.clone(),
                    });
                }
                i += 1;
                j += 1;
            }
        }
    }
    while i < current.len() {
        out.push(McpEnvChange::Added {
            name: current[i].name.clone(),
        });
        i += 1;
    }
    while j < previous.len() {
        out.push(McpEnvChange::Removed {
            name: previous[j].name.clone(),
        });
        j += 1;
    }
    out
}

/// Diff two tool lists, returning the kind of change, the added tools, and
/// the removed tools. Tool lists are sorted on parse, so a same-set / different
/// order case can only arise from a hand-built inventory; the `Reordered`
/// variant is recorded for completeness.
fn diff_tools(
    current: &[String],
    previous: &[String],
) -> (Option<McpToolsChangeKind>, Vec<String>, Vec<String>) {
    if current == previous {
        return (None, Vec::new(), Vec::new());
    }

    // Same set, different order → Reordered.
    let mut cur_sorted = current.to_vec();
    let mut prev_sorted = previous.to_vec();
    cur_sorted.sort();
    prev_sorted.sort();
    if cur_sorted == prev_sorted {
        return (Some(McpToolsChangeKind::Reordered), Vec::new(), Vec::new());
    }

    let cur_set: std::collections::BTreeSet<&str> = current.iter().map(|s| s.as_str()).collect();
    let prev_set: std::collections::BTreeSet<&str> = previous.iter().map(|s| s.as_str()).collect();
    let added: Vec<String> = cur_set
        .difference(&prev_set)
        .map(|s| (*s).to_string())
        .collect();
    let removed: Vec<String> = prev_set
        .difference(&cur_set)
        .map(|s| (*s).to_string())
        .collect();

    let kind = match (added.is_empty(), removed.is_empty()) {
        (false, true) => McpToolsChangeKind::Added,
        (true, false) => McpToolsChangeKind::Removed,
        _ => McpToolsChangeKind::Set,
    };
    (Some(kind), added, removed)
}

/// Load a lockfile from disk and parse it.
///
/// Returns the parsed `McpLockfile` on success.
///
/// `Err` cases — surfaced via [`McpLockLoadError`] so a caller (`mcp verify`,
/// `mcp diff`, a `tirith scan` FileScan dispatcher) can present each
/// differently:
///
/// * [`McpLockLoadError::NotFound`] — the file does not exist. For `mcp
///   verify` this is "no baseline yet, run `tirith mcp lock`", which is a
///   usage error (exit 2). For a `scan` of `mcp.lock` it is "nothing to
///   check" (the scan target was something else).
/// * [`McpLockLoadError::Io`] — the file exists but could not be read
///   (permission denied, etc.).
/// * [`McpLockLoadError::Parse`] — the file is not valid JSON or does not
///   match the [`McpLockfile`] schema.
pub fn load_lockfile(path: &Path) -> Result<McpLockfile, McpLockLoadError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(McpLockLoadError::NotFound);
        }
        Err(e) => return Err(McpLockLoadError::Io(e.to_string())),
    };
    parse_lockfile(&content)
}

/// Parse a lockfile from its on-disk JSON form.
///
/// **Privacy.** A failed parse intentionally **does not** carry the
/// `serde_json::Error`'s message string forward. `serde_json::Error`'s
/// `Display` impl can include the offending JSON value (e.g.
/// `invalid type: string "...", expected ...`), and `.tirith/mcp.lock`
/// frequently carries secret-shaped data (env-value hashes, a userinfo
/// hash, a malformed-but-committed credential the lockfile redaction is
/// meant to protect). Echoing that error string into the parse-error
/// variant would surface it through `Display`, the `mcp verify` /
/// `mcp diff` CLI output, AND the `McpServerDrift` finding's
/// description — a privacy leak via diagnostic. Instead we capture
/// only the structurally-safe `line` and `column` from
/// [`serde_json::Error`] (both are `usize`, neither can echo content)
/// and discard the message itself. Drift detection is unaffected: the
/// lockfile is still recognized as unparseable, the same
/// `McpServerDrift` finding still fires; only the diagnostic tightens.
///
/// **Server ordering.** A parsed lockfile's `servers` list is sorted by
/// `(name, source_config)` here — the same ordering
/// [`McpLockfile::from_inventory`] establishes — so every
/// `McpLockfile` consumer sees a consistent view regardless of
/// on-disk order. A hand-edited or merge-conflict-resolved lockfile
/// whose servers landed out of order would otherwise make
/// [`compute_drift`]'s slow-path merge walk emit spurious
/// `Added`/`Removed` pairs and miss `Changed` entries: the merge
/// walk assumes both sides are sorted, and the fast-path
/// `inventory_hash` short-circuit cannot save it once a single server
/// genuinely differs. Sorting here keeps the invariant load-bearing
/// for every caller (the rule, `mcp verify`, `mcp diff`, future
/// programmatic consumers) without re-sorting at each call site.
pub fn parse_lockfile(content: &str) -> Result<McpLockfile, McpLockLoadError> {
    let mut lock: McpLockfile = serde_json::from_str(content).map_err(|e| {
        // Capture only the safe structural metadata. The error's
        // Display message is deliberately dropped — it can contain
        // the offending JSON content.
        McpLockLoadError::Parse {
            line: e.line(),
            column: e.column(),
        }
    })?;
    // Defensive sort: `compute_drift`'s slow-path merge walk requires
    // `lock.servers` to be sorted by `(name, source_config)`. The
    // lockfile we wrote is always sorted (see `from_inventory`), but a
    // hand-edited or merge-resolved lockfile could land here out of
    // order. Sorting at the parse boundary makes the invariant total
    // over every `McpLockfile` value that exists in the program, so
    // no downstream caller has to re-sort.
    lock.servers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.source_config.cmp(&b.source_config))
    });
    Ok(lock)
}

/// Why a lockfile could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpLockLoadError {
    /// The file does not exist (caller decides whether this is fatal).
    NotFound,
    /// The file exists but cannot be read (permission, encoding, …).
    Io(String),
    /// The file exists and was read but does not parse as a lockfile.
    ///
    /// **Carries only line/column.** The original `serde_json::Error`
    /// message is intentionally **not** captured — see
    /// [`parse_lockfile`] for why. Both fields are `usize`, neither
    /// can carry the offending JSON value, so this variant is safe to
    /// `Display` into a CLI message and into a `McpServerDrift`
    /// finding's description.
    Parse { line: usize, column: usize },
}

impl std::fmt::Display for McpLockLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpLockLoadError::NotFound => write!(f, "lockfile not found"),
            McpLockLoadError::Io(e) => write!(f, "could not read lockfile: {e}"),
            // Line/column only — never the parser's message string.
            // See `parse_lockfile` for the privacy rationale.
            McpLockLoadError::Parse { line, column } => {
                write!(f, "could not parse lockfile (line {line}, column {column})")
            }
        }
    }
}

impl std::error::Error for McpLockLoadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parse_mcp_servers_canonical_shape() {
        let content = r#"{
            "mcpServers": {
                "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"] },
                "remote": { "url": "https://mcp.example.com/sse", "tools": ["search", "fetch"] }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid MCP config");
        assert_eq!(entries.len(), 2);

        let fs_entry = entries.iter().find(|e| e.name == "fs").unwrap();
        assert_eq!(
            fs_entry.transport,
            McpTransport::Stdio {
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-filesystem".to_string(),
                    "/srv".to_string(),
                ],
                env: vec![],
            }
        );
        assert!(fs_entry.tools.is_empty());
        assert_eq!(fs_entry.source_config, ".mcp.json");

        let remote = entries.iter().find(|e| e.name == "remote").unwrap();
        assert_eq!(
            remote.transport,
            McpTransport::Url {
                url: "https://mcp.example.com/sse".to_string(),
                userinfo_hash: None,
            }
        );
        // tools sorted.
        assert_eq!(remote.tools, vec!["fetch", "search"]);
    }

    #[test]
    fn parse_mcp_servers_alias_shape() {
        // The `servers` alias (some IDE configs) parses identically.
        let content = r#"{ "servers": { "a": { "command": "node", "args": ["s.js"] } } }"#;
        let entries = parse_mcp_config(content, ".vscode/mcp.json").expect("valid alias config");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a");
        assert_eq!(
            entries[0].transport,
            McpTransport::Stdio {
                command: "node".to_string(),
                args: vec!["s.js".to_string()],
                env: vec![],
            }
        );
    }

    #[test]
    fn parse_server_with_no_transport_is_unknown() {
        // A server object declaring neither `url` nor `command` is captured
        // with an Unknown transport rather than dropped.
        let content = r#"{ "mcpServers": { "weird": { "tools": ["x"] } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].transport, McpTransport::Unknown);
        assert_eq!(entries[0].tools, vec!["x"]);
    }

    #[test]
    fn parse_url_wins_when_both_declared() {
        // A malformed config declaring both `url` and `command`: the URL (the
        // higher-risk surface) is the one recorded. The bare-host URL is
        // canonicalized to its trailing-`/` form (the same shape it would
        // take after userinfo stripping, so removing a credential never
        // surfaces as a spurious `UrlChanged`).
        let content =
            r#"{ "mcpServers": { "both": { "url": "https://x.example", "command": "node" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        assert_eq!(
            entries[0].transport,
            McpTransport::Url {
                url: "https://x.example/".to_string(),
                userinfo_hash: None,
            }
        );
    }

    #[test]
    fn parse_malformed_json_returns_none() {
        // Not valid JSON → None (recorded as malformed by the caller), no panic.
        for bad in [
            "{ not json",
            "",
            "{\"mcpServers\":",
            "[1,2,3]",
            "\"just a string\"",
        ] {
            assert!(
                parse_mcp_config(bad, ".mcp.json").is_none(),
                "malformed input {bad:?} must yield None"
            );
        }
    }

    #[test]
    fn parse_valid_json_without_mcp_object_returns_none() {
        // Valid JSON but no `mcpServers`/`servers` object → None.
        let content = r#"{ "someOtherKey": { "a": 1 } }"#;
        assert!(parse_mcp_config(content, "mcp.json").is_none());
    }

    #[test]
    fn parse_empty_mcp_object_is_some_empty() {
        // A valid but empty MCP object is a recognized (empty) config — Some(vec![]),
        // distinct from a malformed file.
        let content = r#"{ "mcpServers": {} }"#;
        let entries = parse_mcp_config(content, "mcp.json").expect("recognized empty config");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_skips_non_object_server_keeps_others() {
        // One server value is a string (malformed); the other is valid. The
        // good one survives.
        let content = r#"{ "mcpServers": { "bad": "oops", "good": { "command": "node" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "good");
    }

    #[test]
    fn parse_tools_drops_non_string_entries() {
        let content =
            r#"{ "mcpServers": { "s": { "command": "n", "tools": ["ok", 42, null, "ok"] } } }"#;
        let entries = parse_mcp_config(content, "mcp.json").unwrap();
        // 42 and null dropped; the duplicate "ok" de-duplicated.
        assert_eq!(entries[0].tools, vec!["ok"]);
    }

    #[test]
    fn content_hash_is_stable_and_order_independent_for_tools() {
        let a = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["x".into()],
                env: vec![],
            },
            tools: vec!["alpha".into(), "beta".into()],
            source_config: ".mcp.json".into(),
        };
        // Tools are sorted on parse, so a differently-ordered-but-equal tool
        // set hashes identically.
        let b = McpServerEntry {
            tools: vec!["beta".into(), "alpha".into()],
            ..a.clone()
        };
        let mut b_sorted = b.clone();
        b_sorted.tools.sort();
        assert_eq!(a.content_hash(), b_sorted.content_hash());
    }

    #[test]
    fn content_hash_changes_when_transport_changes() {
        let base = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let changed = McpServerEntry {
            transport: McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            },
            ..base.clone()
        };
        assert_ne!(base.content_hash(), changed.content_hash());
    }

    #[test]
    fn content_hash_ignores_source_config() {
        // Moving an unchanged server between two config files must not change
        // its content hash — only name/transport/tools are hashed.
        let a = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let b = McpServerEntry {
            source_config: ".vscode/mcp.json".into(),
            ..a.clone()
        };
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn lockfile_from_inventory_is_deterministic() {
        let inventory = McpInventory {
            servers: vec![
                McpServerEntry {
                    name: "zeta".into(),
                    transport: McpTransport::Stdio {
                        command: "z".into(),
                        args: vec![],
                        env: vec![],
                    },
                    tools: vec![],
                    source_config: ".mcp.json".into(),
                },
                McpServerEntry {
                    name: "alpha".into(),
                    transport: McpTransport::Url {
                        url: "https://a.example".into(),
                        userinfo_hash: None,
                    },
                    tools: vec!["t".into()],
                    source_config: ".mcp.json".into(),
                },
            ],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let lock1 = McpLockfile::from_inventory(&inventory);
        let lock2 = McpLockfile::from_inventory(&inventory);
        assert_eq!(lock1, lock2);
        assert_eq!(lock1.render(), lock2.render());
        assert_eq!(lock1.format_version, MCP_LOCK_FORMAT_VERSION);
        assert_eq!(lock1.servers.len(), 2);
    }

    #[test]
    fn lockfile_render_ends_with_newline_and_is_valid_json() {
        let inventory = McpInventory::default();
        let lock = McpLockfile::from_inventory(&inventory);
        let rendered = lock.render();
        assert!(rendered.ends_with('\n'));
        let parsed: McpLockfile =
            serde_json::from_str(&rendered).expect("rendered lockfile must round-trip");
        assert_eq!(parsed, lock);
    }

    #[test]
    fn inventory_hash_changes_when_a_server_changes() {
        let mut inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let hash_before = McpLockfile::from_inventory(&inventory).inventory_hash;

        // Mutate the single server's transport.
        inventory.servers[0].transport = McpTransport::Url {
            url: "https://new.example".into(),
            userinfo_hash: None,
        };
        let hash_after = McpLockfile::from_inventory(&inventory).inventory_hash;

        assert_ne!(
            hash_before, hash_after,
            "inventory hash must change when a server changes"
        );
    }

    #[test]
    fn build_inventory_finds_planted_mcp_json() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "fs": { "command": "npx", "args": ["server"] } } }"#,
        )
        .unwrap();

        let inventory = build_inventory(repo.path());
        assert_eq!(inventory.configs, vec![".mcp.json".to_string()]);
        assert_eq!(inventory.servers.len(), 1);
        assert_eq!(inventory.servers[0].name, "fs");
        assert!(inventory.malformed_configs.is_empty());
        assert!(!inventory.is_empty());
    }

    #[test]
    fn build_inventory_empty_repo_is_empty() {
        let repo = tempdir().unwrap();
        let inventory = build_inventory(repo.path());
        assert!(inventory.is_empty());
        assert!(inventory.servers.is_empty());
        assert!(inventory.configs.is_empty());
    }

    #[test]
    fn build_inventory_records_malformed_config() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("mcp.json"), "{ this is not json").unwrap();
        let inventory = build_inventory(repo.path());
        // The file is discovered (it counts as a config) but yields no servers
        // and is recorded as malformed.
        assert_eq!(inventory.configs, vec!["mcp.json".to_string()]);
        assert!(inventory.servers.is_empty());
        assert_eq!(inventory.malformed_configs, vec!["mcp.json".to_string()]);
        // A repo that has only a malformed config is still "non-empty" — a
        // config WAS found, the caller should report it, not say "nothing".
        assert!(!inventory.is_empty());
    }

    #[test]
    fn build_inventory_merges_multiple_configs_sorted() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "root-server": { "command": "a" } } }"#,
        )
        .unwrap();
        fs::create_dir_all(repo.path().join(".vscode")).unwrap();
        fs::write(
            repo.path().join(".vscode/mcp.json"),
            r#"{ "servers": { "ide-server": { "command": "b" } } }"#,
        )
        .unwrap();

        let inventory = build_inventory(repo.path());
        assert_eq!(
            inventory.configs,
            vec![".mcp.json".to_string(), ".vscode/mcp.json".to_string()]
        );
        assert_eq!(inventory.servers.len(), 2);
        // Servers sorted by name: "ide-server" < "root-server".
        assert_eq!(inventory.servers[0].name, "ide-server");
        assert_eq!(inventory.servers[1].name, "root-server");
        assert_eq!(inventory.servers[0].source_config, ".vscode/mcp.json");
        assert_eq!(inventory.servers[1].source_config, ".mcp.json");
    }

    #[test]
    fn discover_mcp_configs_is_repo_local_only() {
        // A config-shaped file outside the repo root must NOT be discovered.
        let outer = tempdir().unwrap();
        fs::write(outer.path().join(".mcp.json"), r#"{ "mcpServers": {} }"#).unwrap();
        let repo = outer.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        // The repo itself has no MCP config.
        let found = discover_mcp_configs(&repo);
        assert!(
            found.is_empty(),
            "discovery must not climb out of the repo root: {found:?}"
        );
    }

    #[test]
    fn build_inventory_empty_mcp_object_counts_as_config_no_servers() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("mcp.json"), r#"{ "mcpServers": {} }"#).unwrap();
        let inventory = build_inventory(repo.path());
        // A recognized-but-empty config: it counts as a discovered config, it
        // is NOT malformed, and it declares zero servers.
        assert_eq!(inventory.configs, vec!["mcp.json".to_string()]);
        assert!(inventory.servers.is_empty());
        assert!(inventory.malformed_configs.is_empty());
        assert!(!inventory.is_empty());
    }

    // -----------------------------------------------------------------------
    // Finding A — `from_inventory` sorts servers before hashing, so a lockfile
    // (and its inventory hash) is identical no matter what order discovery
    // happened to produce.
    // -----------------------------------------------------------------------

    #[test]
    fn from_inventory_sorts_servers_regardless_of_input_order() {
        let alpha = McpServerEntry {
            name: "alpha".into(),
            transport: McpTransport::Url {
                url: "https://a.example".into(),
                userinfo_hash: None,
            },
            tools: vec!["t".into()],
            source_config: ".mcp.json".into(),
        };
        let zeta = McpServerEntry {
            name: "zeta".into(),
            transport: McpTransport::Stdio {
                command: "z".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".vscode/mcp.json".into(),
        };

        // Same two servers, opposite inventory order.
        let in_order = McpInventory {
            servers: vec![alpha.clone(), zeta.clone()],
            configs: vec![".mcp.json".into(), ".vscode/mcp.json".into()],
            malformed_configs: vec![],
        };
        let reversed = McpInventory {
            servers: vec![zeta, alpha],
            configs: vec![".vscode/mcp.json".into(), ".mcp.json".into()],
            malformed_configs: vec![],
        };

        let lock_a = McpLockfile::from_inventory(&in_order);
        let lock_b = McpLockfile::from_inventory(&reversed);

        // Servers land in (name, source_config) order either way.
        assert_eq!(lock_a.servers[0].name, "alpha");
        assert_eq!(lock_a.servers[1].name, "zeta");
        // The whole lockfile — including the order-sensitive inventory hash and
        // the rendered bytes — is identical regardless of discovery order.
        assert_eq!(lock_a, lock_b);
        assert_eq!(lock_a.inventory_hash, lock_b.inventory_hash);
        assert_eq!(lock_a.render(), lock_b.render());
    }

    #[test]
    fn from_inventory_sorts_by_source_config_when_names_tie() {
        // Two servers with the *same* name must order by source_config — and do
        // so deterministically whichever way the inventory listed them.
        let mk = |source: &str| McpServerEntry {
            name: "dup".into(),
            transport: McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            },
            tools: vec![],
            source_config: source.into(),
        };
        let forward = McpInventory {
            servers: vec![mk(".mcp.json"), mk(".vscode/mcp.json")],
            configs: vec![],
            malformed_configs: vec![],
        };
        let backward = McpInventory {
            servers: vec![mk(".vscode/mcp.json"), mk(".mcp.json")],
            configs: vec![],
            malformed_configs: vec![],
        };
        let lock_f = McpLockfile::from_inventory(&forward);
        let lock_b = McpLockfile::from_inventory(&backward);
        assert_eq!(lock_f.servers[0].source_config, ".mcp.json");
        assert_eq!(lock_f.servers[1].source_config, ".vscode/mcp.json");
        assert_eq!(lock_f, lock_b);
    }

    // -----------------------------------------------------------------------
    // Finding B — a symlinked config file (or one under a symlinked directory)
    // is rejected: discovery is repo-local, and a symlink can point anywhere.
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn discover_rejects_symlinked_config_file() {
        use std::os::unix::fs::symlink;

        // A real config lives OUTSIDE the repo.
        let outside = tempdir().unwrap();
        let outside_config = outside.path().join("evil-mcp.json");
        fs::write(
            &outside_config,
            r#"{ "mcpServers": { "evil": { "command": "node" } } }"#,
        )
        .unwrap();

        // Inside the repo, `.mcp.json` is a *symlink* pointing at it.
        let repo = tempdir().unwrap();
        symlink(&outside_config, repo.path().join(".mcp.json")).unwrap();

        // The symlinked config must NOT be discovered…
        let found = discover_mcp_configs(repo.path());
        assert!(
            found.is_empty(),
            "a symlinked .mcp.json must be rejected, not followed: {found:?}"
        );

        // …and the inventory must therefore be empty — the outside server is
        // not pulled in.
        let inventory = build_inventory(repo.path());
        assert!(
            inventory.servers.is_empty(),
            "a symlinked config must contribute no servers"
        );
        assert!(inventory.configs.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn discover_rejects_config_under_symlinked_directory() {
        use std::os::unix::fs::symlink;

        // A real `.vscode/` directory with a config lives outside the repo.
        let outside = tempdir().unwrap();
        let outside_vscode = outside.path().join("vscode-real");
        fs::create_dir_all(&outside_vscode).unwrap();
        fs::write(
            outside_vscode.join("mcp.json"),
            r#"{ "servers": { "evil": { "command": "node" } } }"#,
        )
        .unwrap();

        // Inside the repo, `.vscode` is a symlink to that outside directory.
        let repo = tempdir().unwrap();
        symlink(&outside_vscode, repo.path().join(".vscode")).unwrap();

        // `.vscode/mcp.json` resolves outside the repo via the symlinked
        // parent — it must be rejected.
        let found = discover_mcp_configs(repo.path());
        assert!(
            found.is_empty(),
            "a config reached through a symlinked directory must be rejected: {found:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn discover_still_accepts_a_plain_regular_config() {
        // Control: a plain (non-symlink) config file is still discovered — the
        // symlink rejection must not break the normal case.
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "ok": { "command": "node" } } }"#,
        )
        .unwrap();
        let found = discover_mcp_configs(repo.path());
        assert_eq!(found.len(), 1, "a plain regular config must still be found");
        assert_eq!(found[0].1, ".mcp.json");
    }

    // -----------------------------------------------------------------------
    // Finding C — a stdio server's `env` is captured and an `env` change
    // registers as drift (it is part of the per-server content hash).
    // -----------------------------------------------------------------------

    #[test]
    fn parse_captures_stdio_env() {
        let content = r#"{
            "mcpServers": {
                "s": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": { "API_TOKEN": "secret-1", "DEBUG": "1" }
                }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);
        // env entries are present, sorted by name, and carry hashes — not the
        // raw values. The hashes match `sha256(name || ':' || value)`.
        assert_eq!(
            entries[0].transport,
            McpTransport::Stdio {
                command: "node".to_string(),
                args: vec!["server.js".to_string()],
                env: vec![
                    McpEnvEntry::from_raw("API_TOKEN", "secret-1"),
                    McpEnvEntry::from_raw("DEBUG", "1"),
                ],
            }
        );
    }

    #[test]
    fn parse_env_is_sorted_and_handles_non_string_values() {
        // Keys come back sorted regardless of JSON order; a non-string value is
        // captured by its JSON rendering and then hashed rather than dropped.
        let content = r#"{
            "mcpServers": {
                "s": { "command": "n", "env": { "ZED": "z", "ABLE": 7 } }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        match &entries[0].transport {
            McpTransport::Stdio { env, .. } => {
                // `7` becomes the compact JSON form `"7"` before hashing.
                assert_eq!(
                    env,
                    &vec![
                        McpEnvEntry::from_raw("ABLE", "7"),
                        McpEnvEntry::from_raw("ZED", "z"),
                    ]
                );
            }
            other => panic!("expected stdio transport, got {other:?}"),
        }
    }

    #[test]
    fn content_hash_changes_when_env_changes() {
        // The headline of Finding C: an `env` change must register as drift.
        let base = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "old")],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        // Same server, the env value swapped (a rotated/exfiltrated credential).
        let value_changed = McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "new")],
            },
            ..base.clone()
        };
        // Same server, an extra env var added.
        let var_added = McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![
                    McpEnvEntry::from_raw("API_TOKEN", "old"),
                    McpEnvEntry::from_raw("EXTRA", "x"),
                ],
            },
            ..base.clone()
        };
        assert_ne!(
            base.content_hash(),
            value_changed.content_hash(),
            "swapping an env value must change the content hash"
        );
        assert_ne!(
            base.content_hash(),
            var_added.content_hash(),
            "adding an env var must change the content hash"
        );

        // And it flows through to the inventory hash / lockfile.
        let inv_base = McpInventory {
            servers: vec![base.clone()],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let inv_changed = McpInventory {
            servers: vec![value_changed],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        assert_ne!(
            McpLockfile::from_inventory(&inv_base).inventory_hash,
            McpLockfile::from_inventory(&inv_changed).inventory_hash,
            "an env change must surface as a different inventory hash"
        );
    }

    #[test]
    fn lockfile_format_version_is_4() {
        // v4 extends the salted-hash redaction to the URL transport's
        // userinfo (`https://user:token@host/` is stored as `https://host/`
        // with a `userinfo_hash` of `sha256(server_name || ':' || userinfo)`).
        // A URL with no userinfo serializes with `userinfo_hash` omitted.
        assert_eq!(MCP_LOCK_FORMAT_VERSION, 4);
        let lock = McpLockfile::from_inventory(&McpInventory::default());
        assert_eq!(lock.format_version, 4);
    }

    #[test]
    fn lockfile_with_env_round_trips() {
        // A lockfile carrying a server with `env` must serialize and parse back
        // identically — the new schema field round-trips.
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec!["server.js".into()],
                    env: vec![McpEnvEntry::from_raw("TOKEN", "v")],
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let lock = McpLockfile::from_inventory(&inventory);
        let parsed: McpLockfile =
            serde_json::from_str(&lock.render()).expect("lockfile with env must round-trip");
        assert_eq!(parsed, lock);
    }

    // -----------------------------------------------------------------------
    // Finding E — env raw values must not be persisted in the lockfile. They
    // are commonly secrets (API tokens, credentials), and `.tirith/mcp.lock`
    // is designed to be committed. The lockfile carries a salted hash only.
    // -----------------------------------------------------------------------

    /// A bag of credential-shaped (high-entropy, unique) env values we render
    /// into the lockfile in the test below; **none** of these byte sequences
    /// may appear in the rendered JSON. The values are deliberately distinctive
    /// so a substring scan over the rendered JSON cannot trip on incidental
    /// matches in field names, hashes, or other names — they are not strings
    /// any other part of the lockfile could legitimately contain.
    const ENV_LEAK_PROBES: &[(&str, &str)] = &[
        ("API_TOKEN", "ghp_supersecret_TOKEN_value_42"),
        (
            "GITHUB_PERSONAL_ACCESS_TOKEN",
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("OPENAI_API_KEY", "sk-test-DO_NOT_LEAK_THIS_VALUE"),
        ("DB_PASSWORD", "p4ssw0rd-shouldnt-leak-mY7q"),
        ("WEBHOOK_SECRET", "whsec_xyz123_zyx789_NEVER_LEAK"),
    ];

    #[test]
    fn env_raw_values_never_appear_in_rendered_lockfile() {
        // Plant a server whose env carries values that look exactly like
        // credentials — API tokens, GitHub PATs, OpenAI keys. After rendering,
        // NONE of the raw value bytes may show up.
        //
        // Note: this test deliberately uses high-entropy, distinctive values
        // (not "1" or "true"). A low-entropy value substring-matches incidental
        // parts of the JSON — `"1"` appears inside hashes, `"true"` inside
        // boolean-like keys — so probing for it would false-positive. The
        // security invariant the lockfile guarantees is that a *secret-shaped*
        // value is not persisted: that value, by construction, cannot collide
        // with any other lockfile content.
        let env: Vec<McpEnvEntry> = ENV_LEAK_PROBES
            .iter()
            .map(|(name, value)| McpEnvEntry::from_raw(name, value))
            .collect();
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "secrets".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec!["server.js".into()],
                    env,
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();

        for (name, raw_value) in ENV_LEAK_PROBES {
            // The name is allowed to appear (it is what the human summary shows
            // and the schema serializes), but the raw VALUE must not — its hash
            // is recorded instead.
            assert!(
                rendered.contains(name),
                "the env name {name:?} should appear in the lockfile"
            );
            assert!(
                !rendered.contains(raw_value),
                "env raw value {raw_value:?} (for {name}) leaked into the rendered lockfile:\n{rendered}"
            );
        }
        // Every env entry exposes a `value_hash` field — the wire shape proof.
        assert!(
            rendered.contains("\"value_hash\""),
            "rendered lockfile must serialize a value_hash per env entry"
        );
        // And it must NOT carry a `value` field — the proof we did not also
        // write the raw value as a sibling of the hash. Use the exact JSON
        // field-key form `"value":` so the substring cannot collide with
        // `"value_hash":` (which contains the substring `"value"`).
        assert!(
            !rendered.contains("\"value\":"),
            "rendered lockfile must NOT carry a plaintext `value` field"
        );
    }

    #[test]
    fn parse_env_does_not_persist_raw_values() {
        // The same invariant via the JSON-config entry point (not direct struct
        // construction): a config carrying a real-looking secret must produce a
        // parsed inventory whose lockfile rendering does not contain that
        // secret byte sequence anywhere.
        let secret = "ghp_REAL_LOOKING_TOKEN_DO_NOT_LEAK";
        let content = format!(
            r#"{{
                "mcpServers": {{
                    "s": {{
                        "command": "node",
                        "env": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "{secret}" }}
                    }}
                }}
            }}"#
        );
        let entries = parse_mcp_config(&content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);

        // The parsed env entry carries the SHA-256 hash, not the raw value.
        let env = match &entries[0].transport {
            McpTransport::Stdio { env, .. } => env,
            other => panic!("expected stdio transport, got {other:?}"),
        };
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].name, "GITHUB_PERSONAL_ACCESS_TOKEN");
        assert_eq!(
            env[0].value_hash,
            McpEnvEntry::from_raw("GITHUB_PERSONAL_ACCESS_TOKEN", secret).value_hash,
            "the value hash must be sha256(name || ':' || value)"
        );

        // And the rendered lockfile that descends from this parse must not
        // carry the raw secret bytes anywhere.
        let inventory = McpInventory {
            servers: entries,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();
        assert!(
            !rendered.contains(secret),
            "raw secret leaked from parse_mcp_config -> McpLockfile::render():\n{rendered}"
        );
    }

    #[test]
    fn env_entry_value_hash_is_name_salted() {
        // The hash binds the name to the value, so a low-entropy value cannot
        // be brute-forced once and reused across servers: the same value `1`
        // under two different names hashes to two different digests.
        let a = McpEnvEntry::from_raw("DEBUG", "1");
        let b = McpEnvEntry::from_raw("VERBOSE", "1");
        assert_ne!(
            a.value_hash, b.value_hash,
            "the same raw value under different names must hash differently \
             (the name acts as a per-key salt)"
        );
        // And the hash is exactly sha256(name || ':' || value) — a stable,
        // documented, reproducible-by-hand scheme.
        let expected_a = {
            let mut h = Sha256::new();
            h.update(b"DEBUG:1");
            hex_lower(&h.finalize())
        };
        assert_eq!(a.value_hash, expected_a);
    }

    #[test]
    fn env_entry_hash_is_unambiguous_against_name_value_concatenation() {
        // The `:` delimiter inside `sha256(name || ':' || value)` means
        // `("AB", "c")` hashes `"AB:c"`, never the same byte stream as
        // `("A", "Bc")` (`"A:Bc"`). This is the property we get for free over
        // a no-delimiter scheme and matters for any future caller that might
        // confuse a `name+value` byte stream with our hash input.
        let ab_c = McpEnvEntry::from_raw("AB", "c");
        let a_bc = McpEnvEntry::from_raw("A", "Bc");
        assert_ne!(
            ab_c.value_hash, a_bc.value_hash,
            "the `:` delimiter must prevent name/value boundary forgery"
        );
    }

    // -----------------------------------------------------------------------
    // Finding D — the per-server hash is collision-free: a separator-delimited
    // list scheme cannot distinguish `["a","b"]` from `["ab"]` or `["a\0b"]`;
    // length-prefixing every component makes the hash input unambiguous.
    // -----------------------------------------------------------------------

    #[test]
    fn content_hash_distinguishes_ambiguous_arg_lists() {
        // The three lists below would all feed the bytes `a` `b` to a
        // `\0`-joined hasher in different framings — they must hash distinctly.
        let mk = |args: Vec<&str>| McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: args.into_iter().map(String::from).collect(),
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let two = mk(vec!["a", "b"]);
        let one_joined = mk(vec!["ab"]);
        let one_with_nul = mk(vec!["a\0b"]);

        assert_ne!(
            two.content_hash(),
            one_joined.content_hash(),
            r#"["a","b"] must not hash the same as ["ab"]"#
        );
        assert_ne!(
            two.content_hash(),
            one_with_nul.content_hash(),
            r#"["a","b"] must not hash the same as ["a\0b"]"#
        );
        assert_ne!(
            one_joined.content_hash(),
            one_with_nul.content_hash(),
            r#"["ab"] must not hash the same as ["a\0b"]"#
        );
    }

    #[test]
    fn content_hash_distinguishes_ambiguous_tool_lists() {
        // The same collision class for the `tools` list.
        let mk = |tools: Vec<&str>| McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            },
            tools: tools.into_iter().map(String::from).collect(),
            source_config: ".mcp.json".into(),
        };
        let two = mk(vec!["a", "b"]);
        let one_joined = mk(vec!["ab"]);
        assert_ne!(
            two.content_hash(),
            one_joined.content_hash(),
            r#"tools ["a","b"] must not hash the same as ["ab"]"#
        );
    }

    #[test]
    fn content_hash_distinguishes_ambiguous_env_pairs() {
        // Length-prefixing also disambiguates env: a key/value boundary cannot
        // be forged. {"AB": "c"} vs {"A": "Bc"} must hash distinctly. Note that
        // both layers contribute here: the salted per-entry `value_hash` (via
        // `name + ':' + value`) already differs, AND the framed encoding into
        // the per-server hash adds length prefixes around `name` and
        // `value_hash` themselves.
        let mk = |key: &str, value: &str| McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw(key, value)],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        assert_ne!(
            mk("AB", "c").content_hash(),
            mk("A", "Bc").content_hash(),
            "env with key=AB value=c must not hash the same as key=A value=Bc"
        );
    }

    #[test]
    fn content_hash_arg_boundary_is_unambiguous_vs_command() {
        // The command/args boundary must also be framed: `command="ab"` with no
        // args must not collide with `command="a"` + args `["b"]`.
        let cmd_only = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "ab".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let cmd_and_arg = McpServerEntry {
            transport: McpTransport::Stdio {
                command: "a".into(),
                args: vec!["b".into()],
                env: vec![],
            },
            ..cmd_only.clone()
        };
        assert_ne!(
            cmd_only.content_hash(),
            cmd_and_arg.content_hash(),
            "the command/args boundary must be unambiguous"
        );
    }

    // -----------------------------------------------------------------------
    // Finding G — a URL transport's userinfo (HTTP Basic Auth) must not be
    // persisted in the lockfile. A URL declared as `https://user:token@host/`
    // is recorded as `https://host/` plus a salted `userinfo_hash` (same
    // scheme as `McpEnvEntry`). A URL with no userinfo serializes with
    // `userinfo_hash` omitted, so absence is structurally distinct from
    // presence. Folded into the per-server content hash, so a userinfo
    // change registers as drift.
    // -----------------------------------------------------------------------

    /// Credential-shaped (high-entropy, unique) URL userinfo probes. None of
    /// these byte sequences may appear in the rendered lockfile. They are
    /// distinctive on purpose so a substring scan over the rendered JSON
    /// cannot trip on incidental matches elsewhere (hashes, names, etc.).
    const URL_USERINFO_LEAK_PROBES: &[(&str, &str)] = &[
        // (declared URL, expected raw-credential substring)
        (
            "https://admin:ghp_supersecret_PAT_token_42@mcp.example.com/sse",
            "admin:ghp_supersecret_PAT_token_42",
        ),
        (
            "https://svc-account:DO_NOT_LEAK_xY7q@api.example.com:8443/v1/mcp",
            "svc-account:DO_NOT_LEAK_xY7q",
        ),
        (
            "https://bearer-only:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@host.example/sse",
            "bearer-only:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ];

    #[test]
    fn url_raw_userinfo_never_appears_in_rendered_lockfile() {
        // Plant servers whose URLs carry credential-shaped userinfo
        // (Basic Auth username:password). After rendering, NONE of the raw
        // userinfo byte sequences may show up. The salted hash is what is
        // persisted.
        let servers: Vec<McpServerEntry> = URL_USERINFO_LEAK_PROBES
            .iter()
            .enumerate()
            .map(|(i, (url, _))| {
                let server_name = format!("svc-{i}");
                let (redacted, hash) = redact_url_userinfo(&server_name, url);
                McpServerEntry {
                    name: server_name,
                    transport: McpTransport::Url {
                        url: redacted,
                        userinfo_hash: hash,
                    },
                    tools: vec![],
                    source_config: ".mcp.json".into(),
                }
            })
            .collect();
        let inventory = McpInventory {
            servers,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();

        for (declared_url, raw_credential) in URL_USERINFO_LEAK_PROBES {
            assert!(
                !rendered.contains(raw_credential),
                "raw userinfo {raw_credential:?} (from {declared_url:?}) leaked into the \
                 rendered lockfile:\n{rendered}"
            );
            // And the literal `@` userinfo boundary cannot appear inside an
            // https URL — every captured URL must have been redacted.
            assert!(
                !rendered.contains("@mcp.example.com"),
                "userinfo `@` boundary leaked into the rendered lockfile:\n{rendered}"
            );
            assert!(
                !rendered.contains("@api.example.com"),
                "userinfo `@` boundary leaked into the rendered lockfile:\n{rendered}"
            );
            assert!(
                !rendered.contains("@host.example"),
                "userinfo `@` boundary leaked into the rendered lockfile:\n{rendered}"
            );
        }
        // Every redacted URL exposes a `userinfo_hash` field — the wire
        // shape proof of the redaction.
        assert!(
            rendered.contains("\"userinfo_hash\""),
            "rendered lockfile must serialize a userinfo_hash per URL with credentials"
        );
    }

    #[test]
    fn url_with_userinfo_redacted_url_stored_in_lockfile() {
        // The redacted URL stored in the lockfile is exactly the source URL
        // with `user[:password]` stripped — host, port, path, and query all
        // preserved. Verify byte-for-byte against url::Url's normalized form
        // of the same userinfo-free URL.
        let (redacted, hash) = redact_url_userinfo(
            "svc",
            "https://user:token@host.example:8443/path/to/mcp?x=1",
        );
        assert_eq!(redacted, "https://host.example:8443/path/to/mcp?x=1");
        assert!(hash.is_some(), "userinfo present → hash is Some");

        // Username-only (no password) is still userinfo and is still redacted.
        let (redacted, hash) = redact_url_userinfo("svc", "https://only-user@host.example/path");
        assert_eq!(redacted, "https://host.example/path");
        assert!(hash.is_some());

        // Password-only (`:token@`) is also userinfo and is still redacted.
        let (redacted, hash) = redact_url_userinfo("svc", "https://:token-only@host.example/p");
        assert_eq!(redacted, "https://host.example/p");
        assert!(hash.is_some());
    }

    #[test]
    fn url_without_userinfo_stored_canonical_with_no_hash() {
        // A URL that carried no userinfo is stored in the canonical
        // `url::Url::as_str()` form (so the bytes match the shape the
        // userinfo-strip path produces) and `userinfo_hash` is None (so it
        // is omitted on serialization, not serialized as null). Two
        // categories of inputs:
        //   * `(input, expected_canonical)` for URLs `url::Url` accepts;
        //   * unparseable strings, which fall back to the byte-verbatim
        //     defensive branch.
        let parseable: &[(&str, &str)] = &[
            // Bare-host URLs gain the `url::Url`-default trailing `/`.
            ("https://x.example", "https://x.example/"),
            // URLs that are already canonical round-trip unchanged.
            ("https://mcp.example.com/sse", "https://mcp.example.com/sse"),
            (
                "https://host:8443/path/to/mcp?x=1&y=2",
                "https://host:8443/path/to/mcp?x=1&y=2",
            ),
            ("https://host.example/", "https://host.example/"),
        ];
        for (input, expected) in parseable {
            let (redacted, hash) = redact_url_userinfo("svc", input);
            assert_eq!(
                redacted, *expected,
                "a no-userinfo URL must canonicalize through url::Url::as_str(): \
                 input={input}"
            );
            assert!(
                hash.is_none(),
                "a no-userinfo URL must have userinfo_hash = None: {input}"
            );
        }

        // Unparseable strings are still held byte-verbatim — that is the
        // defensive fallback for inputs `url::Url` cannot parse.
        let (redacted, hash) = redact_url_userinfo("svc", "not a real url at all");
        assert_eq!(
            redacted, "not a real url at all",
            "an unparseable URL must fall through to the byte-verbatim branch"
        );
        assert!(hash.is_none());

        // And on serialization, `userinfo_hash` is OMITTED — not written as
        // `"userinfo_hash": null` — for a no-userinfo URL.
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Url {
                    url: "https://mcp.example.com/sse".into(),
                    userinfo_hash: None,
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();
        assert!(
            !rendered.contains("userinfo_hash"),
            "userinfo_hash must be omitted (not serialized as null) when no userinfo \
             is present:\n{rendered}"
        );
    }

    #[test]
    fn url_without_userinfo_canonicalization_pins_shape() {
        // Regression pin for the canonical-shape contract: a bare-host URL
        // **always** canonicalizes to the same trailing-`/` form as the
        // userinfo-stripped version. This is the load-bearing property
        // behind `mcp_verify_userinfo_removal_without_path_does_not_drift`:
        // without it, `mcp lock` stores `https://host/` and a later
        // userinfo-stripped `https://host` source would diff as
        // `UrlChanged` + `UserinfoRemoved` instead of just
        // `UserinfoRemoved`. Pinned explicitly so a future refactor cannot
        // silently bring back the byte-verbatim early-return.
        let (no_user, _) = redact_url_userinfo("s", "https://host");
        let (with_user, _) = redact_url_userinfo("s", "https://user:token@host");
        assert_eq!(no_user, "https://host/");
        assert_eq!(with_user, "https://host/");
        assert_eq!(
            no_user, with_user,
            "no-userinfo and userinfo-stripped forms of the same URL must be \
             byte-identical after redaction"
        );
    }

    #[test]
    fn url_normalized_empty_userinfo_treated_as_no_userinfo() {
        // `url::Url` parses `https://:@host/` and `https://@host/` by
        // discarding the empty userinfo. Our redaction observes
        // `username() == ""` and `password() == None`, treats it as the
        // no-userinfo case, and stores the canonical `url::Url::as_str()`
        // form (which is the userinfo-free equivalent) with no hash.
        for input in ["https://:@host.example/", "https://@host.example/"] {
            let (redacted, hash) = redact_url_userinfo("svc", input);
            assert_eq!(
                redacted, "https://host.example/",
                "an all-empty `:@` / `@` userinfo is normalized away by url::Url \
                 to the bare-host canonical form: input={input}"
            );
            assert!(
                hash.is_none(),
                "an all-empty `:@` / `@` userinfo is normalized away by url::Url \
                 and must be treated as no-userinfo: {input}"
            );
        }
    }

    #[test]
    fn url_userinfo_change_flips_per_server_hash() {
        // The drift property: same server name, same host/path, but a
        // different userinfo → the per-server content hash and therefore
        // the inventory hash must change. This is the same drift behavior
        // that an env-value change has for stdio.
        let mk = |declared_url: &str| {
            let (redacted, hash) = redact_url_userinfo("svc", declared_url);
            McpServerEntry {
                name: "svc".into(),
                transport: McpTransport::Url {
                    url: redacted,
                    userinfo_hash: hash,
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }
        };
        let with_token_a = mk("https://user:tokenA@host.example/sse");
        let with_token_b = mk("https://user:tokenB@host.example/sse");
        let no_token = mk("https://host.example/sse");

        // Token swap flips the content hash.
        assert_ne!(
            with_token_a.content_hash(),
            with_token_b.content_hash(),
            "swapping the userinfo must flip the per-server content hash (drift)"
        );
        // Adding/removing the credential entirely also flips it.
        assert_ne!(
            with_token_a.content_hash(),
            no_token.content_hash(),
            "adding/removing a credential must flip the per-server content hash"
        );

        // And it propagates to the inventory hash.
        let inv_a = McpInventory {
            servers: vec![with_token_a],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let inv_b = McpInventory {
            servers: vec![with_token_b],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        assert_ne!(
            McpLockfile::from_inventory(&inv_a).inventory_hash,
            McpLockfile::from_inventory(&inv_b).inventory_hash,
            "a userinfo change must surface as a different inventory hash"
        );
    }

    #[test]
    fn url_userinfo_hash_is_name_salted() {
        // The hash binds the MCP server's name to the userinfo, so the same
        // Basic Auth token under two different servers hashes differently —
        // a low-entropy userinfo (`u:p`) is not brute-forceable across
        // servers. Same scheme `McpEnvEntry::from_raw` uses, with the
        // server's name as the per-entry salt.
        let (_, a) = redact_url_userinfo("svc-a", "https://u:p@host.example/");
        let (_, b) = redact_url_userinfo("svc-b", "https://u:p@host.example/");
        assert_ne!(
            a, b,
            "the same userinfo under different server names must hash differently \
             (the server name acts as a per-entry salt)"
        );

        // And the hash is exactly sha256(server_name || ':' || userinfo).
        let expected_a = {
            let mut h = Sha256::new();
            h.update(b"svc-a:u:p");
            hex_lower(&h.finalize())
        };
        assert_eq!(a.as_deref(), Some(expected_a.as_str()));

        // Two different userinfo strings under the SAME server name also
        // hash differently — the natural inner-collision-free property.
        let (_, c) = redact_url_userinfo("svc-a", "https://u:p2@host.example/");
        assert_ne!(
            a, c,
            "two different userinfos under the same server name must hash differently"
        );
    }

    #[test]
    fn url_userinfo_hash_delimiter_prevents_boundary_forgery() {
        // The `:` delimiter inside `sha256(server_name || ':' || userinfo)`
        // means `("AB", "c")` hashes `"AB:c"`, never the same byte stream
        // as `("A", "Bc")` (`"A:Bc"`). This is the same property that
        // motivates the `:` delimiter inside `McpEnvEntry::from_raw`.
        let (_, a) = redact_url_userinfo("AB", "https://c@host.example/");
        let (_, b) = redact_url_userinfo("A", "https://Bc@host.example/");
        assert_ne!(
            a, b,
            "the `:` delimiter must prevent server/userinfo boundary forgery"
        );
    }

    #[test]
    fn parse_mcp_config_url_with_userinfo_is_redacted() {
        // End-to-end through the JSON parser: a config that declares a URL
        // with Basic Auth produces a parsed entry whose `url` field has the
        // userinfo stripped, whose `userinfo_hash` is the expected
        // name-salted SHA-256, AND whose rendered lockfile does not contain
        // the raw userinfo bytes anywhere.
        let secret = "admin:ghp_PARSED_LEAK_PROBE_DONOTLEAK";
        let content = format!(
            r#"{{
                "mcpServers": {{
                    "github": {{
                        "url": "https://{secret}@mcp.example.com/sse",
                        "tools": ["search"]
                    }}
                }}
            }}"#
        );
        let entries = parse_mcp_config(&content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "github");
        match &entries[0].transport {
            McpTransport::Url { url, userinfo_hash } => {
                assert_eq!(
                    url, "https://mcp.example.com/sse",
                    "the stored URL must have the userinfo stripped"
                );
                let expected = {
                    let mut h = Sha256::new();
                    h.update(b"github:");
                    h.update(secret.as_bytes());
                    hex_lower(&h.finalize())
                };
                assert_eq!(
                    userinfo_hash.as_deref(),
                    Some(expected.as_str()),
                    "userinfo_hash must be sha256(server_name || ':' || userinfo)"
                );
            }
            other => panic!("expected Url transport, got {other:?}"),
        }

        // The rendered lockfile descending from this parse must not carry
        // the raw userinfo bytes anywhere.
        let inventory = McpInventory {
            servers: entries,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();
        assert!(
            !rendered.contains(secret),
            "raw userinfo leaked from parse_mcp_config -> McpLockfile::render():\n{rendered}"
        );
    }

    #[test]
    fn parse_mcp_config_url_no_userinfo_is_unchanged() {
        // The common path: a URL declared with NO userinfo is stored in the
        // canonical `url::Url::as_str()` form (which for an already-canonical
        // input is byte-identical), and `userinfo_hash` is None (and
        // therefore omitted from the serialized lockfile).
        let content = r#"{
            "mcpServers": {
                "remote": {
                    "url": "https://mcp.example.com/sse",
                    "tools": ["search"]
                }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid config");
        match &entries[0].transport {
            McpTransport::Url { url, userinfo_hash } => {
                assert_eq!(url, "https://mcp.example.com/sse");
                assert!(userinfo_hash.is_none());
            }
            other => panic!("expected Url transport, got {other:?}"),
        }
    }

    #[test]
    fn parse_mcp_config_url_unparseable_is_held_verbatim() {
        // A non-URL-shaped string is not safely parseable — we refuse to
        // mangle it (we cannot identify the userinfo boundary), so it is
        // stored verbatim and `userinfo_hash` is None. The captured URL
        // still flows through the lockfile (so a later `mcp verify` can
        // see the oddity).
        let content = r#"{ "mcpServers": { "weird": { "url": "not://a real url" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid JSON");
        match &entries[0].transport {
            McpTransport::Url { url, userinfo_hash } => {
                // The string is held verbatim — including the `not://`
                // scheme, since `url::Url` may or may not accept it across
                // versions. The important property is "we did not panic
                // and we did not invent a hash for an unparseable URL".
                assert_eq!(url, "not://a real url");
                assert!(userinfo_hash.is_none());
            }
            other => panic!("expected Url transport, got {other:?}"),
        }
    }

    #[test]
    fn lockfile_with_userinfo_round_trips() {
        // A lockfile carrying a URL transport with `userinfo_hash` must
        // serialize and parse back identically — the new schema field
        // round-trips. The `userinfo_hash` is preserved across the
        // serialize/deserialize cycle (same byte-for-byte hex string).
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Url {
                    url: "https://host.example/sse".into(),
                    userinfo_hash: Some(
                        "abc123def456abc123def456abc123def456abc123def456abc123def456abc1".into(),
                    ),
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let lock = McpLockfile::from_inventory(&inventory);
        let parsed: McpLockfile = serde_json::from_str(&lock.render())
            .expect("lockfile with userinfo_hash must round-trip");
        assert_eq!(parsed, lock);
    }

    // -----------------------------------------------------------------------
    // Chunk 2 — drift detection.
    //
    // The drift core is what `tirith mcp verify` and `tirith mcp diff`
    // consume, and what the new `RuleId::McpServerDrift` rule fires on. The
    // tests below cover every category from the chunk-2 brief: added,
    // removed, transport-change, env added/removed/value-change,
    // tools-change, userinfo-change. Plus the fast-path: an unchanged
    // inventory has empty drift.
    // -----------------------------------------------------------------------

    fn mk_inventory(servers: Vec<McpServerEntry>) -> McpInventory {
        McpInventory {
            servers,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        }
    }

    fn stdio_server(name: &str, command: &str) -> McpServerEntry {
        McpServerEntry {
            name: name.into(),
            transport: McpTransport::Stdio {
                command: command.into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        }
    }

    #[test]
    fn drift_is_empty_when_inventory_matches_lockfile() {
        // Headline fast-path: same inventory, same hash, no drift.
        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv);
        let drifts = compute_drift(&inv, &lock);
        assert!(
            drifts.is_empty(),
            "no-drift case must yield empty: {drifts:?}"
        );
    }

    #[test]
    fn drift_detects_server_added() {
        let prev = mk_inventory(vec![stdio_server("a", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        assert!(matches!(
            &drifts[0],
            McpDrift::Added { name, .. } if name == "b"
        ));
    }

    #[test]
    fn drift_added_carries_new_server_tools() {
        // The Added drift surfaces the new server's tool list so a policy
        // gate (`scan.mcp_allowed_tools`) can inspect what the brand-new
        // server exposes — mirroring `tools_added` on Changed. Without
        // this, an Added server smuggling a disallowed tool would slip
        // through the severity ladder (the asymmetry CodeRabbit flagged).
        let prev = mk_inventory(vec![stdio_server("a", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![
            stdio_server("a", "node"),
            McpServerEntry {
                tools: vec!["read_file".into(), "write_file".into()],
                ..stdio_server("b", "node")
            },
        ]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Added { name, tools, .. } => {
                assert_eq!(name, "b");
                // Tools are surfaced in their canonical (sorted) order —
                // exactly the form `McpServerEntry::tools` carries.
                assert_eq!(
                    tools,
                    &vec!["read_file".to_string(), "write_file".to_string()],
                    "Added drift must carry the new server's declared tools",
                );
            }
            other => panic!("expected Added with tools, got {other:?}"),
        }
    }

    #[test]
    fn drift_added_with_no_tools_has_empty_tools_vec() {
        // A new server that declares no tools yields an empty `tools` vec
        // (not absent / null) — `compute_drift` always surfaces the list,
        // even when it's empty, so consumers can branch on length without
        // an Option dance.
        let prev = mk_inventory(vec![stdio_server("a", "node")]);
        let lock = McpLockfile::from_inventory(&prev);
        let cur = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let drifts = compute_drift(&cur, &lock);
        match &drifts[0] {
            McpDrift::Added { tools, .. } => {
                assert!(
                    tools.is_empty(),
                    "no-tools-declared server must yield an empty Added.tools vec, got {tools:?}",
                );
            }
            other => panic!("expected Added, got {other:?}"),
        }
    }

    #[test]
    fn drift_added_serialization_omits_empty_tools_field() {
        // The schema change is structural-only — when `tools` is empty
        // the field is omitted from JSON, so a drift document produced
        // by the previous version (which had no field) round-trips
        // bit-identically into the new `Added` shape with `tools: []`.
        // This is also the wire-shape proof that the lockfile schema
        // (`format_version` = 4) is unaffected by this change.
        let added = McpDrift::Added {
            name: "newcomer".into(),
            source_config: ".mcp.json".into(),
            tools: vec![],
        };
        let json = serde_json::to_string(&added).unwrap();
        assert!(
            !json.contains("\"tools\""),
            "an empty tools list must be omitted from JSON: {json}"
        );

        let with_tools = McpDrift::Added {
            name: "newcomer".into(),
            source_config: ".mcp.json".into(),
            tools: vec!["read".into()],
        };
        let json = serde_json::to_string(&with_tools).unwrap();
        assert!(
            json.contains("\"tools\""),
            "a non-empty tools list must be present in JSON: {json}"
        );

        // And an older drift document (without the `tools` field) parses
        // cleanly with `tools` defaulting to an empty vec — the
        // structural extension is backwards-compatible at the JSON layer.
        let legacy = r#"{"kind":"added","name":"old","source_config":".mcp.json"}"#;
        let parsed: McpDrift = serde_json::from_str(legacy).expect("legacy Added must parse");
        match parsed {
            McpDrift::Added {
                name,
                source_config,
                tools,
            } => {
                assert_eq!(name, "old");
                assert_eq!(source_config, ".mcp.json");
                assert!(
                    tools.is_empty(),
                    "missing tools field must default to empty: {tools:?}"
                );
            }
            other => panic!("expected Added, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_server_removed() {
        let prev = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("a", "node")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        assert!(matches!(
            &drifts[0],
            McpDrift::Removed { name, .. } if name == "b"
        ));
    }

    #[test]
    fn drift_added_and_removed_sort_deterministically() {
        // Removed sorts before Added. Within each bucket, sort by name.
        let prev = mk_inventory(vec![stdio_server("zeta", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![
            stdio_server("alpha", "node"),
            stdio_server("beta", "node"),
        ]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 3);
        // Removed first.
        assert!(matches!(&drifts[0], McpDrift::Removed { name, .. } if name == "zeta"));
        // Then Added, by name.
        assert!(matches!(&drifts[1], McpDrift::Added { name, .. } if name == "alpha"));
        assert!(matches!(&drifts[2], McpDrift::Added { name, .. } if name == "beta"));
    }

    #[test]
    fn drift_detects_transport_kind_change() {
        let prev = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.name, "s");
                assert_eq!(entry.transport_changes.len(), 1);
                assert!(matches!(
                    &entry.transport_changes[0],
                    McpTransportChange::KindChanged { previous, current }
                        if previous == "stdio" && current == "url"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_command_change() {
        let prev = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("s", "deno")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::CommandChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_args_change() {
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["a.js".into()],
                env: vec![],
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["b.js".into()],
                env: vec![],
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::ArgsChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_env_added() {
        let prev = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "v")],
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::EnvChanged)));
                assert_eq!(entry.env_changes.len(), 1);
                assert!(matches!(
                    &entry.env_changes[0],
                    McpEnvChange::Added { name } if name == "API_TOKEN"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_env_removed() {
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "v")],
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("s", "node")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.env_changes.len(), 1);
                assert!(matches!(
                    &entry.env_changes[0],
                    McpEnvChange::Removed { name } if name == "API_TOKEN"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_env_value_hash_change() {
        // The headline drift property: a rotated credential surfaces as a
        // value-hash change. The raw value never appears in the drift —
        // only the variable's NAME does — exactly as it never appears in
        // the lockfile.
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "old-credential-bytes")],
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "new-credential-bytes")],
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.env_changes.len(), 1);
                assert!(matches!(
                    &entry.env_changes[0],
                    McpEnvChange::ValueHashChanged { name } if name == "API_TOKEN"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        // And no raw credential bytes leak into the drift's serialized form.
        let serialized = serde_json::to_string(&drifts).unwrap();
        assert!(!serialized.contains("old-credential-bytes"));
        assert!(!serialized.contains("new-credential-bytes"));
    }

    #[test]
    fn drift_detects_tools_added_and_removed() {
        let prev = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "c".into()],
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.tools_change, Some(McpToolsChangeKind::Set));
                assert_eq!(entry.tools_added, vec!["c".to_string()]);
                assert_eq!(entry.tools_removed, vec!["b".to_string()]);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_tools_only_added() {
        let prev = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.tools_change, Some(McpToolsChangeKind::Added));
                assert_eq!(entry.tools_added, vec!["b".to_string()]);
                assert!(entry.tools_removed.is_empty());
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_tools_only_removed() {
        let prev = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into()],
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.tools_change, Some(McpToolsChangeKind::Removed));
                assert!(entry.tools_added.is_empty());
                assert_eq!(entry.tools_removed, vec!["b".to_string()]);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_userinfo_added() {
        // Prev: URL with no userinfo. Cur: URL with userinfo (a credential
        // was added in the source config since the lockfile was taken).
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://host.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let (redacted, hash) = redact_url_userinfo("s", "https://user:token@host.example/sse");
        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: redacted,
                userinfo_hash: hash,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UserinfoAdded)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_userinfo_removed() {
        let (redacted, hash) = redact_url_userinfo("s", "https://user:token@host.example/sse");
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: redacted,
                userinfo_hash: hash,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://host.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UserinfoRemoved)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_userinfo_swapped() {
        let (red_a, hash_a) = redact_url_userinfo("s", "https://user:tokenA@host.example/sse");
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: red_a,
                userinfo_hash: hash_a,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let (red_b, hash_b) = redact_url_userinfo("s", "https://user:tokenB@host.example/sse");
        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: red_b,
                userinfo_hash: hash_b,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UserinfoSwapped)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        // Drift carries no raw userinfo bytes — only the change classifier.
        let serialized = serde_json::to_string(&drifts).unwrap();
        assert!(!serialized.contains("tokenA"));
        assert!(!serialized.contains("tokenB"));
    }

    #[test]
    fn drift_detects_url_bytes_changed() {
        // Same kind, no userinfo on either side, URL host differs.
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://old.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://new.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UrlChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_sort_is_deterministic_across_inputs() {
        // The same logical drift produced from two different input orderings
        // must serialize identically.
        let prev = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur1 = mk_inventory(vec![stdio_server("a", "node"), stdio_server("c", "node")]);
        let cur2 = mk_inventory(vec![stdio_server("c", "node"), stdio_server("a", "node")]);
        let d1 = compute_drift(&cur1, &lock);
        let d2 = compute_drift(&cur2, &lock);
        assert_eq!(d1, d2);
    }

    #[test]
    fn drift_silent_when_unchanged_server_moves_between_configs() {
        // `content_hash` deliberately excludes `source_config` — chunk 1's
        // documented invariant — and `inventory_hash` is the ordered
        // concatenation of `content_hash`es. So moving an unchanged server
        // from one config file to another does NOT register as drift: the
        // *content* is the same, only the location changed, and the chunk-1
        // schema treated that as a non-event. The fast-path inventory_hash
        // comparison cleanly catches this and short-circuits to no drift.
        let prev = mk_inventory(vec![McpServerEntry {
            source_config: ".mcp.json".into(),
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            source_config: ".vscode/mcp.json".into(),
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert!(
            drifts.is_empty(),
            "moving an unchanged server between configs must be silent: {drifts:?}"
        );
    }

    #[test]
    fn drift_walk_handles_same_name_in_different_configs() {
        // A repo can legitimately declare *two* servers with the same name
        // in different config files (the lockfile sorts by
        // `(name, source_config)` to handle this). When one of those servers
        // changes its transport, only the changed entry surfaces as drift —
        // the untouched twin stays clean.
        let prev = mk_inventory(vec![
            McpServerEntry {
                source_config: ".mcp.json".into(),
                ..stdio_server("s", "node")
            },
            McpServerEntry {
                source_config: ".vscode/mcp.json".into(),
                ..stdio_server("s", "node")
            },
        ]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![
            // .mcp.json copy: unchanged.
            McpServerEntry {
                source_config: ".mcp.json".into(),
                ..stdio_server("s", "node")
            },
            // .vscode copy: command rotated.
            McpServerEntry {
                source_config: ".vscode/mcp.json".into(),
                ..stdio_server("s", "deno")
            },
        ]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.name, "s");
                assert_eq!(entry.source_config, ".vscode/mcp.json");
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::CommandChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn load_lockfile_returns_not_found_when_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("absent.lock");
        let err = load_lockfile(&missing).unwrap_err();
        assert_eq!(err, McpLockLoadError::NotFound);
    }

    #[test]
    fn load_lockfile_returns_parse_error_on_malformed_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MCP_LOCK_FILENAME);
        fs::write(&path, "not json at all").unwrap();
        let err = load_lockfile(&path).unwrap_err();
        assert!(matches!(err, McpLockLoadError::Parse { .. }));
    }

    #[test]
    fn parse_error_does_not_carry_serde_json_message() {
        // Privacy invariant: `McpLockLoadError::Parse` carries ONLY
        // line/column — it must not echo the `serde_json::Error`
        // message, which can include the offending JSON value (e.g.
        // `invalid type: string "...", expected ...`). A malformed
        // `.tirith/mcp.lock` whose body looks credential-shaped must
        // not leak that body into the parse-error variant or its
        // `Display` rendering.
        let secret = "ghp_PARSE_ERROR_LEAK_PROBE_DONOTLEAK";
        // Build content that is valid JSON syntax but the WRONG TYPE
        // for the lockfile schema. serde_json's Display for this
        // failure mode is the one documented to echo the value:
        // `invalid type: string "...", expected struct ...`.
        let bad = format!(r#""{secret}""#);
        let err = parse_lockfile(&bad).unwrap_err();
        match err {
            McpLockLoadError::Parse { line, column } => {
                // Sanity: line/column are real positions, not zeros
                // forged from a stripped message.
                let _ = (line, column);
            }
            other => panic!("expected Parse, got {other:?}"),
        }
        // The Display rendering must also be free of the probe bytes.
        let displayed = parse_lockfile(&bad).unwrap_err().to_string();
        assert!(
            !displayed.contains(secret),
            "secret leaked into McpLockLoadError::Display: {displayed}"
        );
        assert!(
            !displayed.contains("invalid type"),
            "raw serde_json message leaked into Display: {displayed}"
        );
        assert!(
            !displayed.contains("expected"),
            "raw serde_json message leaked into Display: {displayed}"
        );
    }

    #[test]
    fn parse_lockfile_sorts_servers_for_compute_drift() {
        // Defensive: `compute_drift`'s slow-path merge walk requires
        // `lock.servers` to be sorted by `(name, source_config)`. A
        // hand-edited or merge-resolved lockfile with out-of-order
        // servers must still drift-compare correctly — same drift
        // report as a properly-sorted lockfile, and zero drift when
        // the only difference is order.
        let ordered = mk_inventory(vec![
            stdio_server("alpha", "node"),
            stdio_server("beta", "node"),
            stdio_server("zeta", "node"),
        ]);
        let lock_sorted = McpLockfile::from_inventory(&ordered);
        let lock_sorted_json = lock_sorted.render();

        // Build a deliberately *reversed* on-disk lockfile by serializing
        // a hand-built struct whose `servers` are in reverse name order.
        // (We bypass `from_inventory` so the bytes hit disk unsorted —
        // simulating a hand-edited or merge-conflict-resolved lockfile.)
        let mut unsorted = lock_sorted.clone();
        unsorted.servers.reverse();
        let lock_unsorted_json = serde_json::to_string_pretty(&unsorted).unwrap() + "\n";
        // The on-disk bytes really are different.
        assert_ne!(
            lock_sorted_json, lock_unsorted_json,
            "the unsorted serialization must differ from the sorted one"
        );

        // After parsing, both lockfiles must compare equal because
        // `parse_lockfile` sorts. Equality of `McpLockfile` includes
        // the `servers` Vec ordering.
        let parsed_sorted = parse_lockfile(&lock_sorted_json).expect("sorted lockfile parses");
        let parsed_unsorted =
            parse_lockfile(&lock_unsorted_json).expect("unsorted lockfile parses");
        assert_eq!(
            parsed_sorted, parsed_unsorted,
            "parse_lockfile must sort servers so two lockfiles that differ \
             only in server order compare equal"
        );

        // Drift against the same inventory: both lockfiles must yield
        // zero drift — the inventory genuinely matches.
        let cur_drifts_sorted = compute_drift(&ordered, &parsed_sorted);
        let cur_drifts_unsorted = compute_drift(&ordered, &parsed_unsorted);
        assert!(
            cur_drifts_sorted.is_empty(),
            "sorted lockfile vs identical inventory must yield zero drift: \
             {cur_drifts_sorted:?}"
        );
        assert!(
            cur_drifts_unsorted.is_empty(),
            "unsorted lockfile vs identical inventory must ALSO yield zero \
             drift after parse-time sorting; without the sort the merge \
             walk would emit spurious Added/Removed: {cur_drifts_unsorted:?}"
        );

        // And when a real drift is introduced, both lockfiles report
        // the *same* drift — the merge walk is not confused by the
        // (parsed-away) on-disk order.
        let drifted_current = mk_inventory(vec![
            stdio_server("alpha", "node"),
            // "beta" removed.
            stdio_server("zeta", "deno"), // command rotated.
        ]);
        let d_sorted = compute_drift(&drifted_current, &parsed_sorted);
        let d_unsorted = compute_drift(&drifted_current, &parsed_unsorted);
        assert_eq!(
            d_sorted, d_unsorted,
            "drift report must be identical regardless of on-disk lockfile order"
        );
        // Sanity-check that real drift is detected, not silently swallowed.
        assert!(
            d_sorted
                .iter()
                .any(|d| matches!(d, McpDrift::Removed { name, .. } if name == "beta")),
            "expected a Removed drift for `beta`: {d_sorted:?}"
        );
        assert!(
            d_sorted
                .iter()
                .any(|d| matches!(d, McpDrift::Changed(entry) if entry.name == "zeta")),
            "expected a Changed drift for `zeta`: {d_sorted:?}"
        );
    }

    #[test]
    fn load_lockfile_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MCP_LOCK_FILENAME);
        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv);
        fs::write(&path, lock.render()).unwrap();
        let loaded = load_lockfile(&path).expect("round-trip must succeed");
        assert_eq!(loaded, lock);
    }
}

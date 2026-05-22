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
//!    a hash over the whole inventory. Servers are sorted by name so the
//!    lockfile is stable and diff-friendly — a future `mcp verify` / `mcp diff`
//!    (chunk 2) can diff two lockfiles cleanly.
//!
//! **Repo-local only.** Discovery never walks into `~/.claude/` or any other
//! user-level configuration directory — only files inside the given repo root
//! are inventoried. This is the same scoping decision the policy system makes
//! with org-level lists.
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
pub const MCP_LOCK_FORMAT_VERSION: u32 = 1;

/// Basename of the lockfile, written under `<repo_root>/.tirith/`.
pub const MCP_LOCK_FILENAME: &str = "mcp.lock";

/// How an MCP server is reached. A server declares **either** a remote URL
/// (`url` transport) **or** a local subprocess (`command` + `args`); the two
/// are mutually exclusive in every known config shape, so this is an enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransport {
    /// A network-reachable MCP server (HTTP / SSE / streamable-HTTP). The `url`
    /// is stored verbatim — canonicalization (if any) is the diff layer's job.
    Url { url: String },
    /// A local MCP server spawned as a subprocess.
    Stdio {
        /// The executable to run.
        command: String,
        /// Arguments passed to the executable, in declared order.
        #[serde(default)]
        args: Vec<String>,
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
    /// A stable per-server content hash over name + transport + tools. Two
    /// entries hash identically iff they declare the same server the same way,
    /// so a future `mcp diff` can detect a changed server by hash alone.
    ///
    /// `source_config` is deliberately **excluded**: moving an unchanged server
    /// definition between two config files must not register as drift.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"mcp-server\0");
        hasher.update(self.name.as_bytes());
        hasher.update(b"\0");
        match &self.transport {
            McpTransport::Url { url } => {
                hasher.update(b"url\0");
                hasher.update(url.as_bytes());
            }
            McpTransport::Stdio { command, args } => {
                hasher.update(b"stdio\0");
                hasher.update(command.as_bytes());
                for arg in args {
                    hasher.update(b"\0arg\0");
                    hasher.update(arg.as_bytes());
                }
            }
            McpTransport::Unknown => {
                hasher.update(b"unknown\0");
            }
        }
        for tool in &self.tools {
            hasher.update(b"\0tool\0");
            hasher.update(tool.as_bytes());
        }
        hex_lower(&hasher.finalize())
    }
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
    /// inventory always yields the same lockfile.
    pub fn from_inventory(inventory: &McpInventory) -> Self {
        let servers: Vec<McpLockServer> = inventory
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
/// path for determinism. Only regular files are returned. Discovery is strictly
/// repo-local: every probed path is a fixed relative path joined onto
/// `repo_root`, so it can never escape the repository.
pub fn discover_mcp_configs(repo_root: &Path) -> Vec<(PathBuf, String)> {
    let mut found: Vec<(PathBuf, String)> = Vec::new();
    for rel in MCP_CONFIG_RELATIVE_PATHS {
        let abs = repo_root.join(rel);
        if abs.is_file() {
            found.push((abs, (*rel).to_string()));
        }
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
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

        let transport = parse_transport(obj);
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
fn parse_transport(obj: &serde_json::Map<String, serde_json::Value>) -> McpTransport {
    if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
        return McpTransport::Url {
            url: url.to_string(),
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
        return McpTransport::Stdio {
            command: command.to_string(),
            args,
        };
    }

    McpTransport::Unknown
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
            }
        );
        assert!(fs_entry.tools.is_empty());
        assert_eq!(fs_entry.source_config, ".mcp.json");

        let remote = entries.iter().find(|e| e.name == "remote").unwrap();
        assert_eq!(
            remote.transport,
            McpTransport::Url {
                url: "https://mcp.example.com/sse".to_string(),
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
        // higher-risk surface) is the one recorded.
        let content =
            r#"{ "mcpServers": { "both": { "url": "https://x.example", "command": "node" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        assert_eq!(
            entries[0].transport,
            McpTransport::Url {
                url: "https://x.example".to_string(),
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
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let changed = McpServerEntry {
            transport: McpTransport::Url {
                url: "https://x.example".into(),
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
                    },
                    tools: vec![],
                    source_config: ".mcp.json".into(),
                },
                McpServerEntry {
                    name: "alpha".into(),
                    transport: McpTransport::Url {
                        url: "https://a.example".into(),
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
}

# `tirith doctor` modes (full vs `--quick`)

`tirith doctor` has two report depths:

- **Full** (`tirith doctor`, the default) — a complete installation and
  configuration diagnostic: shell/hook state, policy discovery, threat-DB
  status, anomaly-baseline status, detection-gap analysis from the audit log,
  shadow-binary detection, and (on Unix) the bash enter-mode capability cache.
  Some of these probes are deliberately expensive: they parse the audit log
  (which can grow to tens of MB), deserialize the threat database, read the
  baseline store, and walk `PATH`.
- **Quick** (`tirith doctor --quick`) — a fast, read-only status snapshot that
  reports only what a polling integration needs. It skips every expensive probe
  the full report runs, so it is cheap enough to poll on a short interval.

The full report's behavior, fields, and output are unchanged by the addition of
`--quick`.

## When to use `--quick`

`--quick` exists for integrations that need a frequently-refreshed protection
status without paying for the full diagnostic — most notably the VS Code
extension, which polls `tirith doctor --quick --format json` roughly every 30
seconds.

`--quick` is **read-only**: it never materializes hooks, downloads anything, or
mutates state. It is **safe to poll** at a short interval.

`--quick` is compatible with `--format json` (and the hidden `--json` alias).
It is mutually exclusive with the mutating and full-report flags: `--fix`,
`--reset-bash-safe-mode`, `--simulate-enter`, `--compat`, and `--bundle`.

## What `--quick` skips

`--quick` does **not** run any of these full-report probes:

| Skipped probe          | What the full report does with it                      |
| ---------------------- | ------------------------------------------------------ |
| Audit-log analysis     | Reads and parses `data_dir()/log.jsonl` (can be large) |
| Threat-DB status       | Loads and deserializes the threat database             |
| Anomaly-baseline status| Reads the baseline observation store                   |
| Shadow-binary check    | Walks `PATH` looking for other `tirith` binaries       |
| Bash enter-capability  | Reads the cached bash enter-mode self-test verdict     |

Because none of these run, `--quick` returns quickly and performs no large file
reads, no deserialization, and no `PATH` walk.

## `--quick --format json` output

The JSON object is intentionally minimal and stable — exactly these fields:

| field             | type             | meaning                                                                                                                                                                                                       |
| ----------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version`  | integer          | Version of this payload's shape. Currently `1`. Bumped only on a breaking change to the field set or meaning.                                                                                                  |
| `protection_mode` | string           | Live protection mode. `doctor --quick` is an external process, so it reads the hook-EXPORTED `TIRITH_BASH_EFFECTIVE_PROTECTION` first (the bash hook re-exports it for exactly this reason) and falls back to `TIRITH_STATUS`, which the hooks deliberately leave non-exported. One of `guarded`, `warn-only`, `degraded`, or `off`; an unrecognized value is passed through verbatim. (`off` here can also mean "a configured hook whose live mode this external process cannot see" — `tirith status` reports that case as still-protected.) |
| `policy_path_used`| string or `null` | The single policy file the engine would load for the current directory, or `null` when none is discovered. Existence-based discovery only — never a network fetch.                                            |
| `hook_configured` | boolean          | Whether the tirith shell hook is configured in the detected shell's profile.                                                                                                                                   |

Example:

```json
{
  "schema_version": 1,
  "protection_mode": "guarded",
  "policy_path_used": "/path/to/repo/.tirith/policy.yaml",
  "hook_configured": true
}
```

### `protection_mode` values

`protection_mode` uses the same vocabulary as `tirith prompt-status` (see
`docs/prompt-integration.md`), derived from the hook's effective-protection
signal — `TIRITH_BASH_EFFECTIVE_PROTECTION` first, falling back to
`TIRITH_STATUS`. Both carry the same value set:

| hook signal value   | `protection_mode` | meaning                                            |
| ------------------- | ----------------- | -------------------------------------------------- |
| `blocks`            | `guarded`         | A dangerous command is stopped before it runs.     |
| `warn-only`         | `warn-only`       | Commands are checked but not blocked.              |
| `degraded`          | `degraded`        | Protection was downgraded to warn-only this session.|
| `off`, empty, unset | `off`             | No live mode visible to this external process / protection off.|
| (any other value)   | (verbatim)        | Forwarded unchanged for forward compatibility.     |

`protection_mode` reflects the live hook state of the process that invoked
`doctor`. A non-interactive subshell with no tirith hook sourced reports `off`.

## `--quick` human output

Without `--format json`, `--quick` prints a short 2-3 line summary instead of
the full diagnostic:

```text
  protection:   guarded
  hook:         configured
  policy:       /path/to/repo/.tirith/policy.yaml
```

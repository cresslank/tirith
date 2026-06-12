//! `tirith pending`: list, resolve, and export pending decisions.
//!
//! This is a thin CLI over `tirith_core::pending`. It never runs a restore:
//! for a rollback it marks the entry and prints the exact
//! `tirith checkpoint restore <id>` command for the operator to run.

use std::path::PathBuf;

use tirith_core::pending::{self, PendingStatus};

/// List unresolved pending decisions as a human table or JSON.
pub fn list(format_json: bool) -> i32 {
    let entries = pending::list_unresolved();
    if format_json {
        match serde_json::to_string_pretty(&entries) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("tirith pending list: JSON serialization failed: {e}");
                2
            }
        }
    } else {
        if entries.is_empty() {
            println!("No pending decisions.");
            return 0;
        }
        println!(
            "{id:<10} {created:<26} {source:<11} {severity:<9} Command",
            id = "ID",
            created = "Created",
            source = "Source",
            severity = "Severity"
        );
        println!("{}", "-".repeat(90));
        for e in &entries {
            let source = format!("{:?}", e.source).to_lowercase();
            let command = e.command_redacted.chars().take(32).collect::<String>();
            println!(
                "{:<10} {:<26} {:<11} {:<9} {}",
                e.id, e.created_at, source, e.severity, command
            );
        }
        println!("\n{} pending decision(s)", entries.len());
        0
    }
}

/// Resolve a pending decision. `action` is one of keep|rollback|approve|deny.
///
/// For `rollback`, the entry is marked `RolledBack` and, if a
/// `refs.checkpoint_id` is present, the exact restore command is printed for
/// the operator to run. This handler never performs the restore itself.
pub fn resolve(id: &str, action: &str, reason: Option<String>) -> i32 {
    let status = match action {
        "keep" => PendingStatus::Kept,
        "rollback" => PendingStatus::RolledBack,
        "approve" => PendingStatus::Approved,
        "deny" => PendingStatus::Denied,
        other => {
            eprintln!(
                "tirith pending resolve: unknown action '{other}' (expected keep|rollback|approve|deny)"
            );
            return 2;
        }
    };

    // For rollback, surface the restore command (if any) before mutating, so
    // the operator sees it even when the entry is already resolved.
    let checkpoint_id = if action == "rollback" {
        pending::load_all()
            .into_iter()
            .find(|d| d.id == id)
            .and_then(|d| d.refs.get("checkpoint_id").cloned())
    } else {
        None
    };

    match pending::resolve(id, status, reason, Some("cli".to_string())) {
        Ok(true) => {
            println!("Resolved {id} ({action}).");
            if action == "rollback" {
                match checkpoint_id {
                    Some(cp) => {
                        println!("To roll back, run:");
                        println!("  tirith checkpoint restore {cp}");
                    }
                    None => {
                        println!(
                            "No checkpoint reference recorded; nothing to restore automatically."
                        );
                    }
                }
            }
            0
        }
        Ok(false) => {
            eprintln!("tirith pending resolve: '{id}' not found or already resolved.");
            1
        }
        Err(e) => {
            eprintln!("tirith pending resolve: {e}");
            2
        }
    }
}

/// Export all pending decisions as pretty JSON to a file or stdout.
pub fn export(output: Option<PathBuf>) -> i32 {
    let all = pending::load_all();
    let json = match serde_json::to_string_pretty(&all) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith pending export: JSON serialization failed: {e}");
            return 2;
        }
    };

    match output {
        Some(path) => match std::fs::write(&path, json.as_bytes()) {
            Ok(()) => {
                println!(
                    "Wrote {} pending decision(s) to {}",
                    all.len(),
                    path.display()
                );
                0
            }
            Err(e) => {
                eprintln!("tirith pending export: write {}: {e}", path.display());
                2
            }
        },
        None => {
            println!("{json}");
            0
        }
    }
}

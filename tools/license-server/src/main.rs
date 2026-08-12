mod config;
mod db;
mod error;
mod routes;
mod sign;
mod state;
mod webhook_verify;

use std::sync::Arc;
use std::time::Duration;

use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use config::Config;
use db::Db;
use sign::TokenSigner;
use state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Fail-fast: Config::from_env panics if any required var is missing.
    let config = Config::from_env();
    let port = config.port;

    let db = Db::open(&config.database_url).expect("failed to open database");

    let signer = TokenSigner::from_hex_seed(&config.ed25519_seed_hex, config.kid.clone())
        .expect("failed to init token signer");

    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .build()
        .expect("failed to build HTTP client");

    let state = AppState {
        db: db.clone(),
        signer: Arc::new(signer),
        config: Arc::new(config.clone()),
        http_client: http_client.clone(),
    };

    spawn_cleanup_task(db.clone());
    spawn_dead_letter_retry_task(db.clone(), Arc::new(config.clone()), http_client);
    spawn_backup_task(config.clone());

    // No permissive CORS. Receipts (`/receipt/lookup`, `/receipt/{secret}`)
    // deliver one-time license tokens / API keys and are viewed same-origin in
    // a browser. The previous global `CorsLayer::permissive()` reflected any
    // Origin and set `Access-Control-Allow-Origin: *`, which would have let a
    // malicious cross-origin page read a victim's receipt via fetch(). With no
    // CORS layer the browser default — same-origin only — applies to every
    // route, blocking cross-origin reads. None of the other endpoints need
    // cross-origin access: the Polar webhook is server-to-server and license
    // refresh is called by the CLI (neither is subject to browser CORS), and
    // health is trivial.
    let app = routes::router()
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{port}");
    info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

/// Cleanup expired receipts, old dead letters, old tokens — every 10 minutes.
fn spawn_cleanup_task(db: Db) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            if let Err(e) = db.cleanup().await {
                error!("cleanup task failed: {e}");
            }
        }
    });
}

/// Dead-letter auto-retry: re-fetch unresolvable products from the Polar
/// API every five minutes.
///
/// Only subscription-type dead letters are retried here. `order.paid` with
/// an unknown product returns 500 so Polar retries the full event, and
/// those never land in the dead-letter table.
fn spawn_dead_letter_retry_task(db: Db, config: Arc<Config>, http_client: reqwest::Client) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(e) = retry_dead_letters(&db, &config, &http_client).await {
                error!("dead-letter retry task failed: {e}");
            }
        }
    });
}

async fn retry_dead_letters(
    db: &Db,
    config: &Config,
    http_client: &reqwest::Client,
) -> Result<(), String> {
    let entries = db
        .get_retryable_dead_letters()
        .await
        .map_err(|e| format!("query: {e}"))?;

    for entry in entries {
        let sub_id = match &entry.subscription_id {
            Some(id) => id.clone(),
            None => continue,
        };

        // Stale if the tier was already fixed by a newer event.
        if entry.current_tier.as_deref() != Some("unknown") {
            info!(
                dead_letter_id = entry.id,
                sub_id = %sub_id,
                "tier already resolved, removing stale dead letter"
            );
            let _ = db.delete_dead_letter(entry.id).await;
            continue;
        }

        // Stale if a newer event has landed on the subscription.
        if let (Some(ref dl_occurred), Some(ref sub_last)) =
            (&entry.occurred_at, &entry.last_event_at)
        {
            // Compare as instants, not raw strings — a different UTC offset or
            // fractional-second encoding sorts incorrectly lexicographically. If
            // either timestamp fails to parse, keep the dead letter: its retry
            // reconciles against the CURRENT subscription state, which is safe.
            if let (Ok(dl_ts), Ok(sub_ts)) = (
                chrono::DateTime::parse_from_rfc3339(dl_occurred),
                chrono::DateTime::parse_from_rfc3339(sub_last),
            ) {
                if dl_ts < sub_ts {
                    info!(
                        dead_letter_id = entry.id,
                        sub_id = %sub_id,
                        "dead letter older than latest event, removing stale entry"
                    );
                    let _ = db.delete_dead_letter(entry.id).await;
                    continue;
                }
            }
        }

        let url = format!("https://api.polar.sh/v1/subscriptions/{sub_id}");
        let resp = http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", config.polar_api_key))
            .send()
            .await;

        let resp = match resp {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    status = %r.status(),
                    "Polar API returned non-success for retry"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    "Polar API request failed for retry: {e}"
                );
                continue;
            }
        };

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    dead_letter_id = entry.id,
                    "failed to parse Polar API response: {e}"
                );
                continue;
            }
        };

        let product_id = body.get("product_id").and_then(|v| v.as_str());

        if let Some(pid) = product_id {
            if let Some(tier) = config.tier_for_product(pid) {
                info!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    tier = %tier,
                    "resolved product via Polar API retry"
                );
                let _ = db.apply_retry_tier_fix(entry.id, &sub_id, tier, pid).await;
            } else {
                warn!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    product_id = %pid,
                    "Polar API returned product_id but it still doesn't map to a tier"
                );
            }
        }
    }

    Ok(())
}

/// Daily SQLite backup at 03:00 UTC — runs local .backup, optionally uploads to R2.
fn spawn_backup_task(config: Config) {
    tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now();
            let next_3am = {
                let today_3am = now.date_naive().and_hms_opt(3, 0, 0).unwrap();
                let today_3am_utc = today_3am.and_utc();
                if today_3am_utc > now {
                    today_3am_utc
                } else {
                    (today_3am + chrono::Duration::days(1)).and_utc()
                }
            };
            let sleep_dur = (next_3am - now)
                .to_std()
                .unwrap_or(Duration::from_secs(3600));
            tokio::time::sleep(sleep_dur).await;

            let db_path = config.database_url.clone();
            let date_str = chrono::Utc::now().format("%Y-%m-%d").to_string();

            let db_dir = std::path::Path::new(&db_path)
                .parent()
                .unwrap_or(std::path::Path::new("/data"));
            let backup_dir = db_dir.join("backup");
            if let Err(e) = std::fs::create_dir_all(&backup_dir) {
                error!("failed to create backup dir: {e}");
                continue;
            }

            let backup_path = backup_dir.join(format!("tirith-license-{date_str}.db"));
            let backup_path_str = backup_path.display().to_string();

            // VACUUM INTO is run on a separate read-only handle so writers
            // are never blocked by the backup.
            let result = tokio::task::spawn_blocking({
                let db_path = db_path.clone();
                let backup_path_str = backup_path_str.clone();
                move || -> Result<(), String> {
                    let src =
                        Db::open_readonly(&db_path).map_err(|e| format!("open readonly: {e}"))?;
                    let safe_path = backup_path_str.replace('\'', "''");
                    src.execute_batch(&format!("VACUUM INTO '{safe_path}'"))
                        .map_err(|e| format!("VACUUM INTO: {e}"))?;
                    Ok(())
                }
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    info!(path = %backup_path_str, "daily backup completed");

                    if let Ok(data) = tokio::fs::read(&backup_path).await {
                        use sha2::{Digest, Sha256};
                        let hash = hex::encode(Sha256::digest(&data));
                        let checksum_path = format!("{backup_path_str}.sha256");
                        let content = format!("{hash}  tirith-license-{date_str}.db\n");
                        if let Err(e) = tokio::fs::write(&checksum_path, &content).await {
                            error!("failed to write checksum: {e}");
                        }
                    }

                    cleanup_old_backups(&backup_dir, 7).await;

                    if let (
                        Some(ref endpoint),
                        Some(ref bucket),
                        Some(ref key_id),
                        Some(ref secret),
                    ) = (
                        config.backup_r2_endpoint.clone(),
                        config.backup_r2_bucket.clone(),
                        config.backup_r2_access_key_id.clone(),
                        config.backup_r2_secret_access_key.clone(),
                    ) {
                        upload_to_r2(
                            endpoint,
                            bucket,
                            key_id,
                            secret,
                            &backup_path_str,
                            &date_str,
                        )
                        .await;
                    }
                }
                Ok(Err(e)) => error!("backup failed: {e}"),
                Err(e) => error!("backup task panicked: {e}"),
            }
        }
    });
}

async fn cleanup_old_backups(backup_dir: &std::path::Path, keep: usize) {
    let mut entries: Vec<_> = match std::fs::read_dir(backup_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("tirith-license-") && n.ends_with(".db"))
                    .unwrap_or(false)
            })
            .collect(),
        Err(e) => {
            error!("failed to read backup dir: {e}");
            return;
        }
    };

    entries.sort_by_key(|e| e.file_name());
    entries.reverse();

    for old in entries.into_iter().skip(keep) {
        let path = old.path();
        let _ = std::fs::remove_file(&path);
        let sha_path = format!("{}.sha256", path.display());
        let _ = std::fs::remove_file(sha_path);
    }
}

async fn upload_to_r2(
    endpoint: &str,
    bucket_name: &str,
    access_key: &str,
    secret_key: &str,
    backup_path: &str,
    date_str: &str,
) {
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            error!("failed to build R2 HTTP client: {e}");
            return;
        }
    };

    let data = match tokio::fs::read(backup_path).await {
        Ok(d) => d,
        Err(e) => {
            error!("failed to read backup for R2 upload: {e}");
            return;
        }
    };

    let key = format!("backups/tirith-license-{date_str}.db");
    match put_r2_object(
        &client,
        endpoint,
        bucket_name,
        access_key,
        secret_key,
        &key,
        data,
    )
    .await
    {
        Ok(status) if status.is_success() => {
            info!(key = %key, "backup uploaded to R2");
        }
        Ok(status) => {
            error!(%status, "R2 upload returned error");
        }
        Err(e) => {
            error!("R2 upload failed: {e}");
        }
    }

    let checksum_path = format!("{backup_path}.sha256");
    if let Ok(checksum_data) = tokio::fs::read(&checksum_path).await {
        let checksum_key = format!("backups/tirith-license-{date_str}.db.sha256");
        match put_r2_object(
            &client,
            endpoint,
            bucket_name,
            access_key,
            secret_key,
            &checksum_key,
            checksum_data,
        )
        .await
        {
            Ok(status) if status.is_success() => {}
            Ok(status) => error!(%status, "R2 checksum upload returned error"),
            Err(e) => error!("R2 checksum upload failed: {e}"),
        }
    }
}

const R2_REGION: &str = "auto";
const S3_SERVICE: &str = "s3";
const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SIGV4_SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

struct SignedR2Put {
    url: reqwest::Url,
    host: String,
    amz_date: String,
    payload_hash: String,
    authorization: String,
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts keys of every length");
    mac.update(input);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&bytes);
    output
}

/// Build a path-style R2 PUT request signed with AWS Signature Version 4.
///
/// R2 uses the standard S3 SigV4 protocol with the fixed `auto` region. The
/// endpoint is deployment configuration, but it still has to be an HTTPS origin
/// with no credentials, query, or fragment so Authorization can never be sent to
/// a redirected or ambiguous target.
fn sign_r2_put(
    endpoint: &str,
    bucket_name: &str,
    access_key: &str,
    secret_key: &str,
    key: &str,
    body: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<SignedR2Put, &'static str> {
    use sha2::{Digest, Sha256};

    if bucket_name.is_empty()
        || access_key.is_empty()
        || secret_key.is_empty()
        || key.is_empty()
        || key.split('/').any(str::is_empty)
    {
        return Err("R2 signing inputs are incomplete");
    }

    let mut url = reqwest::Url::parse(endpoint).map_err(|_| "R2 endpoint is not a valid URL")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("R2 endpoint must be a credential-free HTTPS origin");
    }

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| "R2 endpoint cannot be used as a URL base")?;
        segments.pop_if_empty().push(bucket_name);
        for segment in key.split('/') {
            segments.push(segment);
        }
    }

    let hostname = url.host_str().ok_or("R2 endpoint has no host")?;
    let host = match url.port() {
        Some(port) => format!("{hostname}:{port}"),
        None => hostname.to_string(),
    };
    let canonical_uri = url.path();
    let payload_hash = hex::encode(Sha256::digest(body));
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let canonical_request = format!(
        "PUT\n{canonical_uri}\n\n{canonical_headers}\n{SIGV4_SIGNED_HEADERS}\n{payload_hash}"
    );
    let scope = format!("{date}/{R2_REGION}/{S3_SERVICE}/aws4_request");
    let string_to_sign = format!(
        "{SIGV4_ALGORITHM}\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let date_key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, R2_REGION.as_bytes());
    let service_key = hmac_sha256(&region_key, S3_SERVICE.as_bytes());
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "{SIGV4_ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={SIGV4_SIGNED_HEADERS}, Signature={signature}"
    );

    Ok(SignedR2Put {
        url,
        host,
        amz_date,
        payload_hash,
        authorization,
    })
}

async fn put_r2_object(
    client: &reqwest::Client,
    endpoint: &str,
    bucket_name: &str,
    access_key: &str,
    secret_key: &str,
    key: &str,
    body: Vec<u8>,
) -> Result<reqwest::StatusCode, &'static str> {
    use reqwest::header::{AUTHORIZATION, HOST};

    let signed = sign_r2_put(
        endpoint,
        bucket_name,
        access_key,
        secret_key,
        key,
        &body,
        chrono::Utc::now(),
    )?;
    client
        .put(signed.url)
        .header(HOST, signed.host)
        .header("x-amz-content-sha256", signed.payload_hash)
        .header("x-amz-date", signed.amz_date)
        .header(AUTHORIZATION, signed.authorization)
        .body(body)
        .send()
        .await
        .map(|response| response.status())
        .map_err(|_| "R2 upload request failed")
}

#[cfg(test)]
mod r2_signing_tests {
    use super::*;
    use chrono::TimeZone;

    fn test_time() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2026, 8, 12, 3, 4, 5)
            .single()
            .unwrap()
    }

    #[test]
    fn r2_signature_matches_fixed_independent_vector() {
        let signed = sign_r2_put(
            "https://account.r2.cloudflarestorage.com",
            "tirith-backups",
            "AKIAEXAMPLE",
            "very-secret-test-key",
            "backups/tirith-license-2026-08-12.db",
            b"abc",
            test_time(),
        )
        .unwrap();

        assert_eq!(
            signed.url.as_str(),
            "https://account.r2.cloudflarestorage.com/tirith-backups/backups/tirith-license-2026-08-12.db"
        );
        assert_eq!(
            signed.payload_hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260812/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=8640f3028fe5b7c57a6d90c4da75539c28984c62d1a593b334d90f5a96cf8ab9"
        );
        assert!(!signed.authorization.contains("very-secret-test-key"));
    }

    #[test]
    fn r2_signer_rejects_ambiguous_or_insecure_endpoints() {
        for endpoint in [
            "http://account.r2.cloudflarestorage.com",
            "https://user@account.r2.cloudflarestorage.com",
            "https://account.r2.cloudflarestorage.com/api/",
            "https://account.r2.cloudflarestorage.com?redirect=1",
            "https://account.r2.cloudflarestorage.com#fragment",
        ] {
            assert!(sign_r2_put(
                endpoint,
                "bucket",
                "key",
                "secret",
                "backup.db",
                b"x",
                test_time()
            )
            .is_err());
        }
    }

    #[test]
    fn r2_signature_binds_payload_and_percent_encoded_path() {
        let first = sign_r2_put(
            "https://account.r2.cloudflarestorage.com",
            "backup bucket",
            "key",
            "secret",
            "daily/backup file.db",
            b"first",
            test_time(),
        )
        .unwrap();
        let second = sign_r2_put(
            "https://account.r2.cloudflarestorage.com",
            "backup bucket",
            "key",
            "secret",
            "daily/backup file.db",
            b"second",
            test_time(),
        )
        .unwrap();

        assert_eq!(first.url.path(), "/backup%20bucket/daily/backup%20file.db");
        assert_ne!(first.payload_hash, second.payload_hash);
        assert_ne!(first.authorization, second.authorization);
    }
}

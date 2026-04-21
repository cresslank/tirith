use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use sha2::{Digest, Sha256};
use tracing::error;

use crate::error::AppError;
use crate::state::AppState;

pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing or invalid Authorization header".into()))?;

    if api_key.is_empty() {
        return Err(AppError::Unauthorized("empty API key".into()));
    }

    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let sub_id = state.db.lookup_api_key(&key_hash).await?.ok_or_else(|| {
        AppError::Unauthorized("Authentication failed. Check your API key.".into())
    })?;

    let sub = state.db.get_subscription(&sub_id).await?.ok_or_else(|| {
        error!(sub_id = %sub_id, "api_key references missing subscription");
        AppError::Internal("subscription not found".into())
    })?;

    // canceled still gets tokens — benefits continue until period end.
    if sub.status != "active" && sub.status != "canceled" {
        return Err(AppError::PaymentRequired(
            "Subscription inactive. Renew at https://tirith.dev/account".into(),
        ));
    }

    // Fail closed on any unknown/invalid tier.
    match sub.tier.as_str() {
        "pro" | "team" | "enterprise" => {}
        other => {
            error!(
                sub_id = %sub.id,
                tier = %other,
                "invalid tier, cannot sign token"
            );
            return Err(AppError::Internal(
                "License configuration error. Contact support@tirith.dev".into(),
            ));
        }
    }

    let exp_ts = chrono::Utc::now().timestamp() + (state.config.token_ttl_days * 86400);
    let token = state.signer.sign_token(&sub.tier, exp_ts);

    state.db.insert_token(&sub.id, &token, exp_ts).await?;

    Ok((
        StatusCode::OK,
        [
            ("content-type", "text/plain"),
            ("cache-control", "no-store"),
            ("pragma", "no-cache"),
            ("x-content-type-options", "nosniff"),
        ],
        token,
    ))
}

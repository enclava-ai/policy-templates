use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_policy_signing_service::{
    canonical::ce_v1_bytes,
    genpolicy::GenpolicyConfig,
    owner_store::{BootstrapOutcome, OwnerStore},
    policy::{
        decode_signing_blobs, load_signing_key_material, sign_verified_policy,
        verify_signing_inputs, SignRequest, SignedPolicyArtifact, SigningKeyMaterial,
    },
    policy::{template_sha256, verify_signed_artifact},
    TEMPLATE_ID,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    key_material: Arc<SigningKeyMaterial>,
    owner_store: Arc<OwnerStore>,
    genpolicy: GenpolicyConfig,
    template_sha256: String,
}

#[derive(Debug, Deserialize)]
struct BootstrapOrgRequest {
    org_id: Uuid,
    #[serde(default)]
    owner_pubkey_b64: Option<String>,
    #[serde(default)]
    owner_pubkey_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct BootstrapOrgResponse {
    org_id: Uuid,
    state: &'static str,
    owner_pubkey_fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct RotateOwnerRequest {
    org_id: Uuid,
    replacement_owner_pubkey_b64: String,
    signed_at: DateTime<Utc>,
    reason: String,
    signing_pubkey_b64: String,
    signature_b64: String,
}

#[derive(Debug, Serialize)]
struct RotateOwnerResponse {
    org_id: Uuid,
    version: u64,
    owner_pubkey_fingerprint: String,
    rotated_at: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    policy_template_id: &'static str,
    policy_template_sha256: String,
    signing_key_id: String,
    genpolicy_version_pin: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let key_material = load_signing_key_material()?;
    let owner_db_path = env::var("OWNER_DB_PATH").unwrap_or_else(|_| "owner-state.sqlite3".into());
    let owner_store = OwnerStore::open(PathBuf::from(owner_db_path))?;
    let genpolicy = GenpolicyConfig::from_env();
    let state = AppState {
        key_material: Arc::new(key_material),
        owner_store: Arc::new(owner_store),
        genpolicy,
        template_sha256: hex::encode(template_sha256()),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/sign", post(sign_policy))
        .route("/bootstrap-org", post(bootstrap_org))
        .route("/rotate-owner", post(rotate_owner))
        .with_state(state);

    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("invalid BIND_ADDR")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "policy signing service listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        policy_template_id: TEMPLATE_ID,
        policy_template_sha256: state.template_sha256,
        signing_key_id: state.key_material.key_id.clone(),
        genpolicy_version_pin: state.genpolicy.version_pin,
    })
}

async fn sign_policy(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignedPolicyArtifact>, AppError> {
    let blobs = decode_signing_blobs(&req)?;
    if blobs.descriptor_envelope.descriptor.org_id != blobs.keyring_envelope.keyring.org_id {
        return Err(AppError(anyhow!(
            "descriptor org_id does not match org keyring org_id"
        )));
    }
    let owner = state
        .owner_store
        .require_owner(blobs.descriptor_envelope.descriptor.org_id)?;
    let inputs = verify_signing_inputs(blobs, &owner.owner_pubkey)?;
    let artifact = sign_verified_policy(&req, inputs, &state.key_material, Utc::now())?;
    let verify_key = state.key_material.signing_key.verifying_key();
    verify_signed_artifact(&artifact, &verify_key)?;
    Ok(Json(artifact))
}

async fn bootstrap_org(
    State(state): State<AppState>,
    Json(req): Json<BootstrapOrgRequest>,
) -> Result<Json<BootstrapOrgResponse>, AppError> {
    let owner_pubkey = match (&req.owner_pubkey_b64, &req.owner_pubkey_hex) {
        (Some(raw), None) => decode_pubkey_b64("owner_pubkey_b64", raw)?,
        (None, Some(raw)) => decode_pubkey_hex("owner_pubkey_hex", raw)?,
        (Some(_), Some(_)) => {
            return Err(AppError(anyhow!(
                "provide only one of owner_pubkey_b64 or owner_pubkey_hex"
            )));
        }
        (None, None) => {
            return Err(AppError(anyhow!(
                "owner_pubkey_b64 or owner_pubkey_hex is required"
            )));
        }
    };
    let outcome = state
        .owner_store
        .bootstrap_owner(req.org_id, owner_pubkey, Utc::now())?;
    let state_label = match outcome {
        BootstrapOutcome::Created => "bootstrapped",
        BootstrapOutcome::AlreadyExists => "already-bootstrapped",
    };
    Ok(Json(BootstrapOrgResponse {
        org_id: req.org_id,
        state: state_label,
        owner_pubkey_fingerprint: hex::encode(owner_pubkey.to_bytes()),
    }))
}

async fn rotate_owner(
    State(state): State<AppState>,
    Json(req): Json<RotateOwnerRequest>,
) -> Result<Json<RotateOwnerResponse>, AppError> {
    if req.reason.trim().is_empty() {
        return Err(AppError(anyhow!("rotation reason is required")));
    }
    let current = state.owner_store.require_owner(req.org_id)?;
    let signing_pubkey = decode_pubkey_b64("signing_pubkey_b64", &req.signing_pubkey_b64)?;
    if signing_pubkey.to_bytes() != current.owner_pubkey.to_bytes() {
        return Err(AppError(anyhow!(
            "rotation directive must be signed by the current owner"
        )));
    }
    let replacement = decode_pubkey_b64(
        "replacement_owner_pubkey_b64",
        &req.replacement_owner_pubkey_b64,
    )?;
    let signature = decode_signature_b64("signature_b64", &req.signature_b64)?;
    let directive = recovery_directive_bytes(
        req.org_id,
        &current.owner_pubkey,
        &replacement,
        req.signed_at,
        &req.reason,
    );
    signing_pubkey
        .verify(&directive, &signature)
        .map_err(|err| anyhow!("owner rotation signature verification failed: {err}"))?;

    let rotated = state.owner_store.rotate_owner(
        req.org_id,
        current.owner_pubkey,
        replacement,
        Utc::now(),
    )?;
    Ok(Json(RotateOwnerResponse {
        org_id: req.org_id,
        version: rotated.version,
        owner_pubkey_fingerprint: hex::encode(rotated.owner_pubkey.to_bytes()),
        rotated_at: rotated.rotated_at.unwrap_or_else(Utc::now).to_rfc3339(),
    }))
}

fn recovery_directive_bytes(
    org_id: Uuid,
    revoked_pubkey: &VerifyingKey,
    replacement_pubkey: &VerifyingKey,
    signed_at: DateTime<Utc>,
    reason: &str,
) -> Vec<u8> {
    let revoked = revoked_pubkey.to_bytes();
    let replacement = replacement_pubkey.to_bytes();
    let signed_at = signed_at.to_rfc3339();
    ce_v1_bytes(&[
        ("purpose", b"enclava-recovery-v1"),
        ("org_id", org_id.as_bytes().as_slice()),
        ("revoked_pubkey", &revoked),
        ("replacement_pubkey", &replacement),
        ("signed_at", signed_at.as_bytes()),
        ("reason", reason.as_bytes()),
    ])
}

fn decode_pubkey_b64(name: &str, raw: &str) -> Result<VerifyingKey> {
    let bytes = B64
        .decode(raw.as_bytes())
        .with_context(|| format!("decoding {name}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|err| anyhow!("{name} is not a valid Ed25519 key: {err}"))
}

fn decode_pubkey_hex(name: &str, raw: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(raw).with_context(|| format!("decoding {name}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|err| anyhow!("{name} is not a valid Ed25519 key: {err}"))
}

fn decode_signature_b64(name: &str, raw: &str) -> Result<Signature> {
    let bytes = B64
        .decode(raw.as_bytes())
        .with_context(|| format!("decoding {name}"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 64 bytes"))?;
    Ok(Signature::from_bytes(&arr))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

struct AppError(anyhow::Error);

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.0.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn recovery_directive_signature_round_trips() {
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let current = SigningKey::from_bytes(&[0x11; 32]);
        let replacement = SigningKey::from_bytes(&[0x22; 32]).verifying_key();
        let signed_at = DateTime::parse_from_rfc3339("2026-04-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let bytes = recovery_directive_bytes(
            org_id,
            &current.verifying_key(),
            &replacement,
            signed_at,
            "routine owner rotation",
        );
        let signature = current.sign(&bytes);
        current.verifying_key().verify(&bytes, &signature).unwrap();
    }
}

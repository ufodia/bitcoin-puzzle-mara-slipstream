use std::{path::PathBuf, time::Duration};

use reqwest::{redirect::Policy, Client};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::{validation::validate_manifest, Error, Result, SweepManifest};

const MAX_COOKIE_BYTES: u64 = 4096;
const MAX_RPC_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone)]
pub struct CoreRpcConfig {
    pub port: u16,
    pub cookie_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorePolicyResult {
    pub allowed: bool,
    pub reject_reason: Option<String>,
    pub vsize: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationResult {
    pub found_unspent_output: bool,
    pub confirmations: u64,
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

pub async fn test_mempool_accept(
    config: CoreRpcConfig,
    manifest: SweepManifest,
) -> Result<CorePolicyResult> {
    validate_manifest(&manifest)?;
    let value: Value = rpc_call(
        config,
        "testmempoolaccept",
        json!([[manifest.signed_transaction_hex]]),
    )
    .await?;
    let first = value
        .as_array()
        .and_then(|array| array.first())
        .ok_or_else(|| Error::Rpc("testmempoolaccept returned an unexpected result".to_owned()))?;
    let allowed = first
        .get("allowed")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::Rpc("testmempoolaccept omitted the allowed field".to_owned()))?;
    let reject_reason = first
        .get("reject-reason")
        .or_else(|| first.get("reject_reason"))
        .and_then(Value::as_str)
        .map(|value| value.chars().take(500).collect());
    let vsize = first.get("vsize").and_then(Value::as_u64);
    Ok(CorePolicyResult {
        allowed,
        reject_reason,
        vsize,
    })
}

pub async fn check_destination_confirmations(
    config: CoreRpcConfig,
    manifest: SweepManifest,
) -> Result<ConfirmationResult> {
    validate_manifest(&manifest)?;
    let value: Value = rpc_call(
        config,
        "gettxout",
        json!([manifest.transaction_id, 0, true]),
    )
    .await?;
    if value.is_null() {
        return Ok(ConfirmationResult {
            found_unspent_output: false,
            confirmations: 0,
        });
    }
    let confirmations = value
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok(ConfirmationResult {
        found_unspent_output: true,
        confirmations,
    })
}

async fn rpc_call<T: DeserializeOwned>(
    config: CoreRpcConfig,
    method: &str,
    params: Value,
) -> Result<T> {
    if config.port == 0 {
        return Err(Error::invalid("Bitcoin Core RPC port must be between 1 and 65535"));
    }
    let metadata = std::fs::metadata(&config.cookie_path)
        .map_err(|_| Error::Rpc("cannot read the configured Bitcoin Core cookie file".to_owned()))?;
    if metadata.len() == 0 || metadata.len() > MAX_COOKIE_BYTES {
        return Err(Error::policy("Bitcoin Core cookie file has an invalid size"));
    }
    let mut cookie = std::fs::read_to_string(&config.cookie_path)
        .map_err(|_| Error::Rpc("cannot read the configured Bitcoin Core cookie file".to_owned()))?;
    let trimmed = cookie.trim();
    let (username, password) = trimmed
        .split_once(':')
        .ok_or_else(|| Error::Rpc("Bitcoin Core cookie has an invalid format".to_owned()))?;
    if username.is_empty() || password.is_empty() {
        cookie.zeroize();
        return Err(Error::Rpc("Bitcoin Core cookie has an invalid format".to_owned()));
    }

    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| Error::Rpc("failed to construct the loopback RPC client".to_owned()))?;
    let endpoint = format!("http://127.0.0.1:{}/", config.port);
    let request = client
        .post(endpoint)
        .basic_auth(username, Some(password))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "puzzleslipstream",
            "method": method,
            "params": params,
        }));
    cookie.zeroize();

    let response = request
        .send()
        .await
        .map_err(|_| Error::Rpc("loopback Bitcoin Core request failed".to_owned()))?;
    if response.status().is_redirection() {
        return Err(Error::Rpc("Bitcoin Core RPC attempted an HTTP redirect".to_owned()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
    {
        return Err(Error::Rpc("Bitcoin Core RPC response exceeded 1 MiB".to_owned()));
    }
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| Error::Rpc("failed to read Bitcoin Core RPC response".to_owned()))?;
    if bytes.len() > MAX_RPC_RESPONSE_BYTES {
        return Err(Error::Rpc("Bitcoin Core RPC response exceeded 1 MiB".to_owned()));
    }
    if !status.is_success() {
        return Err(Error::Rpc(format!(
            "Bitcoin Core RPC returned HTTP {}",
            status.as_u16()
        )));
    }

    let envelope: RpcEnvelope<T> = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Rpc("Bitcoin Core returned malformed JSON".to_owned()))?;
    if let Some(error) = envelope.error {
        return Err(Error::Rpc(format!(
            "Bitcoin Core error {}: {}",
            error.code,
            error.message.chars().take(500).collect::<String>()
        )));
    }
    envelope
        .result
        .ok_or_else(|| Error::Rpc("Bitcoin Core response omitted its result".to_owned()))
}

use std::{fmt, time::Duration};

use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{validation::validate_manifest, ChainNetwork, Error, Result, SweepManifest};

// Keep this preset isolated and compare it with current official MARA documentation before use.
const MARA_PRODUCTION_SUBMIT_URL: &str =
    "https://slipstream.mara.com/rest-api/transaction/submit";
const LOOPBACK_MOCK_SUBMIT_URL: &str = "http://127.0.0.1:18765/v1/transaction/submit";
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const RESPONSE_PREVIEW_CHARS: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTarget {
    MaraProduction,
    LoopbackMock,
}

impl RelayTarget {
    pub const ALL: [Self; 2] = [Self::MaraProduction, Self::LoopbackMock];

    fn url(self) -> &'static str {
        match self {
            Self::MaraProduction => MARA_PRODUCTION_SUBMIT_URL,
            Self::LoopbackMock => LOOPBACK_MOCK_SUBMIT_URL,
        }
    }
}

impl fmt::Display for RelayTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MaraProduction => "MARA Slipstream — Production",
            Self::LoopbackMock => "Loopback mock — 127.0.0.1:18765",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct SubmitRequest<'a> {
    tx_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_code: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReceipt {
    pub target: String,
    pub transaction_id: String,
    pub http_status: u16,
    pub accepted_not_confirmed: bool,
    pub provider_reference: Option<String>,
    pub response_preview: String,
}

pub async fn submit_private_transaction(
    target: RelayTarget,
    manifest: SweepManifest,
    client_code: Option<String>,
) -> Result<RelayReceipt> {
    validate_manifest(&manifest)?;
    enforce_target_policy(target, manifest.network)?;

    let client = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("PuzzleSlipstream/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| Error::Relay("failed to construct a hardened HTTP client".to_owned()))?;

    let normalized_client_code = client_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if normalized_client_code.is_some_and(|value| value.len() > 200) {
        return Err(Error::invalid("client code exceeds 200 bytes"));
    }

    let response = client
        .post(target.url())
        .json(&SubmitRequest {
            tx_hex: &manifest.signed_transaction_hex,
            client_code: normalized_client_code,
        })
        .send()
        .await
        .map_err(|error| Error::Relay(sanitize_transport_error(&error.to_string())))?;

    if response.status().is_redirection() {
        return Err(Error::Relay("private relay attempted an HTTP redirect".to_owned()));
    }
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(Error::Relay("private relay response exceeded 1 MiB".to_owned()));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| Error::Relay("failed to read the private relay response".to_owned()))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Relay("private relay response exceeded 1 MiB".to_owned()));
    }

    let body = String::from_utf8_lossy(&bytes);
    let redacted = redact_response(&body, &manifest.signed_transaction_hex);
    let provider_reference = extract_reference(&bytes);
    let accepted = status.is_success();

    if !accepted {
        return Err(Error::Relay(format!(
            "private relay returned HTTP {}: {}",
            status.as_u16(),
            truncate(&redacted, RESPONSE_PREVIEW_CHARS)
        )));
    }

    Ok(RelayReceipt {
        target: target.to_string(),
        transaction_id: manifest.transaction_id,
        http_status: status.as_u16(),
        accepted_not_confirmed: true,
        provider_reference,
        response_preview: truncate(&redacted, RESPONSE_PREVIEW_CHARS),
    })
}

fn enforce_target_policy(target: RelayTarget, network: ChainNetwork) -> Result<()> {
    match target {
        RelayTarget::MaraProduction => {
            network.ensure_enabled()?;
            if network != ChainNetwork::Mainnet {
                return Err(Error::policy(
                    "MARA production submission is permitted only for a reviewed mainnet manifest",
                ));
            }
            if !cfg!(feature = "mainnet") {
                return Err(Error::policy(
                    "MARA production is disabled because this build lacks the mainnet feature",
                ));
            }
        }
        RelayTarget::LoopbackMock => {}
    }
    Ok(())
}

fn extract_reference(body: &[u8]) -> Option<String> {
    let json: Value = serde_json::from_slice(body).ok()?;
    for key in [
        "reference",
        "submission_id",
        "id",
        "txid",
        "transaction_id",
    ] {
        if let Some(value) = find_string_key(&json, key) {
            return Some(truncate(value, 200));
        }
    }
    None
}

fn find_string_key<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(candidate)) = map.get(key) {
                return Some(candidate);
            }
            map.values().find_map(|child| find_string_key(child, key))
        }
        Value::Array(array) => array.iter().find_map(|child| find_string_key(child, key)),
        _ => None,
    }
}

fn redact_response(body: &str, raw_transaction: &str) -> String {
    let replaced = body.replace(raw_transaction, "[raw transaction redacted]");
    truncate(&replaced, RESPONSE_PREVIEW_CHARS)
}

fn sanitize_transport_error(message: &str) -> String {
    let lowered = message.replace(MARA_PRODUCTION_SUBMIT_URL, "MARA production endpoint");
    lowered.replace(LOOPBACK_MOCK_SUBMIT_URL, "loopback mock endpoint")
}

fn truncate(value: &str, maximum_chars: usize) -> String {
    value.chars().take(maximum_chars).collect()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_rejects_test_networks() {
        let error = enforce_target_policy(RelayTarget::MaraProduction, ChainNetwork::Regtest)
            .expect_err("must reject");
        assert!(error.to_string().contains("mainnet"));
    }

    #[test]
    fn response_redaction_removes_raw_transaction() {
        let raw = "deadbeef";
        let redacted = redact_response(r#"{"tx_hex":"deadbeef"}"#, raw);
        assert!(!redacted.contains(raw));
    }
}

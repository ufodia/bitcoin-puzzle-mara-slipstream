use std::{fmt, str::FromStr};

use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const UTXO_BUNDLE_FORMAT: &str = "puzzle-slipstream-utxos";
pub const SWEEP_MANIFEST_FORMAT: &str = "puzzle-slipstream-sweep-manifest";
pub const ENCRYPTED_ENVELOPE_FORMAT: &str = "puzzle-slipstream-encrypted-sweep";
pub const FORMAT_VERSION: u16 = 1;
pub const MAX_INPUTS: usize = 512;
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PREVIOUS_TX_HEX_CHARS: usize = 800_000;
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainNetwork {
    Regtest,
    Testnet4,
    Signet,
    Mainnet,
}

impl ChainNetwork {
    pub const TEST_NETWORKS: [Self; 3] = [Self::Regtest, Self::Testnet4, Self::Signet];

    pub fn bitcoin_network(self) -> Network {
        match self {
            Self::Regtest => Network::Regtest,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Mainnet => Network::Bitcoin,
        }
    }

    pub fn ensure_enabled(self) -> Result<()> {
        if self == Self::Mainnet && !cfg!(feature = "mainnet") {
            return Err(Error::policy(
                "mainnet support is not compiled into this build; rebuild with --features mainnet",
            ));
        }
        Ok(())
    }

    pub fn is_mainnet(self) -> bool {
        self == Self::Mainnet
    }

    pub fn default_rpc_port(self) -> u16 {
        match self {
            Self::Mainnet => 8332,
            Self::Testnet4 => 48332,
            Self::Signet => 38332,
            Self::Regtest => 18443,
        }
    }
}

impl fmt::Display for ChainNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Regtest => "Regtest",
            Self::Testnet4 => "Testnet4",
            Self::Signet => "Signet",
            Self::Mainnet => "Mainnet",
        })
    }
}

impl FromStr for ChainNetwork {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "regtest" => Ok(Self::Regtest),
            "testnet4" => Ok(Self::Testnet4),
            "signet" => Ok(Self::Signet),
            "mainnet" | "bitcoin" => Ok(Self::Mainnet),
            _ => Err(Error::invalid("unsupported Bitcoin network")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoBundle {
    pub format: String,
    pub version: u16,
    pub network: ChainNetwork,
    pub inputs: Vec<UtxoRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoRecord {
    pub previous_transaction_hex: String,
    pub vout: u32,
    #[serde(default)]
    pub label: Option<String>,
}

impl UtxoBundle {
    pub fn from_json_bounded(json: &str) -> Result<Self> {
        if json.len() > MAX_BUNDLE_BYTES {
            return Err(Error::invalid("UTXO bundle exceeds the 8 MiB limit"));
        }
        let bundle: Self = serde_json::from_str(json)?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != UTXO_BUNDLE_FORMAT || self.version != FORMAT_VERSION {
            return Err(Error::invalid("unsupported UTXO bundle format or version"));
        }
        self.network.ensure_enabled()?;
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(Error::invalid(format!(
                "UTXO bundle must contain between 1 and {MAX_INPUTS} inputs"
            )));
        }
        for (index, input) in self.inputs.iter().enumerate() {
            let tx_hex = input.previous_transaction_hex.trim();
            if tx_hex.len() < 20
                || tx_hex.len() > MAX_PREVIOUS_TX_HEX_CHARS
                || tx_hex.len() % 2 != 0
                || !tx_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(Error::invalid(format!(
                    "input {} contains malformed or oversized previous transaction hex",
                    index + 1
                )));
            }
            if input.label.as_ref().is_some_and(|label| label.len() > 200) {
                return Err(Error::invalid(format!(
                    "input {} label exceeds 200 bytes",
                    index + 1
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeePolicy {
    pub target_sat_per_vbyte: u64,
    pub max_absolute_fee_sats: u64,
    pub max_fee_basis_points: u16,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            target_sat_per_vbyte: 10,
            max_absolute_fee_sats: 250_000,
            max_fee_basis_points: 500,
        }
    }
}

impl FeePolicy {
    pub fn validate(self) -> Result<()> {
        if !(1..=1_000_000).contains(&self.target_sat_per_vbyte) {
            return Err(Error::invalid(
                "target fee rate must be between 1 and 1,000,000 sat/vB",
            ));
        }
        if self.max_absolute_fee_sats == 0 {
            return Err(Error::invalid("absolute fee cap must be greater than zero"));
        }
        if !(1..=10_000).contains(&self.max_fee_basis_points) {
            return Err(Error::invalid(
                "fee percentage cap must be between 1 and 10,000 basis points",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PubkeyEncoding {
    Compressed,
    Uncompressed,
}

impl fmt::Display for PubkeyEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Compressed => "compressed",
            Self::Uncompressed => "uncompressed",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SweepManifestInput {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub source_address: String,
    pub pubkey_encoding: PubkeyEncoding,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SweepManifest {
    pub format: String,
    pub version: u16,
    pub network: ChainNetwork,
    pub destination_address: String,
    pub inputs: Vec<SweepManifestInput>,
    pub total_input_sats: u64,
    pub output_sats: u64,
    pub fee_sats: u64,
    pub target_sat_per_vbyte: u64,
    pub actual_vsize: u64,
    pub actual_fee_rate_millisat_per_vbyte: u64,
    pub transaction_id: String,
    pub signed_transaction_hex: String,
}

impl SweepManifest {
    pub fn new_base(network: ChainNetwork, destination_address: String) -> Self {
        Self {
            format: SWEEP_MANIFEST_FORMAT.to_owned(),
            version: FORMAT_VERSION,
            network,
            destination_address,
            inputs: Vec::new(),
            total_input_sats: 0,
            output_sats: 0,
            fee_sats: 0,
            target_sat_per_vbyte: 0,
            actual_vsize: 0,
            actual_fee_rate_millisat_per_vbyte: 0,
            transaction_id: String::new(),
            signed_transaction_hex: String::new(),
        }
    }

    pub fn actual_fee_rate_display(&self) -> String {
        format!(
            "{}.{:03} sat/vB",
            self.actual_fee_rate_millisat_per_vbyte / 1000,
            self.actual_fee_rate_millisat_per_vbyte % 1000
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfDescriptor {
    pub name: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherDescriptor {
    pub name: String,
    pub nonce_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSweepEnvelope {
    pub format: String,
    pub version: u16,
    pub kdf: KdfDescriptor,
    pub cipher: CipherDescriptor,
    pub ciphertext_b64: String,
}

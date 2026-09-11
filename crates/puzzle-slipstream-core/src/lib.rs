//! Security-oriented primitives for PuzzleSlipstream.
//!
//! The `signer` feature adds private-key parsing and transaction signing.
//! The `network` feature adds private-relay and loopback Bitcoin Core clients.
//! Mainnet is rejected unless the `mainnet` feature is explicitly enabled.

pub mod envelope;
pub mod error;
pub mod model;
pub mod validation;

#[cfg(feature = "network")]
pub mod relay;
#[cfg(feature = "network")]
pub mod rpc;
#[cfg(feature = "signer")]
pub mod signing;

pub use error::{Error, Result};
pub use model::{
    ChainNetwork, EncryptedSweepEnvelope, FeePolicy, PubkeyEncoding, SweepManifest,
    UtxoBundle,
};

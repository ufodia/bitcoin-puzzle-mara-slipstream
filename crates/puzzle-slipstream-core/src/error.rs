use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("security policy rejected the operation: {0}")]
    Policy(String),

    #[error("Bitcoin data is invalid: {0}")]
    Bitcoin(String),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("encrypted envelope is invalid or the passphrase is incorrect")]
    EnvelopeAuthentication,

    #[error("JSON data is invalid: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "network")]
    #[error("private relay request failed: {0}")]
    Relay(String),

    #[cfg(feature = "network")]
    #[error("local Bitcoin Core RPC failed: {0}")]
    Rpc(String),
}

impl Error {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }

    pub fn policy(message: impl Into<String>) -> Self {
        Self::Policy(message.into())
    }

    pub fn bitcoin(message: impl Into<String>) -> Self {
        Self::Bitcoin(message.into())
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }
}

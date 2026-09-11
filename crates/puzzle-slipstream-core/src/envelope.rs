use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    model::{
        CipherDescriptor, EncryptedSweepEnvelope, KdfDescriptor, SweepManifest,
        ENCRYPTED_ENVELOPE_FORMAT, FORMAT_VERSION, MAX_ENVELOPE_BYTES, MAX_MANIFEST_BYTES,
    },
    validation::validate_manifest,
    Error, Result,
};

const TRANSPORT_PREFIX: &str = "PSW1:";
const AAD: &[u8] = b"PuzzleSlipstream/SweepManifest/v1";
const ARGON_MEMORY_KIB: u32 = 65_536;
const ARGON_ITERATIONS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const MIN_PASSPHRASE_BYTES: usize = 12;
const MAX_PASSPHRASE_BYTES: usize = 1024;

pub fn encrypt_manifest(
    manifest: &SweepManifest,
    passphrase: &str,
) -> Result<EncryptedSweepEnvelope> {
    validate_manifest(manifest)?;
    validate_passphrase(passphrase)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(manifest)?);
    if plaintext.len() > MAX_MANIFEST_BYTES {
        return Err(Error::invalid("sweep manifest exceeds the encryption size limit"));
    }

    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut key = Zeroizing::new([0_u8; 32]);
    derive_key(passphrase.as_bytes(), &salt, &mut key)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| Error::crypto("cannot initialize XChaCha20-Poly1305"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: AAD,
            },
        )
        .map_err(|_| Error::crypto("authenticated encryption failed"))?;

    Ok(EncryptedSweepEnvelope {
        format: ENCRYPTED_ENVELOPE_FORMAT.to_owned(),
        version: FORMAT_VERSION,
        kdf: KdfDescriptor {
            name: "argon2id".to_owned(),
            memory_kib: ARGON_MEMORY_KIB,
            iterations: ARGON_ITERATIONS,
            parallelism: ARGON_PARALLELISM,
            salt_b64: URL_SAFE_NO_PAD.encode(salt),
        },
        cipher: CipherDescriptor {
            name: "xchacha20poly1305".to_owned(),
            nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
        },
        ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_manifest(
    envelope: &EncryptedSweepEnvelope,
    passphrase: &str,
) -> Result<SweepManifest> {
    validate_passphrase(passphrase)?;
    validate_envelope_header(envelope)?;

    let salt = URL_SAFE_NO_PAD
        .decode(&envelope.kdf.salt_b64)
        .map_err(|_| Error::EnvelopeAuthentication)?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&envelope.cipher.nonce_b64)
        .map_err(|_| Error::EnvelopeAuthentication)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| Error::EnvelopeAuthentication)?;
    if salt.len() != 16 || nonce.len() != 24 || ciphertext.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::EnvelopeAuthentication);
    }

    let mut key = Zeroizing::new([0_u8; 32]);
    derive_key(passphrase.as_bytes(), &salt, &mut key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| Error::EnvelopeAuthentication)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| Error::EnvelopeAuthentication)?;
    if plaintext.len() > MAX_MANIFEST_BYTES {
        plaintext.zeroize();
        return Err(Error::EnvelopeAuthentication);
    }
    let parsed = serde_json::from_slice::<SweepManifest>(&plaintext)
        .map_err(|_| Error::EnvelopeAuthentication);
    plaintext.zeroize();
    let manifest = parsed?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn envelope_to_pretty_json(envelope: &EncryptedSweepEnvelope) -> Result<String> {
    validate_envelope_header(envelope)?;
    serde_json::to_string_pretty(envelope).map_err(Error::from)
}

pub fn envelope_from_json_bounded(json: &str) -> Result<EncryptedSweepEnvelope> {
    if json.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::invalid("encrypted envelope exceeds the 8 MiB limit"));
    }
    let envelope: EncryptedSweepEnvelope = serde_json::from_str(json)?;
    validate_envelope_header(&envelope)?;
    Ok(envelope)
}

pub fn envelope_to_transport(envelope: &EncryptedSweepEnvelope) -> Result<String> {
    let json = serde_json::to_vec(envelope)?;
    if json.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::invalid("encrypted envelope exceeds the transport limit"));
    }
    Ok(format!("{TRANSPORT_PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

pub fn envelope_from_transport(text: &str) -> Result<EncryptedSweepEnvelope> {
    let compact = text.trim();
    let encoded = compact
        .strip_prefix(TRANSPORT_PREFIX)
        .ok_or_else(|| Error::invalid("transport text must begin with PSW1:"))?;
    if encoded.len() > MAX_ENVELOPE_BYTES * 2 {
        return Err(Error::invalid("transport text exceeds the size limit"));
    }
    let json = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::invalid("transport text is not valid base64url"))?;
    if json.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::invalid("decoded transport exceeds the size limit"));
    }
    let json = std::str::from_utf8(&json)
        .map_err(|_| Error::invalid("decoded transport is not UTF-8 JSON"))?;
    envelope_from_json_bounded(json)
}

fn validate_envelope_header(envelope: &EncryptedSweepEnvelope) -> Result<()> {
    if envelope.format != ENCRYPTED_ENVELOPE_FORMAT || envelope.version != FORMAT_VERSION {
        return Err(Error::invalid("unsupported encrypted envelope format or version"));
    }
    if envelope.kdf.name != "argon2id"
        || envelope.kdf.memory_kib != ARGON_MEMORY_KIB
        || envelope.kdf.iterations != ARGON_ITERATIONS
        || envelope.kdf.parallelism != ARGON_PARALLELISM
        || envelope.cipher.name != "xchacha20poly1305"
    {
        return Err(Error::policy("unsupported or weakened envelope cryptography parameters"));
    }
    if envelope.ciphertext_b64.len() > MAX_ENVELOPE_BYTES * 2 {
        return Err(Error::invalid("encrypted envelope ciphertext is oversized"));
    }
    Ok(())
}

fn validate_passphrase(passphrase: &str) -> Result<()> {
    let length = passphrase.len();
    if !(MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&length) {
        return Err(Error::invalid(format!(
            "transfer passphrase must contain between {MIN_PASSPHRASE_BYTES} and {MAX_PASSPHRASE_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn derive_key(passphrase: &[u8], salt: &[u8], output: &mut [u8; 32]) -> Result<()> {
    let params = Params::new(
        ARGON_MEMORY_KIB,
        ARGON_ITERATIONS,
        ARGON_PARALLELISM,
        Some(32),
    )
    .map_err(|_| Error::crypto("invalid Argon2id parameters"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, output)
        .map_err(|_| Error::crypto("Argon2id key derivation failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ChainNetwork;

    #[test]
    fn transport_rejects_wrong_prefix() {
        let error = envelope_from_transport("not-a-transport").expect_err("must fail");
        assert!(error.to_string().contains("PSW1"));
    }

    #[test]
    fn passphrase_policy_is_enforced_before_manifest_validation() {
        let manifest = SweepManifest::new_base(ChainNetwork::Regtest, "invalid".to_owned());
        let error = encrypt_manifest(&manifest, "short").expect_err("must fail");
        assert!(error.to_string().contains("input count") || error.to_string().contains("passphrase"));
    }
}

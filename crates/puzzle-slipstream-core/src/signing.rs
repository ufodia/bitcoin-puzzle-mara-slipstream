use std::{collections::HashSet, str::FromStr};

use bitcoin::{
    absolute,
    address::NetworkUnchecked,
    consensus::{deserialize, encode::serialize_hex, serialize},
    hashes::Hash,
    key::PrivateKey,
    script::{Builder, PushBytesBuf},
    secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    transaction, Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use zeroize::Zeroizing;

use crate::{
    model::{
        FeePolicy, PubkeyEncoding, SweepManifest, SweepManifestInput, UtxoBundle,
        FORMAT_VERSION, SWEEP_MANIFEST_FORMAT,
    },
    validation::validate_manifest,
    Error, Result,
};

const CONSERVATIVE_DUST_FLOOR_SATS: u64 = 546;

#[derive(Debug, Clone)]
struct PreparedInput {
    outpoint: OutPoint,
    txout: TxOut,
    source_address: Address,
    public_key: PublicKey,
    encoding: PubkeyEncoding,
    label: Option<String>,
}

/// Build a one-output, no-change, final-sequence legacy P2PKH sweep.
///
/// The function never performs network I/O. `private_key_text` may be WIF or 64 hexadecimal
/// characters. Every previous transaction is decoded and matched against the derived compressed
/// or uncompressed P2PKH script before signing.
pub fn build_signed_sweep(
    bundle: &UtxoBundle,
    private_key_text: &str,
    destination_text: &str,
    fee_policy: FeePolicy,
) -> Result<SweepManifest> {
    bundle.validate()?;
    fee_policy.validate()?;
    bundle.network.ensure_enabled()?;

    let network = bundle.network.bitcoin_network();
    let destination_unchecked = Address::<NetworkUnchecked>::from_str(destination_text.trim())
        .map_err(|_| Error::invalid("destination address is not a valid Bitcoin address"))?;
    let destination = destination_unchecked
        .require_network(network)
        .map_err(|_| Error::invalid("destination address is not valid for the selected network"))?;

    let secret = parse_secret(private_key_text)?;
    let secp = Secp256k1::new();
    let secp_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let compressed_public = PublicKey::new(secp_public);
    let uncompressed_public = PublicKey::new_uncompressed(secp_public);
    let compressed_address = Address::p2pkh(&compressed_public, network);
    let uncompressed_address = Address::p2pkh(&uncompressed_public, network);
    let compressed_script = compressed_address.script_pubkey();
    let uncompressed_script = uncompressed_address.script_pubkey();

    let mut seen = HashSet::with_capacity(bundle.inputs.len());
    let mut prepared = Vec::with_capacity(bundle.inputs.len());
    let mut total_input_sats = 0_u64;

    for (index, record) in bundle.inputs.iter().enumerate() {
        let raw = Zeroizing::new(
            hex::decode(record.previous_transaction_hex.trim()).map_err(|_| {
                Error::invalid(format!(
                    "input {} previous transaction is not valid hexadecimal",
                    index + 1
                ))
            })?,
        );
        let previous: Transaction = deserialize(raw.as_slice()).map_err(|_| {
            Error::bitcoin(format!(
                "input {} previous transaction cannot be decoded",
                index + 1
            ))
        })?;
        let previous_txid = previous.compute_txid();
        let txout = previous.output.get(record.vout as usize).cloned().ok_or_else(|| {
            Error::invalid(format!(
                "input {} vout {} does not exist in the supplied previous transaction",
                index + 1,
                record.vout
            ))
        })?;
        let outpoint = OutPoint::new(previous_txid, record.vout);
        if !seen.insert(outpoint) {
            return Err(Error::invalid(format!(
                "duplicate outpoint {}:{}",
                previous_txid, record.vout
            )));
        }

        let (source_address, public_key, encoding) = if txout.script_pubkey == compressed_script {
            (
                compressed_address.clone(),
                compressed_public,
                PubkeyEncoding::Compressed,
            )
        } else if txout.script_pubkey == uncompressed_script {
            (
                uncompressed_address.clone(),
                uncompressed_public,
                PubkeyEncoding::Uncompressed,
            )
        } else {
            return Err(Error::policy(format!(
                "input {} does not pay to either legacy P2PKH address derived from the supplied private key",
                index + 1
            )));
        };

        total_input_sats = total_input_sats
            .checked_add(txout.value.to_sat())
            .ok_or_else(|| Error::invalid("input amount overflow"))?;
        prepared.push(PreparedInput {
            outpoint,
            txout,
            source_address,
            public_key,
            encoding,
            label: record.label.clone(),
        });
    }

    let maximum_vsize = maximum_legacy_vsize(&prepared, destination.script_pubkey().len())?;
    let fee_sats = maximum_vsize
        .checked_mul(fee_policy.target_sat_per_vbyte)
        .ok_or_else(|| Error::invalid("fee calculation overflow"))?;
    enforce_fee_caps(fee_sats, total_input_sats, fee_policy)?;

    let output_sats = total_input_sats
        .checked_sub(fee_sats)
        .ok_or_else(|| Error::policy("fee is greater than or equal to the input total"))?;
    if output_sats < CONSERVATIVE_DUST_FLOOR_SATS {
        return Err(Error::policy(format!(
            "destination output would be below the conservative {} sat dust floor",
            CONSERVATIVE_DUST_FLOOR_SATS
        )));
    }

    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: prepared
            .iter()
            .map(|input| TxIn {
                previous_output: input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(output_sats),
            script_pubkey: destination.script_pubkey(),
        }],
    };

    let mut signed = unsigned.clone();
    for (index, prepared_input) in prepared.iter().enumerate() {
        let sighash = SighashCache::new(&unsigned)
            .legacy_signature_hash(
                index,
                prepared_input.txout.script_pubkey.as_script(),
                EcdsaSighashType::All.to_u32(),
            )
            .map_err(|_| Error::bitcoin("failed to calculate legacy signature hash"))?;
        let message = Message::from_digest(sighash.to_byte_array());
        let mut signature: Signature = secp.sign_ecdsa(&message, &secret);
        signature.normalize_s();
        secp.verify_ecdsa(&message, &signature, &prepared_input.public_key.inner)
            .map_err(|_| Error::crypto("newly-created ECDSA signature did not verify"))?;

        let mut signature_bytes = signature.serialize_der().to_vec();
        signature_bytes.push(EcdsaSighashType::All.to_u32() as u8);
        let signature_push = PushBytesBuf::try_from(signature_bytes)
            .map_err(|_| Error::crypto("signature cannot be encoded as a script push"))?;
        signed.input[index].script_sig = Builder::new()
            .push_slice(signature_push)
            .push_key(&prepared_input.public_key)
            .into_script();
    }

    if signed
        .input
        .iter()
        .any(|input| input.sequence != Sequence::MAX || !input.witness.is_empty())
    {
        return Err(Error::policy(
            "internal invariant failed: all inputs must use final sequence and empty witness",
        ));
    }
    if signed.output.len() != 1 {
        return Err(Error::policy(
            "internal invariant failed: sweep must have exactly one output",
        ));
    }

    let actual_vsize = serialize(&signed).len() as u64;
    if actual_vsize > maximum_vsize {
        return Err(Error::policy(
            "signed transaction exceeded the conservative maximum size estimate",
        ));
    }
    let actual_fee_rate_millisat_per_vbyte = fee_sats
        .checked_mul(1000)
        .ok_or_else(|| Error::invalid("fee-rate calculation overflow"))?
        / actual_vsize.max(1);

    let mut manifest = SweepManifest::new_base(bundle.network, destination.to_string());
    manifest.format = SWEEP_MANIFEST_FORMAT.to_owned();
    manifest.version = FORMAT_VERSION;
    manifest.inputs = prepared
        .iter()
        .map(|input| SweepManifestInput {
            txid: input.outpoint.txid.to_string(),
            vout: input.outpoint.vout,
            value_sats: input.txout.value.to_sat(),
            script_pubkey_hex: hex::encode(input.txout.script_pubkey.as_bytes()),
            source_address: input.source_address.to_string(),
            pubkey_encoding: input.encoding,
            label: input.label.clone(),
        })
        .collect();
    manifest.total_input_sats = total_input_sats;
    manifest.output_sats = output_sats;
    manifest.fee_sats = fee_sats;
    manifest.target_sat_per_vbyte = fee_policy.target_sat_per_vbyte;
    manifest.actual_vsize = actual_vsize;
    manifest.actual_fee_rate_millisat_per_vbyte = actual_fee_rate_millisat_per_vbyte;
    manifest.transaction_id = signed.compute_txid().to_string();
    manifest.signed_transaction_hex = serialize_hex(&signed);

    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn parse_secret(value: &str) -> Result<SecretKey> {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let decoded = Zeroizing::new(
            hex::decode(trimmed)
                .map_err(|_| Error::invalid("private key hexadecimal is malformed"))?,
        );
        return SecretKey::from_slice(decoded.as_slice())
            .map_err(|_| Error::invalid("private key is outside the secp256k1 scalar range"));
    }

    PrivateKey::from_wif(trimmed)
        .map(|key| key.inner)
        .map_err(|_| Error::invalid("private key must be valid WIF or 64 hexadecimal characters"))
}

fn maximum_legacy_vsize(inputs: &[PreparedInput], destination_script_len: usize) -> Result<u64> {
    let input_count = u64::try_from(inputs.len())
        .map_err(|_| Error::invalid("input count conversion failed"))?;
    let mut size = 4_u64
        .checked_add(compact_size_len(input_count))
        .ok_or_else(|| Error::invalid("transaction size overflow"))?;

    for input in inputs {
        // Maximum strict-DER signature is 72 bytes, plus one SIGHASH byte and push opcodes.
        let script_sig_len = match input.encoding {
            PubkeyEncoding::Compressed => 1 + 73 + 1 + 33,
            PubkeyEncoding::Uncompressed => 1 + 73 + 1 + 65,
        } as u64;
        let input_size = 36_u64
            .checked_add(compact_size_len(script_sig_len))
            .and_then(|value| value.checked_add(script_sig_len))
            .and_then(|value| value.checked_add(4))
            .ok_or_else(|| Error::invalid("transaction input size overflow"))?;
        size = size
            .checked_add(input_size)
            .ok_or_else(|| Error::invalid("transaction size overflow"))?;
    }

    let script_len = u64::try_from(destination_script_len)
        .map_err(|_| Error::invalid("destination script size conversion failed"))?;
    size = size
        .checked_add(compact_size_len(1))
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(compact_size_len(script_len)))
        .and_then(|value| value.checked_add(script_len))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| Error::invalid("transaction output size overflow"))?;
    Ok(size)
}

fn compact_size_len(value: u64) -> u64 {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn enforce_fee_caps(fee: u64, total: u64, policy: FeePolicy) -> Result<()> {
    if fee > policy.max_absolute_fee_sats {
        return Err(Error::policy(format!(
            "calculated fee of {fee} sats exceeds the absolute cap of {} sats",
            policy.max_absolute_fee_sats
        )));
    }
    let fee_bps = (u128::from(fee) * 10_000_u128) / u128::from(total.max(1));
    if fee_bps > u128::from(policy.max_fee_basis_points) {
        return Err(Error::policy(format!(
            "calculated fee exceeds the configured {} basis-point input-value cap",
            policy.max_fee_basis_points
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute,
        consensus::encode::serialize_hex,
        opcodes, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };

    use super::*;
    use crate::model::{ChainNetwork, UtxoRecord, UTXO_BUNDLE_FORMAT};

    fn fixture(compressed: bool) -> (UtxoBundle, String, String) {
        let network = ChainNetwork::Regtest;
        let secret_bytes = [7_u8; 32];
        let secret = SecretKey::from_slice(&secret_bytes).expect("valid fixture secret");
        let secp = Secp256k1::new();
        let raw_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let public = if compressed {
            PublicKey::new(raw_public)
        } else {
            PublicKey::new_uncompressed(raw_public)
        };
        let source = Address::p2pkh(&public, network.bitcoin_network());
        let destination_secret = SecretKey::from_slice(&[8_u8; 32]).expect("valid fixture secret");
        let destination_public = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp,
            &destination_secret,
        ));
        let destination = Address::p2pkh(&destination_public, network.bitcoin_network());

        let previous = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_1).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: source.script_pubkey(),
            }],
        };
        let bundle = UtxoBundle {
            format: UTXO_BUNDLE_FORMAT.to_owned(),
            version: FORMAT_VERSION,
            network,
            inputs: vec![UtxoRecord {
                previous_transaction_hex: serialize_hex(&previous),
                vout: 0,
                label: Some("fixture".to_owned()),
            }],
        };
        (bundle, hex::encode(secret_bytes), destination.to_string())
    }

    #[test]
    fn signs_and_validates_compressed_p2pkh() {
        let (bundle, secret, destination) = fixture(true);
        let manifest = build_signed_sweep(
            &bundle,
            &secret,
            &destination,
            FeePolicy {
                target_sat_per_vbyte: 12,
                max_absolute_fee_sats: 50_000,
                max_fee_basis_points: 500,
            },
        )
        .expect("sweep");
        assert_eq!(manifest.inputs[0].pubkey_encoding, PubkeyEncoding::Compressed);
        assert_eq!(manifest.output_sats + manifest.fee_sats, manifest.total_input_sats);
        validate_manifest(&manifest).expect("manifest validates");
        let envelope = crate::envelope::encrypt_manifest(&manifest, "correct horse battery")
            .expect("encrypt");
        let recovered = crate::envelope::decrypt_manifest(&envelope, "correct horse battery")
            .expect("decrypt");
        assert_eq!(recovered.transaction_id, manifest.transaction_id);
        assert!(crate::envelope::decrypt_manifest(&envelope, "incorrect password").is_err());
    }

    #[test]
    fn signs_and_validates_uncompressed_p2pkh() {
        let (bundle, secret, destination) = fixture(false);
        let manifest = build_signed_sweep(
            &bundle,
            &secret,
            &destination,
            FeePolicy {
                target_sat_per_vbyte: 12,
                max_absolute_fee_sats: 50_000,
                max_fee_basis_points: 500,
            },
        )
        .expect("sweep");
        assert_eq!(manifest.inputs[0].pubkey_encoding, PubkeyEncoding::Uncompressed);
        validate_manifest(&manifest).expect("manifest validates");
    }

    #[test]
    fn rejects_wrong_private_key() {
        let (bundle, _, destination) = fixture(true);
        let wrong = hex::encode([9_u8; 32]);
        let error = build_signed_sweep(&bundle, &wrong, &destination, FeePolicy::default())
            .expect_err("wrong key must fail");
        assert!(error.to_string().contains("does not pay"));
    }
}

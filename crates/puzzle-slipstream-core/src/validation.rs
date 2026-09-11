use std::{collections::HashSet, str::FromStr};

use bitcoin::{
    address::NetworkUnchecked,
    consensus::{deserialize, serialize},
    hashes::Hash,
    script::Instruction,
    secp256k1::{ecdsa::Signature, Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    Address, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, Txid,
};

use crate::{
    model::{
        PubkeyEncoding, SweepManifest, FORMAT_VERSION, MAX_INPUTS, MAX_MANIFEST_BYTES,
        SWEEP_MANIFEST_FORMAT,
    },
    Error, Result,
};

pub fn manifest_from_json_bounded(json: &str) -> Result<SweepManifest> {
    if json.len() > MAX_MANIFEST_BYTES {
        return Err(Error::invalid("sweep manifest exceeds the 4 MiB limit"));
    }
    let manifest: SweepManifest = serde_json::from_str(json)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Independently parses and verifies the complete signed sweep and its ECDSA signatures.
pub fn validate_manifest(manifest: &SweepManifest) -> Result<()> {
    if manifest.format != SWEEP_MANIFEST_FORMAT || manifest.version != FORMAT_VERSION {
        return Err(Error::invalid("unsupported sweep manifest format or version"));
    }
    manifest.network.ensure_enabled()?;
    if manifest.inputs.is_empty() || manifest.inputs.len() > MAX_INPUTS {
        return Err(Error::invalid("invalid sweep input count"));
    }
    if manifest.signed_transaction_hex.len() > MAX_MANIFEST_BYTES * 2
        || manifest.signed_transaction_hex.len() % 2 != 0
        || !manifest
            .signed_transaction_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::invalid("signed transaction hex is malformed or oversized"));
    }

    let raw = hex::decode(&manifest.signed_transaction_hex)
        .map_err(|_| Error::bitcoin("signed transaction hexadecimal is malformed"))?;
    let transaction: Transaction = deserialize(&raw)
        .map_err(|_| Error::bitcoin("signed transaction cannot be decoded"))?;

    if transaction.compute_txid().to_string() != manifest.transaction_id {
        return Err(Error::policy("manifest transaction ID does not match raw transaction"));
    }
    if transaction.input.len() != manifest.inputs.len() {
        return Err(Error::policy("manifest input count does not match raw transaction"));
    }
    if transaction.output.len() != 1 {
        return Err(Error::policy("sweep transaction must contain exactly one output"));
    }

    let network = manifest.network.bitcoin_network();
    let destination_unchecked = Address::<NetworkUnchecked>::from_str(&manifest.destination_address)
        .map_err(|_| Error::invalid("manifest destination address is malformed"))?;
    let destination = destination_unchecked
        .require_network(network)
        .map_err(|_| Error::policy("manifest destination address is for a different network"))?;
    let output = &transaction.output[0];
    if output.script_pubkey != destination.script_pubkey() {
        return Err(Error::policy("raw transaction output does not pay the reviewed destination"));
    }
    if output.value.to_sat() != manifest.output_sats {
        return Err(Error::policy("manifest output amount does not match raw transaction"));
    }

    let mut seen = HashSet::<OutPoint>::with_capacity(manifest.inputs.len());
    let mut total_input_sats = 0_u64;
    let secp = Secp256k1::verification_only();

    for (index, (txin, input)) in transaction
        .input
        .iter()
        .zip(manifest.inputs.iter())
        .enumerate()
    {
        if txin.sequence != Sequence::MAX {
            return Err(Error::policy(format!(
                "input {} does not use final sequence",
                index + 1
            )));
        }
        if !txin.witness.is_empty() {
            return Err(Error::policy(format!(
                "input {} unexpectedly contains witness data",
                index + 1
            )));
        }

        let txid = Txid::from_str(&input.txid)
            .map_err(|_| Error::invalid(format!("input {} txid is malformed", index + 1)))?;
        let expected_outpoint = OutPoint::new(txid, input.vout);
        if txin.previous_output != expected_outpoint {
            return Err(Error::policy(format!(
                "input {} outpoint differs from the manifest",
                index + 1
            )));
        }
        if !seen.insert(expected_outpoint) {
            return Err(Error::policy("duplicate outpoint in sweep manifest"));
        }

        let script_bytes = hex::decode(&input.script_pubkey_hex).map_err(|_| {
            Error::invalid(format!("input {} scriptPubKey is malformed", index + 1))
        })?;
        if script_bytes.len() > 10_000 {
            return Err(Error::invalid(format!(
                "input {} scriptPubKey exceeds the policy limit",
                index + 1
            )));
        }
        let previous_script = ScriptBuf::from_bytes(script_bytes);
        if !previous_script.is_p2pkh() {
            return Err(Error::policy(format!(
                "input {} is not a legacy P2PKH output",
                index + 1
            )));
        }

        let (signature, public_key) = parse_p2pkh_script_sig(&txin.script_sig, index)?;
        let encoding = if public_key.compressed {
            PubkeyEncoding::Compressed
        } else {
            PubkeyEncoding::Uncompressed
        };
        if encoding != input.pubkey_encoding {
            return Err(Error::policy(format!(
                "input {} public-key encoding differs from the manifest",
                index + 1
            )));
        }

        let source_address = Address::p2pkh(&public_key, network);
        if source_address.to_string() != input.source_address
            || source_address.script_pubkey() != previous_script
        {
            return Err(Error::policy(format!(
                "input {} public key does not match the selected previous output",
                index + 1
            )));
        }

        let sighash = SighashCache::new(&transaction)
            .legacy_signature_hash(
                index,
                previous_script.as_script(),
                EcdsaSighashType::All.to_u32(),
            )
            .map_err(|_| Error::bitcoin("failed to calculate legacy signature hash"))?;
        let message = Message::from_digest(sighash.to_byte_array());
        secp.verify_ecdsa(&message, &signature, &public_key.inner)
            .map_err(|_| {
                Error::crypto(format!("input {} ECDSA signature is invalid", index + 1))
            })?;

        total_input_sats = total_input_sats
            .checked_add(input.value_sats)
            .ok_or_else(|| Error::invalid("input amount overflow"))?;
    }

    if total_input_sats != manifest.total_input_sats {
        return Err(Error::policy("manifest input total is inconsistent"));
    }
    let fee_sats = total_input_sats
        .checked_sub(output.value.to_sat())
        .ok_or_else(|| Error::policy("output amount exceeds input total"))?;
    if fee_sats != manifest.fee_sats {
        return Err(Error::policy("manifest fee does not match transaction amounts"));
    }

    let actual_vsize = serialize(&transaction).len() as u64;
    if actual_vsize != manifest.actual_vsize {
        return Err(Error::policy("manifest vsize does not match raw transaction"));
    }
    let actual_rate = fee_sats
        .checked_mul(1000)
        .ok_or_else(|| Error::invalid("fee-rate calculation overflow"))?
        / actual_vsize.max(1);
    if actual_rate != manifest.actual_fee_rate_millisat_per_vbyte {
        return Err(Error::policy("manifest fee rate is inconsistent"));
    }
    Ok(())
}

fn parse_p2pkh_script_sig(script: &ScriptBuf, index: usize) -> Result<(Signature, PublicKey)> {
    let instructions = script
        .instructions_minimal()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| {
            Error::bitcoin(format!("input {} scriptSig is non-minimal or malformed", index + 1))
        })?;
    if instructions.len() != 2 {
        return Err(Error::policy(format!(
            "input {} scriptSig must contain exactly signature and public-key pushes",
            index + 1
        )));
    }

    let signature_push = match &instructions[0] {
        Instruction::PushBytes(bytes) => bytes.as_bytes(),
        Instruction::Op(_) => {
            return Err(Error::policy(format!(
                "input {} signature is not a direct data push",
                index + 1
            )))
        }
    };
    if signature_push.len() < 9 {
        return Err(Error::crypto(format!(
            "input {} signature push is too short",
            index + 1
        )));
    }
    let (&sighash_type, der) = signature_push
        .split_last()
        .ok_or_else(|| Error::crypto("signature push is empty"))?;
    if sighash_type != EcdsaSighashType::All.to_u32() as u8 {
        return Err(Error::policy(format!(
            "input {} does not use SIGHASH_ALL",
            index + 1
        )));
    }
    let signature = Signature::from_der(der)
        .map_err(|_| Error::crypto(format!("input {} signature DER is invalid", index + 1)))?;

    let public_key_push = match &instructions[1] {
        Instruction::PushBytes(bytes) => bytes.as_bytes(),
        Instruction::Op(_) => {
            return Err(Error::policy(format!(
                "input {} public key is not a direct data push",
                index + 1
            )))
        }
    };
    let public_key = PublicKey::from_slice(public_key_push)
        .map_err(|_| Error::crypto(format!("input {} public key is invalid", index + 1)))?;
    Ok((signature, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_manifest_header() {
        let manifest = SweepManifest::new_base(
            crate::model::ChainNetwork::Regtest,
            "not-an-address".to_owned(),
        );
        let error = validate_manifest(&manifest).expect_err("empty manifest must fail");
        assert!(error.to_string().contains("input count"));
    }
}

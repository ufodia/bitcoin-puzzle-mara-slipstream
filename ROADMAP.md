# Roadmap

Roadmap items do not imply a release date or security guarantee.

## Before beta

- Independent review of P2PKH transaction construction and signature verification.
- Confirm the current MARA production endpoint, request schema, terms, rate limits, and response semantics against official documentation.
- Reproducible Windows and Linux release builds with signed checksums and provenance.
- Expanded Regtest vectors: multiple inputs, mixed compressed/uncompressed source addresses from one scalar, large CompactSize boundaries, malformed DER, duplicate outpoints, fee caps, and tampered envelopes.
- Memory/crash-dump review on Windows 11 and Linux.
- Hardware-assisted air-gap transfer guidance and deterministic release attestations.

## Candidate improvements

- Animated multi-frame QR transport for envelopes too large for one QR code.
- Optional camera scanning in the Relay without adding camera code to the Signer.
- Multiple reviewed private-relay adapters with an explicit one-at-a-time selection and no fallback.
- Bitcoin Core descriptor-assisted UTXO bundle export.
- Local-only fee estimation snapshots imported from the online machine.
- Internationalized documentation after the English security terminology stabilizes.

## Permanently out of scope

- Bitcoin Puzzle solving, brute force, key-space scanning, kangaroo/BSGS engines, or private-key recovery.
- Adversarial RBF, transaction interception, public-mempool monitoring, or capture of another party's funds.
- Automatic public broadcast or “try every relay” behavior.

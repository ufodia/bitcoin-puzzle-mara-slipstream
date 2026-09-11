# Changelog

All notable changes are documented here. This project follows Semantic Versioning once it leaves alpha.

## [0.1.0-alpha.1] - 2026-09-12

### Added

- Offline native Signer for WIF or 32-byte hexadecimal legacy keys.
- Full previous-transaction verification and automatic compressed/uncompressed P2PKH matching.
- One-output, no-change sweep construction with `SIGHASH_ALL`, final sequence, low-S ECDSA signatures, absolute fee cap, and percentage fee cap.
- Independent signed-transaction validation in the online Relay.
- Argon2id + XChaCha20-Poly1305 `.swe` envelopes and `PSW1:` transport text.
- MARA Slipstream production adapter isolated behind mainnet compile and runtime gates.
- Loopback-only mock relay, Bitcoin Core `testmempoolaccept`, and destination confirmation checks.
- English Iced GUIs, JSON Schemas, threat model, security policy, CI, dual open-source license, and donation information.

### Security status

Alpha, unaudited, and not approved for valuable mainnet use.

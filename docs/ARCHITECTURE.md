# Architecture

## Components

### `puzzle-slipstream-core`

Feature-separated Rust library:

- `model`: versioned JSON types and bounded parsers;
- `signing`: offline P2PKH transaction construction and ECDSA signing;
- `validation`: independent manifest and signature verification;
- `envelope`: Argon2id + XChaCha20-Poly1305 transfer container;
- `relay` (`network` feature): MARA and loopback mock submission;
- `rpc` (`network` feature): loopback-only Bitcoin Core policy/confirmation RPC.

### `puzzle-slipstream-signer`

Native Iced GUI. Its dependency declaration enables only the core library's `signer` feature. CI runs `scripts/check-signer-boundary.py` to reject network dependencies in the Signer dependency tree and source imports.

### `puzzle-slipstream-relay`

Native Iced GUI. It enables core `network` support and can access only compiled private-relay profiles plus loopback Bitcoin Core.

## Data flow

```text
Own Bitcoin Core
    │ full previous tx hex
    ▼
UTXO bundle JSON ──► Offline Signer ──► encrypted .swe / PSW1 text
                                              │
                                              ▼
                                      Online Relay
                                      ├─ local verification
                                      ├─ optional loopback testmempoolaccept
                                      └─ MARA Slipstream submission
```

## No shared private-key type

The private key is parsed inside the offline signing function. It is not stored in the manifest, envelope, Relay model, or serialized error. GUI input is zeroized immediately after each attempt.

## Mainnet gate

`ChainNetwork::Mainnet` exists in the data model so the format is stable, but `ensure_enabled()` rejects it unless the library was compiled with the `mainnet` feature. Both binaries propagate the feature and add separate typed runtime confirmations.

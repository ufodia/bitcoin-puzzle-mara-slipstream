# Build and release guide

## Reproducible intent

The repository pins all resolved Rust dependencies in `Cargo.lock`. Release artifacts should be produced from a signed Git tag on a clean GitHub-hosted runner or a documented clean local environment.

## Local verification

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release --workspace
```

Mainnet compile check:

```bash
cargo build --release --workspace --features mainnet
```

## Windows package

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package-windows.ps1
```

The package script copies the two executables, README, licenses, threat model, disclaimer, and checksum file into `dist/`.

## Source release

```bash
bash scripts/package-source.sh
```

Never include `target/`, `.swe`, `.env`, Bitcoin Core cookie files, private keys, WIFs, logs, or captured production responses.

## Release gates

A valuable-mainnet release should remain blocked until all of the following are independently evidenced:

- external review of transaction construction and signature verification;
- review of the exact MARA API preset and TLS behavior;
- dependency and supply-chain review;
- Windows and Linux clean-room builds;
- Regtest multi-input vectors for compressed and uncompressed P2PKH;
- Testnet4 end-to-end operational rehearsal;
- memory, crash-dump, logging, clipboard, and file-remanence review;
- signed tags, checksums, SBOM, and provenance attestation.

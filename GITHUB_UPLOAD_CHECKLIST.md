# GitHub upload checklist

1. Create an empty public repository named `bitcoin-puzzle-mara-slipstream`.
2. Use this description:

   > Offline-first Rust GUI for safely sweeping authorized Bitcoin Puzzle P2PKH keys through MARA Slipstream without public mempool broadcast.

3. Extract the source ZIP and upload the **contents of the repository folder**, not the outer folder itself.
4. Confirm that the root `Cargo.toml` points to `https://github.com/ufodia/bitcoin-puzzle-mara-slipstream`.
5. Keep GitHub Actions enabled and inspect the first CI and supply-chain runs.
6. Enable GitHub Security Advisories and private vulnerability reporting.
7. Protect the `main` branch and require CI before merge.
8. Add repository topics from `REPOSITORY.md`.
9. Publish the first release as `v0.1.0-alpha.1`, source-only, and keep the unaudited warning prominent.
10. Do not upload `.swe` files, raw valuable transactions, keys, WIFs, seeds, Bitcoin Core cookies, API credentials, logs containing sensitive data, or compiled binaries from an untrusted machine.

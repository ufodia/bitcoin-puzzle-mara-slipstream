## Purpose

Describe the defensive, authorized-use problem this change solves.

## Security impact

- [ ] No private-key, seed, WIF, valuable raw transaction, API credential, or cookie is included.
- [ ] The offline Signer has no new network code path.
- [ ] No public-broadcast or automatic fallback path was added.
- [ ] Destination, amount, fee, network, and transaction ID remain explicitly reviewable.
- [ ] Mainnet still requires compile-time and typed runtime gates.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `python scripts/check-signer-boundary.py`
- [ ] `cargo test --workspace`
- [ ] `cargo check --release --workspace --features mainnet`
- [ ] New behavior has Regtest tests.
- [ ] Documentation and threat model were updated.

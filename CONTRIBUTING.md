# Contributing

Contributions are welcome when they preserve the defensive, authorized-use scope.

## Before opening a pull request

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets
```

Use Regtest fixtures. Never commit mainnet private keys, WIFs, seeds, signed pre-confirmation transactions, API credentials, `.swe` files, or personal Bitcoin Core cookies.

## Architectural rules

- The Signer package may not depend on HTTP, DNS, RPC, or relay crates.
- The core `signing` module may not import the `relay` or `rpc` modules.
- No public broadcast provider may be added, even as a fallback.
- New relay endpoints must be compiled constants and separately reviewed.
- Mainnet remains opt-in at compile time and at runtime.
- All changes to transaction construction require deterministic tests.
- UI text and documentation are written in English.

## Pull-request checklist

- [ ] The change is for authorized defensive use.
- [ ] No private key or raw valuable transaction appears in tests or logs.
- [ ] Destination, amount, fee, network, and transaction ID remain reviewable.
- [ ] The signer still builds without network dependencies.
- [ ] Malformed and oversized inputs fail closed.
- [ ] Regtest tests cover the new behavior.
- [ ] Security and threat-model documents were updated when needed.

# Security policy

## Supported versions

Only the latest tagged release and the current default branch are considered for security fixes. The project is pre-audit alpha software; “supported” does not mean safe for valuable mainnet use.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could expose keys, redirect transactions, leak pre-confirmation raw transactions, bypass mainnet gates, or alter fee/destination review.

Create a private GitHub Security Advisory for the repository. Include:

- affected commit and platform;
- minimal reproduction using Regtest or Testnet4 only;
- expected and actual behavior;
- whether secrets or signed raw transactions were exposed;
- a suggested fix, if available.

Do **not** include a live private key, seed phrase, WIF, valuable raw transaction, API credential, or real puzzle solution. Maintainers will never ask for one.

## Scope priorities

1. private-key exposure from the Signer;
2. destination or amount substitution;
3. signature or prevout validation bypass;
4. public broadcast, redirect, DNS/proxy, or endpoint bypass;
5. envelope authentication or KDF weakness;
6. mainnet feature-gate bypass;
7. denial of service from malformed input.

## Not accepted

Requests to add brute-force, key-range scanning, adversarial RBF, transaction interception, or fund-capture functionality are outside project scope.

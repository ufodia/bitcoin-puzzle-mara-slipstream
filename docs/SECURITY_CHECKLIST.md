# Operator security checklist

## Before building

- [ ] The exact source commit has been reviewed.
- [ ] `Cargo.lock` is present and dependency changes were inspected.
- [ ] The build machine is clean and trusted.
- [ ] Regtest tests and the offline-boundary check pass.
- [ ] Mainnet is not enabled for routine testing.

## Offline Signer

- [ ] Wi-Fi, Ethernet, Bluetooth, cellular, cloud clipboard, telemetry, crash upload, remote access, and shared folders are disabled.
- [ ] The UTXO bundle came from your own node and contains complete previous transactions.
- [ ] The displayed source address exactly matches the authorized Bitcoin Puzzle address.
- [ ] Compressed or uncompressed public-key encoding is expected.
- [ ] Every intended UTXO is present exactly once.
- [ ] Destination is verified independently on the receiving wallet.
- [ ] Fee rate and both fee caps are deliberate.
- [ ] Transaction has one output and no change.
- [ ] Transaction ID and amounts are recorded offline.
- [ ] A unique strong transfer passphrase is used.

## Online Relay

- [ ] No private key is entered or present on the computer.
- [ ] Relay summary exactly matches the offline record.
- [ ] Local `testmempoolaccept` succeeds or the reason for bypass is documented.
- [ ] The compiled MARA endpoint and request schema match current official documentation.
- [ ] No VPN, proxy, TLS interception, EDR upload, remote access, or clipboard monitor can leak the transaction.
- [ ] “Relay accepted” is not treated as confirmation.
- [ ] Confirmation is observed through a trusted Bitcoin Core node.

## Stop

- [ ] Stop on any mismatch, unexpected redirect, endpoint/API drift, fee anomaly, source-address mismatch, signature error, or uncertainty about authorization.

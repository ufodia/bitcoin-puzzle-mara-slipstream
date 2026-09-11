# User guide

## 1. Understand the boundary

PuzzleSlipstream does not hide a P2PKH public key from MARA or a miner. It keeps the signed transaction away from ordinary public-broadcast code paths in this application. The transaction may still leak through a compromised computer, transfer medium, relay, miner, network, or operator action.

## 2. Prepare two computers

### Offline Signer computer

- Prefer a clean installation dedicated to signing.
- Verify source and build dependencies before disconnecting it.
- Disable Wi-Fi, Bluetooth, Ethernet, cellular, virtualization sharing, cloud clipboard, crash upload, telemetry, and remote-management software.
- Never reconnect it after entering a valuable private key unless your operating procedure explicitly accounts for that risk.

### Online Relay computer

- Keep it patched and free of browser extensions, clipboard utilities, and remote-access tools.
- Prefer your own Bitcoin Core node on the same computer or trusted local network; the application itself permits RPC only to literal loopback.
- Do not open the `.swe` file in unrelated tools.

## 3. Create a UTXO bundle

Use complete previous transaction hex from your own node. Do not trust a copied amount or source address. The Signer computes those fields itself.

Follow [CREATING_UTXO_BUNDLE.md](CREATING_UTXO_BUNDLE.md), then move the JSON file to the offline computer.

## 4. Sign offline

1. Open **PuzzleSlipstream Signer**.
2. Select the correct network.
3. Load the UTXO bundle.
4. Enter the private key as WIF or exactly 64 hexadecimal characters.
5. Enter the destination address. Prefer a newly verified hardware-wallet address.
6. Set the target fee rate, absolute fee cap, and fee-percentage cap.
7. For a mainnet-capable build, type `SWEEP MAINNET`.
8. Confirm that you own or are authorized to spend every input.
9. Select **Build, sign & verify**.
10. Compare the displayed source address, destination, input total, output amount, fee, vsize, and transaction ID.
11. Enter a strong one-time transfer passphrase and export a `.swe` file.
12. The private-key field is zeroized and cleared after the attempt. Close the application and follow your key-destruction or archival policy.

The Signer intentionally refuses partial sends and change. To retain value, move the entire authorized UTXO set to a destination wallet you control, then split it after confirmation using that wallet.

## 5. Validate and submit online

1. Open **PuzzleSlipstream Relay**.
2. Load the encrypted `.swe` file or paste its `PSW1:` transport text.
3. Enter the one-time transfer passphrase.
4. Select **Decrypt & independently verify**.
5. Compare all displayed values with the offline review.
6. Configure the optional loopback Bitcoin Core cookie and RPC port.
7. Run **Local policy check**. This calls `testmempoolaccept` on `127.0.0.1` and does not broadcast.
8. For a production mainnet submission, type `SUBMIT TO MARA` and acknowledge the relay/miner visibility warning.
9. Select **Submit privately** once. Do not submit to multiple services unless your reviewed procedure explicitly permits it.

## 6. Interpret statuses

- **Envelope verified:** local structure and ECDSA checks passed.
- **Local policy accepted:** your own Bitcoin Core node currently accepts the transaction under its mempool policy; nothing was broadcast.
- **Relay accepted — not confirmed:** MARA's HTTP endpoint returned success. This does not prove miner acceptance or inclusion.
- **Confirmed:** your own node reports confirmations for output zero.

## 7. Stop conditions

Stop immediately if:

- the source address is not the expected puzzle address;
- compressed/uncompressed encoding is unexpected;
- any input is missing or duplicated;
- the destination differs by one character;
- the fee or output amount is unexpected;
- the Relay summary differs from the Signer summary;
- the endpoint, TLS behavior, source revision, or binary checksum is uncertain;
- antivirus, EDR, remote access, clipboard monitoring, or network interception is present;
- MARA's documented API contract differs from the adapter in this revision.

Never “test” a valuable key by pasting it into the online Relay, a website, an explorer, a chat, an issue, or a support request.

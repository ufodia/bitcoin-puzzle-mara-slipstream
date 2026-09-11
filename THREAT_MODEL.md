# Threat model

## Goal

Move all value from authorized legacy P2PKH UTXOs controlled by one private key to one user-selected destination while reducing pre-confirmation exposure in the public mempool.

## Trust boundaries

### Offline Signer

The private key, previous transactions, destination, and fee policy enter this boundary. The Signer must not have a network code path. Its only intended output is an encrypted sweep envelope or QR representation of that envelope.

### Transfer medium

USB media, QR images, and copied encrypted transport text are considered attacker-controlled. Confidentiality and integrity rely on Argon2id-derived XChaCha20-Poly1305 authenticated encryption and a strong transfer passphrase.

### Online Relay

The Relay receives only the encrypted envelope and passphrase. After decryption, the raw signed transaction is sensitive until mined. The Relay may send it only to a compiled private-relay preset or a literal loopback test endpoint.

### MARA / miner boundary

MARA and any downstream miner necessarily receive the full transaction. They can see the public key in every P2PKH input. They are not trusted with the private key, but they are trusted not to leak or misuse the transaction before inclusion. This trust cannot be removed by client software.

## In-scope adversaries

- public-mempool watchers competing after a public key is revealed;
- malware modifying destination, amount, UTXO selection, or fee;
- malicious files and oversized JSON inputs;
- accidental public broadcast or proxy routing;
- HTTP redirects to an unapproved host;
- replay or tampering during offline-to-online transfer;
- operator mistakes involving compressed versus uncompressed P2PKH keys;
- excessive fees or leaving change behind;
- a compromised online Relay computer.

## Out-of-scope / not solved

- a compromised offline OS, BIOS, firmware, CPU, RNG, or compiler;
- side-channel extraction from the signing computer;
- a private key already known to an attacker;
- a malicious or compromised MARA/miner infrastructure;
- censorship, reorganization, or guaranteed block inclusion;
- quantum attacks or a key-space search completed before confirmation;
- legal authority to claim or spend a particular puzzle output;
- cryptographic weaknesses in secp256k1, Bitcoin consensus, Argon2id, or XChaCha20-Poly1305.

## Required invariants

1. Full previous transactions are parsed and their computed transaction IDs are used.
2. Every selected output script matches the compressed or uncompressed P2PKH address derived from the supplied private key.
3. Every selected UTXO is included exactly once.
4. The transaction has exactly one output: the reviewed destination.
5. There is no change output.
6. Every input uses final sequence and an empty witness.
7. Every signature uses `SIGHASH_ALL` and verifies against the selected prevout script.
8. The fee stays below both an absolute cap and a percentage cap.
9. The Relay revalidates all structural and signature invariants.
10. Production relay submission never redirects, uses no environment proxy, and has no public fallback.

## RBF statement

Final sequence communicates that the transaction does not opt in to BIP125 signaling. It is not treated as a security boundary. Nodes and miners can apply replacement policies independent of that signal, and anyone who possesses the private key can create a conflicting transaction. The defense is private delivery, rapid inclusion, sufficient fee, and sweeping every authorized UTXO at once—not an “RBF-proof” flag.

## Residual risk decision

The application deliberately labels a successful HTTP response as **Relay accepted — not confirmed**. Only a block confirmation observed through a trusted node changes that status.

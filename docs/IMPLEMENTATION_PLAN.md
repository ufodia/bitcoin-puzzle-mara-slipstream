# Approved implementation plan

> Repository implementation name: **PuzzleSlipstream**. This plan is retained as the design baseline for version `0.1.0-alpha.1`. Where the code and plan differ, the stricter fail-closed behavior takes precedence and the difference must be reviewed.

# PuzzleSlipstream — Security and Implementation Plan

**Working title:** PuzzleSlipstream  
**Product:** Private-miner Bitcoin sweep tool for high-risk legacy P2PKH funds  
**Primary platform:** Windows 11 x64  
**UI language:** English only for v1  
**Plan date:** 11 September 2026  
**Status:** Planning baseline — implementation should follow the security gates in this document

---

## 1. Executive decision

PuzzleSlipstream will be an offline-first desktop application that creates an **all-funds, one-output, no-change P2PKH sweep transaction**, signs it locally, and submits the signed raw transaction directly to a private miner relay such as **MARA Slipstream**, without first broadcasting it to the public Bitcoin mempool.

The safest v1 design is two separate executables built from one Rust workspace:

1. **PuzzleSlipstream Signer** — offline; contains private-key and transaction-signing code; contains no HTTP or networking dependency.
2. **PuzzleSlipstream Relay** — online; contains MARA/private-relay code; never accepts, parses, stores, or requests a private key.

An integrated one-device edition may be added later, but it must not be the security-default build.

### Core protection model

```text
Private key / puzzle solution
          │
          ▼
Offline Signer ── creates + verifies signed sweep ──► protected QR/file
                                                        │
                                                        ▼
Online Relay ── direct HTTPS submission ──► MARA private mempool
                                                        │
                                                        ▼
                                              Included in MARA block
                                                        │
                                                        ▼
                                            Public only after confirmation
```

This reduces the public interval-ECDLP/RBF race by keeping the signed transaction out of the public mempool before confirmation.

---

## 2. Critical technical correction

The product must never claim that it creates a legacy spend “without a public key.”

A standard P2PKH input necessarily contains:

```text
scriptSig = <ECDSA signature> <public key>
```

Therefore:

- The selected private relay/miner can read the public key.
- The public key becomes public to the entire network when the transaction is included in a block.
- PuzzleSlipstream’s guarantee is narrower and accurate: **the signed transaction is not intentionally published to the public mempool before miner confirmation.**
- This is a trust-reduction mechanism, not a cryptographic guarantee against a malicious or compromised relay operator.

For a normal uniformly random 256-bit private key, public-key exposure does not make key recovery practical. The special risk here is a puzzle or weak-key scenario where the private key is known to lie in a sufficiently small interval; public-key exposure can then enable a Pollard kangaroo/interval-ECDLP race.

---

## 3. Product objective

PuzzleSlipstream should let an authorized user move funds from a vulnerable legacy P2PKH address to a fresh, strong destination address with minimal exposure and minimal opportunity for a competing replacement transaction.

The application must:

- accept one WIF or 32-byte hexadecimal private key;
- derive compressed and uncompressed public-key/address candidates;
- prove that exactly one candidate matches the source P2PKH script;
- validate every selected UTXO against that script;
- spend all validated UTXOs in one transaction;
- create exactly one user output and no change output;
- use `SIGHASH_ALL` and locally verify every signature;
- calculate the exact serialized size and effective fee rate after signing;
- prevent public-mempool fallback in Critical Sweep mode;
- send the raw transaction only to the explicitly selected private relay;
- distinguish relay acceptance from blockchain confirmation;
- erase private-key and signed-transaction material as soon as operationally possible.

---

## 4. Explicit non-goals

PuzzleSlipstream v1 will not:

- search for, derive, crack, brute-force, or solve third-party private keys;
- include a kangaroo, Pollard rho, BSGS, or puzzle-solving engine;
- scan arbitrary addresses looking for vulnerable balances;
- broadcast through ordinary public Bitcoin P2P peers, public explorer APIs, or public broadcast websites;
- manage a reusable wallet, seed phrase, HD wallet, or address book;
- create change outputs;
- support CoinJoin, payjoin, Lightning, inscriptions, multisig, P2SH, P2WSH, or Taproot inputs;
- import a private key into Bitcoin Core or another wallet;
- promise protection against a malicious miner, relay compromise, local malware, chain reorganization, or already-exposed public keys;
- describe “relay accepted” as “safe,” “complete,” or “confirmed.”

The tool is for funds the operator is legally authorized to spend, including a legitimately solved public puzzle reward.

---

## 5. Threat model

### 5.1 Assets to protect

- The source private key.
- The signed raw transaction before confirmation, because it contains the public key.
- The exact puzzle/source identity before confirmation.
- The destination address against substitution.
- Correct UTXO values and fee calculations.

### 5.2 Primary adversaries

1. **Public-mempool watcher**  
   Watches new P2PKH spends, extracts the public key, solves the bounded interval, and broadcasts a higher-fee conflict.

2. **Clipboard or UI malware**  
   Replaces the destination address or captures the private key.

3. **Compromised online computer**  
   Reads a signed transaction imported into the relay app and starts an interval attack before submission/confirmation.

4. **Compromised private relay/miner**  
   Reads the public key from the submitted transaction or leaks it to another party.

5. **API or DNS/TLS attacker**  
   Redirects submission, downgrades security, alters fee information, or returns false status information.

6. **Operator error**  
   Uses the wrong key-compression form, omits a UTXO, chooses a wrong-network destination, underpays the fee, or assumes relay acceptance means confirmation.

7. **Software supply-chain attacker**  
   Introduces secret logging, dependency compromise, updater compromise, or a modified binary.

### 5.3 Out-of-scope residual risks

- A public key that was already exposed by an earlier spend.
- A relay operator that intentionally steals or leaks the transaction.
- Malware with administrator/kernel access on the signing machine.
- Physical compromise of the air-gapped computer.
- A miner producing a conflicting block or a later chain reorganization.
- A puzzle interval so small that the selected relay can solve it before creating a block.

---

## 6. Security invariants

These are hard requirements, not preferences.

### SI-01 — No public fallback

Critical Sweep mode must contain no public broadcast button, hidden fallback, retry route, explorer relay, Bitcoin P2P relay, or `sendrawtransaction` call to a public node.

### SI-02 — Offline signer has no networking code

The signer binary’s dependency graph must not include HTTP, DNS, sockets, telemetry, update, browser, or analytics libraries. CI must fail if a network dependency appears.

### SI-03 — Relay has no private-key code

The relay binary must not link the secret-key parsing/signing module. It accepts only a protected sweep envelope or raw signed transaction.

### SI-04 — Exact source match

Signing is impossible until the derived compressed or uncompressed P2PKH script exactly equals every input’s previous-output script.

### SI-05 — All funds, one output, no change

Critical Sweep mode must create exactly one transaction output:

```text
output_value = sum(actual_input_values) - exact_transaction_fee
```

No source-address reuse and no change output are permitted.

### SI-06 — No secret persistence

Private keys, WIF strings, raw key bytes, public keys, unsigned signing payloads, signed raw transactions, and protected-envelope passwords are never written to logs, settings, crash reports, temporary files, recent-file lists, or automatic backups.

### SI-07 — Fail closed

Unknown scripts, malformed UTXOs, stale/unknown fee data, relay API schema changes, TLS errors, amount mismatch, status ambiguity, or failed local signature verification must stop the workflow.

### SI-08 — Accepted is not confirmed

The UI must use separate states and language:

```text
Relay Accepted — Not Confirmed
Mined — 1 Confirmation
Confirmed — N Confirmations
```

### SI-09 — Full-RBF is acknowledged

Inputs may use final sequence numbers to avoid explicit opt-in signaling, but the UI and documentation must state that modern full-RBF policy means this is not a theft-prevention guarantee.

### SI-10 — The signed transaction is sensitive until confirmed

The signer and relay must treat raw transaction data as confidential during transfer and while waiting for confirmation.

---

## 7. Recommended implementation stack

### 7.1 Language and GUI

- **Rust** for all transaction, cryptography, networking, and application logic.
- **iced** for an all-Rust native desktop GUI.
- No JavaScript runtime and no embedded browser/WebView in the signer.
- Windows 11 x64 is the first release target; Linux can follow after the Windows security model is stable.

### 7.2 Core dependencies

Exact versions should be pinned at implementation time after audit.

- `bitcoin` / rust-bitcoin — addresses, scripts, transaction serialization, sighash helpers.
- `secp256k1` — deterministic ECDSA signing and verification.
- `zeroize` and `secrecy` — secret containers and memory clearing.
- `iced` — native GUI.
- `serde` and `serde_json` — non-secret configuration and envelopes.
- `reqwest` with `rustls` — relay HTTPS, in relay binary only.
- `tokio` — relay async runtime only.
- `thiserror` — typed error handling.
- `tracing` with a mandatory redaction layer — non-secret diagnostics only.
- `argon2` and `chacha20poly1305` — optional protected transfer envelope.
- `qrcode` plus a camera/QR decoder — offline-to-online transfer.
- `windows` crate — Windows memory locking, clipboard clearing, screen-capture mitigation, and process-hardening hooks where practical.

### 7.3 Why not Python or Electron for the signing core

A Python or Electron prototype would be faster, but it creates a larger runtime and secret-handling surface. For a tool whose only purpose is protecting a high-risk private key, a small native Rust signer is the preferred baseline.

---

## 8. Repository and binary architecture

```text
puzzleslipstream/
├─ Cargo.toml                         # workspace only
├─ Cargo.lock                         # committed and reviewed
├─ crates/
│  ├─ domain/                         # non-secret shared data types
│  ├─ bitcoin-core/                   # address/script/tx construction
│  ├─ key-vault/                      # private-key parsing + zeroization
│  ├─ signer-engine/                  # P2PKH sighash/sign/verify
│  ├─ envelope/                       # QR/file transfer format
│  ├─ relay-interface/                # PrivateRelay trait + normalized states
│  ├─ relay-mara/                     # MARA API adapter; relay build only
│  ├─ node-rpc/                       # optional local Bitcoin Core adapter
│  ├─ secure-ui/                      # redacted widgets and confirmation controls
│  └─ test-vectors/                   # deterministic fixtures; no real keys
├─ apps/
│  ├─ signer/                         # puzzleslipstream-signer.exe
│  ├─ relay/                          # puzzleslipstream-relay.exe
│  └─ dev-regtest/                    # non-production integration harness
├─ tests/
│  ├─ unit/
│  ├─ property/
│  ├─ fuzz/
│  ├─ regtest/
│  ├─ api-contract/
│  └─ secret-leak/
├─ docs/
│  ├─ THREAT_MODEL.md
│  ├─ SECURITY_INVARIANTS.md
│  ├─ RELEASE_CHECKLIST.md
│  └─ USER_GUIDE.md
└─ scripts/
   ├─ verify-signer-no-network.ps1
   ├─ verify-relay-no-key-code.ps1
   ├─ reproduce-build.ps1
   └─ run-regtest.ps1
```

### Dependency boundaries

```text
Signer application
  ├── bitcoin-core
  ├── key-vault
  ├── signer-engine
  ├── envelope
  └── secure-ui
  X── no relay-mara
  X── no reqwest/tokio/network stack

Relay application
  ├── bitcoin-core (decode/validate only)
  ├── envelope
  ├── relay-interface
  ├── relay-mara
  └── secure-ui
  X── no key-vault
  X── no signer-engine
```

---

## 9. Supported transaction scope for v1

### Source

- Mainnet legacy P2PKH address only for production.
- Testnet4, signet, and regtest enabled in test/development builds.
- One private key per sweep.
- WIF compressed, WIF uncompressed, or exactly 32-byte hexadecimal scalar.
- One or more confirmed UTXOs, all locked to the same matching P2PKH script.

### Destination

A fresh address controlled outside PuzzleSlipstream:

- P2WPKH recommended;
- P2TR supported;
- P2PKH supported but not recommended;
- address network must exactly match the selected network.

PuzzleSlipstream never asks for the destination private key.

### Transaction policy

- Transaction version: `2`.
- Locktime: `0` in v1.
- Sequence: `0xffffffff` for every input.
- Sighash: `SIGHASH_ALL` only.
- ECDSA: strict DER and low-S.
- Exactly one output.
- No change.
- No data output.
- No unconfirmed inputs in Critical Sweep mode.

Sequence finality is retained as a conservative construction choice, but must not be presented as protection against full-RBF replacement.

---

## 10. Private-key import and source verification

### 10.1 Accepted formats

- Mainnet/testnet WIF.
- Raw 64-character hexadecimal secret scalar.
- Optional secure QR scan on the offline signer.

Never accept a private key as a command-line argument, URL, environment variable, configuration value, or support bundle.

### 10.2 Compression handling

For WIF:

- respect its compressed/uncompressed marker;
- derive the corresponding public key and P2PKH address;
- still display the alternative address as a diagnostic only, without allowing accidental selection.

For raw hexadecimal:

- derive both compressed and uncompressed public keys;
- derive both P2PKH addresses;
- compare both against the provided source address and every input script;
- automatically select only the exact match;
- abort if neither or both match unexpectedly.

### 10.3 Key verification output

The UI may show:

- source address;
- compression mode;
- HASH160 fingerprint, abbreviated;
- `Key matches source` badge.

The UI must not redisplay the private key after verification. A deliberate “Clear and re-enter key” action is safer than a reveal toggle.

---

## 11. UTXO acquisition and verification

Public blockchain explorers are disabled in Critical Sweep mode because queries can reveal intent and because untrusted amount data can produce catastrophic fee mistakes.

### Mode A — Local Bitcoin Core, recommended

The online preparation tool or a separate watch-only helper can obtain:

- txid;
- vout;
- exact value in satoshis;
- scriptPubKey;
- confirmation count;
- block hash/height when available;
- full previous transaction for offline verification.

Use local RPC methods such as `gettxout`, `getrawtransaction`, and descriptor/UTXO scanning as appropriate. RPC credentials must never be passed to the signer.

### Mode B — Offline UTXO bundle

The relay/preparation app exports an unsigned bundle containing full previous transactions and outpoint metadata. The signer:

1. recomputes every previous transaction ID;
2. locates the specified vout;
3. reads the output value directly from the previous transaction;
4. verifies the exact scriptPubKey against the derived P2PKH source script;
5. rejects duplicates or malformed transactions.

The signer cannot independently prove that an output remains unspent without trusted chain state, so the bundle must include a visible “Unspent state checked at block N / time T” field.

### Mode C — Manual advanced entry

Manual input is hidden behind an Advanced warning. It requires:

- txid;
- vout;
- value in satoshis;
- scriptPubKey;
- preferably the full previous transaction.

If full previous-transaction data is absent, production signing should require an explicit high-risk typed confirmation.

### Mandatory checks

- Every UTXO is confirmed.
- Every outpoint is unique.
- Every previous transaction ID is correct when raw previous transaction is supplied.
- Every previous output value is positive and within Bitcoin money range.
- Every script is exactly the source P2PKH script.
- Total input value does not overflow and is sufficient for fee plus non-dust output.
- All selected UTXOs are included; no silent partial selection.

---

## 12. Transaction construction and signing algorithm

### 12.1 Build plan

1. Parse network and destination address.
2. Derive destination scriptPubKey.
3. Sort inputs deterministically by outpoint for reproducibility.
4. Create one provisional output.
5. Estimate initial fee conservatively.
6. Build the unsigned version-2 transaction.
7. For each P2PKH input, compute the legacy `SIGHASH_ALL` digest using that input’s previous-output script.
8. Sign deterministically with libsecp256k1.
9. Normalize to low-S, encode strict DER, append sighash byte `0x01`.
10. Construct `scriptSig = push(signature+sighash) push(public_key)`.
11. Serialize the fully signed transaction.
12. Measure exact byte size/vsize and actual fee rate.
13. Recalculate the single output value from exact fee.
14. Rebuild and re-sign until the target fee rate is met within a deterministic tolerance.
15. Locally verify every signature and all policy invariants.
16. Compute txid, wtxid, raw-transaction SHA-256 fingerprint, size, fee, and fee rate.

For a non-witness P2PKH sweep, txid and wtxid are equal, but the code should still model both fields explicitly.

### 12.2 Fee convergence

DER signature length can vary. Fee calculation must use the final serialization, not a hard-coded “148 bytes per input” assumption.

A safe convergence rule:

```text
required_fee = ceil(final_vsize × target_sat_per_vbyte)
output_value = total_input_value - required_fee
```

Re-sign if changing the output value changes the signature/size. Stop after a small bounded number of iterations and fail if convergence does not occur.

### 12.3 Local post-sign validation

Before export, the signer must prove:

- all signatures verify against the exact sighash;
- all input scripts match the source;
- exactly one output exists;
- output script equals the reviewed destination;
- output value equals inputs minus fee;
- fee is within configured absolute and percentage limits;
- effective fee rate meets the selected target;
- no change, OP_RETURN, unknown script, or extra output exists;
- all sequences, version, locktime, and sighash types match policy.

Optional local Bitcoin Core `testmempoolaccept` validation belongs on an isolated trusted node and must never automatically relay the transaction. It is not available inside the strictly offline signer unless connected through a deliberately audited local workflow.

---

## 13. Fee strategy

MARA exposes dynamic submission and mineable-rate information. PuzzleSlipstream must never hard-code the live fee rate.

### Fee profiles

- **Private Priority — Recommended**  
  Uses the relay’s current mineable rate plus a configurable safety margin.

- **Relay Minimum — Not recommended for vulnerable funds**  
  Uses the current submission floor; requires a strong warning.

- **Manual**  
  User enters sat/vB; must still meet the current relay submission minimum.

### Quote workflow for two-device mode

1. Online Relay fetches current rate information.
2. Relay displays `Submission minimum`, `Currently mineable`, network, block height, and quote time.
3. Relay exports a small fee quote by QR/file.
4. Offline Signer imports the quote and shows its age.
5. A stale quote blocks signing unless the user explicitly overrides it.

### Safety limits

- configurable maximum fee in satoshis;
- configurable maximum fee percentage;
- configurable maximum sat/vB;
- typed override required above limits;
- output must remain above the destination script’s dust threshold;
- zero/negative output is impossible.

The default must favor prompt private inclusion rather than the lowest possible fee. A high-risk puzzle sweep is not the place for fee minimization.

---

## 14. MARA Slipstream adapter

### 14.1 Current API surface to isolate

The implementation should be generated or manually coded against the live OpenAPI description, with contract tests for:

```text
GET  /api/system
GET  /api/block-info
GET  /api/rates
GET  /api/transactions/status
POST /api/transactions
POST /api/transactions/packages      # not used in v1 critical flow
POST /api/mempool/tests               # not called before submission by default
```

Expected submission body according to the currently published API shape:

```json
{
  "tx_hex": "<raw_transaction_hex_string>",
  "client_code": "<optional identifier>"
}
```

`client_code` must be optional and blank by default. No analytics identifier should be invented.

### 14.2 Relay trait

```rust
#[async_trait]
pub trait PrivateRelay {
    async fn system_info(&self) -> Result<SystemInfo, RelayError>;
    async fn fee_quote(&self) -> Result<FeeQuote, RelayError>;
    async fn submit(&self, tx: &SensitiveRawTransaction)
        -> Result<SubmissionReceipt, RelayError>;
    async fn status(&self, txid: Txid)
        -> Result<NormalizedTxStatus, RelayError>;
}
```

### 14.3 Submission rules

- Validate the signed transaction locally before any network call carrying it.
- Use HTTPS with system trust roots/rustls and strict hostname verification.
- Disable implicit HTTP proxy use by default; expose proxy/Tor only as an explicit advanced profile.
- Do not send the transaction to an analytics, crash, test, or public endpoint.
- Do not call the separate mempool-test endpoint before the real private submission by default.
- Retry the exact same transaction only after an ambiguous transport failure and only with a bounded idempotent retry policy.
- Never fan out to another relay automatically.
- Never fall back to public broadcast.
- Preserve the exact raw bytes used to compute the displayed txid during submission.
- On an API schema mismatch, stop and show `Relay API changed — submission blocked`.

### 14.4 Multi-relay tradeoff

A later Advanced mode may support explicitly configured private miner endpoints. It must explain:

- more private miners can reduce expected time to a block;
- every additional operator receives the exposed public key;
- fanout increases trust and leakage surface;
- the default remains one explicitly selected relay.

For unusually valuable or very small-interval puzzle rewards, a negotiated direct-miner endpoint with authenticated contact may be safer than an anonymous public API.

---

## 15. Status and confirmation model

Normalize relay-specific responses into these application states:

```text
Draft
Validated Offline
Signed — Sensitive
Imported by Relay — Sensitive
Submitting
Relay Accepted — Not Confirmed
Relay Rejected
Relay Status Unknown
Mined — 1 Confirmation
Confirmed — N Confirmations
Conflicted / Input Spent
Expired / Dropped
```

### Rules

- HTTP 2xx is not automatically “accepted”; parse the documented response.
- Relay acceptance is not confirmation and not a mining guarantee.
- Confirmation should be checked through the relay status API and, when available, the user’s own Bitcoin Core node.
- Do not query a public explorer before confirmation in Critical Sweep mode.
- After one confirmed block, the public-key/RBF race for those spent inputs is closed under the normal chain tip, but the UI should continue tracking confirmations.
- The relay app may retain txid/status metadata, but must erase raw transaction bytes after a confirmed acceptance or completed submission state unless the user explicitly chooses an encrypted recovery session.

---

## 16. Protected transfer between Signer and Relay

The signed transaction is sensitive before confirmation.

### Preferred — direct QR transfer

- Signer displays a QR or animated QR sequence.
- Relay scans it locally.
- Nothing is copied to the clipboard or stored on disk.
- Signer shows the envelope checksum; Relay shows the same checksum.

### Secondary — encrypted `.swe` file

Envelope encryption:

- Argon2id password derivation;
- XChaCha20-Poly1305 authenticated encryption;
- random salt and nonce from the OS CSPRNG;
- explicit format version and network;
- checksum/fingerprint shown on both devices;
- no plaintext temporary file.

Suggested envelope payload:

```json
{
  "format": "puzzleslipstream-envelope",
  "version": 1,
  "network": "bitcoin",
  "raw_tx_hex": "...",
  "txid": "...",
  "vsize": 0,
  "input_total_sats": 0,
  "output_sats": 0,
  "fee_sats": 0,
  "fee_rate_sat_vb": 0.0,
  "source_address": "...",
  "destination_address": "...",
  "policy_hash": "...",
  "created_at_utc": "..."
}
```

The outer encrypted container should not reveal source, destination, txid, or raw transaction.

### Disabled in Critical mode

- unencrypted raw-hex file;
- system clipboard copy;
- email, cloud drive, chat, browser form, or remote support transfer;
- automatic LAN discovery.

---

## 17. Secret-handling design

### Private key

- Stored in a `SecretBox`/zeroizing wrapper immediately after parsing.
- Never cloned unless the type system requires an audited temporary copy.
- Locked in memory with Windows facilities where practical.
- Cleared after signing, on cancellation, on error, and on window close.
- Never included in panic messages or debug formatting.
- Secret types implement no ordinary `Display`, `Debug`, `Serialize`, or `Clone`.

### GUI input

- Native secure text field.
- Paste is optional and followed by immediate clipboard clearing.
- No “remember,” history, autocomplete, spellcheck, or accessibility text export for the secret field where the GUI framework permits control.
- No reveal button in Critical mode; use clear-and-reenter.
- Disable screenshots/screen capture on the key screen where Windows supports it, with a warning that this is not foolproof.

### Signed transaction

- Stored in a sensitive buffer in both applications.
- Cleared after protected export in Signer when the user closes the result screen.
- Cleared in Relay after definitive submission handling.
- Never written to standard logs.

### Logging

Allowed:

```text
event=relay_submit result=accepted txid_prefix=abcd1234 duration_ms=420
```

Forbidden:

```text
private_key=...
wif=...
raw_tx=...
pubkey=...
full_source_address=...
full_destination_address=...
```

A secret-leak test must scan logs, temporary directories, crash artifacts, configuration files, and process output after every integration run.

---

## 18. English GUI/UX specification

### 18.1 Visual direction

- Calm, professional security-tool appearance; no casino/price-chart styling.
- Native Windows typography, preferably Segoe UI.
- Dark and light themes, with dark as default.
- Neutral graphite surfaces, amber for caution, red for blocking errors, green only for verified/confirmed states.
- Large readable transaction figures and address grouping.
- 44×44 px minimum interactive targets.
- Full keyboard navigation, visible focus rings, high contrast, and screen-reader labels.

### 18.2 Signer home screen

```text
PuzzleSlipstream Signer
Create and sign a private legacy-address sweep offline.

[ Start Critical Sweep ]
[ Import UTXO Bundle ]
[ Verify Existing Envelope ]

Network status: OFFLINE / CONNECTED
Security build: Signer — networking code not included
```

If any Windows network interface is active, Critical mode displays:

```text
Network connection detected
For the strongest protection, disconnect Wi-Fi, Ethernet, VPN, and Bluetooth before entering a private key.

[ Recheck ]   [ Continue with typed override ]
```

### 18.3 Signer wizard

#### Step 1 — Safety Check

```text
Critical Sweep
This workflow is designed for a vulnerable legacy P2PKH key.

Important: A P2PKH spend always contains its public key. PuzzleSlipstream keeps the signed transaction out of the public mempool until the selected miner confirms it; the private relay can still see it.

☐ I am authorized to spend these funds.
☐ I understand that the selected relay can read the signed transaction.
☐ I understand that relay acceptance is not blockchain confirmation.

[ Continue ]
```

#### Step 2 — Source Key

```text
Source Private Key
Enter WIF or a 32-byte hexadecimal private key.

Private key  [••••••••••••••••••••]
Source legacy address [1...]

[ Verify Key ]

Result:
✓ Key matches source address
Compression: Compressed / Uncompressed
Source script: P2PKH
Fingerprint: 1A2B…91EF
```

#### Step 3 — Inputs

```text
Sweep Inputs
All validated UTXOs will be spent. Partial sweep is disabled.

[ Import verified UTXO bundle ]
[ Add full previous transaction ]
[ Advanced manual entry ]

Outpoint           Amount       Conf.     Script
abcd…1234:0        0.100 BTC    42        ✓ Match

Total input: 10,000,000 sats
✓ All inputs match the source key
✓ No duplicate outpoints
✓ Confirmed inputs only
```

#### Step 4 — Destination

```text
Destination
Use a fresh address from a secure wallet. PuzzleSlipstream creates no change output.

Destination address [bc1...]
[ Scan QR ]

✓ Bitcoin mainnet
✓ Valid P2WPKH address

Re-enter the final 8 characters: [________]
```

#### Step 5 — Fee

```text
Fee & Private Relay
Relay profile: MARA Slipstream
Quote block: 000000
Quote age: 00:01:24

Submission minimum: X sat/vB
Currently mineable: Y sat/vB

● Private Priority — Recommended
○ Relay Minimum — Higher delay risk
○ Manual

Target fee rate: Z sat/vB
Estimated fee: N sats
Estimated destination amount: N sats
```

#### Step 6 — Final Review

```text
Final Review

Source                  1ABC…WXYZ
Compression             Compressed
Inputs                   1
Total input              10,000,000 sats
Destination              bc1q…9xyz
Outputs                  1
Change output            NONE
Fee                      4,440 sats
Effective rate           20.0 sat/vB
Sighash                   ALL
Public mempool fallback  OFF
Selected relay           MARA Slipstream

WARNING
The relay can see the public key. Full-RBF exists; a final sequence number is not a theft-prevention guarantee.

Type SWEEP and the destination suffix 9xyz to continue.
[________________]

[ Sign Sweep Transaction ]
```

#### Step 7 — Signed Transaction

```text
Signed and Verified
The transaction is now sensitive until it is confirmed.

✓ Every signature verified locally
✓ One destination output
✓ No change
✓ Fee policy satisfied

Transaction ID: abcd…1234
Envelope fingerprint: 8F21-77AC-...

[ Show Transfer QR ]
[ Save Encrypted .swe File ]
[ Clear Signed Transaction ]
```

### 18.4 Relay home screen

```text
PuzzleSlipstream Relay
Submit a pre-signed sweep directly to a private miner relay.

[ Scan Signer QR ]
[ Open Encrypted .swe File ]
[ Check Existing Transaction ]

Private relay: MARA Slipstream
Public broadcast fallback: OFF
```

### 18.5 Relay review

The relay independently decodes the raw transaction and does not trust envelope display fields.

```text
Imported Sweep

✓ Raw transaction decoded locally
✓ Transaction ID matches envelope
✓ One output only
✓ No change output detected
✓ Final sequence values
✓ SIGHASH_ALL signatures

Source:       1ABC…WXYZ
Destination:  bc1q…9xyz
Amount:       9,995,560 sats
Fee:          4,440 sats
Fee rate:     20.0 sat/vB

Selected private relay: MARA Slipstream
No public fallback will be used.

[ Submit Privately ]
```

### 18.6 Relay status screen

```text
Relay Accepted — Not Confirmed
MARA accepted the transaction for best-effort private mining.

Transaction: abcd…1234
Submitted:   14:32:08 UTC
Current state: Waiting for a MARA block

Do not publish the transaction or public key elsewhere.

[ Refresh Status ]
[ Verify with My Bitcoin Core Node ]
```

On confirmation:

```text
Mined — 1 Confirmation
The spending transaction is now included in block 000000.

[ Continue tracking confirmations ]
[ Clear sensitive session data ]
```

---

## 19. Required English warning copy

These strings should be treated as product requirements:

- `Never paste your private key into a website, chat, email, or support form.`
- `A P2PKH spend always contains its public key.`
- `PuzzleSlipstream avoids the public mempool; it does not hide the transaction from the selected relay.`
- `Public broadcast fallback is disabled.`
- `Sweep all validated UTXOs. No change output will be created.`
- `Relay acceptance is not blockchain confirmation.`
- `Full-RBF exists. A final sequence number does not prevent all replacements.`
- `The signed transaction is sensitive until it is confirmed.`
- `The selected relay can read the signed transaction and public key.`
- `Use a fresh destination address controlled by a secure wallet.`
- `Do not test this build with valuable funds.`

Avoid misleading labels such as:

- `Public key hidden`
- `RBF-proof`
- `Guaranteed mining`
- `Unstealable`
- `100% secure`
- `Anonymous`

---

## 20. Application state machine

```text
START
  │
  ▼
SafetyAcknowledged
  │
  ▼
KeyValidated ── failure ──► KeyCleared
  │
  ▼
InputsValidated ─ failure ─► Blocked
  │
  ▼
DestinationValidated
  │
  ▼
FeePolicyValidated
  │
  ▼
ReviewConfirmed
  │
  ▼
SignedLocally
  │
  ├── local verification failure ─► Zeroize + Blocked
  │
  ▼
ProtectedEnvelopeCreated
  │
  ▼
ImportedByRelay
  │
  ▼
DecodedAndRevalidated
  │
  ▼
PrivateSubmission
  │
  ├── rejected ─► Rebuild/Re-sign offline
  ├── unknown  ─► Query same relay; never public fallback
  └── accepted
          │
          ▼
WaitingPrivate
          │
          ├── conflict/input spent ─► Critical warning
          └── mined
                │
                ▼
Confirmed + SensitiveDataCleared
```

---

## 21. Error handling

Every error should be typed and actionable without exposing secrets.

### Blocking examples

- `KEY_FORMAT_INVALID`
- `KEY_OUT_OF_RANGE`
- `SOURCE_ADDRESS_MISMATCH`
- `KEY_COMPRESSION_MISMATCH`
- `UTXO_SCRIPT_MISMATCH`
- `UTXO_AMOUNT_UNVERIFIED`
- `UTXO_UNCONFIRMED`
- `DUPLICATE_OUTPOINT`
- `DESTINATION_NETWORK_MISMATCH`
- `DESTINATION_EQUALS_SOURCE`
- `OUTPUT_BELOW_DUST`
- `FEE_EXCEEDS_LIMIT`
- `FEE_RATE_BELOW_RELAY_MINIMUM`
- `SIGNATURE_VERIFICATION_FAILED`
- `POLICY_INVARIANT_FAILED`
- `ENVELOPE_AUTHENTICATION_FAILED`
- `TXID_MISMATCH`
- `TLS_VALIDATION_FAILED`
- `RELAY_API_SCHEMA_CHANGED`
- `RELAY_REJECTED`
- `RELAY_STATUS_AMBIGUOUS`
- `INPUT_ALREADY_SPENT`

No error dialog may include raw transaction hex, full key material, stack dumps, or request bodies.

---

## 22. Testing strategy

### 22.1 Unit tests

- WIF decoding and checksum rejection.
- Raw scalar range checks (`1 <= k < n`).
- Compressed/uncompressed public-key derivation.
- Mainnet/testnet P2PKH address derivation.
- ScriptPubKey generation and matching.
- Destination address/network validation.
- Legacy sighash calculation.
- DER signature encoding and low-S normalization.
- scriptSig construction.
- exact serialization/vsize/fee convergence.
- one-output/no-change enforcement.
- envelope encryption/decryption and tamper rejection.
- relay response normalization.

### 22.2 Golden vectors

Use public, non-valuable deterministic test keys and known transactions. Cross-check:

- derived addresses;
- sighashes;
- signatures where deterministic behavior is stable;
- raw transaction hex;
- txid;
- decoded scripts;
- fee and vsize.

### 22.3 Cross-implementation tests

For each generated transaction:

- decode with Bitcoin Core;
- compare txid and output values;
- run `testmempoolaccept` on regtest/testnet infrastructure;
- verify signatures independently using libsecp256k1/Bitcoin Core.

### 22.4 Regtest end-to-end tests

1. Create a funded P2PKH output.
2. Export a verified UTXO bundle.
3. Build and sign a no-change sweep offline.
4. Transfer through the protected envelope.
5. Submit to a local mock private relay.
6. Mine a block.
7. Verify destination value and confirmation.
8. Assert the source has no remaining selected UTXOs.
9. Assert no public-broadcast code path was invoked.

Test compressed and uncompressed keys, one and multiple inputs, fee changes, malformed bundles, wrong destination network, and API failures.

### 22.5 API contract tests

- Snapshot the current MARA OpenAPI schema during a controlled developer update.
- Mock all documented responses.
- Test unknown/missing fields and changed types.
- Production app fails closed when required semantics cannot be proven.
- Never run automated mainnet submission tests with a real funded transaction.

### 22.6 Property and fuzz tests

- Transaction parser and envelope parser.
- Address and WIF parsing.
- UTXO bundle parsing.
- Fee convergence.
- Integer overflow and money-range boundaries.
- Malformed DER/scriptSig inputs.
- Relay JSON parsing.

### 22.7 Secret-leak tests

After simulated failures and successful runs, scan:

- application logs;
- Windows temp folders;
- config/cache folders;
- crash artifacts;
- process stdout/stderr;
- recent files;
- clipboard contents;
- saved UI state.

Seed the test with unique canary keys and fail CI if any canary appears outside an authorized in-memory test buffer.

### 22.8 UI tests

- Full keyboard-only workflow.
- High-DPI and 125/150/200% scaling.
- Screen-reader labels.
- Long addresses and large satoshi values.
- Confirmation phrase behavior.
- No secret retained after back navigation.
- Window close/cancel zeroization.
- Network-active warning.
- Clear distinction between accepted and confirmed.

---

## 23. Build, CI, and release security

### Required CI gates

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- strict unit/integration tests
- `cargo audit`
- dependency-license and source review
- signer dependency graph proves no network crates
- relay dependency graph proves no key/signing crates
- secret-leak test suite
- regtest end-to-end suite
- SBOM generation
- reproducible-build comparison where practical
- signed release artifacts

### Release policy

- No auto-update inside PuzzleSlipstream Signer.
- Updates are downloaded separately, signature-verified, and transferred offline.
- Relay may check for update metadata, but updates remain explicit.
- Every release publishes checksums and a signed provenance statement.
- Mainnet mode is compile-time gated until all release checks pass.
- Debug builds display `NOT FOR REAL FUNDS` and cannot enable production submission.
- Production builds remove debug logging and panic backtraces containing runtime values.

### Code review focus

- secret lifetimes and copies;
- private-key parsing;
- sighash correctness;
- value/fee arithmetic;
- exact script matching;
- destination substitution;
- networking boundaries;
- TLS/proxy behavior;
- logging redaction;
- API schema assumptions;
- fail-closed behavior.

---

## 24. Development phases and gates

### Phase 0 — Specification freeze

Deliverables:

- threat model;
- security invariants;
- UI flow;
- transaction policy;
- current MARA API snapshot;
- mainnet disabled.

Gate:

- every claim in the UI accurately describes P2PKH public-key exposure and private-relay trust.

### Phase 1 — Bitcoin core library and CLI harness

Build:

- key parsing;
- compressed/uncompressed matching;
- UTXO/previous-transaction validation;
- one-output transaction builder;
- exact fee convergence;
- P2PKH signing and local verification;
- decode/report command using test keys only.

Gate:

- golden vectors, independent decode, and regtest acceptance all pass.

### Phase 2 — Offline Signer GUI

Build:

- English wizard;
- secure key field;
- UTXO bundle import;
- destination verification;
- review/typed confirmation;
- QR and encrypted-envelope export;
- zeroization and secret-leak tests.

Gate:

- signer dependency graph contains no networking library or socket use.

### Phase 3 — Relay GUI and MARA adapter

Build:

- fee quote retrieval;
- envelope import/decryption;
- independent transaction decode;
- MARA submit/status adapter;
- normalized status UI;
- own-node confirmation option;
- no public fallback.

Gate:

- live API health/rate calls work; mainnet transaction submission remains disabled in automated testing.

### Phase 4 — End-to-end hardening

Build/test:

- Windows process/memory hardening;
- clipboard and screen-capture mitigations;
- API failure injection;
- tampered envelope tests;
- proxy/DNS/TLS behavior;
- installer and signed binaries;
- accessibility and high-DPI polish.

Gate:

- external security review or at minimum two independent code-review passes focused on transaction correctness and secret handling.

### Phase 5 — Mainnet release candidate

Procedure:

1. Reproducible clean build.
2. Full CI and regtest pass.
3. Testnet4 private-relay rehearsal.
4. Tiny-value, non-vulnerable mainnet canary using a fresh test key.
5. Verify no secret/log/public-fallback leaks.
6. Publish signed RC.

Gate:

- only after canary confirmation may the production UI remove the RC warning.

---

## 25. Definition of done for v1

PuzzleSlipstream v1 is complete only when all are true:

- [ ] Signer and Relay are separate Windows executables.
- [ ] Signer has no networking dependency or code path.
- [ ] Relay has no private-key parsing/signing dependency.
- [ ] WIF and raw-hex key formats are supported.
- [ ] Compressed/uncompressed source matching is exact.
- [ ] One or more P2PKH UTXOs can be verified from full previous transactions.
- [ ] Critical mode spends all selected matching UTXOs.
- [ ] Exactly one destination output is created.
- [ ] No change output is possible.
- [ ] SIGHASH_ALL, strict DER, and low-S signatures are enforced.
- [ ] Every signature is independently verified before export.
- [ ] Exact fee/vsize convergence is tested.
- [ ] Destination network and suffix confirmation are enforced.
- [ ] Signed transaction transfer supports QR and encrypted file.
- [ ] MARA fee, submit, and status operations are adapter-isolated.
- [ ] API changes fail closed.
- [ ] Public broadcast fallback does not exist.
- [ ] UI never equates accepted with confirmed.
- [ ] All English warning copy is present.
- [ ] Secret-leak CI tests pass.
- [ ] Regtest end-to-end tests pass.
- [ ] Testnet4 rehearsal passes.
- [ ] A tiny non-vulnerable mainnet canary passes.
- [ ] Signed checksums/SBOM/release provenance are published.

---

## 26. Later enhancements

After v1 is stable:

- additional explicitly configured private-miner relay adapters;
- mutually authenticated direct-miner profiles;
- animated BC-UR QR transfer for large multi-input transactions;
- pre-signed private fee ladder with the same destination;
- local watch-only companion for UTXO preparation;
- stronger destination ownership verification;
- hardware-wallet destination QR workflow;
- signet/testnet4 training mode with guided tutorial;
- Linux signer image for a dedicated air-gapped USB-boot environment;
- deterministic reproducible offline appliance build;
- integration hook that receives a solved key through an authenticated local pipe without command-line/history exposure.

No enhancement may weaken the signer/relay separation or introduce public fallback into Critical Sweep mode.

---

## 27. Residual-risk statement shown before production use

```text
PuzzleSlipstream reduces exposure; it cannot eliminate it.

A legacy P2PKH transaction contains the public key. The private relay receives the signed transaction before confirmation and must be trusted not to leak or misuse it. If the public key was already exposed, the interval is very small, the signing computer is compromised, the destination is replaced, or the relay is malicious, funds may still be lost.

Use an offline signer, a fresh secure destination, an adequate fee, and a trusted direct miner path. Test only with non-valuable keys until the exact release has been independently reviewed.
```

---

## 28. Implementation-time reference checks

The build team must re-check these immediately before coding the production adapter because the MARA API is beta and may change:

```text
Bitcoin P2PKH transaction documentation:
https://developer.bitcoin.org/devguide/transactions.html

MARA Slipstream portal:
https://slipstream.mara.com/

MARA Slipstream OpenAPI UI:
https://slipstream.mara.com/docs/

MARA Testnet4 portal:
https://teststream.mara.com/

Bitcoin Core release notes:
https://bitcoincore.org/en/releases/
```

Current planning assumptions as of 11 September 2026:

- a P2PKH signature script includes the signature and full public key;
- Slipstream supports direct private-mempool submission to MARA;
- the published API includes system, block-info, rates, transaction status, transaction submission, package submission, and mempool-test endpoints;
- the published request example uses `tx_hex` and an optional `client_code`;
- submission/mempool admission is best-effort and does not guarantee mining;
- the published fee floor is dynamic and must be read from the service;
- Bitcoin Core full-RBF is standard behavior, so final/non-signaling sequence values do not guarantee non-replaceability.

---

## 29. Recommended first coding task

Do not begin with the GUI or live MARA calls.

The first implementation milestone should be a test-only Rust crate that accepts:

- a known test private key;
- a full previous transaction and vout;
- a fresh test destination;
- a fixed fee rate;

and emits a locally verified, one-output, no-change P2PKH sweep on regtest. The result must be decoded and accepted by Bitcoin Core regtest before any GUI or mainnet relay code is written.

That sequence prevents an attractive interface from hiding a transaction-construction or fee-calculation defect.

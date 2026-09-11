# Creating a UTXO bundle with your own node

The Signer requires each **complete previous transaction**, not an explorer-provided amount. This lets the offline computer compute the transaction ID, selected output value, and locking script.

## Requirements

- A synchronized Bitcoin Core node that can return the previous transaction.
- `bitcoin-cli` available locally.
- The transaction ID and output index (`vout`) for every authorized UTXO.

## Export one previous transaction

Examples:

```bash
# Mainnet
bitcoin-cli getrawtransaction TXID false

# Testnet4
bitcoin-cli -testnet4 getrawtransaction TXID false

# Regtest
bitcoin-cli -regtest getrawtransaction TXID false
```

If `getrawtransaction` cannot find an older confirmed transaction, the node may need `txindex=1`, a wallet containing the transaction, or a supplied block hash. Reindexing can take substantial time. Consult the documentation for your exact Bitcoin Core version.

## Build the JSON

Copy the returned hex into this structure:

```json
{
  "format": "puzzle-slipstream-utxos",
  "version": 1,
  "network": "testnet4",
  "inputs": [
    {
      "previous_transaction_hex": "PASTE_FULL_RAW_TRANSACTION_HEX",
      "vout": 0,
      "label": "puzzle output"
    }
  ]
}
```

For multiple UTXOs controlled by the same private key, add one object per outpoint. The Signer rejects duplicate outpoints and outputs whose P2PKH script does not match either public-key encoding derived from the supplied secret.

## Helper script

`scripts/export-utxo-bundle.py` invokes your local `bitcoin-cli` executable and writes the JSON. It never contacts an explorer:

```bash
python scripts/export-utxo-bundle.py \
  --network testnet4 \
  --out bundle.json \
  TXID:VOUT TXID:VOUT
```

Inspect the generated file before moving it to the offline computer.

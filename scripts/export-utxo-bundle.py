#!/usr/bin/env python3
"""Create a PuzzleSlipstream UTXO bundle using only local bitcoin-cli."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

NETWORK_FLAGS = {
    "mainnet": [],
    "testnet4": ["-testnet4"],
    "signet": ["-signet"],
    "regtest": ["-regtest"],
}


def parse_outpoint(value: str) -> tuple[str, int]:
    try:
        txid, vout_text = value.rsplit(":", 1)
        if len(txid) != 64 or any(c not in "0123456789abcdefABCDEF" for c in txid):
            raise ValueError("txid must be 64 hexadecimal characters")
        vout = int(vout_text)
        if not 0 <= vout <= 0xFFFFFFFF:
            raise ValueError("vout outside uint32 range")
        return txid.lower(), vout
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid outpoint {value!r}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("outpoints", nargs="+", type=parse_outpoint, metavar="TXID:VOUT")
    parser.add_argument("--network", choices=NETWORK_FLAGS, default="regtest")
    parser.add_argument("--bitcoin-cli", default="bitcoin-cli", help="local bitcoin-cli executable")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    inputs = []
    for txid, vout in args.outpoints:
        command = [args.bitcoin_cli, *NETWORK_FLAGS[args.network], "getrawtransaction", txid, "false"]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            print(f"bitcoin-cli failed for {txid}: {completed.stderr.strip()}", file=sys.stderr)
            return completed.returncode or 1
        raw = completed.stdout.strip()
        if not raw or any(c not in "0123456789abcdefABCDEF" for c in raw):
            print(f"bitcoin-cli returned non-hex data for {txid}", file=sys.stderr)
            return 1
        inputs.append({
            "previous_transaction_hex": raw.lower(),
            "vout": vout,
            "label": f"{txid}:{vout}",
        })

    bundle = {
        "format": "puzzle-slipstream-utxos",
        "version": 1,
        "network": args.network,
        "inputs": inputs,
    }
    args.out.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(inputs)} input(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail CI if network code enters the offline Signer dependency/source boundary."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FORBIDDEN_CRATES = {
    "reqwest", "hyper", "h2", "tonic", "curl", "ureq", "attohttpc",
    "trust-dns-resolver", "hickory-resolver", "socket2",
}
FORBIDDEN_SOURCE_TERMS = (
    "std::net", "tokio::net", "reqwest", "http://", "https://",
    "MARA_SUBMIT_URL", "broadcast_transaction",
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    signer_src = root / "apps" / "puzzle-slipstream-signer" / "src"
    core_signer_files = [
        root / "crates" / "puzzle-slipstream-core" / "src" / name
        for name in ("model.rs", "signing.rs", "validation.rs", "envelope.rs", "lib.rs")
    ]

    problems: list[str] = []
    for path in [*signer_src.rglob("*.rs"), *core_signer_files]:
        text = path.read_text(encoding="utf-8")
        for term in FORBIDDEN_SOURCE_TERMS:
            if term in text:
                problems.append(f"{path.relative_to(root)} contains forbidden term {term!r}")

    metadata = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if metadata.returncode != 0:
        print(metadata.stderr, file=sys.stderr)
        return metadata.returncode

    data = json.loads(metadata.stdout)
    signer = next(p for p in data["packages"] if p["name"] == "puzzle-slipstream-signer")
    direct = {dependency["name"] for dependency in signer["dependencies"]}
    direct_forbidden = sorted(direct & FORBIDDEN_CRATES)
    if direct_forbidden:
        problems.append(f"Signer has forbidden direct dependencies: {', '.join(direct_forbidden)}")

    if problems:
        print("Offline Signer boundary check FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1

    print("Offline Signer boundary check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

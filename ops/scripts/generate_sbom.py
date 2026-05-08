"""Generate a simple SBOM (requirements freeze) for the backend.

Control: SUP-001 (Supply Chain Security)

This script writes a snapshot of Python dependencies to `backups/SBOM.txt`.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

BASE = Path(__file__).parents[3]
OUT = BASE / "backups" / "SBOM.txt"

OUT.parent.mkdir(parents=True, exist_ok=True)


def generate_sbom() -> Path:
    with OUT.open("w", encoding="utf-8") as fh:
        subprocess.run(["pip", "freeze"], stdout=fh, check=True)
    return OUT


if __name__ == "__main__":
    p = generate_sbom()
    print("SBOM written to", p)

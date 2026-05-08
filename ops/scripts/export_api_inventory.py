"""Export the FastAPI route inventory as JSON.

Control: API-001 (API Security)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = BASE_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.main import app
from app.api_inventory import build_api_inventory


OUTPUT = Path(__file__).parents[2] / "api_inventory.json"


def main() -> None:
    inventory = build_api_inventory(app)
    OUTPUT.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print(f"Wrote {len(inventory)} routes to {OUTPUT}")


if __name__ == "__main__":
    main()

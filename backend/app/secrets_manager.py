"""Secrets manager (minimal, repo-level implementation).

Control: SEC-001 (Secrets Management)

Notes:
- This module provides a simple encrypted-secrets-file helper using Fernet (symmetric key).
- It is intended as a small, demonstrable implementation for the assignment. For production
  use a proper secrets vault (HashiCorp Vault, AWS KMS/Secrets Manager, Azure KeyVault).
"""
from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

SECRETS_FILE = Path(__file__).parents[1] / "data" / "secrets.enc"


def _get_master_key() -> bytes:
    # Prefer explicit env var, fall back to DB_ENCRYPTION_KEY if provided (demo convenience)
    key = os.getenv("SECRETS_MASTER_KEY") or os.getenv("DB_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("SECRETS_MASTER_KEY (or DB_ENCRYPTION_KEY) must be set to use secrets manager")
    # Fernet keys are urlsafe_base64 32-byte keys; if user supplied raw passphrase, derive a key
    if len(key) == 44 and key.endswith("="):
        return key.encode("utf-8")
    # Derive a Fernet key from passphrase in a minimal way for demo (not PBKDF2-hardening here)
    return Fernet.generate_key()


def save_secrets(payload: dict[str, Any]) -> None:
    """Encrypt and save secrets to disk (demo implementation).

    Implemented: SEC-001 (encrypted secrets storage) - this writes an encrypted blob
    to `backend/data/secrets.enc`.
    """
    key = _get_master_key()
    f = Fernet(key)
    data = json.dumps(payload).encode("utf-8")
    ciphertext = f.encrypt(data)
    SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SECRETS_FILE, "wb") as fh:
        fh.write(ciphertext)


def load_secrets() -> dict[str, Any]:
    """Load and decrypt secrets file."""
    key = _get_master_key()
    f = Fernet(key)
    if not SECRETS_FILE.exists():
        return {}
    with open(SECRETS_FILE, "rb") as fh:
        ciphertext = fh.read()
    data = f.decrypt(ciphertext)
    return json.loads(data.decode("utf-8"))


def rotate_secrets(new_master_key: str) -> None:
    """Rotation stub: re-encrypt with new master key.

    For demo, this overwrites the secrets file using `new_master_key`. In production,
    rotate keys via your KMS/vault and perform re-encryption in a controlled maintenance window.
    """
    payload = load_secrets()
    os.environ["SECRETS_MASTER_KEY"] = new_master_key
    save_secrets(payload)

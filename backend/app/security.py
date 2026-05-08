from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from typing import Final

import pyotp


# SEC-001 (Secrets Management): Using short-lived access tokens with expiration
# DATA-001 (Data Security & Cryptography): Password hashing with PBKDF2
# IAM-001 (Identity & Access Management): Secure password storage and token validation

PASSWORD_HASH_ITERATIONS = 120_000  # Mitigates: SEC-001, DATA-001
PASSWORD_HASH_ALGORITHM = "sha256"
PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
ENCRYPTION_PREFIX: Final = "enc:v1"
PASSWORD_POLICY_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).+$")


class SecurityError(Exception):
    pass


def validate_password_strength(password: str) -> None:
    """Enforce strong password policy for registration.

    Rules:
    - At least 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        raise SecurityError("Password must be at least 12 characters long")
    if not PASSWORD_POLICY_REGEX.match(password):
        raise SecurityError("Password must include uppercase, lowercase, number, and special character")


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(plain_password: str) -> str:
    # Control: SEC-001 (short-lived credentials), DATA-001 (cryptography)
    # PBKDF2 with 120k iterations and random salt mitigates password cracking
    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac(
        PASSWORD_HASH_ALGORITHM,
        plain_password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return (
        f"{PASSWORD_HASH_PREFIX}${PASSWORD_HASH_ITERATIONS}$"
        f"{_base64url_encode(salt)}${_base64url_encode(derived_key)}"
    )


def verify_password(password_hash: str, plain_password: str) -> bool:
    # Control: DATA-001 (cryptography), IAM-001 (authentication)
    # Uses constant-time HMAC comparison to mitigate timing attacks
    try:
        prefix, iterations_raw, salt_raw, digest_raw = password_hash.split("$", 3)
    except ValueError as error:
        raise SecurityError("Invalid password hash format") from error

    if prefix != PASSWORD_HASH_PREFIX:
        raise SecurityError("Unsupported password hash algorithm")

    iterations = int(iterations_raw)
    salt = _base64url_decode(salt_raw)
    expected_digest = _base64url_decode(digest_raw)

    candidate_digest = hashlib.pbkdf2_hmac(
        PASSWORD_HASH_ALGORITHM,
        plain_password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(candidate_digest, expected_digest)  # Timing-safe comparison


def issue_access_token(payload: dict[str, object], secret: str, expires_in_seconds: int) -> str:
    # Control: SEC-001 (short-lived credentials), IAM-001 (session management)
    # Issues JWT with explicit expiration to enforce token lifetime limits
    now = int(time.time())
    claims = {"iat": now, "exp": now + expires_in_seconds, **payload}
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        f"{_base64url_encode(json.dumps(header, separators=(',', ':'), sort_keys=True).encode('utf-8'))}."
        f"{_base64url_encode(json.dumps(claims, separators=(',', ':'), sort_keys=True).encode('utf-8'))}"
    )
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_base64url_encode(signature)}"


def verify_access_token(token: str, secret: str) -> dict[str, object]:
    # Control: IAM-001 (session management), DATA-001 (cryptography)
    # Validates JWT signature and expiration with timing-safe comparison
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".", 2)
    except ValueError as error:
        raise SecurityError("Invalid token format") from error

    signing_input = f"{encoded_header}.{encoded_payload}"
    expected_signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    provided_signature = _base64url_decode(encoded_signature)

    if not hmac.compare_digest(expected_signature, provided_signature):
        raise SecurityError("Invalid token signature")

    payload = json.loads(_base64url_decode(encoded_payload).decode("utf-8"))
    expires_at = int(payload.get("exp", 0))
    if time.time() > expires_at:
        raise SecurityError("Token has expired")

    return payload


def _derive_encryption_key(key_material: str) -> bytes:
    if not key_material:
        raise SecurityError("Encryption key material is required")
    return hashlib.sha256(key_material.encode("utf-8")).digest()


def _stream_xor(raw: bytes, key: bytes, nonce: bytes) -> bytes:
    chunks: list[bytes] = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) < len(raw):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        chunks.append(block)
        counter += 1

    keystream = b"".join(chunks)[: len(raw)]
    return bytes(left ^ right for left, right in zip(raw, keystream))


def encrypt_for_storage(plain_text: str, key_material: str) -> str:
    key = _derive_encryption_key(key_material)
    nonce = os.urandom(16)
    cipher_text = _stream_xor(plain_text.encode("utf-8"), key, nonce)
    return f"{ENCRYPTION_PREFIX}:{_base64url_encode(nonce)}:{_base64url_encode(cipher_text)}"


def decrypt_from_storage(value: str, key_material: str) -> str:
    # Backward compatible: accept existing plaintext rows during migration.
    if not value.startswith(f"{ENCRYPTION_PREFIX}:"):
        return value

    try:
        payload = value.removeprefix(f"{ENCRYPTION_PREFIX}:")
        nonce_raw, cipher_raw = payload.split(":", 1)
    except ValueError as error:
        raise SecurityError("Invalid encrypted data format") from error

    key = _derive_encryption_key(key_material)
    try:
        nonce = _base64url_decode(nonce_raw)
        cipher_text = _base64url_decode(cipher_raw)
        plain_bytes = _stream_xor(cipher_text, key, nonce)
        return plain_bytes.decode("utf-8")
    except Exception as error:
        raise SecurityError("Encrypted value could not be decrypted with current DATA_ENCRYPTION_KEY") from error


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def generate_totp_code(secret: str, at_time: int | None = None, period_seconds: int = 30) -> str:
    totp = pyotp.TOTP(secret, interval=period_seconds)
    unix_time = int(time.time() if at_time is None else at_time)
    return totp.at(unix_time)


def verify_totp_code(secret: str, code: str, period_seconds: int = 30, window: int = 1) -> bool:
    candidate = code.strip()
    if not candidate.isdigit() or len(candidate) != 6:
        return False
    totp = pyotp.TOTP(secret, interval=period_seconds)
    return bool(totp.verify(candidate, valid_window=window))


def _sso_signing_string(provider: str, subject: str, email: str, role: str, issued_at: int) -> str:
    return "|".join([provider.strip().lower(), subject.strip(), email.strip().lower(), role.strip().lower(), str(issued_at)])


def sign_sso_assertion(provider: str, subject: str, email: str, role: str, issued_at: int, secret: str) -> str:
    data = _sso_signing_string(provider, subject, email, role, issued_at)
    signature = hmac.new(secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).digest()
    return _base64url_encode(signature)


def verify_sso_assertion(
    provider: str,
    subject: str,
    email: str,
    role: str,
    issued_at: int,
    signature: str,
    secret: str,
    max_clock_skew_seconds: int,
) -> None:
    now = int(time.time())
    if abs(now - issued_at) > max_clock_skew_seconds:
        raise SecurityError("SSO assertion expired or clock skew too large")

    expected = sign_sso_assertion(provider, subject, email, role, issued_at, secret)
    if not hmac.compare_digest(expected, signature.strip()):
        raise SecurityError("Invalid SSO assertion signature")

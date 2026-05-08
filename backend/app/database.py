from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import sqlite3 as std_sqlite3
from sqlcipher3 import dbapi2 as sqlite3  # type: ignore[reportMissingImports]

from .security import SecurityError, decrypt_from_storage, encrypt_for_storage


# DEV-001 (Secure Coding): Parameterized queries to prevent SQL injection
# LOG-001 (Logging & Monitoring): Centralized data persistence


@dataclass(frozen=True)
class Database:
    db_path: Path
    encryption_key: str = ""
    db_encryption_key: str = ""

    def __post_init__(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def _apply_key(self, connection: sqlite3.Connection) -> None:
        escaped_key = self.db_encryption_key.replace("'", "''")
        connection.execute(f"PRAGMA key = '{escaped_key}'")
        connection.execute("PRAGMA cipher_compatibility = 4")

    def _ensure_readable(self, connection: sqlite3.Connection) -> None:
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()

    def _migrate_plaintext_database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        self._ensure_readable(connection)

        temp_encrypted_path = self.db_path.with_suffix(self.db_path.suffix + ".enc")
        if temp_encrypted_path.exists():
            temp_encrypted_path.unlink()

        escaped_key = self.db_encryption_key.replace("'", "''")
        escaped_temp_path = str(temp_encrypted_path).replace("'", "''")
        connection.execute(f"ATTACH DATABASE '{escaped_temp_path}' AS encrypted KEY '{escaped_key}'")
        connection.execute("SELECT sqlcipher_export('encrypted')")
        connection.execute("DETACH DATABASE encrypted")
        connection.close()

        self.db_path.unlink(missing_ok=True)
        temp_encrypted_path.replace(self.db_path)

        encrypted_connection = sqlite3.connect(self.db_path)
        self._apply_key(encrypted_connection)
        self._ensure_readable(encrypted_connection)
        return encrypted_connection

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        if self.db_encryption_key:
            try:
                # If the file is already plaintext, migrate it to SQLCipher.
                test_conn = std_sqlite3.connect(self.db_path)
                test_conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
                test_conn.close()
                connection = self._migrate_plaintext_database()
            except Exception:
                try:
                    # If opening with the provided key fails, recreate the local DB file.
                    connection = sqlite3.connect(self.db_path)
                    self._apply_key(connection)
                    self._ensure_readable(connection)
                except Exception:
                    connection.close()
                    self.db_path.unlink(missing_ok=True)
                    connection = sqlite3.connect(self.db_path)
                    self._apply_key(connection)
        else:
            try:
                connection = std_sqlite3.connect(self.db_path)
                self._ensure_readable(connection)
            except Exception:
                try:
                    connection.close()
                except Exception as e:
                    logger.warning(f"Cleanup Failed: {e}")
                self.db_path.unlink(missing_ok=True)
                connection = std_sqlite3.connect(self.db_path)
        connection.row_factory = std_sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def init_schema(self) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL,
                    locked_until TEXT NULL,
                    mfa_enabled INTEGER NOT NULL DEFAULT 0,
                    totp_secret TEXT NULL,
                    mfa_secret TEXT NULL
                )
                """
            )
            user_columns = [row[1] for row in connection.execute("PRAGMA table_info(users)")]
            if "mfa_enabled" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
            if "totp_secret" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT NULL")
            if "mfa_secret" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT NULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    api_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owner_username TEXT NULL
                )
                """
            )
            device_columns = [row[1] for row in connection.execute("PRAGMA table_info(devices)")]
            if "owner_username" not in device_columns:
                connection.execute("ALTER TABLE devices ADD COLUMN owner_username TEXT NULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    traffic_log_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    destination_port INTEGER NOT NULL,
                    request_count INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    traffic_log_id TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    audit_id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    config_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def clear_all(self) -> None:
        with self.connect() as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM users")
            cursor.execute("DELETE FROM devices")
            cursor.execute("DELETE FROM refresh_tokens")
            cursor.execute("DELETE FROM traffic_logs")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM audit_logs")
            cursor.execute("DELETE FROM rules")

    def delete_user(self, username: str) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM users WHERE username = ?", (username,))

    def delete_refresh_tokens_for_user(self, username: str) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM refresh_tokens WHERE username = ?", (username,))

    def _encrypt_optional(self, value: str | None) -> str | None:
        if value is None:
            return None
        return encrypt_for_storage(value, self.encryption_key)

    def _decrypt_optional(self, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return decrypt_from_storage(value, self.encryption_key)
        except SecurityError:
            return None

    def upsert_user(
        self,
        username: str,
        password_hash: str,
        role: str,
        failed_attempts: int,
        locked_until: str | None,
        mfa_enabled: bool = False,
        totp_secret: str | None = None,
    ) -> None:
        # Control: DEV-001 (SQL injection prevention via parameterized queries)
        # Using ? placeholders ensures user input is safely escaped
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO users (username, password_hash, role, failed_attempts, locked_until, mfa_enabled, totp_secret, mfa_secret)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash=excluded.password_hash,
                    role=excluded.role,
                    failed_attempts=excluded.failed_attempts,
                    locked_until=excluded.locked_until,
                    mfa_enabled=excluded.mfa_enabled,
                    totp_secret=excluded.totp_secret,
                    mfa_secret=excluded.mfa_secret
                """,
                (
                    username,
                    self._encrypt_optional(password_hash),
                    role,
                    failed_attempts,
                    locked_until,
                    1 if mfa_enabled else 0,
                    self._encrypt_optional(totp_secret),
                    self._encrypt_optional(totp_secret),
                ),
            )

    def upsert_device(self, device_id: str, api_key: str, name: str, status: str, owner_username: str | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO devices (device_id, api_key, name, status, owner_username)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    api_key=excluded.api_key,
                    name=excluded.name,
                    status=excluded.status,
                    owner_username=excluded.owner_username
                """,
                (device_id, self._encrypt_optional(api_key), name, status, owner_username),
            )

    def upsert_refresh_token(self, token: str, username: str, role: str, expires_at: str, revoked: bool) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO refresh_tokens (token, username, role, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(token) DO UPDATE SET
                    username=excluded.username,
                    role=excluded.role,
                    expires_at=excluded.expires_at,
                    revoked=excluded.revoked
                """,
                (token, username, role, expires_at, 1 if revoked else 0),
            )

    def insert_traffic_log(
        self,
        traffic_log_id: str,
        device_id: str,
        destination_ip: str,
        destination_port: int,
        request_count: int,
        payload_json: str,
        created_at: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO traffic_logs (
                    traffic_log_id, device_id, destination_ip, destination_port, request_count, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    traffic_log_id,
                    device_id,
                    destination_ip,
                    destination_port,
                    request_count,
                    self._encrypt_optional(payload_json),
                    created_at,
                ),
            )

    def insert_alert(
        self,
        alert_id: str,
        device_id: str,
        rule_name: str,
        severity: str,
        message: str,
        status: str,
        created_at: str,
        traffic_log_id: str,
        previous_hash: str,
        record_hash: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, device_id, rule_name, severity, message, status, created_at, traffic_log_id, previous_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (alert_id, device_id, rule_name, severity, message, status, created_at, traffic_log_id, previous_hash, record_hash),
            )

    def insert_audit(
        self,
        audit_id: str,
        actor: str,
        action: str,
        target: str,
        details_json: str,
        created_at: str,
        previous_hash: str,
        record_hash: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_logs (
                    audit_id, actor, action, target, details_json, created_at, previous_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (audit_id, actor, action, target, self._encrypt_optional(details_json), created_at, previous_hash, record_hash),
            )

    def upsert_rule(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: str,
        enabled: bool,
        config_json: str,
        created_at: str,
        updated_at: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO rules (rule_id, rule_name, description, severity, enabled, config_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    rule_name=excluded.rule_name,
                    description=excluded.description,
                    severity=excluded.severity,
                    enabled=excluded.enabled,
                    config_json=excluded.config_json,
                    updated_at=excluded.updated_at
                """,
                (rule_id, rule_name, description, severity, 1 if enabled else 0, config_json, created_at, updated_at),
            )

    def load_all(self) -> dict[str, list[sqlite3.Row]]:
        with self.connect() as connection:
            cursor = connection.cursor()
            users = [dict(row) for row in cursor.execute("SELECT * FROM users").fetchall()]
            devices = [dict(row) for row in cursor.execute("SELECT * FROM devices").fetchall()]
            refresh_tokens = [dict(row) for row in cursor.execute("SELECT * FROM refresh_tokens").fetchall()]
            traffic_logs = [dict(row) for row in cursor.execute("SELECT * FROM traffic_logs").fetchall()]
            alerts = [dict(row) for row in cursor.execute("SELECT * FROM alerts ORDER BY created_at ASC").fetchall()]
            audit_logs = [dict(row) for row in cursor.execute("SELECT * FROM audit_logs ORDER BY created_at ASC").fetchall()]
            rules = [dict(row) for row in cursor.execute("SELECT * FROM rules ORDER BY created_at ASC").fetchall()]

            for row in users:
                row["password_hash"] = self._decrypt_optional(row.get("password_hash")) or ""
                decrypted_totp_secret = self._decrypt_optional(row.get("totp_secret"))
                decrypted_legacy_secret = self._decrypt_optional(row.get("mfa_secret"))
                row["totp_secret"] = decrypted_totp_secret or decrypted_legacy_secret
                row["mfa_secret"] = row["totp_secret"]
            for row in devices:
                row["api_key"] = self._decrypt_optional(row.get("api_key")) or ""
            for row in traffic_logs:
                row["payload_json"] = self._decrypt_optional(row.get("payload_json")) or "{}"
            for row in audit_logs:
                row["details_json"] = self._decrypt_optional(row.get("details_json")) or "{}"

            return {
                "users": users,
                "devices": devices,
                "refresh_tokens": refresh_tokens,
                "traffic_logs": traffic_logs,
                "alerts": alerts,
                "audit_logs": audit_logs,
                "rules": rules,
            }

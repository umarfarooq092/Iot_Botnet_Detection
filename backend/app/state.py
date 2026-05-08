from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import quote
import uuid

from .config import Settings, get_settings
from .database import Database
from .security import (
    SecurityError,
    generate_totp_secret,
    hash_password,
    issue_access_token,
    verify_access_token,
    verify_password,
    verify_totp_code,
)


# IAM-001 (Identity & Access Management): User auth, RBAC, refresh token rotation
# LOG-001 (Logging & Monitoring): Audit logs with tamper-evident chaining
# DATA-001 (Data Security & Cryptography): Hash-chained alert/audit records for tamper evidence
# API-001 (API Security): Admin-only control paths


MAX_FAILED_ATTEMPTS = 5  # Control: IAM-001 (brute-force mitigation)
LOCKOUT_MINUTES = 15  # Control: IAM-001 (account lockout)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json_load(value: str | None, fallback: Any) -> Any:
    if value is None or value == "":
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


@dataclass
class UserRecord:
    username: str
    password_hash: str
    role: str
    failed_attempts: int = 0
    locked_until: datetime | None = None
    mfa_enabled: bool = False
    totp_secret: str | None = None


@dataclass
class DeviceRecord:
    device_id: str
    api_key: str
    name: str
    status: str = "active"
    owner_username: str | None = None


@dataclass
class TrafficLogRecord:
    traffic_log_id: str
    device_id: str
    destination_ip: str
    destination_port: int
    request_count: int
    payload: dict[str, Any]
    created_at: datetime


@dataclass
class AlertRecord:
    alert_id: str
    device_id: str
    rule_name: str
    severity: str
    message: str
    status: str
    created_at: datetime
    traffic_log_id: str
    previous_hash: str
    record_hash: str


@dataclass
class AuditRecord:
    audit_id: str
    actor: str
    action: str
    target: str
    details: dict[str, Any]
    created_at: datetime
    previous_hash: str
    record_hash: str


@dataclass
class RefreshTokenRecord:
    token: str
    username: str
    role: str
    expires_at: datetime
    revoked: bool = False


@dataclass
class RuleRecord:
    rule_id: str
    rule_name: str
    description: str
    severity: str
    enabled: bool
    config: dict[str, Any]
    created_at: datetime
    updated_at: datetime


@dataclass
class AuthState:
    settings: Settings
    users: dict[str, UserRecord] = field(default_factory=dict)
    devices: dict[str, DeviceRecord] = field(default_factory=dict)
    refresh_tokens: dict[str, RefreshTokenRecord] = field(default_factory=dict)
    traffic_logs: list[TrafficLogRecord] = field(default_factory=list)
    alerts: list[AlertRecord] = field(default_factory=list)
    audit_logs: list[AuditRecord] = field(default_factory=list)
    rules: dict[str, RuleRecord] = field(default_factory=dict)
    last_alert_hash: str = "GENESIS"
    last_audit_hash: str = "GENESIS"
    db: Database | None = None

    def __post_init__(self) -> None:
        self.db = Database(
            self._resolve_database_path(),
            encryption_key=self.settings.data_encryption_key,
            db_encryption_key=self.settings.db_encryption_key,
        )
        self._load_from_database()
        if not self.users:
            self._seed_demo_data()

    def _resolve_database_path(self) -> Path:
        database_url = self.settings.database_url or "sqlite:///data/ssd_app.db"
        if not database_url.startswith("sqlite:///"):
            raise ValueError("Only sqlite:/// URLs are supported in this assignment backend")

        raw_path = database_url.removeprefix("sqlite:///")
        db_path = Path(raw_path)
        if db_path.is_absolute():
            return db_path

        backend_root = Path(__file__).resolve().parents[1]
        return backend_root / db_path

    def _load_from_database(self) -> None:
        self.users.clear()
        self.devices.clear()
        self.refresh_tokens.clear()
        self.traffic_logs.clear()
        self.alerts.clear()
        self.audit_logs.clear()
        self.rules.clear()
        self.last_alert_hash = "GENESIS"
        self.last_audit_hash = "GENESIS"

        if self.db is None:
            return

        rows = self.db.load_all()
        for row in rows["users"]:
            self.users[row["username"]] = UserRecord(
                username=row["username"],
                password_hash=row["password_hash"],
                role=row["role"],
                failed_attempts=row["failed_attempts"],
                locked_until=datetime.fromisoformat(row["locked_until"]) if row["locked_until"] else None,
                mfa_enabled=bool(row.get("mfa_enabled", 0)),
                totp_secret=row.get("totp_secret") or row.get("mfa_secret"),
            )

        for row in rows["devices"]:
            self.devices[row["device_id"]] = DeviceRecord(
                device_id=row["device_id"],
                api_key=row["api_key"],
                name=row["name"],
                status=row["status"],
                owner_username=row["owner_username"],
            )

        for row in rows["refresh_tokens"]:
            self.refresh_tokens[row["token"]] = RefreshTokenRecord(
                token=row["token"],
                username=row["username"],
                role=row["role"],
                expires_at=datetime.fromisoformat(row["expires_at"]),
                revoked=bool(row["revoked"]),
            )

        for row in rows["traffic_logs"]:
            self.traffic_logs.append(
                TrafficLogRecord(
                    traffic_log_id=row["traffic_log_id"],
                    device_id=row["device_id"],
                    destination_ip=row["destination_ip"],
                    destination_port=row["destination_port"],
                    request_count=row["request_count"],
                    payload=_safe_json_load(row["payload_json"], {}),
                    created_at=datetime.fromisoformat(row["created_at"]),
                )
            )

        for row in rows["alerts"]:
            alert = AlertRecord(
                alert_id=row["alert_id"],
                device_id=row["device_id"],
                rule_name=row["rule_name"],
                severity=row["severity"],
                message=row["message"],
                status=row["status"],
                created_at=datetime.fromisoformat(row["created_at"]),
                traffic_log_id=row["traffic_log_id"],
                previous_hash=row["previous_hash"],
                record_hash=row["record_hash"],
            )
            self.alerts.append(alert)
            self.last_alert_hash = alert.record_hash

        for row in rows["audit_logs"]:
            audit = AuditRecord(
                audit_id=row["audit_id"],
                actor=row["actor"],
                action=row["action"],
                target=row["target"],
                details=_safe_json_load(row["details_json"], {}),
                created_at=datetime.fromisoformat(row["created_at"]),
                previous_hash=row["previous_hash"],
                record_hash=row["record_hash"],
            )
            self.audit_logs.append(audit)
            self.last_audit_hash = audit.record_hash

        for row in rows["rules"]:
            self.rules[row["rule_id"]] = RuleRecord(
                rule_id=row["rule_id"],
                rule_name=row["rule_name"],
                description=row["description"],
                severity=row["severity"],
                enabled=bool(row["enabled"]),
                config=_safe_json_load(row["config_json"], {}),
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
            )

    def reset(self) -> None:
        if self.db is not None:
            self.db.clear_all()
        self._load_from_database()
        self._seed_demo_data()

    def _seed_demo_data(self) -> None:
        if self.settings.demo_admin_username not in self.users:
            user = UserRecord(
                username=self.settings.demo_admin_username,
                password_hash=hash_password(self.settings.demo_admin_password),
                role="admin",
            )
            self.users[self.settings.demo_admin_username] = user
            if self.db is not None:
                self.db.upsert_user(
                    username=user.username,
                    password_hash=user.password_hash,
                    role=user.role,
                    failed_attempts=user.failed_attempts,
                    locked_until=user.locked_until.isoformat() if user.locked_until else None,
                )
        else:
            # Keep demo admin credentials usable across encryption-key/password changes.
            demo_admin = self.users[self.settings.demo_admin_username]
            needs_reset = False
            try:
                needs_reset = not verify_password(demo_admin.password_hash, self.settings.demo_admin_password)
            except SecurityError:
                needs_reset = True

            if needs_reset:
                demo_admin.password_hash = hash_password(self.settings.demo_admin_password)
                demo_admin.failed_attempts = 0
                demo_admin.locked_until = None
            demo_admin.role = "admin"
            self._persist_user(demo_admin)

        if self.settings.demo_device_id not in self.devices:
            device = DeviceRecord(
                device_id=self.settings.demo_device_id,
                api_key=self.settings.demo_device_api_key,
                name="Demo IoT Sensor",
            )
            self.devices[self.settings.demo_device_id] = device
            if self.db is not None:
                self.db.upsert_device(device.device_id, device.api_key, device.name, device.status, device.owner_username)

        if not self.rules:
            self._seed_default_rules()

    def _seed_default_rules(self) -> None:
        self.create_rule(
            rule_name="suspicious_request_frequency",
            description="Detect unusually high request rates per device",
            severity="high",
            config={"type": "request_frequency", "request_count_threshold": 100, "burst_count_threshold": 6, "window_seconds": 60},
            enabled=True,
        )
        self.create_rule(
            rule_name="unusual_destination_pattern",
            description="Detect traffic sent to non-private destinations",
            severity="medium",
            config={"type": "unusual_destination", "match_public_ip": True},
            enabled=True,
        )
        self.create_rule(
            rule_name="malformed_payload_signature",
            description="Detect payload signatures linked to common attacks",
            severity="high",
            config={"type": "payload_signature", "signatures": ["<script", "drop table", "' or 1=1", "../", "union select"]},
            enabled=True,
        )

    def register_user(self, username: str, password_hash: str, role: str) -> UserRecord:
        if username in self.users:
            raise ValueError("Username already exists")

        user = UserRecord(username=username, password_hash=password_hash, role=role)
        self.users[username] = user
        self._persist_user(user)
        return user

    def ensure_sso_user(self, username: str, role: str) -> UserRecord:
        existing = self.get_user(username)
        if existing is not None:
            return existing

        safe_role = "admin"
        random_password = secrets.token_urlsafe(48)
        user = UserRecord(username=username, password_hash=hash_password(random_password), role=safe_role)
        self.users[username] = user
        self._persist_user(user)
        return user

    def _persist_user(self, user: UserRecord) -> None:
        if self.db is not None:
            self.db.upsert_user(
                username=user.username,
                password_hash=user.password_hash,
                role=user.role,
                failed_attempts=user.failed_attempts,
                locked_until=user.locked_until.isoformat() if user.locked_until else None,
                mfa_enabled=user.mfa_enabled,
                totp_secret=user.totp_secret,
            )

    def get_user(self, username: str) -> UserRecord | None:
        return self.users.get(username)

    def verify_credentials(self, username: str, password: str) -> bool:
        # Control: IAM-001 (authentication + brute-force lockout)
        # Enforces account lockout after MAX_FAILED_ATTEMPTS failed password attempts
        user = self.get_user(username)
        if user is None:
            return False

        now = _utcnow()
        if self.is_user_locked(user):
            return False

        if verify_password(user.password_hash, password):
            user.failed_attempts = 0
            user.locked_until = None
            self._persist_user(user)
            return True

        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
        self._persist_user(user)
        return False

    def is_user_locked(self, user: UserRecord) -> bool:
        return user.locked_until is not None and user.locked_until > _utcnow()

    def record_successful_login(self, username: str) -> None:
        user = self.get_user(username)
        if user is None:
            return

        user.failed_attempts = 0
        user.locked_until = None
        self._persist_user(user)

    def initialize_mfa(self, username: str) -> tuple[str, str]:
        user = self.get_user(username)
        if user is None:
            raise ValueError("User not found")

        secret = generate_totp_secret()
        user.totp_secret = secret
        user.mfa_enabled = False
        self._persist_user(user)

        issuer = quote(self.settings.mfa_issuer)
        account = quote(user.username)
        uri = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
        return secret, uri

    def enable_mfa(self, username: str, code: str) -> None:
        user = self.get_user(username)
        if user is None:
            raise ValueError("User not found")
        if not user.totp_secret:
            raise ValueError("MFA is not initialized")
        if not verify_totp_code(user.totp_secret, code):
            raise ValueError("Invalid MFA code")

        user.mfa_enabled = True
        self._persist_user(user)

    def disable_mfa(self, username: str, code: str) -> None:
        user = self.get_user(username)
        if user is None:
            raise ValueError("User not found")
        if user.mfa_enabled and user.totp_secret and not verify_totp_code(user.totp_secret, code):
            raise ValueError("Invalid MFA code")

        user.mfa_enabled = False
        user.totp_secret = None
        self._persist_user(user)

    def verify_mfa(self, username: str, code: str) -> bool:
        user = self.get_user(username)
        if user is None:
            return False
        if not user.mfa_enabled or not user.totp_secret:
            return True
        return verify_totp_code(user.totp_secret, code)

    def issue_mfa_pending_token(self, username: str, role: str) -> str:
        return issue_access_token(
            {"sub": username, "role": role, "typ": "mfa_pending"},
            self.settings.jwt_secret,
            300,
        )

    def validate_mfa_pending_token(self, pending_token: str, username: str | None = None) -> UserRecord:
        try:
            claims = verify_access_token(pending_token, self.settings.jwt_secret)
        except SecurityError as error:
            raise ValueError("Invalid or expired MFA pending token") from error

        if claims.get("typ") != "mfa_pending":
            raise ValueError("Invalid MFA pending token")

        subject = str(claims.get("sub", "")).strip()
        if not subject:
            raise ValueError("Invalid MFA pending token")
        if username is not None and username != subject:
            raise ValueError("MFA token does not match user")

        user = self.get_user(subject)
        if user is None:
            raise ValueError("User not found")
        return user

    def issue_refresh_token(self, username: str, role: str) -> str:
        token = secrets.token_urlsafe(48)
        expires_at = _utcnow() + timedelta(days=7)
        self.refresh_tokens[token] = RefreshTokenRecord(
            token=token,
            username=username,
            role=role,
            expires_at=expires_at,
        )
        if self.db is not None:
            self.db.upsert_refresh_token(token, username, role, expires_at.isoformat(), False)
        return token

    def remove_user(self, username: str, actor_username: str) -> None:
        user = self.get_user(username)
        if user is None:
            raise ValueError("User not found")
        if username == actor_username:
            raise ValueError("Admin cannot remove their own account")

        self.users.pop(username, None)

        tokens_to_remove = [token for token, record in self.refresh_tokens.items() if record.username == username]
        for token in tokens_to_remove:
            self.refresh_tokens.pop(token, None)

        if self.db is not None:
            self.db.delete_user(username)
            self.db.delete_refresh_tokens_for_user(username)

    def rotate_refresh_token(self, token: str) -> str:
        record = self.refresh_tokens.get(token)
        if record is None or record.revoked or record.expires_at <= _utcnow():
            raise ValueError("Invalid refresh token")

        record.revoked = True
        if self.db is not None:
            self.db.upsert_refresh_token(record.token, record.username, record.role, record.expires_at.isoformat(), True)
        return self.issue_refresh_token(record.username, record.role)

    def revoke_refresh_token(self, token: str) -> None:
        record = self.refresh_tokens.get(token)
        if record is not None:
            record.revoked = True
            if self.db is not None:
                self.db.upsert_refresh_token(record.token, record.username, record.role, record.expires_at.isoformat(), True)

    def verify_device_api_key(self, device_id: str, api_key: str) -> bool:
        device = self.devices.get(device_id)
        if device is None or device.status != "active":
            return False

        return secrets.compare_digest(device.api_key, api_key)

    def register_device(self, device_id: str, name: str, api_key: str | None = None, owner_username: str | None = None) -> DeviceRecord:
        key = api_key or secrets.token_urlsafe(32)
        device = DeviceRecord(device_id=device_id, api_key=key, name=name, owner_username=owner_username)
        self.devices[device_id] = device
        if self.db is not None:
            self.db.upsert_device(device.device_id, device.api_key, device.name, device.status, device.owner_username)
        return device

    def _build_chain_hash(self, previous_hash: str, payload: dict[str, Any]) -> str:
        # Control: LOG-001 (immutable logs), DATA-001 (tamper evidence)
        # Creates cryptographic hash chain to detect tampering
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{previous_hash}:{serialized}".encode("utf-8")).hexdigest()

    def create_audit_log(self, actor: str, action: str, target: str, details: dict[str, Any]) -> AuditRecord:
        # Control: LOG-001 (immutable logs with real-time monitoring), DATA-001 (tamper evidence)
        # Creates hash-chained audit records for forensic analysis and integrity verification
        created_at = _utcnow()
        audit_id = str(uuid.uuid4())
        payload = {
            "audit_id": audit_id,
            "actor": actor,
            "action": action,
            "target": target,
            "details": details,
            "created_at": created_at.isoformat(),
        }
        previous_hash = self.last_audit_hash
        record_hash = self._build_chain_hash(previous_hash, payload)
        record = AuditRecord(
            audit_id=audit_id,
            actor=actor,
            action=action,
            target=target,
            details=details,
            created_at=created_at,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )
        self.audit_logs.append(record)
        self.last_audit_hash = record_hash
        if self.db is not None:
            self.db.insert_audit(
                audit_id=record.audit_id,
                actor=record.actor,
                action=record.action,
                target=record.target,
                details_json=json.dumps(record.details, sort_keys=True),
                created_at=record.created_at.isoformat(),
                previous_hash=record.previous_hash,
                record_hash=record.record_hash,
            )
        return record

    def _is_unusual_destination(self, destination_ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(destination_ip)
        except ValueError:
            return True

        return not (parsed.is_private or parsed.is_loopback)

    def _payload_contains_malicious_signature(self, payload: dict[str, Any], signatures: list[str] | None = None) -> bool:
        flattened = json.dumps(payload, sort_keys=True).lower()
        terms = signatures or ["<script", "drop table", "' or 1=1", "../", "union select"]
        normalized = [term.lower() for term in terms]
        return any(signature in flattened for signature in normalized)

    def _create_alert(
        self,
        # Control: LOG-001 (immutable logs + real-time alerting), DATA-001 (tamper evidence)
        # Creates hash-chained alert records with audit trail for incident response
        device_id: str,
        traffic_log_id: str,
        rule_name: str,
        severity: str,
        message: str,
    ) -> AlertRecord:
        created_at = _utcnow()
        alert_id = str(uuid.uuid4())
        payload = {
            "alert_id": alert_id,
            "device_id": device_id,
            "traffic_log_id": traffic_log_id,
            "rule_name": rule_name,
            "severity": severity,
            "message": message,
            "status": "open",
            "created_at": created_at.isoformat(),
        }
        previous_hash = self.last_alert_hash
        record_hash = self._build_chain_hash(previous_hash, payload)

        alert = AlertRecord(
            alert_id=alert_id,
            device_id=device_id,
            rule_name=rule_name,
            severity=severity,
            message=message,
            status="open",
            created_at=created_at,
            traffic_log_id=traffic_log_id,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )
        self.alerts.append(alert)
        self.last_alert_hash = record_hash
        if self.db is not None:
            self.db.insert_alert(
                alert_id=alert.alert_id,
                device_id=alert.device_id,
                rule_name=alert.rule_name,
                severity=alert.severity,
                message=alert.message,
                status=alert.status,
                created_at=alert.created_at.isoformat(),
                traffic_log_id=alert.traffic_log_id,
                previous_hash=alert.previous_hash,
                record_hash=alert.record_hash,
            )

        self.create_audit_log(
            actor="detection-engine",
            action="alert_created",
            target=device_id,
            details={"alert_id": alert.alert_id, "rule_name": rule_name, "severity": severity},
        )
        return alert

    def ingest_traffic(
        self,
        device_id: str,
        destination_ip: str,
        destination_port: int,
        request_count: int,
        # Control: LOG-001 (real-time detection + alerting)
        # Evaluates DB-persisted rules against ingest traffic and creates alerts for violations
        payload: dict[str, Any],
    ) -> tuple[TrafficLogRecord, list[AlertRecord]]:
        created_at = _utcnow()
        traffic_log = TrafficLogRecord(
            traffic_log_id=str(uuid.uuid4()),
            device_id=device_id,
            destination_ip=destination_ip,
            destination_port=destination_port,
            request_count=request_count,
            payload=payload,
            created_at=created_at,
        )
        self.traffic_logs.append(traffic_log)
        if self.db is not None:
            self.db.insert_traffic_log(
                traffic_log_id=traffic_log.traffic_log_id,
                device_id=traffic_log.device_id,
                destination_ip=traffic_log.destination_ip,
                destination_port=traffic_log.destination_port,
                request_count=traffic_log.request_count,
                payload_json=json.dumps(traffic_log.payload, sort_keys=True),
                created_at=traffic_log.created_at.isoformat(),
            )

        generated_alerts: list[AlertRecord] = []
        for rule in self.list_rules():
            if not rule.enabled:
                continue

            rule_type = str(rule.config.get("type", "")).strip().lower()
            rule_message = str(rule.config.get("message", "")).strip()

            if rule_type == "request_frequency":
                request_count_threshold = int(rule.config.get("request_count_threshold", 100))
                burst_count_threshold = int(rule.config.get("burst_count_threshold", 6))
                window_seconds = int(rule.config.get("window_seconds", 60))
                bounded_recent_logs = [
                    log for log in self.traffic_logs if log.device_id == device_id and (created_at - log.created_at) <= timedelta(seconds=window_seconds)
                ]
                if request_count >= request_count_threshold or len(bounded_recent_logs) >= burst_count_threshold:
                    generated_alerts.append(
                        self._create_alert(
                            device_id=device_id,
                            traffic_log_id=traffic_log.traffic_log_id,
                            rule_name=rule.rule_name,
                            severity=rule.severity,
                            message=rule_message or "Request rate for device appears abnormally high",
                        )
                    )
                continue

            if rule_type == "unusual_destination":
                match_public_ip = bool(rule.config.get("match_public_ip", True))
                if match_public_ip and self._is_unusual_destination(destination_ip):
                    generated_alerts.append(
                        self._create_alert(
                            device_id=device_id,
                            traffic_log_id=traffic_log.traffic_log_id,
                            rule_name=rule.rule_name,
                            severity=rule.severity,
                            message=rule_message or f"Traffic sent to unusual destination: {destination_ip}:{destination_port}",
                        )
                    )
                continue

            if rule_type == "payload_signature":
                signatures = rule.config.get("signatures", [])
                normalized_signatures = [str(signature) for signature in signatures if str(signature).strip()]
                if self._payload_contains_malicious_signature(payload, normalized_signatures):
                    generated_alerts.append(
                        self._create_alert(
                            device_id=device_id,
                            traffic_log_id=traffic_log.traffic_log_id,
                            rule_name=rule.rule_name,
                            severity=rule.severity,
                            message=rule_message or "Payload matched known malicious signature",
                        )
                    )
                continue

        self.create_audit_log(
            actor=f"device:{device_id}",
            action="traffic_ingested",
            target=device_id,
            details={
                "traffic_log_id": traffic_log.traffic_log_id,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "alerts_generated": len(generated_alerts),
            },
        )

        return traffic_log, generated_alerts

    def list_alerts(self) -> list[AlertRecord]:
        return list(reversed(self.alerts))

    def list_users(self) -> list[UserRecord]:
        return list(self.users.values())

    def list_devices(self) -> list[DeviceRecord]:
        return list(self.devices.values())

    def list_rules(self) -> list[RuleRecord]:
        return sorted(self.rules.values(), key=lambda rule: rule.created_at)

    def _rule_name_exists(self, rule_name: str, exclude_rule_id: str | None = None) -> bool:
        for rule in self.rules.values():
            if exclude_rule_id is not None and rule.rule_id == exclude_rule_id:
                continue
            if rule.rule_name == rule_name:
                return True
        return False

    def create_rule(
        self,
        rule_name: str,
        description: str,
        severity: str,
        config: dict[str, Any],
        enabled: bool = True,
    ) -> RuleRecord:
        if self._rule_name_exists(rule_name):
            raise ValueError("Rule name already exists")

        now = _utcnow()
        rule = RuleRecord(
            rule_id=str(uuid.uuid4()),
            rule_name=rule_name,
            description=description,
            severity=severity,
            enabled=enabled,
            config=config,
            created_at=now,
            updated_at=now,
        )
        self.rules[rule.rule_id] = rule
        if self.db is not None:
            self.db.upsert_rule(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                description=rule.description,
                severity=rule.severity,
                enabled=rule.enabled,
                config_json=json.dumps(rule.config, sort_keys=True),
                created_at=rule.created_at.isoformat(),
                updated_at=rule.updated_at.isoformat(),
            )
        return rule

    def update_rule(
        self,
        rule_id: str,
        rule_name: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> RuleRecord:
        rule = self.rules.get(rule_id)
        if rule is None:
            raise ValueError("Rule not found")

        if rule_name is not None and self._rule_name_exists(rule_name, exclude_rule_id=rule_id):
            raise ValueError("Rule name already exists")

        if rule_name is not None:
            rule.rule_name = rule_name
        if description is not None:
            rule.description = description
        if severity is not None:
            rule.severity = severity
        if config is not None:
            rule.config = config
        rule.updated_at = _utcnow()

        if self.db is not None:
            self.db.upsert_rule(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                description=rule.description,
                severity=rule.severity,
                enabled=rule.enabled,
                config_json=json.dumps(rule.config, sort_keys=True),
                created_at=rule.created_at.isoformat(),
                updated_at=rule.updated_at.isoformat(),
            )
        return rule

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> RuleRecord:
        rule = self.rules.get(rule_id)
        if rule is None:
            raise ValueError("Rule not found")

        rule.enabled = enabled
        rule.updated_at = _utcnow()
        if self.db is not None:
            self.db.upsert_rule(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                description=rule.description,
                severity=rule.severity,
                enabled=rule.enabled,
                config_json=json.dumps(rule.config, sort_keys=True),
                created_at=rule.created_at.isoformat(),
                updated_at=rule.updated_at.isoformat(),
            )
        return rule

    def dashboard_summary(self) -> dict[str, int]:
        active_devices = sum(1 for device in self.devices.values() if device.status == "active")
        isolated_devices = sum(1 for device in self.devices.values() if device.status == "isolated")
        open_alerts = sum(1 for alert in self.alerts if alert.status == "open")
        high_severity_alerts = sum(1 for alert in self.alerts if alert.severity == "high")
        return {
            "devices_total": len(self.devices),
            "devices_active": active_devices,
            "devices_isolated": isolated_devices,
            "traffic_logs_total": len(self.traffic_logs),
            "alerts_total": len(self.alerts),
            "alerts_open": open_alerts,
            "alerts_high_severity": high_severity_alerts,
            "audit_entries_total": len(self.audit_logs),
        }

    def isolate_device(self, device_id: str, actor: str, reason: str) -> DeviceRecord:
        device = self.devices.get(device_id)
        if device is None:
            raise ValueError("Device not found")

        if device.status != "isolated":
            device.status = "isolated"
            if self.db is not None:
                self.db.upsert_device(device.device_id, device.api_key, device.name, device.status, device.owner_username)
            self.create_audit_log(
                actor=actor,
                action="device_isolated",
                target=device_id,
                details={"reason": reason},
            )
        return device

    def deisolate_device(self, device_id: str, actor: str, reason: str) -> DeviceRecord:
        device = self.devices.get(device_id)
        if device is None:
            raise ValueError("Device not found")

        if device.status == "isolated":
            device.status = "active"
            if self.db is not None:
                self.db.upsert_device(device.device_id, device.api_key, device.name, device.status, device.owner_username)
            self.create_audit_log(
                actor=actor,
                action="device_deisolated",
                target=device_id,
                details={"reason": reason},
            )
        return device

    def export_backup_snapshot(self) -> dict[str, Any]:
        return {
            "exported_at": _utcnow().isoformat(),
            "users": [
                {
                    "username": user.username,
                    "role": user.role,
                    "failed_attempts": user.failed_attempts,
                    "locked_until": user.locked_until.isoformat() if user.locked_until else None,
                    "mfa_enabled": user.mfa_enabled,
                }
                for user in self.users.values()
            ],
            "devices": [
                {
                    "device_id": device.device_id,
                    "name": device.name,
                    "status": device.status,
                }
                for device in self.devices.values()
            ],
            "traffic_logs": [
                {
                    "traffic_log_id": log.traffic_log_id,
                    "device_id": log.device_id,
                    "destination_ip": log.destination_ip,
                    "destination_port": log.destination_port,
                    "request_count": log.request_count,
                    "payload": log.payload,
                    "created_at": log.created_at.isoformat(),
                }
                for log in self.traffic_logs
            ],
            "alerts": [
                {
                    "alert_id": alert.alert_id,
                    "device_id": alert.device_id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity,
                    "message": alert.message,
                    "status": alert.status,
                    "created_at": alert.created_at.isoformat(),
                    "traffic_log_id": alert.traffic_log_id,
                    "previous_hash": alert.previous_hash,
                    "record_hash": alert.record_hash,
                }
                for alert in self.alerts
            ],
            "audit_logs": [
                {
                    "audit_id": audit.audit_id,
                    "actor": audit.actor,
                    "action": audit.action,
                    "target": audit.target,
                    "details": audit.details,
                    "created_at": audit.created_at.isoformat(),
                    "previous_hash": audit.previous_hash,
                    "record_hash": audit.record_hash,
                }
                for audit in self.audit_logs
            ],
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "description": rule.description,
                    "severity": rule.severity,
                    "enabled": rule.enabled,
                    "config": rule.config,
                    "created_at": rule.created_at.isoformat(),
                    "updated_at": rule.updated_at.isoformat(),
                }
                for rule in self.list_rules()
            ],
        }


auth_state = AuthState(get_settings())

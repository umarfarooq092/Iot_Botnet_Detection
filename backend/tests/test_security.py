from __future__ import annotations

import os
import time
import unittest

from sqlcipher3 import dbapi2 as sqlite3

from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET", "a" * 32)
os.environ.setdefault("ACCESS_TOKEN_TTL", "15m")
os.environ.setdefault("PORT", "8000")
os.environ.setdefault("SSO_ENABLED", "true")
os.environ.setdefault("SSO_PROVIDER_SECRET", "s" * 40)
os.environ.setdefault("DATA_ENCRYPTION_KEY", "k" * 40)
os.environ.setdefault("DB_ENCRYPTION_KEY", "d" * 40)
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-google-client-id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-google-client-secret")

from app.main import app
from app.config import get_settings
from app.security import (
    generate_totp_code,
    hash_password,
    issue_access_token,
    sign_sso_assertion,
    verify_access_token,
    verify_password,
)
from app.state import auth_state


class SecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        auth_state.reset()

    def test_password_hash_round_trip(self) -> None:
        password_hash = hash_password("correct horse battery staple")
        self.assertTrue(verify_password(password_hash, "correct horse battery staple"))
        self.assertFalse(verify_password(password_hash, "wrong password"))

    def test_token_round_trip(self) -> None:
        token = issue_access_token({"sub": "alice", "role": "admin"}, "a" * 32, 60)
        payload = verify_access_token(token, "a" * 32)
        self.assertEqual(payload["sub"], "alice")
        self.assertEqual(payload["role"], "admin")

    def test_register_and_login_new_admin(self) -> None:
        client = TestClient(app)

        register_response = client.post(
            "/api/v1/auth/register",
            json={"username": "newadmin@example.com", "password": "NewUserPass123!NewUserPass123!", "role": "admin"},
        )
        self.assertEqual(register_response.status_code, 200)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "newadmin@example.com", "password": "NewUserPass123!NewUserPass123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        self.assertIn("access_token", login_response.json())

    def test_mfa_enable_and_enforced_login(self) -> None:
        client = TestClient(app)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        bearer = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

        setup_response = client.post("/api/v1/auth/mfa/setup", headers=bearer)
        self.assertEqual(setup_response.status_code, 200)
        secret = setup_response.json()["secret"]

        enable_code = generate_totp_code(secret)
        enable_response = client.post("/api/v1/auth/mfa/verify", headers=bearer, json={"code": enable_code})
        self.assertEqual(enable_response.status_code, 200)
        self.assertTrue(enable_response.json()["enabled"])

        login_missing_mfa = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_missing_mfa.status_code, 200)
        self.assertIn("mfa_pending", login_missing_mfa.json())

        login_with_mfa = client.post(
            "/api/v1/auth/mfa/validate",
            json={"mfa_pending": login_missing_mfa.json()["mfa_pending"], "code": generate_totp_code(secret)},
        )
        self.assertEqual(login_with_mfa.status_code, 200)

    def test_sso_login_and_encrypted_database_fields(self) -> None:
        client = TestClient(app)
        settings = get_settings()
        issued_at = int(time.time())
        signature = sign_sso_assertion(
            provider="oidc",
            subject="subject-123",
            email="sso_admin@example.com",
            role="admin",
            issued_at=issued_at,
            secret=settings.sso_provider_secret,
        )

        sso_response = client.post(
            "/api/v1/auth/sso",
            json={
                "provider": "oidc",
                "subject": "subject-123",
                "email": "sso_admin@example.com",
                "role": "admin",
                "issued_at": issued_at,
                "signature": signature,
            },
        )
        self.assertEqual(sso_response.status_code, 200)

        db_path = auth_state.db.db_path if auth_state.db is not None else None
        self.assertIsNotNone(db_path)
        with sqlite3.connect(str(db_path)) as connection:
            # Control: DATA-001 / DB_ENCRYPTION_KEY
            # In development/test the app intentionally uses a plaintext DB, while production
            # can enforce SQLCipher by setting DB_ENCRYPTION_KEY.
            if settings.db_encryption_key:
                connection.execute(f"PRAGMA key = '{settings.db_encryption_key}'")
            user_row = connection.execute("SELECT password_hash FROM users WHERE username = ?", ("sso_admin@example.com",)).fetchone()
            self.assertIsNotNone(user_row)
            self.assertTrue(str(user_row[0]).startswith("enc:v1:"))

    def test_login_refresh_rbac_and_device_auth(self) -> None:
        client = TestClient(app)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        tokens = login_response.json()

        bearer = {"Authorization": f"Bearer {tokens['access_token']}"}
        admin_response = client.post("/api/v1/admin/rbac-check", headers=bearer)
        self.assertEqual(admin_response.status_code, 200)

        device_register = client.post(
            "/api/v1/devices/register",
            headers=bearer,
            json={"device_id": "device-002", "name": "Lab Sensor", "api_key": "device-key-002"},
        )
        self.assertEqual(device_register.status_code, 200)

        ingest_response = client.post(
            "/api/v1/devices/ingest",
            headers={"X-Device-Id": "device-002", "X-Api-Key": "device-key-002"},
            json={"destination_ip": "10.0.0.20", "destination_port": 1883, "request_count": 10, "payload": {"temperature": 42}},
        )
        self.assertEqual(ingest_response.status_code, 200)

        wrong_login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "wrong-password"},
        )
        self.assertEqual(wrong_login.status_code, 400)

        refresh_response = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self.assertEqual(refresh_response.status_code, 200)

    def test_admin_api_inventory(self) -> None:
        client = TestClient(app)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        bearer = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

        inventory_response = client.get("/api/v1/admin/api-inventory", headers=bearer)
        self.assertEqual(inventory_response.status_code, 200)
        paths = {route["path"] for route in inventory_response.json()}
        self.assertIn("/api/v1/auth/login", paths)
        self.assertIn("/api/v1/admin/api-inventory", paths)

    def test_day3_detection_alerts_and_dashboard(self) -> None:
        client = TestClient(app)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        bearer = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

        register_response = client.post(
            "/api/v1/devices/register",
            headers=bearer,
            json={"device_id": "device-003", "name": "Anomaly Probe", "api_key": "device-key-003"},
        )
        self.assertEqual(register_response.status_code, 200)

        ingest_response = client.post(
            "/api/v1/devices/ingest",
            headers={"X-Device-Id": "device-003", "X-Api-Key": "device-key-003"},
            json={
                "destination_ip": "8.8.8.8",
                "destination_port": 443,
                "request_count": 120,
                "payload": {"query": "<script>alert('x')</script>"},
            },
        )
        self.assertEqual(ingest_response.status_code, 200)
        self.assertGreaterEqual(ingest_response.json()["alerts_created"], 2)

        alerts_response = client.get("/api/v1/alerts", headers=bearer)
        self.assertEqual(alerts_response.status_code, 200)
        alerts = alerts_response.json()
        self.assertGreaterEqual(len(alerts), 2)
        rule_names = {alert["rule_name"] for alert in alerts}
        self.assertIn("suspicious_request_frequency", rule_names)
        self.assertIn("unusual_destination_pattern", rule_names)
        self.assertIn("malformed_payload_signature", rule_names)

        devices_response = client.get("/api/v1/devices", headers=bearer)
        self.assertEqual(devices_response.status_code, 200)
        self.assertTrue(any(device["device_id"] == "device-003" for device in devices_response.json()))

        summary_response = client.get("/api/v1/dashboard/summary", headers=bearer)
        self.assertEqual(summary_response.status_code, 200)
        summary = summary_response.json()
        self.assertGreaterEqual(summary["traffic_logs_total"], 1)
        self.assertGreaterEqual(summary["alerts_total"], 2)
        self.assertGreaterEqual(summary["audit_entries_total"], 1)

    def test_day4_isolation_workflow(self) -> None:
        client = TestClient(app)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        bearer = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

        register_response = client.post(
            "/api/v1/devices/register",
            headers=bearer,
            json={"device_id": "device-004", "name": "Field Sensor", "api_key": "device-key-004"},
        )
        self.assertEqual(register_response.status_code, 200)

        isolate_response = client.post(
            "/api/v1/response/isolate-device",
            headers=bearer,
            json={"device_id": "device-004", "reason": "High-risk anomaly detected"},
        )
        self.assertEqual(isolate_response.status_code, 200)
        self.assertEqual(isolate_response.json()["status"], "isolated")

        ingest_after_isolation = client.post(
            "/api/v1/devices/ingest",
            headers={"X-Device-Id": "device-004", "X-Api-Key": "device-key-004"},
            json={"destination_ip": "10.1.0.2", "destination_port": 1883, "request_count": 4, "payload": {"ok": True}},
        )
        self.assertEqual(ingest_after_isolation.status_code, 401)

        deisolate_response = client.post(
            "/api/v1/response/deisolate-device",
            headers=bearer,
            json={"device_id": "device-004", "reason": "Threat cleared"},
        )
        self.assertEqual(deisolate_response.status_code, 200)
        self.assertEqual(deisolate_response.json()["status"], "active")

        ingest_after_deisolation = client.post(
            "/api/v1/devices/ingest",
            headers={"X-Device-Id": "device-004", "X-Api-Key": "device-key-004"},
            json={"destination_ip": "10.1.0.3", "destination_port": 1883, "request_count": 3, "payload": {"ok": True}},
        )
        self.assertEqual(ingest_after_deisolation.status_code, 200)

    def test_admin_rule_crud_and_dynamic_detection(self) -> None:
        client = TestClient(app)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        bearer = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

        rules_response = client.get("/api/v1/admin/rules", headers=bearer)
        self.assertEqual(rules_response.status_code, 200)
        rules = rules_response.json()
        self.assertGreaterEqual(len(rules), 3)

        created_rule = client.post(
            "/api/v1/admin/rules",
            headers=bearer,
            json={
                "rule_name": "custom_payload_probe",
                "description": "Catch custom token in payload",
                "severity": "medium",
                "enabled": True,
                "config": {
                    "type": "payload_signature",
                    "message": "Custom payload signature matched",
                    "signatures": ["evil-marker-123"],
                },
            },
        )
        self.assertEqual(created_rule.status_code, 200)
        rule_id = created_rule.json()["rule_id"]

        register_device = client.post(
            "/api/v1/devices/register",
            headers=bearer,
            json={"device_id": "device-rule-001", "name": "Rule Test Device", "api_key": "device-rule-key-001"},
        )
        self.assertEqual(register_device.status_code, 200)

        ingest_trigger = client.post(
            "/api/v1/devices/ingest",
            headers={"X-Device-Id": "device-rule-001", "X-Api-Key": "device-rule-key-001"},
            json={
                "destination_ip": "10.0.0.50",
                "destination_port": 8080,
                "request_count": 5,
                "payload": {"note": "contains evil-marker-123"},
            },
        )
        self.assertEqual(ingest_trigger.status_code, 200)
        self.assertGreaterEqual(ingest_trigger.json()["alerts_created"], 1)

        disabled = client.post(f"/api/v1/admin/rules/{rule_id}/disable", headers=bearer)
        self.assertEqual(disabled.status_code, 200)
        self.assertFalse(disabled.json()["enabled"])

        ingest_after_disable = client.post(
            "/api/v1/devices/ingest",
            headers={"X-Device-Id": "device-rule-001", "X-Api-Key": "device-rule-key-001"},
            json={
                "destination_ip": "10.0.0.51",
                "destination_port": 8080,
                "request_count": 5,
                "payload": {"note": "contains evil-marker-123"},
            },
        )
        self.assertEqual(ingest_after_disable.status_code, 200)
        self.assertEqual(ingest_after_disable.json()["alerts_created"], 0)

        updated = client.patch(
            f"/api/v1/admin/rules/{rule_id}",
            headers=bearer,
            json={"severity": "high", "config": {"type": "payload_signature", "message": "Updated signature", "signatures": ["evil-marker-123"]}},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["severity"], "high")

        enabled = client.post(f"/api/v1/admin/rules/{rule_id}/enable", headers=bearer)
        self.assertEqual(enabled.status_code, 200)
        self.assertTrue(enabled.json()["enabled"])

    def test_day5_backup_and_security_checks(self) -> None:
        client = TestClient(app)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(login_response.status_code, 200)
        bearer = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

        sql_injection_like_payload = client.post(
            "/api/v1/devices/ingest",
            headers={"X-Device-Id": "device-001", "X-Api-Key": "device-key-001"},
            json={
                "destination_ip": "10.0.0.8",
                "destination_port": 8080,
                "request_count": 40,
                "payload": {"query": "SELECT * FROM users WHERE name = '' OR 1=1; DROP TABLE users;"},
            },
        )
        self.assertEqual(sql_injection_like_payload.status_code, 200)
        self.assertGreaterEqual(sql_injection_like_payload.json()["alerts_created"], 1)

        alerts_response = client.get("/api/v1/alerts", headers=bearer)
        self.assertEqual(alerts_response.status_code, 200)
        self.assertTrue(any(alert["rule_name"] == "malformed_payload_signature" for alert in alerts_response.json()))

        invalid_token_access = client.get("/api/v1/alerts", headers={"Authorization": "Bearer bad-token"})
        self.assertEqual(invalid_token_access.status_code, 401)

        backup_response = client.get("/api/v1/admin/backup/snapshot", headers=bearer)
        self.assertEqual(backup_response.status_code, 200)
        backup = backup_response.json()
        self.assertIn("devices", backup)
        self.assertIn("alerts", backup)
        self.assertIn("audit_logs", backup)
        self.assertTrue(any(entry["action"] == "backup_snapshot_exported" for entry in backup["audit_logs"]))

    def test_bruteforce_lockout(self) -> None:
        client = TestClient(app)

        for _ in range(5):
            response = client.post(
                "/api/v1/auth/login",
                json={"username": "admin@example.com", "password": "bad-password"},
            )
            self.assertEqual(response.status_code, 400)

        locked_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "ChangeMe123!ChangeMe123!ChangeMe123!"},
        )
        self.assertEqual(locked_response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

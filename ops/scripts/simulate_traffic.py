from __future__ import annotations

import argparse
import json
import os
import random
import time
import urllib.request
import urllib.error
from typing import Any


def request_json(
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None
) -> dict[str, Any]:

    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url=url, data=body, method=method)

    request.add_header("Content-Type", "application/json")

    for key, value in (headers or {}).items():
        request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        print(f"HTTP Error {e.code}: {e.reason}")

        if error_body:
            print(f"Response: {error_body}")

        # IMPORTANT: do NOT crash simulation
        return {}

    except Exception as e:
        print(f"Unexpected error: {e}")
        return {}


def random_public_ip() -> str:
    return random.choice(["8.8.8.8", "1.1.1.1", "142.250.190.78", "208.67.222.222"])


def random_private_ip() -> str:
    return random.choice(["10.0.0.21", "10.1.2.13", "192.168.1.15", "172.16.0.44"])


def benign_payload() -> dict[str, Any]:
    return {
        "sensor": random.choice(["temp", "humidity", "pressure"]),
        "value": round(random.uniform(15.0, 40.0), 2),
        "ts": int(time.time()),
    }


def malicious_payload() -> dict[str, Any]:
    candidates = [
        {"query": "<script>alert('xss')</script>"},
        {"query": "SELECT * FROM users WHERE name='' OR 1=1; DROP TABLE users;"},
        {"path": "../../etc/passwd"},
        {"query": "UNION SELECT password FROM users"},
    ]
    return random.choice(candidates)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IoT traffic simulator for security testing"
    )

    base_url = parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000/api/v1"
    )

    parser.add_argument("--username", default=os.getenv("DEMO_ADMIN_USERNAME", "admin@example.com"))
    parser.add_argument("--password", default=os.getenv("DEMO_ADMIN_PASSWORD", "ChangeMe123!ChangeMe123!ChangeMe123!"))

    # FIXED: device_id must be ≤ 9 chars (backend constraint)
    parser.add_argument("--device-id", default="dev001")

    parser.add_argument("--device-name", default="Simulator Device")
    parser.add_argument("--device-api-key", default=os.getenv("DEMO_DEVICE_API_KEY", "sim-device-key-001"))
    parser.add_argument("--no-register", action="store_true", help="Do not register device; use provided device credentials as-is")

    parser.add_argument("--packets", type=int, default=20)
    parser.add_argument("--malicious-ratio", type=float, default=0.35)

    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    # ---------------- LOGIN ----------------
    login = request_json(
        f"{base_url}/auth/login",
        method="POST",
        payload={
            "username": args.username,
            "password": args.password,
        },
    )

    token = login.get("access_token", "")
    if not token:
        print("Login failed - no token received")
        return

    bearer_headers = {
        "Authorization": f"Bearer {token}"
    }

    # ---------------- REGISTER DEVICE (optional) ----------------
    if not args.no_register:
        print(f"Registering device {args.device_id}...")
        request_json(
            f"{base_url}/devices/register",
            method="POST",
            payload={
                "device_id": args.device_id,
                "name": args.device_name,
                "api_key": args.device_api_key,
            },
            headers=bearer_headers,
        )
    else:
        print(f"Skipping device registration; using device_id={args.device_id} and provided api_key.")

    total_alerts = 0

    # ---------------- TRAFFIC SIMULATION ----------------
    for index in range(args.packets):

        is_malicious = random.random() < args.malicious_ratio
        use_high_frequency = random.random() < 0.25

        destination_ip = random_public_ip() if random.random() < 0.45 else random_private_ip()
        request_count = random.randint(100, 170) if use_high_frequency else random.randint(1, 45)

        payload = malicious_payload() if is_malicious else benign_payload()

        ingest_response = request_json(
            f"{base_url}/devices/ingest",
            method="POST",
            payload={
                "destination_ip": destination_ip,
                "destination_port": random.choice([80, 443, 1883, 8080]),
                "request_count": request_count,
                "payload": payload,
            },
            headers={
                "X-Device-Id": args.device_id,
                "X-Api-Key": args.device_api_key,
            },
        )

        created = int(ingest_response.get("alerts_created", 0))
        total_alerts += created

        print(f"packet={index+1:02d} malicious={is_malicious} alerts_created={created}")

        time.sleep(random.uniform(0.08, 0.35))

    # ---------------- FETCH ALERTS ----------------
    alerts = request_json(f"{base_url}/alerts", headers=bearer_headers)

    if isinstance(alerts, list):
        print("\nRecent alerts:")
        for item in alerts[:10]:
            print(f"- {item.get('rule_name')} | {item.get('severity')} | {item.get('message')}")

        print(f"\nTotal alerts returned: {len(alerts)}")

    print(f"\nSimulation completed. Total alerts created: {total_alerts}")


if __name__ == "__main__":
    main()
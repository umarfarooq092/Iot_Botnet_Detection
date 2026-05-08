from __future__ import annotations

import argparse
import json
import os
import random
import time
import urllib.request
from typing import Any


def request_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
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
        # Read error response body for better debugging
        error_body = e.read().decode("utf-8") if e.fp else ""
        print(f"HTTP Error {e.code}: {e.reason}")
        if error_body:
            print(f"Response: {error_body}")
        raise


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
    parser = argparse.ArgumentParser(description="Send mixed normal/malicious IoT traffic and trigger alert rules")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api/v1", help="Backend API base URL")
    parser.add_argument("--username", default=os.getenv("DEMO_ADMIN_USERNAME", "admin@example.com"), help="Admin username")
    parser.add_argument("--password", default=os.getenv("DEMO_ADMIN_PASSWORD", "ChangeMe123!ChangeMe123!ChangeMe123!"), help="Admin password")
    parser.add_argument("--device-id", default="sim-device-001", help="Device ID to register/use")
    parser.add_argument("--device-name", default="Simulator Device", help="Device display name")
    parser.add_argument("--device-api-key", default=os.getenv("DEMO_DEVICE_API_KEY", "sim-device-key-001"), help="Device API key")
    parser.add_argument("--packets", type=int, default=20, help="Number of packets to send")
    parser.add_argument("--malicious-ratio", type=float, default=0.35, help="Percent (0-1) of malicious packets")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    try:
        login = request_json(
            f"{base_url}/auth/login",
            method="POST",
            payload={"username": args.username, "password": args.password},
        )
    except Exception as e:
        print(f"Login failed: {e}")
        raise
    token = str(login.get("access_token", ""))
    if not token:
        raise RuntimeError("Failed to obtain access token from /auth/login")

    bearer_headers = {"Authorization": f"Bearer {token}"}

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

    total_alerts = 0
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
        print(f"packet={index + 1:02d} malicious={is_malicious} alerts_created={created}")
        time.sleep(random.uniform(0.08, 0.35))

    alerts = request_json(f"{base_url}/alerts", headers=bearer_headers)
    if isinstance(alerts, list):
        recent = alerts[: min(10, len(alerts))]
        print("\nRecent alerts:")
        for item in recent:
            print(f"- {item.get('rule_name')} | {item.get('severity')} | {item.get('message')}")
        print(f"\nTotal alerts returned by API: {len(alerts)}")

    print(f"Simulation completed. Total alerts created in this run: {total_alerts}")


if __name__ == "__main__":
    main()

import requests, json

url = "http://localhost:8000/api/v1/auth/login"
results = []

payloads = [
    "' OR 1=1 --", "'; DROP TABLE users; --", "admin'--",
    "; ls -la", "&& whoami", "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "../../etc/passwd",
    "%00", "true", "-1", "null", '{"injected": true}',
    "A" * 10001, "\u0000\u0001"
]

for p in payloads:
    r = requests.post(url, json={"username": p, "password": "test"}, timeout=5)
    flag = " <-- INTERESTING" if r.status_code not in [400, 422, 429] else ""
    print(f"[{r.status_code}] {repr(p[:40])}{flag}")
    results.append({"payload": p, "status": r.status_code, "response": r.text[:80]})

with open("fuzz_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nDone. Results saved to fuzz_results.json")
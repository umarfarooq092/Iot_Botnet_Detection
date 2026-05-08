# Run and Test Guide (Day 1 + Day 2 + Day 3 + Day 4 + Day 5)

This guide shows exactly how to run and test the Python backend and frontend work completed for Day 1 to Day 5.

## 1) Open Terminal in Project Root

Use the folder:

D:\Lectures\Secure Software Design\Assignment 3

## 2) Activate Virtual Environment

PowerShell:

```powershell
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& ".\.venv\Scripts\Activate.ps1")
```

## 3) Install Backend Dependencies

```powershell
cd backend
pip install -r requirements.txt
```

## 4) Environment Variables (Optional in Local Development)

You can run locally without setting JWT/TOKEN variables manually.

- Backend now uses a built-in development JWT secret when `ENVIRONMENT=development`.
- SQLite database is automatically created at:
  - backend/data/ssd_app.db

Demo credentials are now read from `backend/.env`.

If you want to override them for a terminal session:

```powershell
$env:DEMO_ADMIN_USERNAME = "admin@example.com"
$env:DEMO_ADMIN_PASSWORD = "ChangeMe123!ChangeMe123!ChangeMe123!"
$env:DEMO_DEVICE_ID = "device-001"
$env:DEMO_DEVICE_API_KEY = "device-key-001"
```

## 5) Run Backend Server

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Health check URL:

http://127.0.0.1:8000/api/v1/health

## 6) Run Frontend Dashboard (Day 4)

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Dashboard URL:

http://127.0.0.1:5173

Frontend auto-login behavior:
- The dashboard automatically logs in with demo admin credentials on first load.
- No manual token copy/paste is required.

## 7) Run Full Automated Backend Tests (Day 2 to Day 5 coverage)

Open another terminal, activate venv again, then run:

```powershell
cd backend
python -m unittest discover tests -v
```

Expected result:
- 10 tests pass
- Includes login, registration, refresh rotation, RBAC denial for non-admin, brute-force lockout, device API-key auth, detection and alerts flow, device isolation workflow, backup export endpoint, invalid token checks, and admin rule CRUD/evaluation checks

## 8) Run Day 1 Security Baseline Smoke Test

From backend folder:

```powershell
python -c "import os; os.environ['JWT_SECRET']='a'*32; os.environ['ACCESS_TOKEN_TTL']='15m'; os.environ['PORT']='8000'; os.environ['RATE_LIMIT_MAX']='5'; os.environ['RATE_LIMIT_WINDOW_SECONDS']='60'; from fastapi.testclient import TestClient; from app.main import app; c=TestClient(app); h=c.get('/api/v1/health'); assert h.status_code==200; assert h.headers.get('x-content-type-options')=='nosniff'; assert h.headers.get('x-frame-options')=='DENY'; o=c.post('/api/v1/security/hash-password', headers={'content-length':'999999999'}, json={'password':'abc'}); assert o.status_code==413; blocked=False; [ (blocked := True) if c.get('/api/v1/health').status_code==429 else None for _ in range(10) ]; assert blocked; print('Day 1 checks passed')"
```

Expected result:
- Prints: Day 1 checks passed

## 9) Manual API Checks (Optional)

Use Swagger in browser:

http://127.0.0.1:8000/docs

Recommended manual flow:
1. POST /api/v1/auth/login with admin credentials.
2. POST /api/v1/admin/rbac-check with Bearer token from login.
3. POST /api/v1/devices/register with Bearer token.
4. POST /api/v1/devices/ingest with headers X-Device-Id and X-Api-Key and body fields destination_ip, destination_port, request_count, payload.
5. GET /api/v1/alerts with Bearer token and confirm generated alerts appear.
6. GET /api/v1/devices and GET /api/v1/dashboard/summary with Bearer token.
7. POST /api/v1/response/isolate-device and confirm device status changes to isolated.
8. GET /api/v1/admin/backup/snapshot and confirm export payload includes alerts and audit logs.
9. POST /api/v1/auth/refresh using refresh token from login.
10. Try refresh again with old refresh token and confirm rejection.

## 10) Troubleshooting

- Error: JWT_SECRET must be at least 32 characters
  Set JWT_SECRET to at least 32 characters before running app/tests.

- Error: No module named httpx
  Run: pip install -r requirements.txt

- Many 429 responses while testing multiple APIs quickly
  This is expected from rate limiting. Restart app process or wait for rate limit window.

- Frontend cannot call backend (network/CORS errors)
  Ensure backend is running on port 8000 and frontend on port 5173.

## 11) Simulate Real Traffic and Trigger Alerts (Random + Malicious)

Run this from project root in a new terminal while backend and frontend are running:

```powershell
python ops/scripts/simulate_traffic.py --packets 30 --malicious-ratio 0.4
```

What it does:
- Logs in as admin
- Registers a simulator device
- Sends mixed normal and malicious packets to `/api/v1/devices/ingest`
- Triggers alert rules when conditions match
- Prints recent alerts at the end

To observe in website:
- Open Dashboard and Alerts pages after running the script
- Alerts and summary counters update as new data is ingested
# SSD Assignment 3

Secure IoT botnet detection and response platform with a Python FastAPI backend and a React TypeScript frontend.

This repository demonstrates an end-to-end secure workflow:
- Device traffic ingestion
- Rule-based attack detection
- Alerting and response actions
- RBAC-protected administration
- MFA and SSO authentication
- Backup and security baseline support

## 1. What This Project Does

The system monitors device traffic and detects suspicious patterns (for example high request bursts or suspicious payloads). It exposes APIs for authentication, device management, alerts, and incident response. A web dashboard lets admins and users view activity and take response actions.

The project is built as a monorepo so backend, frontend, operations scripts, and documentation stay in sync.

## 2. High-Level Architecture

### Backend
- Framework: FastAPI
- Core location: `backend/app`
- Responsibilities:
  - Auth (JWT, refresh token rotation, MFA, SSO)
  - Authorization (RBAC and owner-based access for `/me/*` endpoints)
  - Device ingestion pipeline
  - Rule evaluation and alert creation
  - Audit logging and snapshot export
  - Security middleware (rate limiting, CSP, request-size checks, secure headers)

### Frontend
- Framework: React + TypeScript + Vite
- Core location: `frontend/src`
- Responsibilities:
  - Login and token handling
  - MFA challenge/setup interactions
  - Alerts, devices, and dashboard views
  - Response actions (isolate/de-isolate)

### Operations and Security Scripts
- Location: `ops/scripts`
- Includes:
  - Traffic simulation
  - Backup utilities
  - API inventory export
  - SBOM generation

## 3. Repository Layout

- `backend/` FastAPI service, tests, and API security logic
- `frontend/` React dashboard and auth UX
- `ops/` utility scripts for backups, simulation, and security operations
- `submission/` packaged mirror for submission artifacts

## 4. How It Works (Runtime Flow)

1. A client logs in through `/api/v1/auth/login`.
2. If MFA is enabled, login returns a pending MFA token, then OTP is verified via `/api/v1/auth/mfa/validate`.
3. Admins can register devices and rules.
4. Devices send telemetry to `/api/v1/devices/ingest` using device credentials.
5. Backend evaluates rules and writes alerts + audit records.
6. Dashboard and alert endpoints display system state.
7. Response endpoints isolate/de-isolate compromised devices.

## 5. Security Features Implemented

### Identity and Access
- JWT access tokens and refresh token rotation
- Role-based authorization for admin endpoints
- Owner-based object-level authorization for user-scoped endpoints
- TOTP MFA flow using `pyotp`
- Google OAuth2/OIDC SSO using `authlib`

### API and App Hardening
- Global request rate limiting
- Request body size limits
- Server-side schema validation
- Security headers + CSP
- SSRF whitelist helper for redirect URL validation
- API inventory endpoint and export script

### Data Protection
- Application-layer field encryption
- SQLCipher path for database at-rest encryption (production key-based)
- TLS support for in-transit encryption in development and deployment

### Logging, Audit, and Recovery
- Structured application logging
- Hash-chained audit records
- Backup snapshot endpoint and backup scripts

## 6. Authentication and Authorization Endpoints

### Core Auth
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`

### MFA
- `POST /api/v1/auth/mfa/setup`
- `POST /api/v1/auth/mfa/verify`
- `POST /api/v1/auth/mfa/validate`

### Google SSO
- `POST /api/v1/auth/sso/google`
- `GET /api/v1/auth/sso/google/callback`

### Admin API Inventory
- `GET /api/v1/admin/api-inventory`

## 7. Prerequisites

- Python 3.13+
- Node.js 20+
- npm 10+
- PowerShell (for Windows commands/scripts)

## 8. Quick Start

From repository root:

```powershell
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& ".\.venv\Scripts\Activate.ps1")
cd backend
pip install -r requirements.txt
# Run locally bound to localhost only to avoid exposing the service on the LAN
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Useful URLs:
- API health: `http://127.0.0.1:8000/api/v1/health`
- Swagger: `http://127.0.0.1:8000/docs`
- Frontend: `http://127.0.0.1:5173`

## 9. Environment Configuration

Main backend environment file: `backend/.env`

Common variables:
- `ENVIRONMENT`
- `JWT_SECRET`
- `ACCESS_TOKEN_TTL`
- `DATA_ENCRYPTION_KEY`
- `DB_ENCRYPTION_KEY`
- `SSO_ENABLED`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`
- `TLS_ENABLED`
- `TLS_CERTFILE`
- `TLS_KEYFILE`

Notes:
- In production, use strong non-placeholder secrets and a managed secret source.
- For SQLCipher at-rest encryption, set `DB_ENCRYPTION_KEY` to a strong value.

## 10. Testing

Backend unit tests:

```powershell
cd backend
python -m unittest discover tests -v
```

The current backend suite includes authentication, MFA, SSO, RBAC, ingestion/detection, response workflow, and security validation coverage.

## 11. Operations Scripts

### Simulate Traffic

```powershell
python ops/scripts/simulate_traffic.py --packets 30 --malicious-ratio 0.4
```

### Export API Inventory

```powershell
python ops/scripts/export_api_inventory.py
```

### Backup/Restore Sanity

```powershell
python ops/scripts/backup_and_restore.py
```

### Generate SBOM Snapshot

```powershell
python ops/scripts/generate_sbom.py
```

## 12. Security Baseline Tracking

Code-only baseline status is tracked in:
- `Security_Baseline_Code_Checklist.md`

This separates code-implementable controls from infrastructure, organizational, and physical controls.

## 13. Known Scope Boundaries

The following are intentionally outside pure application-code scope and are typically handled by platform/operations teams:
- Network perimeter controls (firewalls/IDS/DDoS)
- Physical security controls
- Human security programs
- Organization-wide governance and compliance workflows

## 14. Documents You Should Read Next

- `run.md` for full run and manual test sequence
- `Security_Baseline.md` for security baseline requirements
- `Security_Baseline_Code_Checklist.md` for code-only pass/partial/fail tracking

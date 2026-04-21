# Daily Plan for Assignment 3 (4/21/2026 to 4/26/2026)

## 1) What You Should Build First (Starting Point)

Start with the security-critical backbone before UI polish:

1. Authentication and authorization foundation (login, session/JWT, RBAC for admin actions)
2. Device ingestion API (TLS-ready, API key authentication, strict input validation)
3. Data model and secure storage (users, devices, traffic logs, alerts, admin audit logs)
4. Threat detection pipeline (rule-based first, anomaly extension later)
5. Threat response action (device isolation workflow + audit trail)
6. Dashboard and alerts UI

Reason: Your diagrams and security baseline prioritize trust boundaries, authentication, authorization, secure flows, logging, and response actions. Building these first prevents major rework and covers the core grading criteria.

---

## 2) Recommended Tech Stack (Best Fit for Your Scope + Deadline)

## Frontend
- Language: TypeScript
- Framework: React (with Vite)
- UI: Tailwind CSS + component library (optional)
- Why: Fast development speed, strong ecosystem, easy secure form validation, rapid dashboard creation

## Backend
- Language: TypeScript
- Runtime/Framework: Node.js + NestJS (or Express if you want simpler)
- Why: Excellent structure for modular security architecture (Auth module, Device module, Detection module, Response module), strong validation and guard patterns

## Database
- Primary DB: PostgreSQL
- Why: Strong ACID consistency for logs/actions, great for relational entities (users/devices/alerts/audit logs), supports row-level controls and mature tooling

## Cache / Rate Limiting Store
- Redis
- Why: Reliable rate limiting, lockout counters, short-lived token/session helpers

## Queue (if time allows)
- BullMQ (Redis-backed) for async detection processing
- Why: Keeps ingestion API responsive and improves resilience

## Security & Infra Tools
- Auth: JWT access tokens + refresh tokens (short expiry)
- Password hashing: Argon2id (or bcrypt)
- Validation: Zod or class-validator (server-side mandatory)
- ORM: Prisma
- Logging: Pino/Winston + immutable append-style audit table
- Secrets: .env for local, but no hardcoded secrets in code
- Dependency scanning: npm audit + Snyk/OSV (if available)

---

## 3) Functional Scope You Must Finish

From your diagrams and report, your minimum fully functional website should include:

1. Admin secure login/logout
2. Role-based authorization for sensitive actions
3. Device registration/authentication via API key
4. Device traffic ingestion endpoint
5. Threat detection (rule-based checks)
6. Alert generation and viewing
7. Device isolation/block action workflow
8. Dashboard with device status + alert summaries
9. Audit logging for sensitive admin actions
10. Security controls: validation, rate limiting, secure errors, no plaintext secrets/passwords

---

## 4) Daily Execution Plan

## Day 1 - Tue, 4/21/2026 (Architecture + Secure Foundation)

### Coding Goals
- Initialize monorepo or two folders:
  - frontend/
  - backend/
- Backend initial modules:
  - auth
  - users
  - devices
  - traffic
  - alerts
  - response
  - audit
- Configure PostgreSQL + Prisma schema:
  - User
  - Device
  - TrafficLog
  - Alert
  - AdminActionLog
- Add baseline security middleware:
  - Helmet
  - CORS policy (restricted)
  - request size limits
  - centralized error handler
- Add environment variable validation at startup

### Security Implementation
- Password hashing utility (Argon2/bcrypt)
- JWT issuance utility with short expiry
- API response sanitizer for errors

### Deliverables by End of Day
- Running backend skeleton
- DB migrations created and applied
- README draft with setup steps started

---

## Day 2 - Wed, 4/22/2026 (Authentication + RBAC + Device Auth)

### Coding Goals
- Implement secure login endpoint:
  - input validation
  - credential check
  - hashed password verification
  - failed-attempt counter + lockout/rate limiting
- Implement token/session flow:
  - access token
  - refresh token rotation (or simple revocation list)
- Implement RBAC guards:
  - only admin role can isolate device/configure rules
- Device API key authentication for device ingestion endpoint

### Security Implementation
- Add brute-force protection on login
- Add API rate limiting (global + endpoint specific)
- Add secure cookie flags if cookie-based auth is used

### Deliverables by End of Day
- Auth flow fully working via Postman/Insomnia
- Protected routes cannot be accessed without correct role/auth

---

## Day 3 - Thu, 4/23/2026 (Traffic Pipeline + Detection + Alerts)

### Coding Goals
- Implement device traffic ingestion endpoint:
  - schema validation
  - anti-injection safety
  - store encrypted-sensitive fields if needed
- Implement detection engine (rule-based MVP):
  - suspicious request frequency
  - unusual destination patterns
  - malformed payload signatures
- Create alert generation service
- Build APIs:
  - GET /alerts
  - GET /devices
  - GET /dashboard/summary

### Security Implementation
- Ensure all DB access is parameterized via ORM
- Add tamper-evident hash chain field for alert/audit records (MVP optional but strong)
- Ensure audit entries for detection and admin actions

### Deliverables by End of Day
- End-to-end: device sends data -> detection runs -> alert appears in DB/API

---

## Day 4 - Fri, 4/24/2026 (Frontend Dashboard + Isolation Workflow)

### Coding Goals
- Build frontend pages:
  - Login
  - Dashboard summary cards
  - Alerts table
  - Device list/status
- Build secure API client with token handling
- Implement isolation action button for admin-only users
- Implement device isolation backend endpoint:
  - privilege check
  - action log
  - device status update (isolated)

### Security Implementation
- Frontend input validation and output encoding hygiene
- No sensitive data stored in local storage beyond necessary tokens
- Add CSRF protection strategy if cookie auth is used

### Deliverables by End of Day
- Functional website where admin can login, view alerts/devices, isolate suspicious device

---

## Day 5 - Sat, 4/25/2026 (Hardening + Testing + Documentation)

### Coding Goals
- Add missing controls from Security_Baseline.md that are practical in assignment scope:
  - secure headers
  - stricter validation
  - consistent audit logging
  - backup script for DB export
- Refactor code quality issues (modularization, naming, cleanup)

### Testing Plan (Must Complete)
- Unit tests:
  - auth service
  - validation logic
  - detection rules
- Integration tests:
  - login flow
  - device data ingestion
  - alert generation
  - isolation endpoint authorization
- Security tests/checks:
  - SQL injection attempts
  - XSS payload handling
  - invalid token access
  - brute-force attempt simulation
  - rate limit verification
- Manual QA:
  - full user flow from login to response action

### Documentation Deliverables
- Final README.md:
  - setup
  - env variables
  - run steps
  - security features
- Security_Documentation.md:
  - auth model
  - authorization model
  - encryption choices
  - API security controls
  - input validation strategy
  - session management

---

## Day 6 - Sun, 4/26/2026 (Final Verification + Packaging + Submission)

### Morning (Code Freeze)
- Fix only critical/high bugs
- Re-run all tests
- Re-run dependency vulnerability scan
- Confirm no secrets in repository

### Afternoon (Submission Readiness)
- Final checklist:
  - source code complete
  - README complete
  - security documentation complete
  - env example file included
  - config files included
- Validate project starts from clean clone using README only

### Evening (Before 11:59 PM)
- Prepare ZIP: SSD_Assignment3_GroupName.zip
- Quick smoke test from zipped/extracted project
- Submit before deadline buffer (target: submit by 10:30 PM)

---

## 5) Project Structure Recommendation

- backend/
  - src/
    - modules/
      - auth/
      - users/
      - devices/
      - traffic/
      - detection/
      - alerts/
      - response/
      - audit/
    - common/
      - guards/
      - middleware/
      - validators/
      - utils/
  - prisma/
  - tests/
- frontend/
  - src/
    - pages/
    - components/
    - services/
    - hooks/
    - utils/
  - tests/
- docs/
  - Security_Documentation.md
- README.md
- .env.example

---

## 6) Must-Not-Miss Security Checklist

1. No plaintext passwords or secrets
2. Strict server-side validation on every input
3. Parameterized DB access only
4. TLS/HTTPS enforced in deployment settings
5. Role checks on every sensitive endpoint
6. Rate limiting for login and device endpoints
7. Safe error messages (no stack traces to clients)
8. Audit logs for admin actions and response operations
9. Token expiration and secure session handling
10. Dependency scan + patch vulnerable packages

---

## 7) Language + DB Final Decision (Recommended)

- Frontend language: TypeScript
- Frontend framework: React + Vite
- Backend language: TypeScript
- Backend framework: NestJS
- Database: PostgreSQL
- Additional stores: Redis for rate limits/caching

This stack gives the best balance of speed, maintainability, and security implementation coverage for your 6-day deadline.

---

## 8) Fast Risk Management for Deadline

If you start slipping on schedule:

1. Keep detection engine rule-based only (do not add ML now)
2. Prioritize fully working secure core over extra UI polish
3. Keep cloud deployment optional unless required by instructor
4. Complete testing + docs no later than 4/25 night
5. Reserve 4/26 mostly for bug-fix + packaging only

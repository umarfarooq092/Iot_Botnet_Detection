# Security Baseline

## 1. Identity & Access Management (IAM)

**Control ID:** IAM-001
**Severity:** Critical

### Requirements

* MUST enforce Multi-Factor Authentication (MFA) for all users
* MUST implement SSO using OAuth 2.0, SAML, or OpenID Connect
* MUST enforce Role-Based or Attribute-Based Access Control
* MUST enforce least privilege access
* MUST implement secure session management (expiration, secure cookies)

### OWASP Top 10

* A07: Identification & Authentication Failures
* A01: Broken Access Control

### OWASP ASVS

* V2: Authentication
* V3: Session Management
* V4: Access Control

### NIST CSF

* PR.AC

### NIST SP 800-53

* AC
* IA

---

## 2. Secrets Management

**Control ID:** SEC-001
**Severity:** Critical

### Requirements

* MUST store secrets in secure vaults
* MUST implement automatic secret rotation
* MUST use short-lived credentials
* MUST NOT store secrets in code or logs

### OWASP Top 10

* A02: Cryptographic Failures

### OWASP ASVS

* V6: Cryptography

### NIST CSF

* PR.DS

### NIST SP 800-53

* SC-12
* IA-5

---

## 3. Secure Coding Practices

**Control ID:** DEV-001
**Severity:** Critical

### Requirements

* MUST validate all inputs (server-side)
* MUST encode outputs to prevent XSS
* MUST prevent injection using parameterized queries
* MUST securely handle file uploads

### OWASP Top 10

* A03: Injection
* A05: Security Misconfiguration
* A04: Insecure Design

### OWASP ASVS

* V5
* V10

### NIST CSF

* PR.IP

### NIST SP 800-53

* SI-10
* SI-11

---

## 4. API Security

**Control ID:** API-001
**Severity:** Critical

### Requirements

* MUST maintain API inventory
* MUST enforce object-level authorization (BOLA protection)
* MUST implement rate limiting and quotas
* MUST validate and whitelist URLs to prevent SSRF

### OWASP Top 10

* A01: Broken Access Control
* A10: SSRF

### OWASP ASVS

* V4
* V14

### NIST CSF

* PR.AC
* DE.CM

### NIST SP 800-53

* AC-3
* SC-7

---

## 5. Cloud & Infrastructure Security

**Control ID:** INFRA-001
**Severity:** High

### Requirements

* MUST isolate networks using VPCs
* MUST secure containers (non-root, minimal images)
* MUST implement micro-segmentation

### OWASP Top 10

* A05: Security Misconfiguration

### OWASP ASVS

* V14

### NIST CSF

* PR.PT

### NIST SP 800-53

* SC-7
* CM-2

---

## 6. Supply Chain Security

**Control ID:** SUP-001
**Severity:** Critical

### Requirements

* MUST maintain SBOM
* MUST scan dependencies for vulnerabilities
* MUST sign and verify build artifacts

### OWASP Top 10

* A06: Vulnerable Components
* A08: Software Integrity Failures

### OWASP ASVS

* V1
* V10

### NIST CSF

* ID.SC

### NIST SP 800-53

* SA-12

---

## 7. DevSecOps & CI/CD

**Control ID:** CICD-001
**Severity:** Critical

### Requirements

* MUST implement SAST, DAST, or IAST
* MUST secure CI/CD pipelines
* MUST sign code before deployment

### OWASP Top 10

* A08: Software Integrity Failures

### OWASP ASVS

* V1

### NIST CSF

* PR.IP
* DE.CM

### NIST SP 800-53

* SA-11
* CM-3

---

## 8. Logging & Monitoring

**Control ID:** LOG-001
**Severity:** High

### Requirements

* MUST implement centralized logging
* MUST ensure logs are immutable
* MUST enable real-time alerting

### OWASP Top 10

* A09: Logging & Monitoring Failures

### OWASP ASVS

* V7

### NIST CSF

* DE.AE
* DE.CM

### NIST SP 800-53

* AU

---

## 9. Incident Response

**Control ID:** IR-001
**Severity:** High

### Requirements

* MUST maintain an incident response plan
* MUST support forensic analysis
* MUST conduct post-incident reviews

### NIST CSF

* RS

### NIST SP 800-53

* IR

---

## 10. Vulnerability Management

**Control ID:** VULN-001
**Severity:** Critical

### Requirements

* MUST perform continuous vulnerability scanning
* MUST apply patches promptly
* MUST conduct periodic penetration testing

### OWASP Top 10

* A06: Vulnerable Components

### NIST CSF

* ID.RA

### NIST SP 800-53

* RA-5
* SI-2

---

## 11. Data Security & Cryptography

**Control ID:** DATA-001
**Severity:** Critical

### Requirements

* MUST encrypt data at rest and in transit
* MUST implement key rotation
* MUST use secure key management systems

### OWASP Top 10

* A02: Cryptographic Failures

### OWASP ASVS

* V6

### NIST CSF

* PR.DS

### NIST SP 800-53

* SC-13

---

## 12. Network Security

**Control ID:** NET-001
**Severity:** High

### Requirements

* MUST implement firewalls and IDS/IPS
* MUST protect against DDoS attacks
* MUST enforce Zero Trust networking

### NIST CSF

* PR.PT

### NIST SP 800-53

* SC-7

---

## 13. Endpoint Security

**Control ID:** END-001
**Severity:** High

### Requirements

* MUST enforce device hardening
* MUST encrypt disks
* MUST deploy endpoint detection and response

### NIST CSF

* PR.PT

### NIST SP 800-53

* CM-6
* SI-3

---

## 14. Backup & Recovery

**Control ID:** BACKUP-001
**Severity:** Critical

### Requirements

* MUST maintain offline backups
* MUST test restoration regularly
* MUST define RTO and RPO

### NIST CSF

* RC

### NIST SP 800-53

* CP

---

## 15. Human Security

**Control ID:** HUM-001
**Severity:** High

### Requirements

* MUST conduct security awareness training
* MUST simulate phishing attacks
* MUST monitor insider threats

### NIST CSF

* PR.AT

### NIST SP 800-53

* AT

---

## 16. Physical Security

**Control ID:** PHY-001
**Severity:** Medium

### Requirements

* MUST secure physical data center access
* MUST monitor facilities
* MUST securely dispose of hardware

### NIST SP 800-53

* PE

---

## 17. Governance, Risk & Compliance

**Control ID:** GRC-001
**Severity:** High

### Requirements

* MUST perform risk assessments
* MUST maintain security policies
* MUST track compliance requirements

### NIST CSF

* ID.GV
* ID.RA

### NIST SP 800-53

* PL
* PM

---

## 18. Resilience & Availability

**Control ID:** RES-001
**Severity:** High

### Requirements

* MUST implement failover mechanisms
* MUST use circuit breakers
* MUST support auto-scaling

### OWASP Top 10

* A04: Insecure Design

### NIST CSF

* PR.PT
* RC

### NIST SP 800-53

* CP-10

---
# Use Case Diagram Details

## 1. Actors

### Admin

The Admin is the primary actor. The Admin interacts with the following use cases:

* Login
* View Alerts
* Isolate Device
* View Dashboard
* Configure Rules
* Monitor Device Activity

### IoT Device

The IoT Device is another actor. It interacts with:

* Monitor Device Activity

---

## 2. System Boundary

All use cases are inside a system boundary labeled "Usecase".
Both actors (Admin and IoT Device) are outside this boundary and interact with the system.

---

## 3. Use Cases and Relationships

### Login

* Connected to Admin
* «include» → Authenticate User

### Authenticate User

* Included by Login

---

### View Alerts

* Connected to Admin
* «extend» → Log Activity

### Log Activity

* Extended by View Alerts

---

### Isolate Device

* Connected to Admin
* «include» → Authorize Access

---

### View Dashboard

* Connected to Admin
* «include» → Authorize Access

---

### Authorize Access

* Included by:

  * Isolate Device
  * View Dashboard

---

### Configure Rules

* Connected to Admin
* No include or extend relationships

---

### Monitor Device Activity

* Connected to:

  * Admin
  * IoT Device
* «include» → Encrypt Communication
* «extend» → Generate Alert

---

### Encrypt Communication

* Included by Monitor Device Activity

---

### Generate Alert

* Extended by Monitor Device Activity

---

## 4. Summary of Relationships

### Include Relationships

* Login → Authenticate User
* Isolate Device → Authorize Access
* View Dashboard → Authorize Access
* Monitor Device Activity → Encrypt Communication

### Extend Relationships

* View Alerts → Log Activity
* Monitor Device Activity → Generate Alert

---

## 5. Interaction Overview

* The Admin performs multiple system operations.
* The IoT Device participates only in monitoring device activity.
* «include» represents required sub-processes.
* «extend» represents optional or conditional behavior.


# Misuse Case Diagram Details

## 1. Actors

### Admin

The Admin interacts with:

* Login
* View Data

### IoT Device

The IoT Device interacts with:

* Send Device Data

### Attacker

The Attacker interacts with:

* Brute Force Attack
* DoS Attack
* Spoof Device
* Tamper Data

---

## 2. System Boundary

All use cases and misuse cases are inside a system boundary labeled "Misusecase".
All actors (Admin, IoT Device, Attacker) are outside this boundary.

---

## 3. Use Cases, Misuse Cases, and Relationships

### Login

* Connected to Admin
* «include» → Credential Guessing

---

### Credential Guessing

* Included by Login

---

### Brute Force Attack

* Mitigated by:

  * Rate Limiting
* «extend» → DoS Attack

---

### Rate Limiting

* Mitigates Brute Force Attack

---

### Traffic Filtering

* Mitigates DoS Attack

---

### DoS Attack

* Extended by Brute Force Attack
* Mitigated by Traffic Filtering
* Threatens:

  * Send Device Data

---

### Send Device Data

* Connected to IoT Device
* Threatened by:

  * DoS Attack
  * Spoof Device

---

### Spoof Device

* Threatens Send Device Data
* «include» → Fake Identity
* Mitigated by:

  * Device Authentication

---

### Fake Identity

* Included by Spoof Device

---

### Device Authentication

* Mitigates Spoof Device

---

### View Data

* Connected to Admin
* Threatened by:

  * Tamper Data

---

### Packet Injection

* «include» → Tamper Data

---

### Tamper Data

* Included by Packet Injection
* Mitigated by:

  * TLS Encryption
* Threatens:

  * View Data

---

### TLS Encryption

* Mitigates Tamper Data

---

## 4. Summary of Relationships

### Include Relationships

* Login → Credential Guessing
* Spoof Device → Fake Identity
* Packet Injection → Tamper Data

---

### Extend Relationships

* Brute Force Attack → DoS Attack

---

### Threat Relationships

* DoS Attack → Send Device Data
* Spoof Device → Send Device Data
* Tamper Data → View Data

---

### Mitigation Relationships

* Rate Limiting → Brute Force Attack
* Traffic Filtering → DoS Attack
* Device Authentication → Spoof Device
* TLS Encryption → Tamper Data

---

## 5. Interaction Overview

* The Admin performs Login and View Data.
* The IoT Device sends device data to the system.
* The Attacker performs multiple misuse actions including Brute Force Attack, DoS Attack, Spoof Device, and Tamper Data.
* Some misuse cases include other misuse cases.
* Some misuse cases extend others.
* Some misuse cases threaten normal use cases.
* Some mechanisms mitigate misuse cases.

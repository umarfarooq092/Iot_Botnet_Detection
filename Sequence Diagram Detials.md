# Secure Login Sequence Diagram Details

## 1. Participants

The sequence diagram consists of the following participants:

* Admin
* Browser
* Server
* DB

---

## 2. Sequence Flow

### Step 1: Input Credentials

* Admin → Browser

  * Enter username & password {sensitive}

---

### Step 2: Send Credentials

* Browser → Server

  * Send credentials {encrypted, TLS}

---

### Step 3: Validate Input

* Server (self-action)

  * Validate input {input_validation, integrity}

---

### Step 4: Fetch User Record

* Server → DB

  * Fetch user record {secure_query}

* DB → Server

  * User data (hashed password) {confidential}

---

### Step 5: Verify Password

* Server (self-action)

  * Verify password (bcrypt) {secure_hash}

---

## 3. Conditional Flow (alt)

### [Valid Credentials]

* Server (self-action)

  * Generate session token {secure_session}

* Server → Browser

  * Login success + token {encrypted}

* Browser → Admin

  * Access granted

---

### [Invalid Credentials]

* Server → Browser

  * Error message {safe_response}

---

## 4. Summary of Flow

* Credentials are entered by Admin and passed through Browser to Server.
* Credentials are transmitted in encrypted form using TLS.
* Server performs input validation before querying the database.
* Database returns user data containing hashed password.
* Server verifies the password using bcrypt.
* Based on validation:

  * If valid, a secure session token is generated and access is granted.
  * If invalid, an error message is returned.


# Device Data Transmission Sequence Diagram Details

## 1. Participants

The sequence diagram consists of the following participants:

* Device
* Server
* DB

---

## 2. Sequence Flow

### Step 1: Send Traffic Data

* Device → Server

  * Send traffic data {encrypted, TLS, API_key}

---

### Step 2: Verify API Key

* Server (self-action)

  * Verify API key {authentication}

---

## 3. Conditional Flow (alt)

### [Valid Device]

#### Step 3: Validate Data

* Server (self-action)

  * Validate data {input_validation, integrity}

---

#### Step 4: Store Traffic Data

* Server → DB

  * Store traffic data {encrypted_at_rest, confidentiality}

* DB → Server

  * Acknowledgement

---

#### Step 5: Send Response

* Server → Device

  * Data received {secure_response}

---

### [Invalid Device]

#### Step 6: Reject Request

* Server → Device

  * Reject request {access_control}

---

## 4. Summary of Flow

* Device sends traffic data to Server with encryption, TLS, and API key.
* Server verifies API key for authentication.
* If device is valid:
  * Server validates incoming data.
  * Data is stored securely in DB with encryption at rest.
  * DB sends acknowledgement to Server.
  * Server responds to Device with secure confirmation.
* If device is invalid:
  * Server rejects the request with access control.


  # Threat Detection Process Sequence Diagram Details

## 1. Participants

The sequence diagram consists of the following participants:

* Server
* DetectionEngine
* DB
* Admin

---

## 2. Sequence Flow

### Step 1: Send Device Data

* Server → DetectionEngine

  * Send device data {secure_transfer}

---

### Step 2: Analyze Patterns

* DetectionEngine (self-action)

  * Analyze patterns {integrity}

---

### Step 3: Compare with Rules

* DetectionEngine (self-action)

  * Compare with rules {protected_rules}

---

## 3. Conditional Flow (alt)

### [Suspicious Activity Detected]

#### Step 4: Log Alert

* DetectionEngine → DB

  * Log alert {secure_log, non_repudiation}

* DB → DetectionEngine

  * Stored

---

#### Step 5: Send Alert

* DetectionEngine → Admin

  * Send alert {availability}

---

### [Normal Behavior]

#### Step 6: Store Normal Logs

* DetectionEngine → DB

  * Store normal logs {secure_storage}

* DB → DetectionEngine

  * Stored

---

## 4. Summary of Flow

* Server sends device data to DetectionEngine using secure transfer.
* DetectionEngine analyzes patterns and compares them with protected rules.
* If suspicious activity is detected:
  * Alert is logged in DB.
  * DB confirms storage.
  * Alert is sent to Admin.
* If behavior is normal:
  * Normal logs are stored in DB.
  * DB confirms storage.


  # Device Isolation Response Sequence Diagram Details

## 1. Participants

The sequence diagram consists of the following participants:

* Admin
* Server
* Firewall
* Device

---

## 2. Sequence Flow

### Step 1: Request Device Isolation

* Admin → Server

  * Request device isolation {auth_required, critical}

---

### Step 2: Verify Admin Privileges

* Server (self-action)

  * Verify admin privileges {authorization}

---

## 3. Conditional Flow (alt)

### [Authorized Admin]

#### Step 3: Block Device IP

* Server → Firewall

  * Block device IP {network_control, critical}

* Firewall → Server

  * Confirmation

---

#### Step 4: Terminate Connection

* Firewall → Device

  * Connection terminated {enforced}

---

#### Step 5: Log Action

* Server (self-action)

  * Log action {audit_log, non_repudiation}

---

#### Step 6: Isolation Successful

* Server → Admin

  * Isolation successful

---

### [Unauthorized]

#### Step 7: Access Denied

* Server → Admin

  * Access denied {access_control}

---

## 4. Summary of Flow

* Admin requests device isolation from Server with required authentication.
* Server verifies admin privileges for authorization.
* If admin is authorized:
  * Server instructs Firewall to block device IP.
  * Firewall confirms the action.
  * Firewall terminates connection with Device.
  * Server logs the action.
  * Server notifies Admin that isolation is successful.
* If admin is unauthorized:
  * Server denies access to Admin.
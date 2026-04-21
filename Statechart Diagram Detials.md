# Sequence Diagram Details

## Title: Admin Authentication

### States and Transitions

* **Start → Idle**

* **Idle → EnterCredentials**

  * Trigger: `start login`

* **EnterCredentials → Validating**

  * Trigger: `submit {TLS}`

* **Validating → Authenticated**

  * Condition: `valid credentials`

* **Validating → Failed**

  * Condition: `invalid credentials`

* **Failed → EnterCredentials**

  * Trigger: `retry`

* **Failed → Locked**

  * Condition: `too many attempts {rate_limit}`

* **Locked → End**

* **Authenticated → SessionActive**

  * Action: `create session {secure_token}`

* **SessionActive → Logout**

  * Trigger: `user logout`

* **SessionActive → Timeout**

  * Condition: `inactivity`

* **Logout → Idle**

* **Timeout → Idle**


# Sequence Diagram Details

## Title: IoT Device

### States and Transitions

* **Start → Unregistered**

* **Unregistered → entry / assignAPIKey {secure}**

  * Trigger: `register_device {valid_id / authenticate {auth}}`

* **entry / assignAPIKey {secure} → SendingData**

  * Trigger: `start_comm / TLSHandshake {encrypted}`

---

### SendingData

* **Start → entry / sendPackets**

* **entry / sendPackets → entry / sendPackets**

  * Trigger: `continuous_send`

* **entry / sendPackets → Monitoring**

  * Trigger: `data_sent`

---

### Monitoring

* **[H] → AnalyzeTraffic**

* **Start → AnalyzeTraffic**

* **AnalyzeTraffic → Decision**

* **Decision → Normal**

  * Condition: `safe`

* **Decision → Normal**

  * Condition: `no_anomaly`

* **Decision → Suspicious**

  * Condition: `threat`

* **AnalyzeTraffic → Suspicious**

  * Condition: `anomaly_detected {critical}`

* **Normal → Monitoring**

  * Trigger: `continue_monitoring`

---

* **Suspicious → entry / markDevice**

  * Trigger: `generate_alert / logEvent {secure_log}`

* **entry / markDevice → ApplyPolicy**

* **entry / markDevice → NotifyAdmin**

* **ApplyPolicy → (join)**

* **NotifyAdmin → (join)**

* **(join) → entry / disconnectDevice**

  * Trigger: `isolate_device / firewall_block {auth}`

* **entry / disconnectDevice → End**


# Sequence Diagram Details

## Title: Detection Engine

### States and Transitions

* **Start → entry / listenTraffic**

* **entry / listenTraffic → entry / listenTraffic**

  * Trigger: `continuous_monitoring`

* **entry / listenTraffic → entry / bufferData**

  * Trigger: `incoming_data`

* **entry / bufferData → entry / integrityCheck {integrity}**

---

### entry / integrityCheck {integrity}

* **Start → PreProcessing**

* **[H] → PreProcessing**

* **PreProcessing → FeatureExtraction**

* **FeatureExtraction → Done**

* **Done → End**

---

* **entry / integrityCheck {integrity} → CompareRules**

  * Trigger: `process`

* **CompareRules → Normal**

  * Condition: `no_anomaly`

* **CompareRules → Decision**

* **Decision → Normal**

  * Condition: `safe`

* **Decision → ThreatDetected**

  * Condition: `threat`

* **CompareRules → ThreatDetected**

  * Condition: `suspicious_pattern {critical}`

* **Normal → entry / listenTraffic**

* **ThreatDetected → entry / writeTamperProofLog**

  * Trigger: `create_alert {secure_log}`

* **entry / writeTamperProofLog → NotifyAdmin**

  * Trigger: `send_notification`

* **NotifyAdmin → End**

  * Trigger: `shutdown`

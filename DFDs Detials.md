# DFDs Details

## Level 0

### Entities
- Admin
- IoT Devices

### System
- System

### Trust Boundary
- Trust Boundary - Internet

### Data Flows
1. Admin → System  
   - Login Requests HTTPS

2. System → Admin  
   - Dashboard Alerts HTTPS

3. System → IoT Devices  
   - Control Commands

4. IoT Devices → System  
   - Network Traffic TLS


   # DFDs Details

## Level 1

### Entities
- Admin
- IoT Devices

### Processes
- Authentication
- Dashboard
- Device Registration
- Traffic Analysis
- Threat Response

### Data Stores
- Admin Credentials
- Device Registry
- Traffic Logs
- Alerts

### External Network
- External Network

### Layers
- Database Layer
- Processing Layer

### Data Flows
1. Admin → Authentication  
   - Login HTTPS

2. Authentication → Admin  
   - Auth Token

3. Admin → Dashboard  
   - Dashboard Request

4. Dashboard → Device Registry

5. Authentication → Admin Credentials

6. Device Registration → Device Registry

7. Device Registration → Traffic Logs

8. IoT Devices → Device Registration  
   - Traffic Data TLS

9. Traffic Logs → Traffic Analysis

10. Traffic Analysis → Threat Response

11. Threat Response → IoT Devices  
   - Block Device

12. Threat Response → Alerts

13. Dashboard → Alerts


# DFDs Details

## Level 2 - Traffic Analysis

### Processes
- Data Collection
- Preprocessing
- Behavior Analysis
- Anomaly Detection
- Alert Generation

### Data Stores
- Traffic Logs
- Alerts

### Data Flows
1. Traffic Logs → Data Collection

2. Data Collection → Preprocessing

3. Preprocessing → Behavior Analysis

4. Behavior Analysis → Anomaly Detection  
   - Analysis Engine

5. Anomaly Detection → Alert Generation

6. Alert Generation → Alerts


# DFD Details - Level 2 (Authentication)

## External Entities
- Admin

## Processes
- Input Validation
- Verification
- Session Management

## Data Stores
- Admin Credentials

## Subsystem
- Auth Server

## Data Flows
- Admin → Input Validation
- Input Validation → Verification
- Verification → Admin Credentials
- Verification → Session Management
- Session Management → Admin: Session Token


# DFD Details - Level 2 (Device Registration)

## External Entities
- IoT Device

## Processes
- Device Identification
- Data Validation
- Device Registration
- Traffic Monitoring

## Data Stores
- Device Registry
- Traffic Logs

## Layers
- Application Layer
- Secure Storage

## Data Flows
- IoT Device → Device Identification: Device Info
- Device Identification → Data Validation
- Data Validation → Device Registration
- Device Registration → Device Registry
- IoT Device → Traffic Monitoring: Traffic Data
- Traffic Monitoring → Traffic Logs


# DFDs Details.md

## Level 2 DFD - Dashboard

### External Entities
- Admin

### Processes
1. Request Handling
2. Data Retrieval
3. Data Processing
4. Visualization

### Data Stores
- Device Registry
- Alerts

### Data Flows

#### Admin → Request Handling
- Dashboard Request

#### Request Handling → Data Retrieval
- Internal Flow

#### Data Retrieval ↔ Data Stores
- Device Registry (Data Retrieval → Device Registry)
- Alerts (Data Retrieval → Alerts)

#### Data Retrieval → Data Processing
- Web Application Layer

#### Data Processing → Visualization
- Internal Flow

#### Visualization → Admin
- Dashboard Output

### System Boundaries
- Web Application Layer (contains Request Handling, Data Retrieval, Data Processing, Visualization)
- Database Layer (contains Device Registry, Alerts)


# DFDs Details.md

## Level 2 DFD - Threat Response

### External Entities
- IoT Device

### Processes
1. Threat Evaluation
2. Decision Making
3. Action Execution
4. Alert Logging

### Data Stores
- Alerts

### Data Flows

#### Threat Evaluation → Decision Making
- Internal Flow

#### Decision Making → Action Execution
- Processing Layer

#### Action Execution → IoT Device
- Block or Isolate

#### Action Execution → Alert Logging
- Internal Flow

#### Alert Logging → Alerts
- Alerts

### System Boundaries
- Processing Layer (contains Threat Evaluation, Decision Making, Action Execution, Alert Logging)